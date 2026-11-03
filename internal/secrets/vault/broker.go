package vault

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Decision is the person's answer to "may this program have this secret".
type Decision string

const (
	AllowOnce   Decision = "ALLOW_ONCE"
	Allow8h     Decision = "ALLOW_8H"
	AllowAlways Decision = "ALLOW_ALWAYS"
	Deny        Decision = "DENY"
)

// Request is a program asking for a vaulted secret. Owner is the user the request comes from
// (the OS says so, the caller cannot claim it); a vault entry belongs to one owner and is
// never released to another. Program and SHA name the requesting binary: its full path and the
// SHA-256 of the file as it was read through the pinned process.
type Request struct {
	Kind    string
	Ref     string
	Owner   string
	Program string
	SHA     string
	// ViaAI: the program runs under an AI tool (its process chain leads to one). Such a request is
	// never answered by a standing grant, and an "8 hours" or "always" answer counts once.
	ViaAI bool
}

// interpreters run whatever script they are given, so a grant to one is a grant to any code.
var interpreters = map[string]bool{
	"python": true, "node": true, "bash": true, "sh": true, "dash": true, "zsh": true, "fish": true, "ksh": true,
	"pwsh": true, "powershell": true, "cmd": true, "ruby": true, "perl": true, "php": true, "deno": true, "bun": true,
	"java": true, "lua": true, "osascript": true, "wscript": true, "cscript": true, "env": true, "busybox": true,
}

// isInterpreter matches the program's file name without ".exe" and version digits (python3.12).
func isInterpreter(program string) bool {
	n := strings.ToLower(program)
	if i := strings.LastIndexAny(n, `/\`); i >= 0 {
		n = n[i+1:]
	}
	n = strings.TrimSuffix(n, ".exe")
	n = strings.TrimRight(n, "0123456789.-")
	return interpreters[n]
}

// standingGrants is false where the requesting binary cannot be pinned to its caller: on Windows
// any program of the same user can start the helper with another parent process recorded
// (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS), so a grant to a binary would be a grant to everyone.
var standingGrants = runtime.GOOS != "windows"

// OnceOnly reports whether the request can only be answered for this one call: no standing
// grant is looked up for it and none is kept from the answer.
func OnceOnly(r Request) bool {
	return r.Kind == kindRestore || r.Program == "" || r.SHA == "" || r.ViaAI || isInterpreter(r.Program) || !standingGrants
}

// Approver asks the person. WARDEN's prompt replaces the console approval path by supplying
// another implementation to Broker.
type Approver interface {
	Ask(ctx context.Context, r Request) (Decision, error)
}

type grant struct {
	Until  time.Time `json:"until,omitempty"`
	Always bool      `json:"always,omitempty"`
}

type flight struct {
	done chan struct{}
	d    Decision
}

// Broker releases vaulted secrets: a standing grant, or an answer from the Approver. It never
// releases on an error. Prompts for different programs wait side by side; the lock is never
// held while a person is asked.
type Broker struct {
	V        *Vault
	A        Approver
	Now      func() time.Time
	OnDenied func(Request) // optional: reported to Manar

	mu       sync.Mutex
	inflight map[string]*flight
}

func (b *Broker) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// The grant belongs to the owner, the secret, and the exact binary (path and hash): a changed
// binary asks again.
func grantKey(r Request) string {
	return sum([]byte(r.Owner + "\x00" + r.Kind + "\x00" + r.Ref + "\x00" + r.Program + "\x00" + r.SHA))[:24]
}

func (b *Broker) grants() map[string]grant {
	m := map[string]grant{}
	if raw, err := b.V.Store.Get("grants"); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func (b *Broker) saveGrants(m map[string]grant) error {
	raw, _ := json.Marshal(m)
	return b.V.Store.Put("grants", raw)
}

var errNotAllowed = errors.New("Manar: access to this secret was not allowed")

// Credential returns the AWS secret for a request, or an error.
func (b *Broker) Credential(ctx context.Context, r Request) ([]byte, error) {
	if r.Kind != "aws" || r.Owner == "" {
		return nil, errors.New("unsupported secret request")
	}
	if err := b.Authorize(ctx, r); err != nil {
		return nil, err
	}
	return b.V.AWSCredentialProcess(r.Owner, r.Ref)
}

// Authorize is the whole release decision for a vaulted secret (aws profile or ssh key): a standing
// grant for this exact binary, or the person's answer. It returns nil only for an allow. Concurrent
// asks for the same program and secret share one question.
func (b *Broker) Authorize(ctx context.Context, r Request) error {
	if r.Owner == "" {
		return errors.New("unsupported secret request")
	}
	restore := r.Kind == kindRestore
	if !restore {
		if _, err := b.V.Entry(r.Owner, r.Kind, r.Ref); err != nil {
			return errors.New("no such secret in the vault for you")
		}
	}
	key := grantKey(r)
	b.mu.Lock()
	g, ok := b.grants()[key]
	if !OnceOnly(r) && ok && (g.Always || b.now().Before(g.Until)) {
		b.mu.Unlock()
		return nil
	}
	if f, running := b.inflight[key]; running { // the same program is already being asked
		b.mu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		if f.d == Deny || f.d == "" {
			return errNotAllowed
		}
		return nil
	}
	f := &flight{done: make(chan struct{})}
	if b.inflight == nil {
		b.inflight = map[string]*flight{}
	}
	b.inflight[key] = f
	b.mu.Unlock()

	d, err := b.A.Ask(ctx, r) // no lock held while the person decides
	if err != nil || (d != AllowOnce && d != Allow8h && d != AllowAlways) {
		d = Deny
	}

	b.mu.Lock()
	if !OnceOnly(r) { // never keep a standing grant for a binary we could not pin, or for an AI tool's call
		switch d {
		case Allow8h:
			m := b.grants()
			m[key] = grant{Until: b.now().Add(8 * time.Hour)}
			_ = b.saveGrants(m)
		case AllowAlways:
			m := b.grants()
			m[key] = grant{Always: true}
			_ = b.saveGrants(m)
		}
	}
	f.d = d
	delete(b.inflight, key)
	close(f.done)
	b.mu.Unlock()

	if d == Deny {
		if b.OnDenied != nil {
			b.OnDenied(r)
		}
		return errNotAllowed
	}
	return nil
}

// kindRestore is the approval kind for "take this key out of the vault". Only a one-time answer
// counts: no standing grant is ever kept for it.
const kindRestore = "ssh-restore"

// AuthorizeRestore asks the person before an AI tool's own restore request is carried out. toolPID
// is the AI tool of the caller's chain; ref is the key name, or "" for all of the user's keys.
func (b *Broker) AuthorizeRestore(ctx context.Context, toolPID int, owner, ref string) error {
	if b == nil || b.A == nil {
		return errNotAllowed
	}
	path, sha := "", ""
	if HashExe != nil && toolPID > 0 {
		path, sha = HashExe(toolPID)
	}
	if ref == "" {
		ref = "*"
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute+10*time.Second)
	defer cancel()
	return b.Authorize(ctx, Request{Kind: kindRestore, Ref: ref, Owner: owner, Program: path, SHA: sha})
}
