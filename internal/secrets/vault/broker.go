package vault

import (
	"context"
	"encoding/json"
	"errors"
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
	if _, err := b.V.Entry(r.Owner, r.Kind, r.Ref); err != nil {
		return errors.New("no such secret in the vault for you")
	}
	key := grantKey(r)
	b.mu.Lock()
	g, ok := b.grants()[key]
	if r.Program != "" && r.SHA != "" && ok && (g.Always || b.now().Before(g.Until)) {
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
	if r.Program != "" && r.SHA != "" { // never keep a standing grant for a binary we could not pin
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
