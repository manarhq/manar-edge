package watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/secrets/vault"
)

// Gate is "WARDEN asks once per program". A denied open starts one question (never inside the
// permission path); the answer is remembered, so the program's next try passes. The question goes
// through vault.Approver, which WARDEN's prompt replaces.
//
// Once means a 60 second window: the program retries after the person said yes and a git push or
// an aws call may open its key several times. 8 hours and Always are kept on disk (0600) so a
// restart does not ask again. A grant belongs to (tool, file class, tool executable path).
//
// ponytail: the grant is not tied to the binary hash (the catalogue itself matches on paths); add
// the hash to Key if a path-swap threat matters.
type Gate struct {
	Approver vault.Approver
	Out      chan<- Event
	Path     string // grants file; empty keeps them in memory only
	Now      func() time.Time
	// Wait bounds one question. No answer in this time is a denial, logged.
	Wait time.Duration

	mu       sync.Mutex
	grants   map[string]gateGrant
	inflight map[string]bool
	denied   map[string]time.Time
	shas     map[string]string
}

type gateGrant struct {
	Until  time.Time `json:"until,omitempty"`
	Always bool      `json:"always,omitempty"`
}

// GateKey names what a grant covers.
type GateKey struct{ Tool, Class, Exe string }

func (k GateKey) s() string { return k.Tool + "\x00" + k.Class + "\x00" + k.Exe }

const (
	onceWindow     = 60 * time.Second
	denyCooldown   = 5 * time.Minute
	defaultAskWait = 2 * time.Minute
)

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gate) load() {
	if g.grants != nil {
		return
	}
	g.grants, g.inflight, g.denied, g.shas = map[string]gateGrant{}, map[string]bool{}, map[string]time.Time{}, map[string]string{}
	if g.Path == "" {
		return
	}
	if raw, err := os.ReadFile(g.Path); err == nil {
		_ = json.Unmarshal(raw, &g.grants)
	}
}

// Allows is the check on the permission path: memory only, no I/O.
func (g *Gate) Allows(k GateKey) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.load()
	gr, ok := g.grants[k.s()]
	return ok && (gr.Always || g.now().Before(gr.Until))
}

// Ask starts the question for k unless one is open or the person just said no. It returns at once.
func (g *Gate) Ask(k GateKey, toolProc Proc) {
	if g.Approver == nil {
		return
	}
	g.mu.Lock()
	g.load()
	if g.inflight[k.s()] || g.now().Sub(g.denied[k.s()]) < denyCooldown {
		g.mu.Unlock()
		return
	}
	g.inflight[k.s()] = true
	g.mu.Unlock()
	go g.ask(k, toolProc)
}

func (g *Gate) ask(k GateKey, p Proc) {
	defer func() { _ = recover() }()
	wait := g.Wait
	if wait <= 0 {
		wait = defaultAskWait
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	d, err := g.Approver.Ask(ctx, vault.Request{Kind: "file", Ref: k.Class, Program: k.Exe, SHA: g.sha(k.Exe)})
	g.mu.Lock()
	delete(g.inflight, k.s())
	switch {
	case err == nil && d == vault.AllowOnce:
		g.grants[k.s()] = gateGrant{Until: g.now().Add(onceWindow)}
	case err == nil && d == vault.Allow8h:
		g.grants[k.s()] = gateGrant{Until: g.now().Add(8 * time.Hour)}
	case err == nil && d == vault.AllowAlways:
		g.grants[k.s()] = gateGrant{Always: true}
	default:
		g.denied[k.s()] = g.now()
		d = vault.Deny
	}
	g.save()
	g.mu.Unlock()
	if d == vault.Deny { // an unanswered question is a denial and is logged as one
		select {
		case g.Out <- Event{Type: "secret.vault.denied", ToolID: k.Tool, Process: filepath.Base(p.Exe), PathClass: k.Class, Blocked: true, At: g.now().UTC()}:
		default:
		}
	}
}

func (g *Gate) save() { // caller holds mu
	if g.Path == "" {
		return
	}
	keep := map[string]gateGrant{}
	for k, v := range g.grants {
		if v.Always || g.now().Before(v.Until) {
			keep[k] = v
		}
	}
	g.grants = keep
	raw, _ := json.Marshal(keep)
	_ = os.MkdirAll(filepath.Dir(g.Path), 0o700)
	tmp := g.Path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("manar-edge: saving secret grants: %v", err)
		return
	}
	_ = os.Rename(tmp, g.Path)
}

// sha is the SHA-256 of the program the question names (cached by path). An unreadable file gives
// a fixed placeholder; the prompt shows the path as well.
func (g *Gate) sha(exe string) string {
	g.mu.Lock()
	s, ok := g.shas[exe]
	g.mu.Unlock()
	if ok {
		return s
	}
	s = "0000000000000000000000000000000000000000000000000000000000000000"
	if f, err := os.Open(exe); err == nil {
		h := sha256.New()
		if _, err := io.Copy(h, f); err == nil {
			s = hex.EncodeToString(h.Sum(nil))
		}
		f.Close()
	}
	g.mu.Lock()
	g.shas[exe] = s
	g.mu.Unlock()
	return s
}
