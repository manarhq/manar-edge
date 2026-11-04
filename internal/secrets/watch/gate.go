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
	"strconv"
	"sync"
	"time"

	"github.com/manarhq/manar-edge/internal/secrets/vault"
)

// Gate is "WARDEN asks once per program". A denied open starts one question (never inside the
// permission path); the answer is remembered, so the program's next try passes. The question goes
// through vault.Approver, which WARDEN's prompt replaces.
//
// Once means a 60 second window: the program retries after the person said yes and a git push or
// an aws call may open its key several times. 8 hours and Always are kept on disk (0600) so a
// restart does not ask again. A grant belongs to (tool, file class, tool executable path).
//
// A grant is tied to the user and to the executable's hash. The hash is taken from the opening
// process's own /proc/<pid>/exe link (not the path), cached by file identity (device, inode, size,
// mtime). Hashing a big binary can take longer than the permission path may wait, so the first
// open of a program is always refused and hashed in the background; the question follows.
type Gate struct {
	Approver vault.Approver
	Out      chan<- Event
	Path     string // grants file; empty keeps them in memory only
	Now      func() time.Time
	// Wait bounds one question. No answer in this time is a denial, logged.
	Wait time.Duration

	// Open returns the executable of a running process through its /proc link. Tests replace it.
	Open func(pid int) (*os.File, error)

	mu       sync.Mutex
	grants   map[string]gateGrant
	inflight map[string]bool
	denied   map[string]time.Time
	shas     map[fileID]string
}

type fileID struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

type gateGrant struct {
	Until  time.Time `json:"until,omitempty"`
	Always bool      `json:"always,omitempty"`
	// ID is the console request behind an "8 hours" or "Always" grant: it counts only while the
	// server lists it (vault.ServerAllows). Once is the 60-second "allow once" window.
	ID   string `json:"id,omitempty"`
	Once bool   `json:"once,omitempty"`
}

// GateKey names what a grant covers: the user the program runs as, the tool, the file class, the
// tool's executable path and the SHA-256 of that executable as it was when the open happened.
type GateKey struct {
	UID              int
	Tool, Class, Exe string
	SHA              string
}

func (k GateKey) s() string {
	return strconv.Itoa(k.UID) + "\x00" + k.Tool + "\x00" + k.Class + "\x00" + k.Exe + "\x00" + k.SHA
}

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
	g.grants, g.inflight, g.denied, g.shas = map[string]gateGrant{}, map[string]bool{}, map[string]time.Time{}, map[fileID]string{}
	if g.Path == "" {
		return
	}
	if raw, err := os.ReadFile(g.Path); err == nil {
		_ = json.Unmarshal(raw, &g.grants)
	}
}

func (g *Gate) open(pid int) (*os.File, error) {
	if g.Open != nil {
		return g.Open(pid)
	}
	return os.Open("/proc/" + strconv.Itoa(pid) + "/exe")
}

// Decide is the check on the permission path: a /proc open and a stat, memory lookups, no hashing,
// no network. It returns true when the person allowed this program (same user, same executable
// bytes). Otherwise it makes sure one question is on its way and returns false.
func (g *Gate) Decide(pid int, k GateKey) bool {
	f, err := g.open(pid)
	if err != nil {
		return false // cannot pin the program: refuse, no standing grant can apply
	}
	id, ok := identify(f)
	g.mu.Lock()
	g.load()
	sha, cached := g.shas[id]
	g.mu.Unlock()
	if !ok {
		f.Close()
		return false
	}
	if !cached {
		go g.hashThenAsk(f, id, k) // the file stays open so a process that exits is still hashed
		return false
	}
	f.Close()
	k.SHA = sha
	if g.allows(k) {
		return true
	}
	g.ask(k)
	return false
}

func (g *Gate) hashThenAsk(f *os.File, id fileID, k GateKey) {
	defer f.Close()
	defer func() { _ = recover() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		g.deny(k, "") // not hashed: no question, no grant
		return
	}
	sha := hex.EncodeToString(h.Sum(nil))
	g.mu.Lock()
	if len(g.shas) > 256 {
		clear(g.shas)
	}
	g.shas[id] = sha
	g.mu.Unlock()
	k.SHA = sha
	if !g.allows(k) { // a stored grant only needed the hash; the next open passes
		g.ask(k)
	}
}

func (g *Gate) allows(k GateKey) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.load()
	gr, ok := g.grants[k.s()]
	return ok && (gr.Always || g.now().Before(gr.Until)) && (gr.Once || vault.ServerAllows(gr.ID, g.now()))
}

// ask starts the question for k unless one is open or the person just said no. It returns at once.
func (g *Gate) ask(k GateKey) {
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
	go g.run(k)
}

func (g *Gate) run(k GateKey) {
	defer func() { _ = recover() }()
	wait := g.Wait
	if wait <= 0 {
		wait = defaultAskWait
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Owner is the user the program runs as: that user's prompt, nobody else's.
	d, id, err := vault.AskGrant(ctx, g.Approver, vault.Request{Kind: "file", Ref: k.Class, Owner: strconv.Itoa(k.UID), Program: k.Exe, SHA: k.SHA})
	g.mu.Lock()
	delete(g.inflight, k.s())
	switch {
	case err == nil && d == vault.AllowOnce:
		g.grants[k.s()] = gateGrant{Until: g.now().Add(onceWindow), Once: true}
	case err == nil && d == vault.Allow8h:
		g.grants[k.s()] = gateGrant{Until: g.now().Add(8 * time.Hour), ID: id}
	case err == nil && d == vault.AllowAlways:
		g.grants[k.s()] = gateGrant{Always: true, ID: id}
	default:
		d = vault.Deny
	}
	g.save()
	g.mu.Unlock()
	if d == vault.Deny { // an unanswered question is a denial and is logged as one
		g.deny(k, "")
	}
}

// deny remembers a refusal (no new question for a while) and logs it.
func (g *Gate) deny(k GateKey, _ string) {
	g.mu.Lock()
	g.load()
	g.denied[k.s()] = g.now()
	g.mu.Unlock()
	select {
	case g.Out <- Event{Type: "secret.vault.denied", ToolID: k.Tool, Process: filepath.Base(k.Exe), PathClass: k.Class, Blocked: true, At: g.now().UTC()}:
	default:
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
