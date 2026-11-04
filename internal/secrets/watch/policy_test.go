package watch

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/secrets/vault"
)

func TestModeFromFeaturesAndBlocks(t *testing.T) {
	if ModeFromFeatures(nil) != ModeAlert || ModeFromFeatures([]string{"secrets.block"}) != ModeKeys ||
		ModeFromFeatures([]string{"secrets.block", "secrets.block.all"}) != ModeAll {
		t.Fatal("mode from features")
	}
	for _, c := range []string{ClassSSH, ClassAWS, ClassAzure, ClassGCloud, ClassNPM, ClassPyPI, ClassGitHub} {
		if !ModeKeys.Blocks(c) {
			t.Errorf("keys mode must block %s", c)
		}
	}
	for _, c := range []string{ClassEnv, ClassKube, ClassDocker, ClassBrowser} {
		if ModeKeys.Blocks(c) || !ModeAll.Blocks(c) || ModeAlert.Blocks(c) {
			t.Errorf("%s: alert-only in keys, blocked in all", c)
		}
	}
	if ModeAll.Blocks("") {
		t.Error("not a secret file")
	}
}

func TestTokenFileClasses(t *testing.T) {
	for p, want := range map[string]string{
		"/home/a/.npmrc": ClassNPM, "/home/a/.pypirc": ClassPyPI, "/home/a/.git-credentials": ClassGitHub,
		"/home/a/.config/gh/hosts.yml": ClassGitHub, "/home/a/app/node_modules/x/.npmrc": "", "/home/a/.config/gh/config.yml": "",
	} {
		if got := ClassOf(p); got != want {
			t.Errorf("%s: %q want %q", p, got, want)
		}
	}
}

type fakeApprover struct {
	mu    sync.Mutex
	calls []vault.Request
	d     vault.Decision
	block chan struct{}
}

func (f *fakeApprover) Ask(ctx context.Context, r vault.Request) (vault.Decision, error) {
	f.mu.Lock()
	f.calls = append(f.calls, r)
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return vault.Deny, ctx.Err()
		}
	}
	return f.d, nil
}
func (f *fakeApprover) n() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

// AskGrant: every answer comes from console request "w1", which the server lists (TestMain).
func (f *fakeApprover) AskGrant(ctx context.Context, r vault.Request) (vault.Decision, string, error) {
	d, err := f.Ask(ctx, r)
	return d, "w1", err
}

func TestMain(m *testing.M) {
	vault.SetServerGrants([]hostclient.VaultGrant{{ID: "w1"}}, time.Now())
	os.Exit(m.Run())
}

// A standing grant withdrawn in the console (the server's list no longer names it) is asked again.
func TestWithdrawnGrantIsAskedAgain(t *testing.T) {
	defer vault.SetServerGrants([]hostclient.VaultGrant{{ID: "w1"}}, time.Now())
	ap := &fakeApprover{d: vault.AllowAlways}
	var exe string
	g := gateWith(t, ap, "", &exe)
	decideEventually(t, g, key1)
	vault.SetServerGrants([]hostclient.VaultGrant{}, time.Now())
	if g.Decide(1, key1) {
		t.Fatal("a withdrawn grant still let the program through")
	}
	eventually(t, func() bool { return ap.n() == 2 })
}

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout")
}

var testOut = make(chan Event, 64)

// gateWith builds a Gate whose "executable of pid" is a temp file with the given bytes.
func gateWith(t *testing.T, ap vault.Approver, path string, exe *string) *Gate {
	t.Helper()
	if *exe == "" {
		*exe = filepath.Join(t.TempDir(), "cursor-agent")
		_ = os.WriteFile(*exe, []byte("binary v1"), 0o755)
	}
	return &Gate{Approver: ap, Out: testOut, Path: path,
		Open: func(int) (*os.File, error) { return os.Open(*exe) }}
}

func decideEventually(t *testing.T, g *Gate, k GateKey) {
	t.Helper()
	eventually(t, func() bool { return g.Decide(1, k) })
}

var key1 = GateKey{UID: 1000, Tool: "host.cursor", Class: ClassSSH, Exe: "/x/cursor-agent"}

// Default founder policy end to end: a key is denied, the question is asked once, "always" lets the
// program's next open through and survives a restart; .env stays alert-only.
func TestKeysDeniedThenAskedOnceThenAllowed(t *testing.T) {
	const key, env = "/home/alice/.ssh/id_ed25519", "/home/alice/app/.env"
	ap := &fakeApprover{d: vault.AllowAlways}
	path := filepath.Join(t.TempDir(), "g.json")
	var exe string
	g := gateWith(t, ap, path, &exe)
	src := newFake(PermEvent{PID: 12, Path: key, Handle: 1}, PermEvent{PID: 12, Path: env, Handle: 3})
	e, _ := engineFor(src, treeCursorAndTerminal, true)
	e.Gate = g
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	_ = e.Run(ctx)
	if ok, _ := src.answered(1); ok {
		t.Fatal("the first open of a key by an AI tool must be denied")
	}
	if ok, _ := src.answered(3); !ok {
		t.Fatal(".env is alert-only in the default mode")
	}
	eventually(t, func() bool { return ap.n() == 1 })
	if c := ap.calls[0]; c.Kind != "file" || c.Ref != ClassSSH || c.Owner != "1000" || len(c.SHA) != 64 {
		t.Fatalf("one question for ssh keys, naming the user and the hash: %+v", c)
	}
	k := GateKey{UID: 1000, Tool: "host.cursor", Class: ClassSSH, Exe: treeCursorAndTerminal[10].Exe}
	decideEventually(t, g, k)
	// A restart reads the grant from disk (hashing the program again) and does not ask again.
	g2 := gateWith(t, ap, path, &exe)
	decideEventually(t, g2, k)
	if ap.n() != 1 {
		t.Fatal("must not ask again")
	}
}

func TestGrantDoesNotCrossUsersOrBinaries(t *testing.T) {
	ap := &fakeApprover{d: vault.AllowAlways}
	var exe string
	g := gateWith(t, ap, "", &exe)
	decideEventually(t, g, key1)
	other := key1
	other.UID = 1001
	if g.Decide(1, other) {
		t.Fatal("another user's process must not use this user's grant")
	}
	// The program changes (same path, new bytes): the grant no longer applies.
	time.Sleep(10 * time.Millisecond)
	_ = os.WriteFile(exe, []byte("binary v2, longer"), 0o755)
	if g.Decide(1, key1) {
		t.Fatal("a changed executable must not inherit the grant")
	}
}

// The owner comes from the open descriptor. A path swapped to another user's file between the
// event and the decision cannot matter, and an unknown owner never becomes an allow.
func TestOwnerFromDescriptorAndUnknownOwnerStaysDenied(t *testing.T) {
	for name, tc := range map[string]struct {
		ev      PermEvent
		unknown bool
	}{
		"file owned by another uid": {ev: PermEvent{PID: 12, Path: "/home/alice/.ssh/id_ed25519", Handle: 1, Owner: 1001, OwnerKnown: true}},
		"owner unknown":             {ev: PermEvent{PID: 12, Path: "/home/alice/.ssh/id_ed25519", Handle: 1}, unknown: true},
	} {
		t.Run(name, func(t *testing.T) {
			ap := &fakeApprover{d: vault.AllowAlways}
			var exe string
			g := gateWith(t, ap, "", &exe)
			src := newFake(tc.ev)
			src.unknownOwner = tc.unknown
			e, _ := engineFor(src, treeCursorAndTerminal, true)
			e.Gate = g
			ctx, cancel := context.WithCancel(context.Background())
			go func() { time.Sleep(80 * time.Millisecond); cancel() }()
			_ = e.Run(ctx)
			if ok, _ := src.answered(1); ok {
				t.Fatal("must stay denied")
			}
			time.Sleep(30 * time.Millisecond)
			if ap.n() != 0 {
				t.Fatal("nobody is asked")
			}
		})
	}
}

func TestUnhashableProgramIsDeniedNotGranted(t *testing.T) {
	ap := &fakeApprover{d: vault.AllowAlways}
	g := &Gate{Approver: ap, Out: make(chan Event, 4), Open: func(int) (*os.File, error) { return nil, os.ErrNotExist }}
	for i := 0; i < 3; i++ {
		if g.Decide(1, key1) {
			t.Fatal("a program that cannot be pinned is never allowed")
		}
	}
	if ap.n() != 0 {
		t.Fatal("no standing grant can come from an unpinned program")
	}
}

func TestNoAnswerIsDenyAndLoggedAndNotAskedAgainAtOnce(t *testing.T) {
	ap := &fakeApprover{block: make(chan struct{})} // nobody answers
	var exe string
	g := gateWith(t, ap, "", &exe)
	g.Wait = 40 * time.Millisecond
	g.Decide(1, key1)
	g.Decide(1, key1) // the same question is already open
	for len(testOut) > 0 {
		<-testOut
	}
	var ev Event
	select {
	case ev = <-testOut:
	case <-time.After(time.Second):
		t.Fatal("no denial logged")
	}
	if ev.Type != "secret.vault.denied" || !ev.Blocked || ev.PathClass != ClassSSH {
		t.Fatalf("%+v", ev)
	}
	if ap.n() != 1 {
		t.Fatal("one question only")
	}
	g.Decide(1, key1) // inside the cooldown
	time.Sleep(30 * time.Millisecond)
	if ap.n() != 1 {
		t.Fatal("asked again inside the cooldown")
	}
}

func TestOnceExpires(t *testing.T) {
	now := time.Now()
	ap := &fakeApprover{d: vault.AllowOnce}
	var exe string
	g := gateWith(t, ap, "", &exe)
	g.Now = func() time.Time { return now }
	decideEventually(t, g, key1)
	now = now.Add(2 * time.Minute)
	if g.Decide(1, key1) {
		t.Fatal("allow once is a short window")
	}
}

func TestGrantFileIsOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "g.json")
	var exe string
	g := gateWith(t, &fakeApprover{d: vault.AllowAlways}, p, &exe)
	decideEventually(t, g, key1)
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
}
