package watch

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/secrets/vault"
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

// Default founder policy end to end: a key is denied, the question is asked once, "always" lets the
// program's next open through and survives a restart; .env stays alert-only.
func TestKeysDeniedThenAskedOnceThenAllowed(t *testing.T) {
	const key, env = "/home/alice/.ssh/id_ed25519", "/home/alice/app/.env"
	ap := &fakeApprover{d: vault.AllowAlways}
	path := filepath.Join(t.TempDir(), "g.json")
	out := make(chan Event, 16)
	src := newFake(PermEvent{PID: 12, Path: key, Handle: 1}, PermEvent{PID: 12, Path: key, Handle: 2}, PermEvent{PID: 12, Path: env, Handle: 3})
	e, _ := engineFor(src, treeCursorAndTerminal, true)
	e.Gate = &Gate{Approver: ap, Out: out, Path: path}
	e.Mode = func() Mode { return ModeKeys }
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	_ = e.Run(ctx)
	if ok, _ := src.answered(1); ok {
		t.Fatal("the first open of a key by an AI tool must be denied")
	}
	if ok, _ := src.answered(3); !ok {
		t.Fatal(".env is alert-only in the default mode")
	}
	eventually(t, func() bool { return ap.n() >= 1 })
	if ap.n() != 1 || ap.calls[0].Kind != "file" || ap.calls[0].Ref != ClassSSH {
		t.Fatalf("one question for ssh keys: %+v", ap.calls)
	}
	// A new engine (a restart) reads the grant from disk and lets the program through.
	g2 := &Gate{Approver: ap, Out: out, Path: path}
	src2 := newFake(PermEvent{PID: 12, Path: key, Handle: 9})
	e2, _ := engineFor(src2, treeCursorAndTerminal, true)
	e2.Gate = g2
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { time.Sleep(60 * time.Millisecond); cancel2() }()
	_ = e2.Run(ctx2)
	if ok, _ := src2.answered(9); !ok {
		t.Fatal("always-allowed program must pass after a restart")
	}
	if ap.n() != 1 {
		t.Fatal("must not ask again")
	}
}

func TestNoAnswerIsDenyAndLoggedAndNotAskedAgainAtOnce(t *testing.T) {
	ap := &fakeApprover{block: make(chan struct{})} // nobody answers
	out := make(chan Event, 16)
	g := &Gate{Approver: ap, Out: out, Wait: 40 * time.Millisecond}
	k := GateKey{Tool: "host.cursor", Class: ClassAWS, Exe: "/x/cursor-agent"}
	g.Ask(k, Proc{Exe: k.Exe})
	g.Ask(k, Proc{Exe: k.Exe}) // same question is already open
	select {
	case ev := <-out:
		if ev.Type != "secret.vault.denied" || !ev.Blocked || ev.PathClass != ClassAWS {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no denial logged")
	}
	if g.Allows(k) || ap.n() != 1 {
		t.Fatal("no answer must not grant, and one question only")
	}
	g.Ask(k, Proc{Exe: k.Exe}) // inside the cooldown
	time.Sleep(30 * time.Millisecond)
	if ap.n() != 1 {
		t.Fatal("asked again inside the cooldown")
	}
}

func TestOnceExpires(t *testing.T) {
	now := time.Now()
	ap := &fakeApprover{d: vault.AllowOnce}
	g := &Gate{Approver: ap, Out: make(chan Event, 4), Now: func() time.Time { return now }}
	k := GateKey{Tool: "host.codex-cli", Class: ClassNPM, Exe: "/x/codex"}
	g.Ask(k, Proc{Exe: k.Exe})
	eventually(t, func() bool { return g.Allows(k) })
	now = now.Add(2 * time.Minute)
	if g.Allows(k) {
		t.Fatal("allow once is a short window")
	}
}

func TestGrantFileIsOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "g.json")
	ap := &fakeApprover{d: vault.AllowAlways}
	g := &Gate{Approver: ap, Out: make(chan Event, 4), Path: p}
	k := GateKey{Tool: "t", Class: ClassSSH, Exe: "/x"}
	g.Ask(k, Proc{Exe: "/x"})
	eventually(t, func() bool { _, err := os.Stat(p); return err == nil })
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}
