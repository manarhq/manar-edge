//go:build linux && fanotify_integration

package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/secrets/vault"
)

// Run as root: go test -tags fanotify_integration -run Fanotify ./internal/secrets/watch
// A process whose command line matches the catalogue (a copy of cat named like a Cursor agent
// path) is denied; a plain cat is allowed.
func TestFanotifyDeniesAIToolAllowsOthers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	home := t.TempDir()
	aws := filepath.Join(home, ".aws")
	_ = os.MkdirAll(aws, 0o700)
	cred := filepath.Join(aws, "credentials")
	_ = os.WriteFile(cred, []byte("[default]\n"), 0o600)
	src, err := newFanSource(true)
	if err != nil {
		t.Skipf("fanotify unavailable: %v", err)
	}
	if n := markAll(src, Targets(home), nil, nil, false); n == 0 {
		t.Fatal("no marks")
	}
	procs := newProcSource()
	out := make(chan Event, 8)
	e := &Engine{Src: src, Procs: procs, Mode: func() Mode { return ModeKeys }, Self: selfFunc(procs), Out: out,
		Homes: func() []string { return []string{home} }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct{})
	go func() { _ = e.Run(ctx); close(runDone) }()
	time.Sleep(200 * time.Millisecond)

	if err := exec.Command("/bin/cat", cred).Run(); err != nil {
		t.Fatalf("plain cat must be allowed: %v", err)
	}
	// Name the executable path like the Cursor agent's so the catalogue matches.
	dir := filepath.Join(home, ".local", "share", "cursor-agent")
	_ = os.MkdirAll(dir, 0o755)
	fake := filepath.Join(dir, "cat")
	b, _ := os.ReadFile("/bin/cat")
	_ = os.WriteFile(fake, b, 0o755)
	done := make(chan error, 1)
	go func() { done <- exec.Command(fake, cred).Run() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the AI tool's own process read the secret")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("open hung")
	}
	t.Logf("fake AI tool exe: %s", fake)
	cancel()
	<-runDone // no trace line after the test ends
}

// fakeAITool copies cat to a path the catalogue knows as the Cursor agent's.
func fakeAITool(t *testing.T, home string) string {
	t.Helper()
	dir := filepath.Join(home, ".local", "share", "cursor-agent")
	_ = os.MkdirAll(dir, 0o755)
	fake := filepath.Join(dir, "cat")
	b, _ := os.ReadFile("/bin/cat")
	if err := os.WriteFile(fake, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return fake
}

type allowAlways struct{}

func (allowAlways) Ask(context.Context, vault.Request) (vault.Decision, error) {
	return vault.AllowAlways, nil
}

// The founder default on a real kernel: the AI tool is denied an ssh key, the question is asked,
// after "always" the same program reads it; the person's own cat works throughout; .env is only
// reported.
func TestFanotifyKeysAskOnceEnvAlertOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	_ = os.WriteFile(key, []byte("KEY\n"), 0o600)
	envf := filepath.Join(home, ".env")
	_ = os.WriteFile(envf, []byte("A=1\n"), 0o600)
	perm, err := newFanSource(true)
	if err != nil {
		t.Skipf("fanotify unavailable: %v", err)
	}
	notif, _ := newFanSource(false)
	targets := Targets(home)
	markAll(perm, targets, []string{envf}, ModeKeys.Held, false)
	markAll(notif, targets, nil, func(c string) bool { return !ModeKeys.Held(c) }, false)
	procs := newProcSource()
	out := make(chan Event, 32)
	gate := &Gate{Approver: allowAlways{}, Out: out}
	mk := func(s Source) *Engine {
		return &Engine{Src: s, Procs: procs, Mode: func() Mode { return ModeKeys }, Gate: gate, Self: selfFunc(procs), Out: out,
			Homes: func() []string { return []string{home} }}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{}, 2)
	go func() { _ = mk(perm).Run(ctx); done <- struct{}{} }()
	go func() { _ = mk(notif).Run(ctx); done <- struct{}{} }()
	time.Sleep(200 * time.Millisecond)
	fake := fakeAITool(t, home)

	if err := exec.Command("/bin/cat", key).Run(); err != nil {
		t.Fatalf("the person's own cat must work: %v", err)
	}
	if err := exec.Command(fake, key).Run(); err == nil {
		t.Fatal("first open by the AI tool must be denied")
	}
	ok := false
	for i := 0; i < 50 && !ok; i++ { // the question is answered in the background
		time.Sleep(50 * time.Millisecond)
		ok = exec.Command(fake, key).Run() == nil
	}
	if !ok {
		t.Fatal("after always-allow the AI tool must read the key")
	}
	if err := exec.Command(fake, envf).Run(); err != nil {
		t.Fatalf(".env is alert-only: %v", err)
	}
	sawEnv := false
	for len(out) > 0 {
		if ev := <-out; ev.PathClass == ClassEnv && ev.ToolID == "host.cursor" && !ev.Blocked {
			sawEnv = true
		}
	}
	if !sawEnv {
		t.Fatal(".env read by the AI tool must be reported, not blocked")
	}
	if err := exec.Command("/bin/cat", key).Run(); err != nil {
		t.Fatalf("the person's own cat must still work: %v", err)
	}
	cancel()
	<-done
	<-done
}

// Recovery: if the daemon dies (kill -9) or is stopped, opens that were waiting for it go through.
// Run as: FANHOLD=<dir> re-executes this test binary as a holder that never answers.
func TestFanotifyHolderKilledReleasesOpens(t *testing.T) {
	if dir := os.Getenv("FANHOLD"); dir != "" {
		src, err := newFanSource(true)
		if err != nil {
			os.Exit(3)
		}
		markAll(src, Targets(dir), nil, nil, false)
		fmt.Println("ready")
		for { // take events, never answer them
			if _, err := src.Next(); err != nil && !errors.Is(err, ErrIdle) {
				os.Exit(0)
			}
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	_ = os.WriteFile(key, []byte("KEY\n"), 0o600)
	h := exec.Command(os.Args[0], "-test.run", "TestFanotifyHolderKilledReleasesOpens")
	h.Env = append(os.Environ(), "FANHOLD="+home)
	stdout, _ := h.StdoutPipe()
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	defer h.Process.Kill()
	buf := make([]byte, 6)
	if _, err := io.ReadFull(stdout, buf); err != nil || string(buf) != "ready\n" {
		t.Skipf("holder did not start (fanotify unavailable?): %v", err)
	}
	res := make(chan error, 1)
	go func() { res <- exec.Command("/bin/cat", key).Run() }()
	select {
	case <-res:
		t.Fatal("the open should wait for the holder")
	case <-time.After(500 * time.Millisecond):
	}
	_ = h.Process.Kill()
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("open after the holder died: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("open still hangs after the holder was killed: the user would be locked out")
	}
}

// A token file replaced the way npm, pip and editors do it (write a temp file, rename it over) must
// stay protected at once, not after the next rescan.
func TestFanotifyAtomicReplaceKeepsProtection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	home := t.TempDir()
	npmrc := filepath.Join(home, ".npmrc")
	_ = os.WriteFile(npmrc, []byte("//registry:_authToken=x\n"), 0o600)
	perm, err := newFanSource(true)
	if err != nil {
		t.Skipf("fanotify unavailable: %v", err)
	}
	if markAll(perm, Targets(home), nil, ModeKeys.Held, false) == 0 {
		t.Fatal("no marks")
	}
	procs := newProcSource()
	out := make(chan Event, 32)
	e := &Engine{Src: perm, Procs: procs, Mode: func() Mode { return ModeKeys }, Gate: &Gate{Out: out}, Self: selfFunc(procs), Out: out,
		Homes: func() []string { return []string{home} }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = e.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(200 * time.Millisecond)
	fake := fakeAITool(t, home)

	if exec.Command(fake, npmrc).Run() == nil {
		t.Fatal("before the replace: the unapproved program read the token file")
	}
	tmp := npmrc + ".tmp"
	_ = os.WriteFile(tmp, []byte("//registry:_authToken=y\n"), 0o600)
	if err := os.Rename(tmp, npmrc); err != nil {
		t.Fatal(err)
	}
	if exec.Command(fake, npmrc).Run() == nil {
		t.Fatal("after an atomic replace the unapproved program read the token file")
	}
	if err := exec.Command("/bin/cat", npmrc).Run(); err != nil {
		t.Fatalf("the person's own cat must work: %v", err)
	}
}

// Regression for the independent review: a blockable agent must not read a key by cutting itself
// off from its process tree (setsid, a pty, a script) or through a hard link. Needs the host's
// process connector: run with --pid=host --net=host --privileged.
func TestFanotifyEscapesAreBlocked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(ssh, 0o700)
	key := filepath.Join(ssh, "id_ed25519")
	_ = os.WriteFile(key, []byte("SECRET\n"), 0o600)
	src, err := newFanSource(true)
	if err != nil {
		t.Skipf("fanotify unavailable: %v", err)
	}
	if markAll(src, Targets(home), nil, ModeKeys.Held, false) == 0 {
		t.Fatal("no marks")
	}
	procs := newProcSource()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tainted := startTaint(ctx, procs)
	e := &Engine{Src: src, Procs: procsWithTaint(procs), Mode: func() Mode { return ModeKeys }, Self: selfFunc(procs),
		Out: make(chan Event, 256), Homes: func() []string { return []string{home} }, InodeClass: src.ClassOfInode}
	go func() { _ = e.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	dir := filepath.Join(home, ".local", "share", "cursor-agent")
	_ = os.MkdirAll(dir, 0o755)
	tool := filepath.Join(dir, "bash")
	b, _ := os.ReadFile("/bin/bash")
	_ = os.WriteFile(tool, b, 0o755)
	out := filepath.Join(home, "out")
	script := filepath.Join(home, "s.sh")
	_ = os.WriteFile(script, []byte("cat "+key+" > "+out+"\n"), 0o755)
	// hard links: made by the person before the agent runs (so only the inode identifies them) and
	// by the agent itself.
	if err := os.Link(key, filepath.Join(home, "pre-linked")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, script string
		needTaint    bool
	}{
		{"baseline", "cat " + key + " > " + out, false},
		{"hardlink-made-earlier", "cat " + home + "/pre-linked > " + out, false},
		{"hardlink-by-the-agent", "ln " + key + " " + home + "/k1 && cat " + home + "/k1 > " + out, false},
		{"setsid-fork", "setsid -f sh -c 'cat " + key + " > " + out + "'; sleep 1", true},
		{"subshell-bg", "( (sleep 0.3; cat " + key + " > " + out + ") & ); sleep 1", true},
		{"script-pty", "echo 'cat " + key + " > " + out + "; exit' | SHELL=/bin/bash script -q /dev/null >/dev/null; true", false},
		{"bash-script-file", "script -qec 'bash " + script + "' /dev/null >/dev/null; true", false},
	}
	for _, c := range cases {
		if c.needTaint && !tainted {
			t.Logf("%s: process connector unavailable here, skipped", c.name)
			continue
		}
		_ = os.Remove(out)
		_ = exec.Command(tool, "-c", c.script).Run()
		time.Sleep(400 * time.Millisecond)
		if got, _ := os.ReadFile(out); string(got) == "SECRET\n" {
			t.Errorf("%s: the agent's chain read the key", c.name)
		}
	}
}
