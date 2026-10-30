//go:build linux && fanotify_integration

package watch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
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
	if n := markAll(src, Targets(home), nil); n == 0 {
		t.Fatal("no marks")
	}
	procs := newProcSource()
	out := make(chan Event, 8)
	e := &Engine{Src: src, Procs: procs, Block: func() bool { return true }, Self: selfFunc(procs), Out: out,
		Homes: func() []string { return []string{home} }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(200 * time.Millisecond)

	if err := exec.Command("/bin/cat", cred).Run(); err != nil {
		t.Fatalf("plain cat must be allowed: %v", err)
	}
	// Name the executable path like Cursor's so the catalogue matches.
	dir := filepath.Join(t.TempDir(), "cursor")
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
	cancel()
}
