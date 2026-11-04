package discovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

func fakeHome(t *testing.T, dirs ...string) User {
	t.Helper()
	home := t.TempDir()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return User{Name: "sam", Home: home, UID: -1, GID: -1}
}

func probe(procs ...string) Probe {
	p := OSProbe()
	p.Procs = func() []string { return procs }
	return p
}

func TestScanFindsInstallsAndProcesses(t *testing.T) {
	u := fakeHome(t, ".cursor", ".vscode/extensions/github.copilot-1.2.3", ".vscode/extensions/github.copilot-1.10.0", ".gemini")
	got := map[string]Found{}
	for _, f := range Scan([]User{u}, "linux", probe("windsurf", "aider", "bash")) {
		got[f.ReportID()] = f
	}
	for _, id := range []string{"host.cursor", "host.vscode-copilot", "host.gemini-cli", "host.windsurf", "other:aider"} {
		if _, ok := got[id]; !ok {
			t.Errorf("%s not found; got %v", id, got)
		}
	}
	if got["host.vscode-copilot"].Version != "1.2.3" && got["host.vscode-copilot"].Version != "1.10.0" {
		t.Errorf("version %q", got["host.vscode-copilot"].Version)
	}
	if len(got["host.cursor"].Users) != 1 || len(got["host.windsurf"].Users) != 0 {
		t.Errorf("users: cursor %v windsurf %v", got["host.cursor"].Users, got["host.windsurf"].Users)
	}
	if _, ok := got["host.codex-cli"]; ok || len(got) != 5 {
		t.Errorf("found something that is not there: %v", got)
	}
}

func TestReportNeverClaimsProtectionWithoutAMode(t *testing.T) {
	f := []Found{{Spec: Spec{ID: "host.cursor", Name: "Cursor"}}, {Spec: Spec{ID: "host.gemini-cli", Name: "Gemini"}}}
	r := Report(f, map[string]State{"host.cursor": {Protected: true, Mode: ""}, "host.gemini-cli": {Protected: true, Mode: "hook"}})
	by := map[string]hostclient.Tool{}
	for _, x := range r {
		by[x.ID] = x
	}
	if by["host.cursor"].Protected || by["host.cursor"].ProtectMode != "none" || !by["host.gemini-cli"].Protected {
		t.Fatalf("%+v", r)
	}
}

type fakeAPI struct {
	mu   sync.Mutex
	cfg  hostclient.Config
	sent [][]hostclient.Tool
}

func (f *fakeAPI) Config(context.Context) (*hostclient.Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.cfg
	return &c, nil
}
func (f *fakeAPI) Inventory(_ context.Context, t []hostclient.Tool, _ []hostclient.MCPServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, t)
	return nil
}

func TestModuleReportsOnChangeNotEveryPoll(t *testing.T) {
	u := fakeHome(t, ".cursor")
	api := &fakeAPI{}
	p := probe()
	m := &Module{Poll: 10 * time.Millisecond, Report: time.Hour, Probe: &p, Users: func() []User { return []User{u} }, GOOS: "linux"}
	SetReconciler(func(_ context.Context, found []Found, cfg *hostclient.Config) map[string]State {
		return map[string]State{"host.cursor": {Protected: true, Mode: "hook"}}
	})
	defer SetReconciler(nil)
	ctx, cancel := context.WithCancel(context.Background())
	go m.run(ctx, api)
	time.Sleep(120 * time.Millisecond)
	if err := os.MkdirAll(filepath.Join(u.Home, ".gemini"), 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	cancel()
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.sent) != 2 {
		t.Fatalf("sent %d reports, want 2 (first scan, then the new tool)", len(api.sent))
	}
	if len(api.sent[0]) != 1 || len(api.sent[1]) != 2 || !api.sent[0][0].Protected {
		t.Fatalf("%+v", api.sent)
	}
}

type refusingAPI struct {
	fakeAPI
	err error
}

func (r *refusingAPI) Config(context.Context) (*hostclient.Config, error) { return nil, r.err }

// A refused, unreachable or misrouted device keeps its protection: no reply other than the
// authenticated "removed" (410 device_removed, handled by the daemon) may take the hooks out. A
// revoked or stolen laptop answered 401 used to unprotect itself after three refusals.
func TestModuleNeverUnprotectsOnRefusalsOrNetworkErrors(t *testing.T) {
	for _, err := range []error{
		&hostclient.StatusError{Code: 401, Message: "Certificate is unknown or has been revoked"},
		&hostclient.StatusError{Code: 403, Message: "forbidden (a proxy)"},
		&hostclient.StatusError{Code: 423, APICode: "device_revoked"},
		&hostclient.StatusError{Code: 503},
		errors.New("dial tcp: connection refused"),
	} {
		u := fakeHome(t, ".cursor")
		p := probe()
		var mu sync.Mutex
		calls := 0
		// Only this module's calls count (an earlier test's module may still be finishing): its
		// config would be the "revoked" one the module made up, since Manar never sent one.
		SetReconciler(func(_ context.Context, _ []Found, cfg *hostclient.Config) map[string]State {
			if cfg.Status == StatusRevoked {
				mu.Lock()
				calls++
				mu.Unlock()
			}
			return nil
		})
		m := &Module{Poll: 2 * time.Millisecond, Report: time.Hour, Probe: &p, Users: func() []User { return []User{u} }, GOOS: "linux"}
		ctx, cancel := context.WithCancel(context.Background())
		go m.run(ctx, &refusingAPI{err: err})
		time.Sleep(60 * time.Millisecond)
		cancel()
		SetReconciler(nil)
		mu.Lock()
		if calls != 0 {
			t.Errorf("%v: protection was reconciled %d times without a config; it must be left as it is", err, calls)
		}
		mu.Unlock()
	}
}
