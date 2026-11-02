package daemon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

type fake struct {
	name     string
	starts   atomic.Int32
	failOne  bool
	cleaned  atomic.Bool
	cleanErr error
}

func (f *fake) Name() string { return f.name }
func (f *fake) Start(ctx context.Context, _ *hostclient.Client) error {
	if f.starts.Add(1) == 1 && f.failOne {
		return errors.New("boom")
	}
	<-ctx.Done()
	return nil
}
func (f *fake) Cleanup(context.Context) error { f.cleaned.Store(true); return f.cleanErr }

func reset() { modules, cleanups = nil, nil }

func TestRunRestartsAFailingModuleAndKeepsTheOthers(t *testing.T) {
	reset()
	retryPause = 10 * time.Millisecond
	bad, good := &fake{name: "bad", failOne: true}, &fake{name: "good"}
	Register(bad)
	Register(good)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	// heartbeat needs a client; a nil one would panic and the supervisor must survive that too.
	go func() { _ = Run(ctx, nil); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for bad.starts.Load() < 2 || good.starts.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("bad starts=%d good starts=%d", bad.starts.Load(), good.starts.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestCleanupRunsEveryHookEvenWhenOneFails(t *testing.T) {
	reset()
	a := &fake{name: "a", cleanErr: errors.New("restore failed")}
	b := &fake{name: "b"}
	Register(a)
	Register(b)
	var hook atomic.Bool
	RegisterCleanup("hooks", func(context.Context) error { hook.Store(true); return nil })
	RegisterCleanup("panics", func(context.Context) error { panic("x") })
	errs := Cleanup(context.Background())
	if !a.cleaned.Load() || !b.cleaned.Load() || !hook.Load() {
		t.Fatal("not every hook ran")
	}
	if len(errs) != 2 {
		t.Fatalf("errs = %v", errs)
	}
}

func TestMain(m *testing.M) {
	StatusPath = "" // never write /run in tests
	os.Exit(m.Run())
}

func TestStatusFileRoundTrip(t *testing.T) {
	old := StatusPath
	StatusPath = t.TempDir() + "/run/status.json"
	defer func() { StatusPath = old }()
	SetIdentity("h1", "acme")
	recordSync("h1", "APPROVED", "ask", []string{"undo"}, nil)
	SetComponent("door", Component{State: "ok"})
	SetTools([]ToolStatus{{Name: "Cursor", Protected: true, Mode: "hook"}})
	if err := writeStatus(); err != nil {
		t.Fatal(err)
	}
	s, err := ReadStatus(StatusPath)
	if err != nil || s.HostID != "h1" || s.TenantSlug != "acme" || s.Status != "APPROVED" || s.LastSyncAt == nil ||
		s.Components["door"].State != "ok" || len(s.Tools) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	recordSync("", "", "", nil, errors.New("boom"))
	if cur.LastError != "boom" || cur.Status != "APPROVED" {
		t.Fatal("a failed sync must keep the last good state and record the error")
	}
}

type unprotectFake struct {
	fake
	unprotected atomic.Int32
}

func (f *unprotectFake) Unprotect(context.Context) error { f.unprotected.Add(1); return nil }

// removedClient answers every call with the given status and body.
func removedServerClient(t *testing.T, status int, body string) *hostclient.Client {
	t.Helper()
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return hostclient.NewForTest(dir, srv.URL, srv.Client())
}

const removedBody = `{"statusCode":410,"code":"device_removed","message":"This device was removed from the workspace"}`

func TestRemovedDeviceStopsModulesRunsTeardownAndPersists(t *testing.T) {
	reset()
	retryPause = 10 * time.Millisecond
	m := &unprotectFake{fake: fake{name: "m"}}
	Register(m)
	var hook atomic.Int32
	RegisterOnRemoved("hook", func(context.Context) error { hook.Add(1); return nil })
	c := removedServerClient(t, 410, removedBody)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c) }()
	deadline := time.Now().Add(3 * time.Second)
	for m.unprotected.Load() == 0 || hook.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("unprotected=%d hook=%d", m.unprotected.Load(), hook.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !hostclient.IsMarkedRemoved(c.StateDir()) {
		t.Fatal("removed state not saved")
	}
	if m.cleaned.Load() {
		t.Fatal("removal must not run the uninstall cleanup")
	}
	stMu.Lock()
	snap := cur
	stMu.Unlock()
	if !snap.Removed {
		t.Fatalf("status snapshot not marked removed: %+v", snap)
	}
	// A restart must not start the modules again: Run goes straight to teardown.
	starts := m.starts.Load()
	cancel()
	<-done
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- Run(ctx2, c) }()
	time.Sleep(100 * time.Millisecond)
	cancel2()
	<-done2
	if m.starts.Load() != starts {
		t.Fatalf("module started again after restart: %d -> %d", starts, m.starts.Load())
	}
	if m.unprotected.Load() < 2 {
		t.Fatal("restart did not repeat the teardown")
	}
}

func TestNoRemovalForOtherErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{{410, `{"message":"gone"}`}, {401, removedBody}, {403, removedBody}, {500, removedBody}} {
		reset()
		retryPause = 10 * time.Millisecond
		m := &unprotectFake{fake: fake{name: "m"}}
		Register(m)
		c := removedServerClient(t, tc.status, tc.body)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, c) }()
		time.Sleep(150 * time.Millisecond)
		cancel()
		<-done
		if m.unprotected.Load() != 0 || hostclient.IsMarkedRemoved(c.StateDir()) {
			t.Fatalf("status %d %s triggered removal", tc.status, tc.body)
		}
	}
}

func TestRemovedDeviceReturnsWhenItEnrolsAgain(t *testing.T) {
	reset()
	removedPoll = 10 * time.Millisecond
	c := removedServerClient(t, 200, `{}`)
	if err := hostclient.MarkRemoved(c.StateDir()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), c) }()
	time.Sleep(50 * time.Millisecond)
	if err := hostclient.ClearRemoved(c.StateDir()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrReenrolled) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after a new enrolment")
	}
}
