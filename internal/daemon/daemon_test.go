package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
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
