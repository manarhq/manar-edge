package watch

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeSource struct {
	mu           sync.Mutex
	queue        []PermEvent
	responses    map[uint64]bool
	closed       chan struct{}
	once         sync.Once
	unknownOwner bool
	hang         bool // Next blocks until closed, like a stuck read
	wake         chan struct{}
}

func newFake(evs ...PermEvent) *fakeSource {
	return &fakeSource{queue: evs, responses: map[uint64]bool{}, closed: make(chan struct{}), wake: make(chan struct{}, 1)}
}

func (f *fakeSource) Next() (PermEvent, error) {
	f.mu.Lock()
	if len(f.queue) > 0 {
		ev := f.queue[0]
		f.queue = f.queue[1:]
		if !ev.OwnerKnown && !f.unknownOwner { // default: the file belongs to uid 1000
			ev.Owner, ev.OwnerKnown = 1000, true
		}
		f.mu.Unlock()
		return ev, nil
	}
	f.mu.Unlock()
	select {
	case <-f.closed:
		return PermEvent{}, ErrClosed
	case <-time.After(5 * time.Millisecond):
		if f.hang {
			<-f.closed
			return PermEvent{}, ErrClosed
		}
		return PermEvent{}, ErrIdle
	}
}

func (f *fakeSource) Respond(ev PermEvent, allow bool) error {
	f.mu.Lock()
	f.responses[ev.Handle] = allow
	f.mu.Unlock()
	return nil
}
func (f *fakeSource) Close() error { f.once.Do(func() { close(f.closed) }); return nil }

func (f *fakeSource) answered(h uint64) (bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.responses[h]
	return v, ok
}

func engineFor(src Source, procs fakeProcs, block bool) (*Engine, chan Event) {
	out := make(chan Event, 16)
	mode := ModeAlert
	if block {
		mode = ModeKeys
	}
	return &Engine{Src: src, Procs: uidProcs{procs}, Mode: func() Mode { return mode }, Self: func(pid int) bool { return pid == 4242 },
		Out: out, Homes: func() []string { return []string{"/home/alice"} }, StallAfter: 80 * time.Millisecond}, out
}

var treeCursorAndTerminal = fakeProcs{
	10: {PID: 10, PPID: 1, Exe: "/home/alice/.local/share/cursor-agent/cursor-agent", Cmdline: []string{"cursor-agent"}},
	11: {PID: 11, PPID: 10, Exe: "/bin/sh", Cmdline: []string{"sh", "-c", "cat"}, TTY: true},
	12: {PID: 12, PPID: 11, Exe: "/usr/bin/cat"},
	20: {PID: 20, PPID: 10, Exe: "/bin/bash", Cmdline: []string{"bash"}, TTY: true},
	21: {PID: 21, PPID: 20, Exe: "/usr/bin/git"},
	30: {PID: 30, PPID: 1, Exe: "/usr/bin/ssh", Cmdline: []string{"ssh"}},
}

func TestEngineDeniesAIAllowsTerminalAndOthers(t *testing.T) {
	const aws = "/home/alice/.aws/credentials"
	src := newFake(
		PermEvent{PID: 12, Path: aws, Handle: 1},                            // AI tool's non-interactive child
		PermEvent{PID: 21, Path: aws, Handle: 2},                            // behind a shell that merely looks interactive
		PermEvent{PID: 30, Path: aws, Handle: 3},                            // not an AI tool
		PermEvent{PID: 12, Path: "/home/alice/.ssh/known_hosts", Handle: 4}, // not a secret file
		PermEvent{PID: 4242, Path: aws, Handle: 5},                          // Manar itself
	)
	e, out := engineFor(src, treeCursorAndTerminal, true)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	if err := e.Run(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[uint64]bool{1: false, 2: false, 3: true, 4: true, 5: true}
	for h, w := range want {
		if got, ok := src.answered(h); !ok || got != w {
			t.Errorf("handle %d: allow=%v answered=%v, want %v", h, got, ok, w)
		}
	}
	first, second := <-out, <-out
	if !first.Blocked || first.ToolID != "host.cursor" || first.MaskedPath != "~/.aws/credentials" || first.PathClass != ClassAWS {
		t.Errorf("first event %+v", first)
	}
	if !second.Blocked {
		t.Errorf("a pty-looking shell below the agent is still the agent: %+v", second)
	}
	if len(out) != 0 {
		t.Errorf("only AI-attributed opens are reported, got %d more", len(out))
	}
}

func TestBlockingOffAllowsAndReports(t *testing.T) {
	src := newFake(PermEvent{PID: 12, Path: "/home/alice/.aws/credentials", Handle: 1})
	e, out := engineFor(src, treeCursorAndTerminal, false)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(60 * time.Millisecond); cancel() }()
	_ = e.Run(ctx)
	if ok, _ := src.answered(1); !ok {
		t.Fatal("blocking is off: must allow")
	}
	if ev := <-out; ev.Blocked {
		t.Fatal("reported as blocked while off")
	}
}

func TestRepeatsAreFolded(t *testing.T) {
	src := newFake()
	for i := 0; i < 5; i++ {
		src.queue = append(src.queue, PermEvent{PID: 12, Path: "/home/alice/.aws/credentials", Handle: uint64(i)})
	}
	e, out := engineFor(src, treeCursorAndTerminal, true)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(60 * time.Millisecond); cancel() }()
	_ = e.Run(ctx)
	if len(out) != 1 {
		t.Fatalf("got %d reports, want 1", len(out))
	}
}

// slowProcs blocks like a /proc read stuck on a bad mount.
type slowProcs struct{ release chan struct{} }

func (s slowProcs) Get(int) (Proc, error) { <-s.release; return Proc{}, nil }

func TestWatchdogFailsOpenWhenTheResponderStalls(t *testing.T) {
	src := newFake(PermEvent{PID: 12, Path: "/home/alice/.aws/credentials", Handle: 1})
	rel := make(chan struct{})
	defer close(rel)
	e, _ := engineFor(src, nil, true)
	e.Procs = slowProcs{rel}
	done := make(chan error, 1)
	go func() { done <- e.Run(context.Background()) }()
	select {
	case <-src.closed: // marks removed: the kernel allows everything waiting
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog never closed the source")
	}
	if !e.Tripped() {
		t.Fatal("tripped flag not set, so `monitoring unavailable` would not be reported")
	}
	_ = done
}

func TestWatchdogWhenTheLoopStopsTurning(t *testing.T) {
	src := newFake()
	src.hang = true
	e, _ := engineFor(src, nil, true)
	e.StallAfter = 20 * time.Millisecond
	go e.Run(context.Background())
	select {
	case <-src.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not close a stuck source")
	}
}

type panicProcs struct{}

func (panicProcs) Get(int) (Proc, error) { panic("boom") }

func TestPanicInDecisionAllows(t *testing.T) {
	src := newFake(PermEvent{PID: 12, Path: "/home/alice/.aws/credentials", Handle: 1})
	e, _ := engineFor(src, nil, true)
	e.Procs = panicProcs{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(60 * time.Millisecond); cancel() }()
	_ = e.Run(ctx)
	if ok, answered := src.answered(1); !answered || !ok {
		t.Fatal("a crash while deciding must still answer, with allow")
	}
}

// uidProcs gives every fake process the uid 1000.
type uidProcs struct{ fakeProcs }

func (u uidProcs) Get(pid int) (Proc, error) {
	p, err := u.fakeProcs.Get(pid)
	p.UID, p.UIDKnown = 1000, true
	return p, err
}
