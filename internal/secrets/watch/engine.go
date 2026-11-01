package watch

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/secrets/host"
)

// PermEvent is one open of a watched file that waits for our answer.
type PermEvent struct {
	PID    int
	Path   string
	Handle uint64 // source-specific, passed back to Respond
	// Owner is the uid that owns the file that was really opened, taken from the open descriptor
	// (fstat), not by looking the path up again. OwnerKnown is false when the source could not say.
	Owner      int
	OwnerKnown bool
	// Dev and Ino identify the file that was really opened (from the descriptor), so a hard link
	// under another name is still the protected file. InoKnown is false when the source cannot say.
	Dev, Ino uint64
	InoKnown bool
}

// ErrIdle is returned by Source.Next when nothing arrived within its poll interval.
var ErrIdle = errors.New("idle")

// ErrClosed is returned by Source.Next after Close.
var ErrClosed = errors.New("source closed")

// Source delivers permission events and takes the verdicts. Close must make the OS allow every
// event still waiting (fanotify does this when its descriptor is closed).
type Source interface {
	Next() (PermEvent, error)
	Respond(ev PermEvent, allow bool) error
	Close() error
}

// Event is what is reported to Manar (POST /host/v1/events). The path has the home directory
// masked.
type Event struct {
	Type       string    `json:"type"`
	ToolID     string    `json:"toolId"`
	Process    string    `json:"process"`
	PathClass  string    `json:"pathClass"`
	MaskedPath string    `json:"maskedPath"`
	Blocked    bool      `json:"blocked"`
	At         time.Time `json:"at"`
}

// Event types the watcher produces.
const (
	TypeTouched = "secret.touched"
	// TypeUnavailable and TypeAvailable tell Manar the watcher stopped or started, so the device
	// shows `monitoring unavailable` honestly.
	TypeUnavailable = "secret.watch.unavailable"
	TypeAvailable   = "secret.watch.available"
)

// Engine turns permission events into verdicts and reports.
type Engine struct {
	Src   Source
	Procs ProcSource
	// Mode is the device setting (see Mode). Nil or ModeAlert means every open is allowed and
	// reported.
	Mode func() Mode
	// InodeClass returns the class of a protected file by (device, inode); nil means paths only.
	InodeClass func(dev, ino uint64) string
	// Gate, if set, remembers the person's answers and asks the questions (WARDEN ask once).
	Gate *Gate
	// Self reports whether a pid is Manar's own (never delayed, never reported).
	Self func(pid int) bool
	Out  chan<- Event
	// Homes is used to mask paths.
	Homes func() []string
	// StallAfter is how long one event may wait for its verdict before the watchdog gives up and
	// fails open.
	StallAfter time.Duration
	Now        func() time.Time
	// Trace, if set, receives one line per decision about a secret file (tests and debugging).
	Trace func(format string, args ...any)

	busySince atomic.Int64 // unix nanos of the event being decided, 0 when idle
	lastTick  atomic.Int64
	tripped   atomic.Bool
	dropped   atomic.Int64

	mu   sync.Mutex
	seen map[string]time.Time
}

// ErrStalled is what Run returns after the watchdog removed the marks.
var ErrStalled = errors.New("watcher stalled: marks removed, monitoring unavailable")

// Tripped reports whether the watchdog fired.
func (e *Engine) Tripped() bool { return e.tripped.Load() }

// Dropped is the number of reports lost because the reporter was behind.
func (e *Engine) Dropped() int64 { return e.dropped.Load() }

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Run answers events until ctx ends, the source closes, or the watchdog trips (ErrStalled).
// Whatever happens, it closes the source on the way out, which allows everything still waiting.
func (e *Engine) Run(ctx context.Context) error {
	if e.StallAfter <= 0 {
		e.StallAfter = 2 * time.Second
	}
	e.lastTick.Store(e.now().UnixNano())
	stop := make(chan struct{})
	defer close(stop)
	defer e.Src.Close()
	go e.watchdog(stop)
	for ctx.Err() == nil {
		ev, err := e.Src.Next()
		e.lastTick.Store(e.now().UnixNano())
		switch {
		case errors.Is(err, ErrIdle):
			continue
		case errors.Is(err, ErrClosed):
			if e.tripped.Load() {
				return ErrStalled
			}
			return nil
		case err != nil:
			return err
		}
		e.busySince.Store(e.now().UnixNano())
		allow := e.decide(ev)
		_ = e.Src.Respond(ev, allow)
		e.busySince.Store(0)
	}
	return nil
}

// watchdog closes the source when a verdict takes too long or the loop stops turning. Closing
// the fanotify descriptor drops the marks and allows every waiting open, so the machine keeps
// working; the caller reports `monitoring unavailable`.
func (e *Engine) watchdog(stop <-chan struct{}) {
	t := time.NewTicker(e.StallAfter / 4)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			now := e.now().UnixNano()
			busy := e.busySince.Load()
			stuckEvent := busy != 0 && time.Duration(now-busy) > e.StallAfter
			stuckLoop := time.Duration(now-e.lastTick.Load()) > e.StallAfter+3*time.Second
			if stuckEvent || stuckLoop {
				e.tripped.Store(true)
				_ = e.Src.Close()
				return
			}
		}
	}
}

// decide returns true to allow. It never blocks on anything but /proc reads, and any panic or
// doubt is an allow.
func (e *Engine) decide(ev PermEvent) (allow bool) {
	allow = true
	defer func() {
		if r := recover(); r != nil {
			allow = true
		}
	}()
	if e.Self != nil && e.Self(ev.PID) {
		e.trace("pid=%d path=%s: Manar itself: allow", ev.PID, ev.Path)
		return true
	}
	class := ClassOf(ev.Path)
	if class == "" && ev.InoKnown && e.InodeClass != nil {
		class = e.InodeClass(ev.Dev, ev.Ino) // a hard link under another name
	}
	if class == "" {
		return true
	}
	a := Attribute(e.Procs, ev.PID)
	if a.ToolID == "" {
		e.trace("pid=%d process=%q path=%s: no AI tool in the chain (%d processes read): allow", ev.PID, a.Process, ev.Path, len(a.Chain))
		return true
	}
	mode := ModeAlert
	if e.Mode != nil {
		mode = e.Mode()
	}
	deny := a.Deny() && mode.Blocks(class)
	if deny && e.Gate != nil {
		// Once the verdict is "deny", doubt does not turn it into allow: a grant applies only
		// when the opener's user and the opened file's owner (from the descriptor) are both known
		// and the same. Otherwise the open stays refused and nobody is asked.
		op := a.Chain[0]
		if op.UIDKnown && ev.OwnerKnown && op.UID == ev.Owner &&
			e.Gate.Decide(a.ToolProc.PID, GateKey{UID: op.UID, Tool: a.ToolID, Class: class, Exe: a.ToolProc.Exe}) {
			deny = false // the person said yes to this program
		}
	}
	e.trace("pid=%d process=%q path=%s tool=%s toolCanBlock=%v interactive=%v mode=%s: deny=%v",
		ev.PID, a.Process, ev.Path, a.ToolID, a.Block, a.Interactive, mode, deny)
	e.report(Event{
		Type: TypeTouched, ToolID: a.ToolID, Process: a.Process, PathClass: class,
		MaskedPath: host.MaskPath(e.homes(), ev.Path), Blocked: deny, At: e.now().UTC(),
	})
	return !deny
}

func (e *Engine) homes() []string {
	if e.Homes != nil {
		return e.Homes()
	}
	return nil
}

// report queues an event without ever waiting, and folds repeats of the same open inside a
// minute (editors re-read a .env file all the time).
func (e *Engine) report(ev Event) {
	k := ev.ToolID + "|" + ev.Process + "|" + ev.MaskedPath
	if ev.Blocked {
		k += "|b"
	}
	e.mu.Lock()
	if e.seen == nil {
		e.seen = map[string]time.Time{}
	}
	if t, ok := e.seen[k]; ok && ev.At.Sub(t) < time.Minute {
		e.mu.Unlock()
		return
	}
	if len(e.seen) > 4096 {
		clear(e.seen)
	}
	e.seen[k] = ev.At
	e.mu.Unlock()
	select {
	case e.Out <- ev:
	default:
		e.dropped.Add(1)
	}
}

// hinted answers for one process from what the log said (the process may already be gone) and
// asks the real source for the rest of the tree.
type hinted struct {
	base ProcSource
	hint Proc
}

func (h hinted) Get(pid int) (Proc, error) {
	if pr, err := h.base.Get(pid); err == nil {
		return pr, nil
	}
	if pid == h.hint.PID {
		return h.hint, nil
	}
	return Proc{}, errors.New("gone")
}

// Observe handles an open that already happened (Windows, event 4663): alert only, never a
// verdict. hint carries the process id and image name the log gave.
func (e *Engine) Observe(hint Proc, path string) {
	defer func() { _ = recover() }()
	class := ClassOf(path)
	if class == "" {
		return
	}
	a := Attribute(hinted{e.Procs, hint}, hint.PID)
	if a.ToolID == "" {
		return
	}
	e.report(Event{Type: TypeTouched, ToolID: a.ToolID, Process: a.Process, PathClass: class,
		MaskedPath: host.MaskPath(e.homes(), path), At: e.now().UTC()})
}

func (e *Engine) trace(format string, args ...any) {
	if e.Trace != nil {
		e.Trace(format, args...)
	}
}
