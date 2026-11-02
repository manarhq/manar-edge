// Package daemon is the long-running device service (`manar-edge service run`). Feature
// packages register a Module in their init; the service starts them all and keeps them running.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/pause"
)

// OnPanic, when set, is told about a module panic (the value and the stack). telemetry sets it.
var OnPanic func(v any, stack []byte)

// Module is one feature of the device service. Start blocks until ctx is done; an error other
// than context cancellation is logged and Start is called again after a pause.
type Module interface {
	Name() string
	Start(ctx context.Context, c *hostclient.Client) error
}

// Cleaner is optional on a Module: Cleanup restores whatever the module changed on the machine
// (tool configs, hooks, secrets). `manar-edge uninstall` calls it for every registered module.
type Cleaner interface {
	Cleanup(ctx context.Context) error
}

var (
	mu        sync.Mutex
	modules   []Module
	cleanups  []namedCleanup
	onRemoved []namedCleanup

	// retryPause is a variable so tests can shorten it.
	retryPause = 30 * time.Second
)

type namedCleanup struct {
	name string
	fn   func(ctx context.Context) error
}

// Register adds a module. Call it from the module package's init.
func Register(m Module) {
	mu.Lock()
	defer mu.Unlock()
	modules = append(modules, m)
}

// RegisterCleanup adds an uninstall hook for code that has no Module (for example a CLI-only
// feature that edits tool configs).
func RegisterCleanup(name string, fn func(ctx context.Context) error) {
	mu.Lock()
	defer mu.Unlock()
	cleanups = append(cleanups, namedCleanup{name, fn})
}

// Unprotector is optional on a Module: Unprotect gives the user back whatever protection locked
// (network rules, tool settings, vaulted secrets) when the workspace removed the device. The
// module stays installed; Unprotect must be safe to repeat.
type Unprotector interface {
	Unprotect(ctx context.Context) error
}

// RegisterOnRemoved adds a step that runs when the workspace removed the device, for code that
// has no Module.
func RegisterOnRemoved(name string, fn func(ctx context.Context) error) {
	mu.Lock()
	defer mu.Unlock()
	onRemoved = append(onRemoved, namedCleanup{name, fn})
}

// ErrReenrolled is returned by Run when a removed device enrolled again: the service manager
// restarts the service, which then loads the new certificate.
var ErrReenrolled = errors.New("device enrolled again")

// removedPoll is how often a removed device looks for a fresh enrolment (a variable for tests).
var removedPoll = 30 * time.Second

// Run starts every registered module and a heartbeat, then waits for ctx. One failing module
// never stops the others. When the workspace removes the device (HTTP 410 device_removed on any
// host call), or the device is already marked removed, the modules stop, the removal steps run
// and Run only waits for a new enrolment or ctx: the service stays installed.
func Run(ctx context.Context, c *hostclient.Client) error {
	removed := c != nil && c.StateDir() != "" && hostclient.IsMarkedRemoved(c.StateDir())
	if !removed {
		removed = runModules(ctx, c)
	}
	if !removed || ctx.Err() != nil {
		return nil
	}
	// Idempotent: also covers a restart after a crash in the middle of the first teardown.
	unprotect(ctx)
	return idleRemoved(ctx, c)
}

func runModules(parent context.Context, c *hostclient.Client) bool {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var removed atomic.Bool
	if c != nil && c.Removed() != nil {
		go func() {
			select {
			case <-c.Removed():
				// Saved first, so a crash during teardown still leaves the device removed.
				if c.StateDir() != "" {
					if err := hostclient.MarkRemoved(c.StateDir()); err != nil {
						log.Printf("manar-edge: saving the removed state: %v", err)
					}
				}
				log.Printf("manar-edge: this device was removed from the workspace: stopping protection")
				removed.Store(true)
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	mu.Lock()
	ms := append([]Module{heartbeat{}}, modules...)
	mu.Unlock()
	if c != nil && c.Info != nil {
		SetIdentity(c.Info.HostID, c.Info.TenantSlug)
	}
	// Run returns only after the status writer has stopped, so nothing writes the file after it.
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() { statusWriter(done); close(stopped) }()
	defer func() { close(done); <-stopped }()
	var wg sync.WaitGroup
	for _, m := range ms {
		wg.Add(1)
		go func() {
			defer wg.Done()
			supervise(ctx, m, c)
		}()
	}
	wg.Wait()
	return removed.Load()
}

// unprotect runs every removal step and shows the removed state in the status file. A failing
// step is logged; the others still run.
func unprotect(ctx context.Context) {
	mu.Lock()
	ms := append([]Module(nil), modules...)
	hs := append([]namedCleanup(nil), onRemoved...)
	mu.Unlock()
	for _, m := range ms {
		if u, ok := m.(Unprotector); ok {
			if err := safeCleanup(ctx, u.Unprotect); err != nil {
				log.Printf("manar-edge: removed device: %s: %v", m.Name(), err)
			}
		}
	}
	for _, h := range hs {
		if err := safeCleanup(ctx, h.fn); err != nil {
			log.Printf("manar-edge: removed device: %s: %v", h.name, err)
		}
	}
}

// idleRemoved keeps the status file (it says "removed") and waits for ctx, or for the removed
// state to be cleared by a new enrolment. It makes no API calls.
func idleRemoved(ctx context.Context, c *hostclient.Client) error {
	setRemoved()
	if c != nil && c.Info != nil {
		SetIdentity(c.Info.HostID, c.Info.TenantSlug)
	}
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() { statusWriter(done); close(stopped) }()
	defer func() { close(done); <-stopped }()
	t := time.NewTicker(removedPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if c != nil && c.StateDir() != "" && !hostclient.IsMarkedRemoved(c.StateDir()) {
				return ErrReenrolled
			}
		}
	}
}

func supervise(ctx context.Context, m Module, c *hostclient.Client) {
	for ctx.Err() == nil {
		SetComponent("module:"+m.Name(), Component{State: "ok"})
		err := safeStart(ctx, m, c)
		if ctx.Err() != nil {
			return
		}
		SetComponent("module:"+m.Name(), Component{State: "problem", Detail: "stopped and restarting",
			Fix: "look at the service log for the reason: journalctl -u manar-edge -n 50 (Windows: Event Viewer, Application)"})
		log.Printf("manar-edge: module %s stopped: %v; restarting", m.Name(), err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryPause):
		}
	}
}

func safeStart(ctx context.Context, m Module, c *hostclient.Client) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if OnPanic != nil {
				OnPanic(r, debug.Stack())
			}
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	if err := m.Start(ctx, c); err != nil {
		return err
	}
	return errors.New("returned without an error")
}

// Cleanup runs every module's cleanup hook and every registered hook. It does not stop at the
// first failure: it returns all of them so uninstall can say what is left to do by hand.
func Cleanup(ctx context.Context) []error {
	mu.Lock()
	ms := append([]Module(nil), modules...)
	cs := append([]namedCleanup(nil), cleanups...)
	mu.Unlock()
	var errs []error
	for _, m := range ms {
		if cl, ok := m.(Cleaner); ok {
			if err := safeCleanup(ctx, cl.Cleanup); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", m.Name(), err))
			}
		}
	}
	for _, c := range cs {
		if err := safeCleanup(ctx, c.fn); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.name, err))
		}
	}
	return errs
}

func safeCleanup(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(ctx)
}

// heartbeat polls the device configuration. It shows the API that the device is alive and logs
// when the owner approves it.
type heartbeat struct{}

func (heartbeat) Name() string { return "heartbeat" }

func (heartbeat) Start(ctx context.Context, c *hostclient.Client) error {
	last := ""
	// 15 s: "Pause all AI" reaches the device about this fast (the API denies at once anyway).
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		cfg, err := c.Config(ctx)
		if ctx.Err() == nil {
			if err == nil {
				recordSync(cfg.HostID, cfg.Status, cfg.StartMode, cfg.Features, nil)
			} else {
				recordSync("", "", "", nil, err)
			}
		}
		switch {
		case err != nil && ctx.Err() == nil:
			log.Printf("manar-edge: config: %v", err)
		case err == nil && cfg.Status != last:
			last = cfg.Status
			log.Printf("manar-edge: this device is %s", cfg.Status)
		}
		if err == nil && c.StateDir() != "" {
			if perr := pause.Set(c.StateDir(), cfg.Paused); perr != nil {
				log.Printf("manar-edge: pause flag: %v", perr)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
