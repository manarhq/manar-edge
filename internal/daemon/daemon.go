// Package daemon is the long-running device service (`manar-edge service run`). Feature
// packages register a Module in their init; the service starts them all and keeps them running.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
	"gitlab.vax.sh/manar/manar-edge/internal/pause"
)

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
	mu       sync.Mutex
	modules  []Module
	cleanups []namedCleanup

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

// Run starts every registered module and a heartbeat, then waits for ctx. One failing module
// never stops the others.
func Run(ctx context.Context, c *hostclient.Client) error {
	mu.Lock()
	ms := append([]Module{heartbeat{}}, modules...)
	mu.Unlock()
	if c != nil && c.Info != nil {
		SetIdentity(c.Info.HostID, c.Info.TenantSlug)
	}
	done := make(chan struct{})
	defer close(done)
	go statusWriter(done)
	var wg sync.WaitGroup
	for _, m := range ms {
		wg.Add(1)
		go func() {
			defer wg.Done()
			supervise(ctx, m, c)
		}()
	}
	wg.Wait()
	return nil
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
