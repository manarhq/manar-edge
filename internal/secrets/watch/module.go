package watch

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/daemon"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
	"gitlab.vax.sh/manar/manar-edge/internal/secrets/host"
	"gitlab.vax.sh/manar/manar-edge/internal/secrets/vault"
)

func init() { daemon.Register(&Module{}) }

// Module is the secrets watcher as a daemon module.
type Module struct{}

func (*Module) Name() string { return "secrets-watch" }

// Start runs the platform watcher and the reporter. It restarts the watcher when the blocking
// setting changes.
func (m *Module) Start(ctx context.Context, c *hostclient.Client) error {
	out := make(chan Event, 256)
	go report(ctx, c, out)
	gate := &Gate{Approver: vault.NewApprover(c), Out: out, Path: grantsFile()}
	degraded := false
	for ctx.Err() == nil {
		cfg, err := c.Config(ctx)
		mode := ModeAlert
		if err == nil && !degraded {
			mode = ModeFromFeatures(cfg.Features)
		}
		rctx, cancel := context.WithCancel(ctx)
		go func() { // restart on a setting change
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-rctx.Done():
					return
				case <-t.C:
					if cfg, err := c.Config(rctx); err == nil && ModeFromFeatures(cfg.Features) != mode && !degraded {
						cancel()
					}
				}
			}
		}()
		stalled := runPlatform(rctx, out, mode, gate)
		cancel()
		if stalled {
			degraded = true // after a stall the watcher only observes until the service restarts
			log.Printf("manar-edge: secrets watcher stalled: continuing without blocking")
		}
	}
	return nil
}

// Cleanup removes what the watcher put on the machine (Windows audit rules and policy, the
// remembered answers). The fanotify marks go with the process.
func (*Module) Cleanup(ctx context.Context) error {
	_ = os.Remove(grantsFile())
	return cleanupPlatform(ctx)
}

func grantsFile() string { return filepath.Join(host.StateDir(), "secrets", "file-grants.json") }

func stateFile() string { return filepath.Join(host.StateDir(), "secrets", "audit.json") }

func execRunner(ctx context.Context) Runner {
	return func(name string, args ...string) ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return exec.CommandContext(cctx, name, args...).CombinedOutput()
	}
}

func notice(out chan<- Event, typ string) {
	select {
	case out <- Event{Type: typ, At: time.Now().UTC()}:
	default:
	}
}

// report sends queued events to Manar in batches. It is the only place that waits on the
// network, and it never sits in the permission path.
func report(ctx context.Context, c *hostclient.Client, in <-chan Event) {
	const maxHeld = 2000
	var held []Event
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-in:
			held = append(held, ev)
			if len(held) > maxHeld {
				held = held[len(held)-maxHeld:]
			}
		case <-t.C:
			if len(held) == 0 {
				continue
			}
			n := min(len(held), 100)
			if err := c.Do(ctx, http.MethodPost, "/events", map[string]any{"events": held[:n]}, nil); err != nil {
				if se, ok := err.(*hostclient.StatusError); ok && se.Code >= 400 && se.Code < 500 && se.Code != 429 {
					held = held[n:] // the API refused these: do not retry forever
				}
				log.Printf("manar-edge: sending secret events: %v", err)
				continue
			}
			held = held[n:]
		}
	}
}
