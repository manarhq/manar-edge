package watch

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/manarhq/manar-edge/internal/daemon"
	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/secrets/host"
	"github.com/manarhq/manar-edge/internal/secrets/vault"
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
		switch {
		case degraded:
		case err == nil:
			mode = ModeFromFeatures(cfg.Features)
			saveMode(mode)
		default: // offline at boot: keep protecting the way the last known setting said
			mode = loadMode()
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
		stalled := runPlatform(rctx, out, mode, gate, degraded)
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
	_ = os.Remove(modeFile())
	return cleanupPlatform(ctx)
}

func grantsFile() string { return filepath.Join(host.StateDir(), "secrets", "file-grants.json") }

func stateFile() string { return filepath.Join(host.StateDir(), "secrets", "audit.json") }

func execRunner(ctx context.Context) Runner {
	return func(name string, args ...string) ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command (callers pass fixed program names (wevtutil, auditpol))
		return exec.CommandContext(cctx, name, args...).CombinedOutput()
	}
}

func notice(out chan<- Event, typ string) {
	select {
	case out <- Event{Type: typ, At: time.Now().UTC()}:
	default:
	}
}

func outboxFile() string { return filepath.Join(host.StateDir(), "secrets", "events.json") }

func modeFile() string { return filepath.Join(host.StateDir(), "secrets", "mode") }

// saveMode keeps the last mode the workspace asked for, so a boot without the network does not
// quietly drop to alert-only.
func saveMode(m Mode) {
	_ = os.MkdirAll(filepath.Dir(modeFile()), 0o700)
	_ = os.WriteFile(modeFile(), []byte(m.String()), 0o600)
}

func loadMode() Mode {
	b, err := os.ReadFile(modeFile())
	if err != nil {
		return ModeAlert
	}
	switch string(b) {
	case "keys":
		return ModeKeys
	case "all":
		return ModeAll
	}
	return ModeAlert
}
