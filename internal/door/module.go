package door

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/manarhq/manar-edge/internal/daemon"
	"github.com/manarhq/manar-edge/internal/hostclient"
)

func init() { daemon.Register(&module{d: New()}) }

type module struct {
	d  *Door
	ln net.Listener // held for the life of the process, also while the server is restarted
}

func (*module) Name() string { return "door" }

var (
	flushEvery = 60 * time.Second
	pollEvery  = 30 * time.Second
)

const cacheFile = "door-config.json"

var configDir string

// Configure sets the device state directory, where the last known settings are kept.
func Configure(dir string) { configDir = dir }

func (m *module) Start(ctx context.Context, c *hostclient.Client) error {
	m.d.stateDir = configDir
	if m.ln == nil {
		ln, err := listen(Listen)
		if err != nil {
			return errors.New("DOOR cannot listen on " + Listen + ": another program holds the port; tools are not routed to it (" + err.Error() + ")")
		}
		m.ln = ln
	}
	m.d.loadCached()
	return m.d.serve(ctx, m.ln, c)
}

func cleanSettings(s hostclient.DoorSettings) *Settings {
	if s.Secrets != "mask" { // anything but an explicit "mask" is the strict mode
		s.Secrets = "block"
	}
	return &s
}

// loadCached applies the last settings the API sent, if a valid file is there. A missing,
// unreadable or odd file leaves DOOR closed until the first fetch.
func (d *Door) loadCached() {
	if d.stateDir == "" {
		return
	}
	p := filepath.Join(d.stateDir, cacheFile)
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return
	}
	b, err := os.ReadFile(p)
	var s hostclient.DoorSettings
	if err != nil || json.Unmarshal(b, &s) != nil || (s.Secrets != "mask" && s.Secrets != "block") {
		return
	}
	d.settings.Store(cleanSettings(s))
	d.loaded.Store(true)
}

func (d *Door) saveCache(s *Settings) {
	if d.stateDir == "" {
		return
	}
	b, _ := json.Marshal(s)
	p := filepath.Join(d.stateDir, cacheFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("manar-edge: door: cannot keep the settings for offline use: %v", err)
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		log.Printf("manar-edge: door: cannot keep the settings for offline use: %v", err)
		_ = os.Remove(tmp)
	}
}

// refresh fetches the settings. An error changes nothing: the last known state (cached or
// fetched) keeps applying, so a pause or a cap never lapses because the API is unreachable.
func (d *Door) refresh(ctx context.Context, c interface {
	Config(context.Context) (*hostclient.Config, error)
}) {
	cfg, err := c.Config(ctx)
	if err != nil || cfg == nil {
		return
	}
	if cfg.Door == nil || cfg.Door.Unavailable {
		return // no door section or "unavailable": the last known settings keep applying
	}
	s := *cfg.Door
	n := cleanSettings(s)
	if old := d.settings.Load(); !d.loaded.Load() || old.Secrets != n.Secrets || !slices.Equal(old.Paused, n.Paused) {
		d.saveCache(n)
	}
	d.settings.Store(n)
	d.loaded.Store(true)
}

func (d *Door) serve(ctx context.Context, ln net.Listener, c interface {
	Config(context.Context) (*hostclient.Config, error)
	sender
}) error {
	srv := &http.Server{
		Handler:           d,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute, // the whole request; responses (streams) are not limited
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	go func() {
		poll, flush := time.NewTicker(pollEvery), time.NewTicker(flushEvery)
		defer poll.Stop()
		defer flush.Stop()
		retry := time.NewTimer(0)
		defer retry.Stop()
		for {
			d.refresh(ctx, c)
			if d.loaded.Load() {
				retry.Stop()
			} else {
				retry.Reset(5 * time.Second) // waiting for the first settings: ask again soon
			}
			select {
			case <-ctx.Done():
				// last flush so a restart loses little
				fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = d.rec.flush(fctx, c)
				cancel()
				return
			case <-retry.C:
			case <-flush.C:
				if err := d.rec.flush(ctx, c); err != nil && ctx.Err() == nil {
					log.Printf("manar-edge: door: usage report: %v", err)
				}
			case <-poll.C:
			}
		}
	}()
	log.Printf("manar-edge: door: local gateway on %s", ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
