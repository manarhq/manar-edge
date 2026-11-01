package door

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/daemon"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
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

func (m *module) Start(ctx context.Context, c *hostclient.Client) error {
	if m.ln == nil {
		ln, err := listen(Listen)
		if err != nil {
			return errors.New("DOOR cannot listen on " + Listen + ": another program holds the port; tools are not routed to it (" + err.Error() + ")")
		}
		m.ln = ln
	}
	return m.d.serve(ctx, m.ln, c)
}

func (d *Door) serve(ctx context.Context, ln net.Listener, c interface {
	Config(context.Context) (*hostclient.Config, error)
	sender
}) error {
	srv := &http.Server{Handler: d, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	go func() {
		poll, flush := time.NewTicker(pollEvery), time.NewTicker(flushEvery)
		defer poll.Stop()
		defer flush.Stop()
		for {
			if cfg, err := c.Config(ctx); err == nil && cfg.Door != nil {
				s := *cfg.Door
				if s.Secrets != "block" {
					s.Secrets = "mask"
				}
				d.settings.Store(&s)
			}
			select {
			case <-ctx.Done():
				// last flush so a restart loses little
				fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = d.rec.flush(fctx, c)
				cancel()
				return
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
