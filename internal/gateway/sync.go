package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Net configures the WireGuard peers on wg0. The Linux implementation is Kernel; tests use a fake.
type Net interface {
	SetPeers([]WGPeer) error
}

// Syncer long-polls manar-api's peer sync API and applies it to the registry and wg0.
type Syncer struct {
	APIURL     string // manar-api's HTTP base URL
	TokenFile  string
	Client     *http.Client
	Registry   *Registry
	Net        Net
	Metrics    *Metrics
	Log        *slog.Logger
	MinBackoff time.Duration
	MaxBackoff time.Duration

	version uint64
	ready   atomic.Bool
}

// Ready reports whether a full peer set has been applied.
func (s *Syncer) Ready() bool { return s.ready.Load() }

// Run polls until ctx is done. On an error it keeps the last applied state and backs off.
func (s *Syncer) Run(ctx context.Context) {
	backoff := s.MinBackoff
	for ctx.Err() == nil {
		before, start := s.version, time.Now()
		err := s.Poll(ctx)
		if err == nil {
			backoff = s.MinBackoff
			if s.version == before && time.Since(start) < s.MinBackoff {
				// The server answered at once with nothing newer (an install whose version is
				// still 0 answers after=0 with a full set every time); do not spin on it.
				sleepCtx(ctx, s.MinBackoff)
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		s.Log.Warn("peer sync failed, keeping the last applied state", "err", err, "retryIn", backoff)
		sleepCtx(ctx, backoff)
		backoff = min(backoff*2, s.MaxBackoff)
	}
}

// Poll makes one sync call and applies the result.
func (s *Syncer) Poll(ctx context.Context) error {
	set, err := s.fetch(ctx)
	if err != nil {
		return err
	}
	// The registry refuses cut peers from here on. Their connections are closed before the
	// WireGuard peer goes, so the FIN can still reach the agent.
	wg, closers, cuts := s.Registry.Apply(set)
	for _, c := range closers {
		c.Close()
	}
	netErr := s.Net.SetPeers(wg)
	s.Metrics.CutsApplied.Add(int64(cuts))
	s.Metrics.PeersActive.Store(int64(len(wg)))
	_, rejected := s.Registry.Active()
	s.Metrics.PeersRejected.Store(int64(rejected))
	if netErr != nil {
		// The registry already refuses the cut peers; the version is not advanced so the next
		// call returns the same changes and wg0 is configured again.
		return fmt.Errorf("configure wireguard peers: %w", netErr)
	}
	if cuts > 0 || len(set.Peers) > 0 {
		s.Log.Info("peers applied", "version", set.Version, "full", set.Full,
			"changed", len(set.Peers), "active", len(wg), "cuts", cuts)
	}
	s.version = set.Version
	s.Metrics.Synced(time.Now())
	if set.Full {
		s.ready.Store(true)
	}
	return nil
}

func (s *Syncer) fetch(ctx context.Context) (PeerSet, error) {
	var set PeerSet
	token, err := readSecret(s.TokenFile)
	if err != nil {
		return set, err
	}
	url := fmt.Sprintf("%s/internal/v1/edge/peers?after=%d", strings.TrimSuffix(s.APIURL, "/"), s.version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return set, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.Client.Do(req)
	if err != nil {
		return set, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return set, fmt.Errorf("peer sync: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&set); err != nil {
		return set, fmt.Errorf("peer sync: decode: %w", err)
	}
	if !s.Ready() && !set.Full {
		return set, fmt.Errorf("peer sync: first response is not a full set")
	}
	return set, nil
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// readSecret reads a mounted secret file on every use, so a rotated Secret is picked up without a
// restart. The value is never logged.
func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return v, nil
}
