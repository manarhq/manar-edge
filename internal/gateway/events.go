package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Event is one egress connection record (docs/design.md, 2).
type Event struct {
	PeerID     string    `json:"peerId"`
	At         time.Time `json:"at"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason"`
	BytesUp    int64     `json:"bytesUp"`
	BytesDown  int64     `json:"bytesDown"`
	DurationMs int64     `json:"durationMs"`
	// ECH is set when the ClientHello carried encrypted_client_hello (real or GREASE); omitted
	// otherwise, so the contract's event shape is unchanged for every other event.
	ECH bool `json:"ech,omitempty"`
}

var errRejected = errors.New("events batch rejected")

// MaxBatch is the most events one POST carries.
const MaxBatch = 500

// Events is a bounded in-memory queue sent to manar-api in batches. Add never blocks: when the
// queue is full the oldest event is dropped and counted.
type Events struct {
	APIURL    string
	TokenFile string
	Client    *http.Client
	Metrics   *Metrics
	Log       *slog.Logger
	Max       int
	Interval  time.Duration

	mu sync.Mutex
	q  []Event
}

// Add queues an event.
func (e *Events) Add(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.q = append(e.q, ev)
	e.trim()
}

func (e *Events) trim() {
	if n := len(e.q) - e.Max; n > 0 {
		e.q = append(e.q[:0:0], e.q[n:]...)
		e.Metrics.EventsDropped.Add(int64(n))
	}
}

// Run flushes every Interval until ctx is done, then makes one last attempt.
func (e *Events) Run(ctx context.Context) {
	t := time.NewTicker(e.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := e.Flush(fctx); err != nil {
				e.Log.Warn("final event flush failed", "err", err)
			}
			return
		case <-t.C:
			if err := e.Flush(ctx); err != nil {
				e.Log.Warn("event flush failed, will retry", "err", err)
			}
		}
	}
}

// Flush sends everything queued, MaxBatch per call. A batch that failed for a transient reason
// goes back to the front.
func (e *Events) Flush(ctx context.Context) error {
	for {
		e.mu.Lock()
		n := min(len(e.q), MaxBatch)
		batch := append([]Event(nil), e.q[:n]...)
		e.q = e.q[n:]
		e.mu.Unlock()
		if n == 0 {
			return nil
		}
		if unsent, err := e.send(ctx, batch); err != nil {
			e.mu.Lock()
			e.q = append(unsent, e.q...)
			e.trim()
			e.mu.Unlock()
			return err
		}
	}
}

// send posts batch; when the API rejects it (400, 413, 422) it halves the batch so one bad or
// oversized event costs only itself. It returns what is left unsent after a transient error.
func (e *Events) send(ctx context.Context, batch []Event) ([]Event, error) {
	err := e.post(ctx, batch)
	if err == nil {
		return nil, nil
	}
	if !errors.Is(err, errRejected) {
		return batch, err
	}
	if len(batch) == 1 {
		e.Metrics.EventsDropped.Add(1)
		e.Log.Warn("egress event rejected by the API, dropped", "peerId", batch[0].PeerID, "err", err)
		return nil, nil
	}
	h := len(batch) / 2
	if rest, err := e.send(ctx, batch[:h]); err != nil {
		return append(rest, batch[h:]...), err
	}
	return e.send(ctx, batch[h:])
}

func (e *Events) post(ctx context.Context, batch []Event) error {
	token, err := readSecret(e.TokenFile)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string][]Event{"events": batch})
	if err != nil {
		return err
	}
	url := strings.TrimSuffix(e.APIURL, "/") + "/internal/v1/edge/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.Client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return fmt.Errorf("%w: status %d", errRejected, resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("post events: status %d", resp.StatusCode)
	}
	return nil
}
