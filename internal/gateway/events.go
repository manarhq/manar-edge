package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
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

	mu    sync.Mutex
	retry []batch // batches that failed transiently, resent as they are with the same batchId
	q     []Event
}

// batch is one POST. manar-api dedupes retried batches by id, so a retry of the exact same events
// keeps it and any new grouping (a split) gets a fresh one.
type batch struct {
	id     string
	events []Event
}

func newBatch(events []Event) batch { return batch{id: uuid4(), events: events} }

// uuid4 returns a random RFC 9562 version 4 UUID.
func uuid4() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Add queues an event.
func (e *Events) Add(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.q = append(e.q, ev)
	e.trim()
}

// trim drops the oldest events (pending retries first) beyond Max. Callers hold e.mu.
func (e *Events) trim() {
	n := len(e.q) - e.Max
	for _, b := range e.retry {
		n += len(b.events)
	}
	if n <= 0 {
		return
	}
	e.Metrics.EventsDropped.Add(int64(n))
	for n > 0 && len(e.retry) > 0 {
		k := min(n, len(e.retry[0].events))
		e.retry[0].events = e.retry[0].events[k:]
		if len(e.retry[0].events) == 0 {
			e.retry = e.retry[1:]
		}
		n -= k
	}
	if n > 0 {
		e.q = append(e.q[:0:0], e.q[n:]...)
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

// Flush resends pending retries, then sends everything queued, MaxBatch per call. Batches that
// fail for a transient reason are kept for the next Flush with their batchId.
func (e *Events) Flush(ctx context.Context) error {
	for {
		e.mu.Lock()
		var b batch
		if len(e.retry) > 0 {
			b, e.retry = e.retry[0], e.retry[1:]
		} else if n := min(len(e.q), MaxBatch); n > 0 {
			b = newBatch(append([]Event(nil), e.q[:n]...))
			e.q = e.q[n:]
		}
		e.mu.Unlock()
		if len(b.events) == 0 {
			return nil
		}
		if unsent, err := e.send(ctx, b); err != nil {
			e.mu.Lock()
			e.retry = append(unsent, e.retry...)
			e.trim()
			e.mu.Unlock()
			return err
		}
	}
}

// send posts b; when the API rejects it (400, 413, 422) it halves it, each half with a new
// batchId, so one bad or oversized event costs only itself. It returns the batches left unsent
// after a transient error.
func (e *Events) send(ctx context.Context, b batch) ([]batch, error) {
	err := e.post(ctx, b)
	if err == nil {
		return nil, nil
	}
	if !errors.Is(err, errRejected) {
		return []batch{b}, err
	}
	if len(b.events) == 1 {
		e.Metrics.EventsDropped.Add(1)
		e.Log.Warn("egress event rejected by the API, dropped", "peerId", b.events[0].PeerID, "err", err)
		return nil, nil
	}
	h := len(b.events) / 2
	first, second := newBatch(b.events[:h]), newBatch(b.events[h:])
	if rest, err := e.send(ctx, first); err != nil {
		return append(rest, second), err
	}
	return e.send(ctx, second)
}

func (e *Events) post(ctx context.Context, b batch) error {
	token, err := readSecret(e.TokenFile)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		BatchID string  `json:"batchId"`
		Events  []Event `json:"events"`
	}{b.id, b.events})
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
