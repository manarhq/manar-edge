package watch

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

// maxHeld bounds what waits to be sent; past it the oldest events go first.
const maxHeld = 2000

// outbox holds the events that Manar has not taken yet, in memory and in a file (0600, home
// folders already masked), so a restart or a device that waits for its owner's approval (403)
// loses nothing. Only an event Manar refuses on its own (400 for a batch of one) is dropped.
type outbox struct {
	path string
	send func(ctx context.Context, batch []Event) error
	held []Event
}

func (o *outbox) load() {
	b, err := os.ReadFile(o.path)
	if err == nil {
		_ = json.Unmarshal(b, &o.held)
	}
	o.trim()
}

func (o *outbox) save() {
	if o.path == "" {
		return
	}
	b, _ := json.Marshal(o.held)
	tmp := o.path + ".tmp"
	if os.MkdirAll(filepath.Dir(o.path), 0o700) != nil || os.WriteFile(tmp, b, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, o.path)
}

func (o *outbox) add(ev Event) { o.held = append(o.held, ev); o.trim() }

func (o *outbox) trim() {
	if len(o.held) > maxHeld {
		o.held = o.held[len(o.held)-maxHeld:]
	}
}

// flush sends what is held in batches of up to 100. A 400 means something in the batch is invalid:
// the batch is halved until the bad event is alone, and only that one is dropped. Anything else
// (403 while the device is pending, 401, 429, 5xx, no network) keeps every event for the next try.
func (o *outbox) flush(ctx context.Context) {
	defer o.save()
	size := 100
	for len(o.held) > 0 && ctx.Err() == nil {
		n := min(len(o.held), size)
		err := o.send(ctx, o.held[:n])
		var se *hostclient.StatusError
		switch {
		case err == nil:
			o.held, size = o.held[n:], 100
		case errors.As(err, &se) && se.Code == http.StatusBadRequest && n > 1:
			size = n / 2
		case errors.As(err, &se) && se.Code == http.StatusBadRequest:
			log.Printf("manar-edge: secret event refused by Manar and dropped (%s): %v", o.held[0].Type, err)
			o.held, size = o.held[1:], 100
		default:
			log.Printf("manar-edge: sending secret events (kept %d for later): %v", len(o.held), err)
			return
		}
	}
}

// report sends queued events to Manar. It is the only place that waits on the network, and it
// never sits in the permission path.
func report(ctx context.Context, c *hostclient.Client, in <-chan Event) {
	o := &outbox{path: outboxFile(), send: func(ctx context.Context, batch []Event) error {
		return c.Do(ctx, http.MethodPost, "/events", map[string]any{"events": batch}, nil)
	}}
	o.load()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			o.save()
			return
		case ev := <-in:
			o.add(ev)
		case <-t.C:
			if len(o.held) > 0 {
				o.flush(ctx)
			}
		}
	}
}
