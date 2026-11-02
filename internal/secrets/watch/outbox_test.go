package watch

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

// E-011: a pending device (403) keeps what it saw, across a restart too; a 400 drops only the
// event Manar refuses, never the batch around it.
func TestOutboxKeepsEventsAndDropsOnlyTheBadOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	var got []string
	status := 403
	send := func(_ context.Context, b []Event) error {
		if status != 0 {
			return &hostclient.StatusError{Code: status}
		}
		for _, e := range b {
			if e.Type == "bad" {
				return &hostclient.StatusError{Code: 400}
			}
		}
		for _, e := range b {
			got = append(got, e.Process)
		}
		return nil
	}
	o := &outbox{path: path, send: send}
	for i, p := range []string{"a", "b", "c", "d", "e"} {
		ev := Event{Type: TypeTouched, Process: p}
		if i == 2 {
			ev.Type = "bad"
		}
		o.add(ev)
	}
	o.flush(context.Background())
	if len(o.held) != 5 || len(got) != 0 {
		t.Fatalf("403 must keep everything: held %d sent %v", len(o.held), got)
	}
	// The service restarts, then the owner approves the device.
	o = &outbox{path: path, send: send}
	o.load()
	status = 0
	o.flush(context.Background())
	if len(o.held) != 0 || len(got) != 4 || got[0] != "a" || got[2] != "d" {
		t.Fatalf("held %d sent %v", len(o.held), got)
	}
	o = &outbox{path: path, send: send}
	if o.load(); len(o.held) != 0 {
		t.Fatal("sent events still on disk")
	}
	for range maxHeld + 5 {
		o.add(Event{Type: TypeTouched})
	}
	if len(o.held) != maxHeld {
		t.Fatalf("not bounded: %d", len(o.held))
	}
}
