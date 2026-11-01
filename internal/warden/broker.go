package warden

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// writeTimeout bounds one write to a helper (a variable so tests can shorten it).
var writeTimeout = 3 * time.Second

// ErrNoHelper means no per-user helper is connected, so nobody can answer. Callers fail closed:
// the approval stays pending, and a vault release is denied.
var ErrNoHelper = errors.New("warden: no helper is connected")

// PeerCheck decides whether the process on the other end of conn may talk to the broker, and says
// which session it is (the user id on Linux). The real checks are in listen_linux.go (SO_PEERCRED,
// then the peer's executable) and listen_windows.go (the pipe's DACL, then the client's image).
// A nil error means allowed. At most one helper per id is accepted.
type PeerCheck func(conn net.Conn) (id string, err error)

// Broker is the service side: it accepts helper connections that pass the peer check, sends
// prompts to them and returns the first answer.
type Broker struct {
	check PeerCheck

	mu      sync.Mutex
	helpers map[*helper]struct{}
	ids     map[string]bool
}

type helper struct {
	conn net.Conn
	c    *codec
	wmu  sync.Mutex
	// answers: prompt id -> channel waiting for it
	mu      sync.Mutex
	waiting map[string]chan Decision
}

// send writes one line; a helper that stops reading cannot block the service for long.
func (h *helper) send(m msg) error {
	h.wmu.Lock()
	defer h.wmu.Unlock()
	_ = h.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return h.c.send(m)
}

func NewBroker(check PeerCheck) *Broker {
	return &Broker{check: check, helpers: map[*helper]struct{}{}, ids: map[string]bool{}}
}

// Serve accepts connections until the listener closes.
func (b *Broker) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go b.handle(conn)
	}
}

func (b *Broker) handle(conn net.Conn) {
	defer conn.Close()
	id, err := b.check(conn)
	if err != nil {
		log.Printf("warden: refused a connection: %v", err)
		return
	}
	h := &helper{conn: conn, c: newCodec(conn), waiting: map[string]chan Decision{}}
	b.mu.Lock()
	if b.ids[id] {
		// One helper per session: a second connection never replaces the first.
		b.mu.Unlock()
		log.Printf("warden: refused a second helper for the same session")
		return
	}
	b.ids[id] = true
	b.helpers[h] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.helpers, h)
		delete(b.ids, id)
		b.mu.Unlock()
	}()
	for {
		m, err := h.c.recv()
		if err != nil {
			return
		}
		if m.Type != "answer" {
			continue
		}
		h.mu.Lock()
		ch := h.waiting[m.ID]
		h.mu.Unlock()
		if ch != nil {
			select {
			case ch <- m.Decision:
			default:
			}
		}
	}
}

// HasHelper reports whether at least one allowed helper is connected.
func (b *Broker) HasHelper() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.helpers) > 0
}

// Ask shows p on every connected helper and returns the first valid decision, or Dismissed when a
// helper reports that the prompt was closed. Other helpers are told to withdraw the prompt.
// ctx ends the wait (the prompt is withdrawn too).
func (b *Broker) Ask(ctx context.Context, p Prompt) (Decision, error) {
	b.mu.Lock()
	hs := make([]*helper, 0, len(b.helpers))
	for h := range b.helpers {
		hs = append(hs, h)
	}
	b.mu.Unlock()
	if len(hs) == 0 {
		return "", ErrNoHelper
	}
	ch := make(chan Decision, len(hs))
	sent := 0
	for _, h := range hs {
		h.mu.Lock()
		h.waiting[p.ID] = ch
		h.mu.Unlock()
		if err := h.send(msg{Type: "prompt", Prompt: &p}); err == nil {
			sent++
		}
	}
	defer func() {
		for _, h := range hs {
			h.mu.Lock()
			delete(h.waiting, p.ID)
			h.mu.Unlock()
			_ = h.send(msg{Type: "cancel", ID: p.ID})
		}
	}()
	if sent == 0 {
		return "", ErrNoHelper
	}
	closed := 0
	for {
		select {
		case d := <-ch:
			if d.Valid() {
				return d, nil
			}
			closed++
			if closed >= sent {
				return Dismissed, nil
			}
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}
