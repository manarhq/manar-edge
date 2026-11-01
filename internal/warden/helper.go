package warden

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// Prompter shows one prompt to the person at the screen and returns what they chose. It returns
// Dismissed when the prompt is closed or times out, and ctx.Err() when ctx ends first (the prompt
// is then withdrawn).
type Prompter interface {
	Show(ctx context.Context, p Prompt, t Text) (Decision, error)
}

// RunHelper is the per-user process: it connects to the broker, shows each prompt and sends the
// answer back. It reconnects until ctx ends. If the broker refuses this user several times in a
// row (the person is not the one WARDEN was set up for) it returns nil and stays out of the way.
func RunHelper(ctx context.Context, dial func(context.Context) (net.Conn, error), pr Prompter, lang Lang) error {
	refused := 0
	for ctx.Err() == nil {
		conn, err := dial(ctx)
		if err == nil {
			started := time.Now()
			serveHelper(ctx, conn, pr, lang)
			// A connection that is closed at once is a refusal by the peer check.
			if time.Since(started) < 2*time.Second {
				refused++
			} else {
				refused = 0
			}
			if refused >= 5 {
				log.Printf("warden: this user is not set up for WARDEN on this device; exiting")
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retryDial):
		}
	}
	return nil
}

var retryDial = 10 * time.Second

func serveHelper(ctx context.Context, conn net.Conn, pr Prompter, lang Lang) {
	defer conn.Close()
	c := newCodec(conn)
	var wmu sync.Mutex
	send := func(m msg) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = c.send(m)
	}
	var mu sync.Mutex
	cancels := map[string]context.CancelFunc{}
	connCtx, stop := context.WithCancel(ctx)
	defer stop()
	for {
		m, err := c.recv()
		if err != nil {
			return
		}
		switch m.Type {
		case "prompt":
			if m.Prompt == nil || m.Prompt.ID == "" {
				continue
			}
			p := *m.Prompt
			pctx, cancel := context.WithCancel(connCtx)
			mu.Lock()
			cancels[p.ID] = cancel
			mu.Unlock()
			go func() {
				defer cancel()
				d, err := pr.Show(pctx, p, Render(p, lang))
				mu.Lock()
				delete(cancels, p.ID)
				mu.Unlock()
				if err != nil || !d.Valid() {
					d = Dismissed
				}
				if p.ConsoleOnly {
					d = Dismissed
				}
				send(msg{Type: "answer", ID: p.ID, Decision: d})
			}()
		case "cancel":
			mu.Lock()
			if cancel := cancels[m.ID]; cancel != nil {
				cancel()
			}
			mu.Unlock()
		}
	}
}
