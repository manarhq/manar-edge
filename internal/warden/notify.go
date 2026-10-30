package warden

import (
	"context"
	"sync"
	"time"
)

// notifier is the part of a desktop notification service the Linux prompt needs
// (org.freedesktop.Notifications). The D-Bus implementation is in dbus_linux.go; tests use a fake.
type notifier interface {
	// Notify shows a notification with the given action pairs (key, label, key, label...) and
	// returns its id.
	Notify(summary, body string, actions []string, urgent bool) (uint32, error)
	Close(id uint32) error
	// Events delivers action clicks and closes.
	Events() <-chan notifyEvent
}

type notifyEvent struct {
	ID     uint32
	Action string // set for ActionInvoked
	Closed bool   // set for NotificationClosed
}

const (
	actOnce = "approve_once"
	actDeny = "deny"
)

// notifyPrompter shows prompts through a notifier.
type notifyPrompter struct {
	n       notifier
	timeout time.Duration

	once    sync.Once
	mu      sync.Mutex
	waiters map[uint32]chan notifyEvent
}

// dispatch routes each event to the prompt that owns the notification id.
func (p *notifyPrompter) dispatch() {
	for ev := range p.n.Events() {
		p.mu.Lock()
		ch := p.waiters[ev.ID]
		p.mu.Unlock()
		if ch != nil {
			select {
			case ch <- ev:
			default:
			}
		}
	}
}

func (p *notifyPrompter) Show(ctx context.Context, pr Prompt, t Text) (Decision, error) {
	var actions []string
	if !pr.ConsoleOnly {
		actions = []string{actOnce, t.Once, actDeny, t.Deny}
	}
	body := t.Body
	if pr.ConsoleOnly {
		body += "\n" + t.Console
	}
	p.once.Do(func() { p.waiters = map[uint32]chan notifyEvent{}; go p.dispatch() })
	id, err := p.n.Notify(t.Title, body, actions, true)
	if err != nil {
		return "", err
	}
	if pr.ConsoleOnly {
		return Dismissed, nil
	}
	events := make(chan notifyEvent, 2)
	p.mu.Lock()
	p.waiters[id] = events
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waiters, id)
		p.mu.Unlock()
	}()
	timeout := time.After(p.timeout)
	for {
		select {
		case ev := <-events:
			if ev.Closed {
				return Dismissed, nil
			}
			return DecisionFromAction(ev.Action), nil
		case <-timeout:
			_ = p.n.Close(id)
			return Dismissed, nil
		case <-ctx.Done():
			_ = p.n.Close(id)
			return "", ctx.Err()
		}
	}
}

// DecisionFromAction maps an action key from a notification to a decision. Anything that is not
// one of the three keys (including the default click on the body) is Dismissed.
func DecisionFromAction(key string) Decision {
	switch key {
	case actOnce:
		return ApproveOnce
	case actDeny:
		return Deny
	}
	return Dismissed
}
