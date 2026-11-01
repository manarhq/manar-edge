package warden

import (
	"context"
	"log"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/daemon"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
	"gitlab.vax.sh/manar/manar-edge/internal/pause"
)

func init() { daemon.Register(&module{base: ""}) }

// SetStateDir tells the registered module where the state directory is. cmd/manar-edge calls it
// before the service starts.
func SetStateDir(base string) { stateDir.Store(&base) }

type pendingItem struct {
	ID            string `json:"id"`
	ToolID        string `json:"toolId"`
	ActionID      string `json:"actionId"`
	Resource      string `json:"resource"`
	HighRisk      bool   `json:"highRisk"`
	DecidableHere bool   `json:"decidableHere"`
	// Explanation is the API's plain-words risk text in both languages (deterministic templates).
	Explanation struct {
		EN string `json:"en"`
		AR string `json:"ar"`
	} `json:"explanation"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// NoAnswerAfter is how long a prompt stays on screen. The API denies an unanswered approval after
// the same 2 minutes ("denied: no answer") and pushes the phone when the approval opens, which is
// when this prompt appears; the device withdraws the prompt at whichever comes first.
const NoAnswerAfter = 2 * time.Minute

type pendingReply struct {
	OwnerMayApprove bool          `json:"ownerMayApprove"`
	Items           []pendingItem `json:"items"`
}

// module polls this host's pending approvals, asks the helper and sends the decision to the API.
type module struct {
	base string
}

func (*module) Name() string { return "warden" }

func (m *module) Start(ctx context.Context, c *hostclient.Client) error {
	base := m.base
	if p := stateDir.Load(); p != nil {
		base = *p
	}
	if runtime.GOOS == "windows" && LoadSettings(base).WindowsUIOff {
		log.Printf("warden: the Windows prompt was turned off (manar-edge warden windows-ui on turns it back on); approvals are answered in the console")
		<-ctx.Done()
		return nil
	}
	l, check, err := listen(base)
	if err != nil {
		return err
	}
	defer l.Close()
	b := NewBroker(check)
	setAPI(c)
	defer vaultAPI.Store(nil)
	go func() { _ = b.Serve(l) }()

	w := &watcher{broker: b, api: c, seen: map[string]context.CancelFunc{}, paused: func() bool { return pause.Paused(base) }}
	return w.run(ctx)
}

// decider is the part of the API client the watcher needs (a fake in tests).
type decider interface {
	Do(ctx context.Context, method, path string, in, out any) error
}

type watcher struct {
	broker *Broker
	api    decider
	poll   time.Duration
	// paused: while "Pause all AI" is on, nothing is shown (and what is on screen is withdrawn);
	// the API refuses to approve during a pause and expires what was pending.
	paused func() bool

	mu   sync.Mutex
	seen map[string]context.CancelFunc // prompted approvals; the cancel withdraws the prompt
}

func (w *watcher) run(ctx context.Context) error {
	poll := w.poll
	if poll == 0 {
		poll = 3 * time.Second
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		w.tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (w *watcher) tick(ctx context.Context) {
	if w.paused != nil && w.paused() {
		w.mu.Lock()
		for id, cancel := range w.seen {
			cancel()
			delete(w.seen, id)
		}
		w.mu.Unlock()
		return
	}
	if !w.broker.HasHelper() {
		return
	}
	var r pendingReply
	if err := w.api.Do(ctx, http.MethodGet, "/approvals/pending", nil, &r); err != nil {
		if ctx.Err() == nil {
			log.Printf("warden: reading pending approvals: %v", err)
		}
		return
	}
	live := map[string]bool{}
	for _, it := range r.Items {
		live[it.ID] = true
		w.mu.Lock()
		_, done := w.seen[it.ID]
		w.mu.Unlock()
		if done {
			continue
		}
		pctx, cancel := context.WithCancel(ctx)
		w.mu.Lock()
		w.seen[it.ID] = cancel
		w.mu.Unlock()
		go w.handle(pctx, it, r.OwnerMayApprove)
	}
	// Decided elsewhere (the console, another device) or expired: withdraw the prompt and forget it.
	w.mu.Lock()
	for id, cancel := range w.seen {
		if !live[id] {
			cancel()
			delete(w.seen, id)
		}
	}
	w.mu.Unlock()
}

func (w *watcher) handle(ctx context.Context, it pendingItem, ownerMayApprove bool) {
	p := Prompt{
		ID: it.ID, Kind: KindAction, ToolID: it.ToolID, ActionID: it.ActionID, Resource: it.Resource,
		ConsoleOnly: it.HighRisk || !it.DecidableHere || !ownerMayApprove,
		ExplainEN:   clip(it.Explanation.EN, 400), ExplainAR: clip(it.Explanation.AR, 400),
	}
	// A prompt is never left on screen past 2 minutes, whatever the API's clock says.
	limit := time.Now().Add(NoAnswerAfter)
	if !it.ExpiresAt.IsZero() && it.ExpiresAt.Before(limit) {
		limit = it.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(ctx, limit)
	defer cancel()
	d, err := w.broker.Ask(ctx, p)
	if err != nil {
		if err == ErrNoHelper {
			// Nobody to ask yet: forget it so the next poll tries again.
			w.mu.Lock()
			delete(w.seen, it.ID)
			w.mu.Unlock()
		}
		return
	}
	// A device answers once or deny, nothing else: whatever else arrives (a modified helper
	// sending approve_8h) is dropped and the approval stays pending for the console.
	if p.ConsoleOnly || (d != ApproveOnce && d != Deny) {
		return
	}
	var res struct{ Status string }
	if err := w.api.Do(ctx, http.MethodPost, "/approvals/"+it.ID+"/decide", map[string]string{"decision": string(d)}, &res); err != nil {
		log.Printf("warden: sending the decision: %v", err)
	}
}

var stateDir atomic.Pointer[string]
