package warden

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeAPI struct {
	mu      sync.Mutex
	pending pendingReply
	posted  []string // "path decision"
}

func (f *fakeAPI) Do(ctx context.Context, method, path string, in, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if method == "GET" {
		b, _ := json.Marshal(f.pending)
		return json.Unmarshal(b, out)
	}
	f.posted = append(f.posted, path+" "+in.(map[string]string)["decision"])
	return nil
}

func (f *fakeAPI) posts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.posted...)
}

func helperThatAnswers(t *testing.T, b *Broker, l fakeListener, d Decision) {
	t.Helper()
	client := connect(t, l, 1000)
	t.Cleanup(func() { client.Close() })
	waitHelper(t, b, true)
	hc := newCodec(client)
	go func() {
		for {
			m, err := hc.recv()
			if err != nil {
				return
			}
			if m.Type == "prompt" {
				_ = hc.send(msg{Type: "answer", ID: m.Prompt.ID, Decision: d})
			}
		}
	}()
}

func wait(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

var _ net.Conn

func TestEightHourChoiceIsSentToTheAPI(t *testing.T) {
	b, l := serve(t, uidCheck(1000))
	helperThatAnswers(t, b, l, ApproveEight)
	api := &fakeAPI{pending: pendingReply{OwnerMayApprove: true, Items: []pendingItem{
		{ID: "ap1", ToolID: "host.cursor", ActionID: "file.read", Resource: "~/.aws/credentials", DecidableHere: true},
	}}}
	w := &watcher{broker: b, api: api, seen: map[string]context.CancelFunc{}}
	w.tick(context.Background())
	wait(t, func() bool { return len(api.posts()) == 1 })
	if got := api.posts()[0]; got != "/approvals/ap1/decide approve_8h" {
		t.Fatalf("posted %q", got)
	}
	// The same approval is not asked twice.
	w.tick(context.Background())
	time.Sleep(50 * time.Millisecond)
	if len(api.posts()) != 1 {
		t.Fatalf("asked again: %v", api.posts())
	}
}

func TestHighRiskAndNonApproverNeverSendADecision(t *testing.T) {
	for name, reply := range map[string]pendingReply{
		"high risk":    {OwnerMayApprove: true, Items: []pendingItem{{ID: "a", HighRisk: true, DecidableHere: false}}},
		"not approver": {OwnerMayApprove: false, Items: []pendingItem{{ID: "a", DecidableHere: false}}},
	} {
		b, l := serve(t, uidCheck(1000))
		helperThatAnswers(t, b, l, ApproveOnce) // even a helper that says yes
		api := &fakeAPI{pending: reply}
		w := &watcher{broker: b, api: api, seen: map[string]context.CancelFunc{}}
		w.tick(context.Background())
		time.Sleep(100 * time.Millisecond)
		if len(api.posts()) != 0 {
			t.Fatalf("%s: sent %v", name, api.posts())
		}
	}
}

func TestNoHelperMeansNoDecision(t *testing.T) {
	b, _ := serve(t, uidCheck(1000))
	api := &fakeAPI{pending: pendingReply{OwnerMayApprove: true, Items: []pendingItem{{ID: "a", DecidableHere: true}}}}
	w := &watcher{broker: b, api: api, seen: map[string]context.CancelFunc{}}
	w.tick(context.Background())
	if len(api.posts()) != 0 {
		t.Fatal("decided without a helper")
	}
	if _, err := AskSecret(context.Background(), "x", "y"); err != ErrNoHelper {
		t.Fatalf("AskSecret with no broker = %v", err)
	}
}
