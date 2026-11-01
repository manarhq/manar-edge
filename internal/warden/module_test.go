package warden

import (
	"context"
	"encoding/json"
	"net"
	"strings"
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

func TestApproveOnceIsSentToTheAPI(t *testing.T) {
	b, l := serve(t, uidCheck(1000))
	helperThatAnswers(t, b, l, ApproveOnce)
	api := &fakeAPI{pending: pendingReply{OwnerMayApprove: true, Items: []pendingItem{
		{ID: "ap1", ToolID: "host.cursor", ActionID: "file.read", Resource: "~/.aws/credentials", DecidableHere: true},
	}}}
	w := &watcher{broker: b, api: api, seen: map[string]context.CancelFunc{}}
	w.tick(context.Background())
	wait(t, func() bool { return len(api.posts()) == 1 })
	if got := api.posts()[0]; got != "/approvals/ap1/decide approve_once" {
		t.Fatalf("posted %q", got)
	}
	// The same approval is not asked twice.
	w.tick(context.Background())
	time.Sleep(50 * time.Millisecond)
	if len(api.posts()) != 1 {
		t.Fatalf("asked again: %v", api.posts())
	}
}

// 8 hours is a console decision: even a helper that answers approve_8h gets nothing sent.
func TestAnEightHourAnswerFromTheDeviceIsNeverSent(t *testing.T) {
	b, l := serve(t, uidCheck(1000))
	helperThatAnswers(t, b, l, ApproveEight)
	api := &fakeAPI{pending: pendingReply{OwnerMayApprove: true, Items: []pendingItem{
		{ID: "ap1", ToolID: "host.cursor", ActionID: "file.read", Resource: "x", DecidableHere: true},
	}}}
	w := &watcher{broker: b, api: api, seen: map[string]context.CancelFunc{}}
	w.tick(context.Background())
	time.Sleep(150 * time.Millisecond)
	if len(api.posts()) != 0 {
		t.Fatalf("sent %v", api.posts())
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
		t.Fatalf("AskSecret with the service not running = %v", err)
	}
}

// scripted API for AskSecret: opens an approval, then answers the polls in order.
type vaultAPIFake struct {
	statuses []string
	calls    []string
}

func (f *vaultAPIFake) Do(ctx context.Context, method, path string, in, out any) error {
	f.calls = append(f.calls, method+" "+path)
	if method == "POST" {
		return json.Unmarshal([]byte(`{"id":"v1"}`), out)
	}
	s := f.statuses[0]
	if len(f.statuses) > 1 {
		f.statuses = f.statuses[1:]
	}
	return json.Unmarshal([]byte(s), out)
}

func TestAskSecretWaitsForTheConsoleDecision(t *testing.T) {
	for name, tc := range map[string]struct {
		statuses []string
		want     Decision
	}{
		"approved once":               {[]string{`{"status":"PENDING"}`, `{"status":"APPROVED","decision":"approve_once"}`}, ApproveOnce},
		"approved 8h":                 {[]string{`{"status":"APPROVED","decision":"approve_8h"}`}, ApproveEight},
		"denied":                      {[]string{`{"status":"DENIED","decision":"deny"}`}, Deny},
		"expired":                     {[]string{`{"status":"EXPIRED"}`}, Dismissed},
		"approved, no known decision": {[]string{`{"status":"APPROVED","decision":"whatever"}`}, Dismissed},
	} {
		f := &vaultAPIFake{statuses: tc.statuses}
		got, err := askSecret(context.Background(), f, "node", "AWS_KEY", time.Millisecond)
		if err != nil || got != tc.want {
			t.Errorf("%s: %q, %v", name, got, err)
		}
		if f.calls[0] != "POST /approvals/vault" {
			t.Errorf("%s: first call %q", name, f.calls[0])
		}
	}
}

func TestPromptCarriesThePlainWordsExplanationAndWithdrawsAfterTheDeadline(t *testing.T) {
	b, l := serve(t, uidCheck(1000))
	client := connect(t, l, 1000)
	defer client.Close()
	waitHelper(t, b, true)
	hc := newCodec(client)
	got := make(chan Prompt, 1)
	cancelled := make(chan string, 1)
	go func() {
		for {
			m, err := hc.recv()
			if err != nil {
				return
			}
			switch m.Type {
			case "prompt":
				got <- *m.Prompt // never answered: nobody is there
			case "cancel":
				cancelled <- m.ID
			}
		}
	}()
	it := pendingItem{ID: "ap1", ToolID: "host.cursor", ActionID: "bash", Resource: "ls", DecidableHere: true,
		ExpiresAt: time.Now().Add(150 * time.Millisecond)}
	it.Explanation.EN, it.Explanation.AR = "It wants to run a command.", "يريد تشغيل أمر."
	api := &fakeAPI{pending: pendingReply{OwnerMayApprove: true, Items: []pendingItem{it}}}
	w := &watcher{broker: b, api: api, seen: map[string]context.CancelFunc{}}
	w.tick(context.Background())
	p := <-got
	if p.ExplainEN == "" || p.ExplainAR == "" {
		t.Fatalf("explanation missing: %+v", p)
	}
	if en := Render(p, EN).Body; !strings.Contains(en, "run a command") {
		t.Errorf("EN body: %q", en)
	}
	if ar := Render(p, AR); !strings.Contains(ar.Body, "يريد تشغيل أمر") || !ar.RTL {
		t.Errorf("AR body: %q", ar.Body)
	}
	select {
	case id := <-cancelled:
		if id != "ap1" {
			t.Fatalf("cancelled %q", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the prompt was not withdrawn at the deadline")
	}
	if len(api.posts()) != 0 {
		t.Fatalf("a timed-out prompt must decide nothing on the device: %v", api.posts())
	}
}

func TestWindowsPromptIsOnUnlessTurnedOff(t *testing.T) {
	base := t.TempDir()
	if LoadSettings(base).WindowsUIOff {
		t.Fatal("the Windows prompt must be on by default")
	}
	if err := SaveSettings(base, Settings{WindowsUIOff: true}); err != nil || !LoadSettings(base).WindowsUIOff {
		t.Fatalf("opt out not kept: %v", err)
	}
}
