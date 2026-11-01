package protect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

type stubBackend struct {
	asked  atomic.Int32
	result hostclient.AuthorizeResult
	mu     sync.Mutex
	status string
}

func (s *stubBackend) set(v string) { s.mu.Lock(); s.status = v; s.mu.Unlock() }

func (s *stubBackend) Authorize(context.Context, string, string, string, string) (*hostclient.AuthorizeResult, error) {
	s.asked.Add(1)
	r := s.result
	return &r, nil
}
func (s *stubBackend) ApprovalStatus(context.Context, string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, nil
}

func relayFor(t *testing.T, b backend) *Relay {
	srv := httptest.NewServer(relayHandler(b))
	t.Cleanup(srv.Close)
	return &Relay{Base: srv.URL, HTTP: &http.Client{Timeout: 5 * time.Second}, PollMin: time.Millisecond, PollMax: 5 * time.Millisecond}
}

func TestPausedDeniesWithoutAskingManarAndNeverLetsAnApprovalThrough(t *testing.T) {
	old := isPaused
	defer func() { isPaused = old }()
	b := &stubBackend{result: hostclient.AuthorizeResult{Decision: "ALLOW"}, status: "APPROVED"}
	r := relayFor(t, b)

	isPaused = func() bool { return true }
	v := r.Decide(context.Background(), "cursor", "shell", "ls", 5*time.Second)
	if v.Allow || !strings.Contains(v.Reason, "denied: paused") || b.asked.Load() != 0 {
		t.Fatalf("paused authorize: %+v asked=%d", v, b.asked.Load())
	}

	// An approval opened before the pause and approved during it must not let the call run.
	isPaused = func() bool { return false }
	b.result = hostclient.AuthorizeResult{Decision: "APPROVAL_REQUIRED", ApprovalID: "ap1"}
	b.set("PENDING")
	var on atomic.Bool
	isPaused = on.Load
	flip := time.AfterFunc(20*time.Millisecond, func() { b.set("APPROVED"); on.Store(true) })
	defer flip.Stop()
	v = r.Decide(context.Background(), "cursor", "shell", "ls", 5*time.Second)
	if v.Allow || !strings.Contains(v.Reason, "denied: paused") {
		t.Fatalf("approved during a pause: %+v", v)
	}
}

func TestNoAnswerIsDeniedAfterTheLimitOrWhenExpired(t *testing.T) {
	old := isPaused
	defer func() { isPaused = old }()
	isPaused = func() bool { return false }
	b := &stubBackend{result: hostclient.AuthorizeResult{Decision: "APPROVAL_REQUIRED", ApprovalID: "ap1"}, status: "PENDING"}
	r := relayFor(t, b)
	r.NoAnswer = 40 * time.Millisecond
	if v := r.Decide(context.Background(), "cursor", "shell", "ls", 5*time.Second); v.Allow || v.Reason != "Manar denied: no answer" {
		t.Fatalf("limit: %+v", v)
	}
	b.set("EXPIRED")
	if v := r.Decide(context.Background(), "cursor", "shell", "ls", 5*time.Second); v.Allow || v.Reason != "Manar denied: no answer" {
		t.Fatalf("expired: %+v", v)
	}
	if NoAnswerAfter != 2*time.Minute {
		t.Fatal("the founder's limit is 2 minutes")
	}
}
