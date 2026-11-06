package protect

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

type stubBackend struct {
	asked  atomic.Int32
	result hostclient.AuthorizeResult
	mu     sync.Mutex
	status string
}

func (s *stubBackend) set(v string) { s.mu.Lock(); s.status = v; s.mu.Unlock() }

func (s *stubBackend) Authorize(context.Context, string, string, string, string, string) (*hostclient.AuthorizeResult, error) {
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
	srv := httptest.NewUnstartedServer(relayHandler(b))
	srv.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, callerKey{}, "uid:0")
	}
	srv.Start()
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

func TestRevokedBeforeTheDeviceReadItIsRefused(t *testing.T) {
	old := isPaused
	defer func() { isPaused = old }()
	isPaused = func() bool { return false }
	b := &stubBackend{result: hostclient.AuthorizeResult{Decision: "APPROVAL_REQUIRED", ApprovalID: "ap1"}, status: "REVOKED"}
	r := relayFor(t, b)
	if v := r.Decide(context.Background(), "cursor", "shell", "ls", 5*time.Second); v.Allow || !strings.Contains(v.Reason, "approval revoked") {
		t.Fatalf("revoked: %+v", v)
	}
}

// A device Manar locked (revoked, suspended, workspace deleted) keeps its hooks and denies every
// action without asking, with a reason the person can act on, also after a restart.
func TestLockedDeviceDeniesWithoutAskingManar(t *testing.T) {
	dir := t.TempDir()
	Configure(dir)
	b := &stubBackend{result: hostclient.AuthorizeResult{Decision: "ALLOW"}, status: "APPROVED"}
	r := relayFor(t, b)
	locked := relayLocked(t, dir, "device_revoked")
	v := r.Decide(context.Background(), "cursor", "shell", "ls", 5*time.Second)
	if v.Allow || !strings.Contains(v.Reason, "device_locked") || b.asked.Load() != 0 {
		t.Fatalf("locked authorize: %+v asked=%d", v, b.asked.Load())
	}
	locked(false)
	if v := r.Decide(context.Background(), "cursor", "shell", "ls", 5*time.Second); !v.Allow {
		t.Fatalf("unlocked authorize: %+v", v)
	}
}

// relayLocked locks the device the way hostclient does on a 423 reply (a config poll answered
// 423) and returns a switch to unlock it (a good config).
func relayLocked(t *testing.T, dir, code string) func(bool) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("X-Unlock"), "1") {
			_, _ = w.Write([]byte(`{"status":"APPROVED"}`))
			return
		}
		w.WriteHeader(423)
		_, _ = w.Write([]byte(`{"code":"` + code + `"}`))
	}))
	t.Cleanup(srv.Close)
	c := hostclient.NewForTest(dir, srv.URL, srv.Client())
	_, _ = c.Config(context.Background())
	if hostclient.LockedCode(dir) != code {
		t.Fatal("setup: not locked")
	}
	return func(on bool) {
		if !on {
			hc := &http.Client{Transport: unlockHeader{srv.Client().Transport}}
			if _, err := hostclient.NewForTest(dir, srv.URL, hc).Config(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type unlockHeader struct{ rt http.RoundTripper }

func (u unlockHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("X-Unlock", "1")
	return u.rt.RoundTrip(r)
}
