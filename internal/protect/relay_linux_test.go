package protect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

type fakeBackend struct {
	calls  int
	caller string
}

func (f *fakeBackend) Authorize(_ context.Context, tool, action, res, caller string) (*hostclient.AuthorizeResult, error) {
	f.calls++
	f.caller = caller
	return &hostclient.AuthorizeResult{Decision: "ALLOW"}, nil
}
func (f *fakeBackend) ApprovalStatus(context.Context, string) (string, error) { return "APPROVED", nil }

func TestRelayOnlyForwardsKnownToolsAndRecordsTheCaller(t *testing.T) {
	dir := t.TempDir()
	relayDir, relaySock, relayOwner = dir, filepath.Join(dir, "relay.sock"), uint32(os.Geteuid())
	l, err := listenRelay()
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{}
	srv := newRelayServer(b)
	go srv.Serve(l)
	defer srv.Close()
	old := protectedUID
	defer func() { protectedUID = old }()
	me := strconv.Itoa(os.Geteuid())
	protectedUID = func(uid string) bool { return uid == me }

	r := NewRelay()
	if v := r.Decide(context.Background(), "cursor", "shell", "ls", 5e9); !v.Allow || b.calls != 1 {
		t.Fatalf("valid call not forwarded: %+v", v)
	}
	if b.caller != "uid:"+strconv.Itoa(os.Geteuid()) {
		t.Fatalf("caller %q: the kernel's answer must be recorded", b.caller)
	}
	// Tools Manar does not wrap, and empty fields, never reach Manar.
	for _, tool := range []string{"chatgpt-desktop", "nope"} {
		if v := r.Decide(context.Background(), tool, "shell", "ls", 5e9); v.Allow {
			t.Errorf("allowed unknown tool %s", tool)
		}
	}
	if v := r.Decide(context.Background(), "cursor", "", "ls", 5e9); v.Allow {
		t.Error("allowed an empty action")
	}
	if b.calls != 1 {
		t.Fatal("forwarded a bad request")
	}
}

func TestRelayRefusesASocketThatIsNotTheServices(t *testing.T) {
	dir := t.TempDir()
	relayDir, relaySock = dir, filepath.Join(dir, "relay.sock")
	relayOwner = uint32(os.Geteuid()) + 1 // pretend the service is someone else
	l, err := listenRelay()
	if err != nil {
		t.Fatal(err)
	}
	srv := newRelayServer(&fakeBackend{})
	go srv.Serve(l)
	defer srv.Close()
	if v := NewRelay().Decide(context.Background(), "cursor", "shell", "ls", 5e9); v.Allow || !strings.Contains(v.Reason, "manar-edge protect restore") {
		t.Fatalf("trusted a squatted socket, or gave no way out: %+v", v)
	}
}

func TestDecideFailsClosedWithAWayOutWhenTheServiceIsGone(t *testing.T) {
	relayDir, relaySock, relayOwner = t.TempDir(), filepath.Join(t.TempDir(), "none.sock"), uint32(os.Geteuid())
	v := NewRelay().Decide(context.Background(), "cursor", "shell", "ls", 5e9)
	if v.Allow || !strings.Contains(v.Reason, "manar-edge protect restore") {
		t.Fatalf("%+v", v)
	}
}

func TestRelayRefusesAccountsWithoutProtectedTools(t *testing.T) {
	dir := t.TempDir()
	relayDir, relaySock, relayOwner = dir, filepath.Join(dir, "relay.sock"), uint32(os.Geteuid())
	l, err := listenRelay()
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{}
	srv := newRelayServer(b)
	go srv.Serve(l)
	defer srv.Close()
	old := protectedUID
	defer func() { protectedUID = old }()
	protectedUID = func(string) bool { return false }
	if os.Geteuid() == 0 {
		t.Skip("root may always ask")
	}
	if v := NewRelay().Decide(context.Background(), "cursor", "shell", "ls", 5e9); v.Allow || b.calls != 0 {
		t.Fatalf("an account with no protected tools was let through: %+v", v)
	}
	for c, want := range map[string]bool{"uid:0": true, "sid:S-1-5-21-1-2-3-1001": true, "unknown": false, "": false, "uid:1000": false} {
		if callerAllowed(c) != want {
			t.Errorf("callerAllowed(%q) != %v", c, want)
		}
	}
}

func TestTamperReportOnlyFromProtectedAccounts(t *testing.T) {
	got := captureTamper(t)
	old := protectedUID
	defer func() { protectedUID = old }()
	h := relayHandler(&fakeBackend{})
	post := func(caller, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/tamper", strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), callerKey{}, caller))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	body := `{"toolId":"host.claude-code","action":"edit","path":"/home/sam/app/.claude/settings.json"}`
	protectedUID = func(string) bool { return false }
	if c := post("uid:1000", body); c != http.StatusForbidden || len(*got) != 0 {
		t.Fatalf("an account without protected tools reported: %d %v", c, *got)
	}
	protectedUID = func(string) bool { return true }
	if c := post("uid:1000", `{"toolId":"host.nope","action":"edit"}`); c != 400 {
		t.Fatalf("unknown tool: %d", c)
	}
	if c := post("uid:1000", body); c != 200 || len(*got) != 1 || (*got)[0]["type"] != TamperSettingsWrite || (*got)[0]["blocked"] != true {
		t.Fatalf("report: %d %v", c, *got)
	}
}
