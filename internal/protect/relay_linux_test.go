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
	calls    int
	caller   string
	resolved string
}

func (f *fakeBackend) Authorize(_ context.Context, tool, action, res, caller, resolved string) (*hostclient.AuthorizeResult, error) {
	f.calls++
	f.caller, f.resolved = caller, resolved
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
	if v := NewRelay().Decide(context.Background(), "cursor", "shell", "ls", 5e9); v.Allow || !strings.Contains(v.Reason, "restart it or contact their administrator") {
		t.Fatalf("trusted a squatted socket, or gave no hint for the person: %+v", v)
	}
}

func TestDecideFailsClosedAndNamesNoCommandWhenTheServiceIsGone(t *testing.T) {
	relayDir, relaySock, relayOwner = t.TempDir(), filepath.Join(t.TempDir(), "none.sock"), uint32(os.Geteuid())
	v := NewRelay().Decide(context.Background(), "cursor", "shell", "ls", 5e9)
	if v.Allow || !strings.Contains(v.Reason, "restart it or contact their administrator") {
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

// The hook sends the target with its links resolved (a file that does not exist yet: its existing
// folder plus the name), only for file actions, and leaves it out when it cannot be resolved.
func TestHookSendsTheResolvedPathOfAFileAction(t *testing.T) {
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

	root, _ := filepath.EvalSymlinks(t.TempDir())
	secret := filepath.Join(root, "ssh")
	os.MkdirAll(secret, 0o755)
	docs := filepath.Join(root, "docs") // the repo ships docs -> ~/.ssh
	if err := os.Symlink(secret, docs); err != nil {
		t.Skip(err)
	}
	os.WriteFile(filepath.Join(secret, "known_hosts"), []byte("x"), 0o644)
	r := NewRelay()
	for name, c := range map[string]struct{ action, res, want string }{
		"existing file through a link": {"write", filepath.Join(docs, "known_hosts"), filepath.Join(secret, "known_hosts")},
		"new file through a link":      {"write", filepath.Join(docs, "authorized_keys"), filepath.Join(secret, "authorized_keys")},
		"plain file":                   {"read", filepath.Join(root, "ssh", "known_hosts"), filepath.Join(secret, "known_hosts")},
		"folder that does not exist":   {"write", filepath.Join(root, "nodir", "x"), ""},
		"not a file action":            {"shell", "ls " + docs, ""},
	} {
		b.resolved = "unset"
		r.Decide(context.Background(), "cursor", c.action, c.res, 5e9)
		if b.resolved != c.want {
			t.Errorf("%s: resolvedPath %q, want %q", name, b.resolved, c.want)
		}
	}
}
