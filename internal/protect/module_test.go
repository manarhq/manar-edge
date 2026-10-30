package protect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.vax.sh/manar/manar-edge/internal/discovery"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

func TestReconcileFollowsApprovalAndTheOwnersSwitch(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state"))
	u := discovery.User{Name: "sam", Home: filepath.Join(root, "home"), UID: -1, GID: -1}
	hooks := filepath.Join(u.Home, ".gemini", "settings.json")
	orig := `{"theme":"dark"}`
	write(t, hooks, orig)
	found := []discovery.Found{{Spec: discovery.Spec{Key: "gemini-cli", ID: "host.gemini-cli", Name: "Gemini CLI"}, Users: []discovery.User{u}}}
	GatewayURL = "http://127.0.0.1:1" // nothing there

	st := reconcile(context.Background(), found, &hostclient.Config{Status: "PENDING"})
	if st["host.gemini-cli"].Protected || read(t, hooks) != orig {
		t.Fatal("changed a tool before the device was approved")
	}
	st = reconcile(context.Background(), found, &hostclient.Config{Status: "APPROVED"})
	if s := st["host.gemini-cli"]; !s.Protected || s.Mode != "hook" || len(s.Changes) == 0 || !strings.Contains(read(t, hooks), "hook-tool") {
		t.Fatalf("%+v", s)
	}
	off := &hostclient.Config{Status: "APPROVED", Tools: hostclient.ToolInstructions{Unprotect: []string{"host.gemini-cli"}}}
	st = reconcile(context.Background(), found, off)
	if st["host.gemini-cli"].Protected || read(t, hooks) != orig {
		t.Fatal("unprotect did not restore the original")
	}
	// Staying off: no new backup churn, file stays original.
	reconcile(context.Background(), found, off)
	if read(t, hooks) != orig {
		t.Fatal("re-protected while the owner has it off")
	}
	// ChatGPT desktop has nothing to edit and is never reported protected.
	cg := []discovery.Found{{Spec: discovery.Spec{Key: "chatgpt-desktop", ID: "host.chatgpt-desktop"}, Users: []discovery.User{u}}}
	if reconcile(context.Background(), cg, &hostclient.Config{Status: "APPROVED"})["host.chatgpt-desktop"].Protected {
		t.Fatal("ChatGPT desktop reported protected")
	}
	if err := (&relayModule{}).Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type fakeBackend struct{ calls int }

func (f *fakeBackend) Authorize(_ context.Context, tool, action, res string) (*hostclient.AuthorizeResult, error) {
	f.calls++
	return &hostclient.AuthorizeResult{Decision: "ALLOW"}, nil
}
func (f *fakeBackend) ApprovalStatus(context.Context, string) (string, error) { return "APPROVED", nil }

func TestRelayOnlyForwardsKnownTools(t *testing.T) {
	b := &fakeBackend{}
	srv := httptest.NewServer(relayHandler(b))
	defer srv.Close()
	post := func(body string) int {
		res, err := http.Post(srv.URL+"/v1/authorize", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if post(`{"toolId":"host.cursor","actionId":"shell","resource":"ls"}`) != 200 || b.calls != 1 {
		t.Fatal("valid call not forwarded")
	}
	for _, bad := range []string{`{"toolId":"host.claude-code","actionId":"shell","resource":"ls"}`, `{"toolId":"host.cursor","actionId":"","resource":"ls"}`, `nope`} {
		if post(bad) != 400 {
			t.Errorf("accepted %s", bad)
		}
	}
	if b.calls != 1 {
		t.Fatal("forwarded a bad request")
	}
}

func TestRelayDecideEndToEnd(t *testing.T) {
	srv := httptest.NewServer(relayHandler(&fakeBackend{}))
	defer srv.Close()
	r := NewRelay()
	r.Base = srv.URL
	if v := r.Decide(context.Background(), "cursor", "shell", "ls", 5e9); !v.Allow {
		t.Fatal(v)
	}
	r.Base = "http://127.0.0.1:1" // service down: fail closed
	if v := r.Decide(context.Background(), "cursor", "shell", "ls", 5e9); v.Allow {
		t.Fatal("allowed with the service down")
	}
}
