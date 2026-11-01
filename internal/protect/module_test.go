package protect

import (
	"context"
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
	// A revoked device gets its tools back, even with the owner's switch on.
	reconcile(context.Background(), found, &hostclient.Config{Status: "APPROVED"})
	if !strings.Contains(read(t, hooks), "hook-tool") {
		t.Fatal("setup")
	}
	reconcile(context.Background(), found, &hostclient.Config{Status: "REVOKED"})
	if read(t, hooks) != orig {
		t.Fatal("hooks left behind on a revoked device")
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
