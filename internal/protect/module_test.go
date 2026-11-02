package protect

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manarhq/manar-edge/internal/discovery"
	"github.com/manarhq/manar-edge/internal/hostclient"
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

// Claude Code follows the console's switch like every other tool: a PreToolUse hook in the
// person's own settings, kept alongside what is already there, and taken out when switched off.
// Agent mode (install-claude-code wrote Manar's hook into the managed settings) wins and the
// person's settings are left alone.
func TestReconcileProtectsClaudeCodeThroughTheUsersSettings(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state"))
	defer func(p string) { ClaudeSettingsPath = p }(ClaudeSettingsPath)
	ClaudeSettingsPath = filepath.Join(root, "etc", "managed-settings.json")
	u := discovery.User{Name: "sam", Home: filepath.Join(root, "home"), UID: -1, GID: -1}
	settings := filepath.Join(u.Home, ".claude", "settings.json")
	orig := `{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"mine.sh"}]}]}}`
	write(t, settings, orig)
	found := []discovery.Found{{Spec: discovery.Spec{Key: "claude-code", ID: "host.claude-code", Name: "Claude Code"}, Users: []discovery.User{u}}}

	st := reconcile(context.Background(), found, &hostclient.Config{Status: "APPROVED"})
	got := read(t, settings)
	if s := st["host.claude-code"]; !s.Protected || s.Mode != "hook" {
		t.Fatalf("Claude Code not protected: %+v", s)
	}
	for _, want := range []string{`hook-tool claude-code tool"`, `"timeout": 600`, `"matcher": "*"`, `"mine.sh"`, `"model": "opus"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s:\n%s", want, got)
		}
	}
	off := &hostclient.Config{Status: "APPROVED", Tools: hostclient.ToolInstructions{Unprotect: []string{"host.claude-code"}}}
	if reconcile(context.Background(), found, off)["host.claude-code"].Protected || read(t, settings) != orig {
		t.Fatalf("switching Claude Code off did not restore the settings:\n%s", read(t, settings))
	}
	write(t, ClaudeSettingsPath, `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/manar-edge","args":["hook","claude-code","a1"]}]}]}}`)
	if s := reconcile(context.Background(), found, &hostclient.Config{Status: "APPROVED"})["host.claude-code"]; !s.Protected || read(t, settings) != orig {
		t.Fatalf("agent mode: %+v\n%s", s, read(t, settings))
	}
}

func TestSessionID(t *testing.T) {
	for in, want := range map[string]string{
		`{"session_id":"abc-123"}`:        "abc-123",
		`{"conversation_id":"c.1"}`:       "c.1",
		`{"session_id":"bad id; rm -rf"}`: "",
		`{"tool_name":"x"}`:               "",
		`nope`:                            "",
	} {
		if got := SessionID([]byte(in)); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}
