package protect

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manarhq/manar-edge/internal/discovery"
	"github.com/manarhq/manar-edge/internal/hostclient"
)

func (r hookRig) reportedKind(kind string) bool {
	for _, ev := range *r.events {
		if ev["type"] == kind {
			return true
		}
	}
	return false
}

// F9: "disableAllHooks": true in ~/.claude/settings.json is taken out and reported.
func TestDisableAllHooksInUserSettingsIsRemovedAndReported(t *testing.T) {
	r := newRig(t)
	r.reconcile(t)
	b := []byte(read(t, r.settings))
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["disableAllHooks"] = true
	nb, _ := json.MarshalIndent(m, "", "  ")
	write(t, r.settings, string(nb))
	*r.events = nil
	r.reconcile(t)
	if strings.Contains(read(t, r.settings), "disableAllHooks") {
		t.Error("disableAllHooks stayed in the settings")
	}
	if !r.reportedKind(TamperHooksDisabled) {
		t.Error("disableAllHooks was removed without a report")
	}
	if !r.pointsAtOwnBinary(t) {
		t.Error("the hook is not in place")
	}
}

// F8: a hook removed by `protect restore` and put back by the service is reported once.
func TestHookPutBackAfterCLIRestoreIsReported(t *testing.T) {
	r := newRig(t)
	r.reconcile(t)
	if err := RestoreTool("claude-code"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read(t, r.settings), "hook-tool") {
		t.Fatal("restore did not remove the hook")
	}
	*r.events = nil
	r.reconcile(t)
	if !r.reportedKind(TamperHookRemoved) {
		t.Error("the hook was re-added after a CLI restore with no report")
	}
	*r.events = nil
	tamper.mu.Lock()
	tamper.seen = nil
	tamper.mu.Unlock()
	r.reconcile(t)
	if len(*r.events) != 0 {
		t.Errorf("the restore was reported twice: %v", *r.events)
	}
}

// F7: a Manar entry deleted from a file where the tool does not trust the hook (Codex) is reported
// when it is put back; so is a wrapped MCP server unwrapped by hand. The person adding their own
// MCP server is not tampering.
func TestRepairOfAnyManarEntryIsReported(t *testing.T) {
	r := newRig(t)
	codex := filepath.Join(r.u.Home, ".codex", "hooks.json")
	write(t, codex, `{}`)
	found := []discovery.Found{{Spec: discovery.Spec{Key: "codex-cli", ID: "host.codex-cli", Name: "Codex"}, Users: []discovery.User{r.u}}}
	recon := func() { reconcile(context.Background(), found, &hostclient.Config{Status: "APPROVED"}) }
	recon()
	if !strings.Contains(read(t, codex), "hook-tool") {
		t.Fatal("setup: codex hook not written")
	}
	write(t, codex, `{}`)
	*r.events = nil
	recon()
	if !strings.Contains(read(t, codex), "hook-tool") || !r.reported() {
		t.Error("Codex hook removed and silently re-added")
	}

	// MCP wrappers (Claude Desktop keeps its servers in one file)
	mcp := filepath.Join(r.u.Home, ".config", "Claude", "claude_desktop_config.json")
	write(t, mcp, `{"mcpServers":{"a":{"command":"npx","args":["a"]}}}`)
	desk := []discovery.Found{{Spec: discovery.Spec{Key: "claude-desktop", ID: "host.claude-desktop", Name: "Claude Desktop"}, Users: []discovery.User{r.u}}}
	recd := func() { reconcile(context.Background(), desk, &hostclient.Config{Status: "APPROVED"}) }
	recd()
	if !strings.Contains(read(t, mcp), "mcp-wrap") {
		t.Skip("MCP wrapping is not set up in this rig")
	}
	*r.events = nil
	var doc map[string]map[string]any
	_ = json.Unmarshal([]byte(read(t, mcp)), &doc)
	doc["mcpServers"]["b"] = map[string]any{"command": "npx", "args": []any{"b"}}
	nb, _ := json.Marshal(doc)
	write(t, mcp, string(nb))
	recd()
	if r.reported() {
		t.Error("a server the person added was reported as tampering")
	}
	write(t, mcp, `{"mcpServers":{"a":{"command":"npx","args":["a"]}}}`)
	recd()
	if !r.reported() {
		t.Error("a wrapper taken out of an MCP server was put back silently")
	}
}
