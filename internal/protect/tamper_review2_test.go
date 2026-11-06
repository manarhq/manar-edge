package protect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manarhq/manar-edge/internal/discovery"
	"github.com/manarhq/manar-edge/internal/hostclient"
)

// C1: the words "hook-tool " left in the file do not hide that Manar's Codex hook was removed.
func TestRemovedCodexHookIsReportedEvenWithTheWordsLeftBehind(t *testing.T) {
	r := newRig(t)
	codex := filepath.Join(r.u.Home, ".codex", "hooks.json")
	write(t, codex, `{}`)
	found := []discovery.Found{{Spec: discovery.Spec{Key: "codex-cli", ID: "host.codex-cli", Name: "Codex"}, Users: []discovery.User{r.u}}}
	recon := func() { reconcile(context.Background(), found, &hostclient.Config{Status: "APPROVED"}) }
	recon()
	write(t, codex, `{"note":"hook-tool "}`)
	*r.events = nil
	recon()
	if !strings.Contains(read(t, codex), `"command"`) || !r.reported() {
		t.Errorf("Codex hook removed with the words left in the file: repaired silently")
	}
}

func desktopRig(t *testing.T) (hookRig, string, func()) {
	t.Helper()
	r := newRig(t)
	p := filepath.Join(r.u.Home, ".config", "Claude", "claude_desktop_config.json")
	write(t, p, `{"mcpServers":{"a":{"command":"node","args":["a.js"]}}}`)
	found := []discovery.Found{{Spec: discovery.Spec{Key: "claude-desktop", ID: "host.claude-desktop", Name: "Claude Desktop"}, Users: []discovery.User{r.u}}}
	recon := func() { reconcile(context.Background(), found, &hostclient.Config{Status: "APPROVED"}) }
	recon()
	if !strings.Contains(read(t, p), "mcp-wrap") {
		t.Fatalf("setup: not wrapped: %s", read(t, p))
	}
	return r, p, recon
}

// C1: unwrapping a server while leaving "mcp-wrap" text elsewhere is reported.
func TestUnwrappedMCPServerIsReportedEvenWithTheWordLeftBehind(t *testing.T) {
	r, p, recon := desktopRig(t)
	write(t, p, `{"mcpServers":{"a":{"command":"node","args":["a.js"],"env":{"X":"mcp-wrap"}}}}`)
	*r.events = nil
	recon()
	if !r.reported() {
		t.Error("MCP server unwrapped with 'mcp-wrap' text left in env: repaired without a report")
	}
}

// C2: the person replacing their own server a by b is not tampering.
func TestSwappingYourOwnMCPServerIsNotReported(t *testing.T) {
	r, p, recon := desktopRig(t)
	write(t, p, `{"mcpServers":{"b":{"command":"node","args":["b.js"]}}}`)
	*r.events = nil
	recon()
	if r.reported() {
		t.Error("the person replaced server a by b and it was reported as tampering")
	}
	if !strings.Contains(read(t, p), "mcp-wrap") {
		t.Error("the new server was not wrapped")
	}
}

// The CLI restore marker is not writable by others.
func TestCLIRestoreMarkerIsPrivate(t *testing.T) {
	r := newRig(t)
	r.reconcile(t)
	if err := RestoreTool("claude-code"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(theStore().restoredPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		t.Errorf("marker writable by others: %v", fi.Mode())
	}
}

// The CLI tells the running service straight away: POST /v1/restored reports once per tool, and a
// caller the service does not know is refused.
func TestRestoredEndpointReportsTheTool(t *testing.T) {
	r := newRig(t)
	h := relayHandler(nil)
	post := func(caller string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/restored", strings.NewReader(`{"tools":["claude-code","nonsense"]}`))
		req = req.WithContext(context.WithValue(req.Context(), callerKey{}, caller))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if post("uid:0") != 200 {
		t.Fatal("root refused")
	}
	n := 0
	for _, ev := range *r.events {
		if ev["type"] == TamperHookRemoved && ev["toolId"] == "host.claude-code" && ev["process"] == "protect_restore" {
			n++
		}
	}
	if n != 1 || len(*r.events) != 1 {
		t.Errorf("events: %v", *r.events)
	}
	if post("unknown") != http.StatusForbidden {
		t.Error("an unknown caller was accepted")
	}
}
