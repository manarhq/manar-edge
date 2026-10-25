package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGateway plays the local gateway: healthz with a task, authorize, and approvals that answer
// statuses in order.
func fakeGateway(t *testing.T, task string, authorize func(map[string]string) (int, string), approvals []string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "taskId": task})
	})
	mux.HandleFunc("POST /agent/v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		code, out := authorize(body)
		w.WriteHeader(code)
		_, _ = io.WriteString(w, out)
	})
	mux.HandleFunc("GET /agent/v1/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		n := int(polls.Add(1)) - 1
		if n >= len(approvals) {
			n = len(approvals) - 1
		}
		if approvals[n] == "ERROR" {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": r.PathValue("id"), "status": approvals[n]})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &polls
}

func testHook(base string) *hookClient {
	return &hookClient{base: base, http: &http.Client{Timeout: 5 * time.Second},
		pollMin: time.Millisecond, pollMax: 5 * time.Millisecond, deadline: 300 * time.Millisecond}
}

const bashInput = `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x","description":"d"}}`

func reply(code int, body string) func(map[string]string) (int, string) {
	return func(map[string]string) (int, string) { return code, body }
}

func TestHookDecisions(t *testing.T) {
	cases := []struct {
		name      string
		task      string
		authorize func(map[string]string) (int, string)
		approvals []string
		input     string
		allow     bool
		reason    string
	}{
		{"allow", "t1", reply(201, `{"decision":"ALLOW","decisionId":"d"}`), nil, bashInput, true, "allowed"},
		{"deny", "t1", reply(201, `{"decision":"DENY","reason":"policy_denied","decisionId":"d"}`), nil, bashInput, false, "policy_denied"},
		{"approved", "t1", reply(201, `{"decision":"APPROVAL_REQUIRED","reason":"r","approvalId":"ap-1"}`), []string{"PENDING", "PENDING", "APPROVED"}, bashInput, true, "approved"},
		{"approval denied", "t1", reply(201, `{"decision":"APPROVAL_REQUIRED","reason":"r","approvalId":"ap-1"}`), []string{"PENDING", "DENIED"}, bashInput, false, "DENIED"},
		{"approval expired", "t1", reply(201, `{"decision":"APPROVAL_REQUIRED","reason":"r","approvalId":"ap-1"}`), []string{"EXPIRED"}, bashInput, false, "EXPIRED"},
		{"approval timeout", "t1", reply(201, `{"decision":"APPROVAL_REQUIRED","reason":"r","approvalId":"ap-1"}`), []string{"PENDING"}, bashInput, false, "not decided in time"},
		{"approval poll error", "t1", reply(201, `{"decision":"APPROVAL_REQUIRED","reason":"r","approvalId":"ap-1"}`), []string{"ERROR"}, bashInput, false, "approval check failed"},
		{"approval without id", "t1", reply(201, `{"decision":"APPROVAL_REQUIRED","reason":"risk","riskScore":80}`), nil, bashInput, false, "no approval id"},
		{"unknown decision", "t1", reply(201, `{"decision":"MAYBE"}`), nil, bashInput, false, "unknown decision"},
		{"server error", "t1", reply(503, `{"message":"enforcement_dependency_unavailable"}`), nil, bashInput, false, "enforcement_dependency_unavailable"},
		{"bad json", "t1", reply(201, `not json`), nil, bashInput, false, "authorization failed"},
		{"no task", "", reply(201, `{"decision":"ALLOW"}`), nil, bashInput, false, "no task"},
		{"bad input", "t1", reply(201, `{"decision":"ALLOW"}`), nil, `{"tool_input":`, false, "cannot read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gw, _ := fakeGateway(t, c.task, c.authorize, c.approvals)
			allow, reason := testHook(gw.URL).decide(context.Background(), []byte(c.input))
			if allow != c.allow || !strings.Contains(reason, c.reason) {
				t.Fatalf("got (%v, %q), want (%v, ...%q...)", allow, reason, c.allow, c.reason)
			}
		})
	}
}

func TestHookGatewayDownDenies(t *testing.T) {
	allow, reason := testHook("http://127.0.0.1:1").decide(context.Background(), []byte(bashInput))
	if allow || !strings.Contains(reason, "local gateway unavailable") {
		t.Fatalf("got (%v, %q)", allow, reason)
	}
}

func TestHookAuthorizeRequest(t *testing.T) {
	var got map[string]string
	gw, _ := fakeGateway(t, "task-9", func(b map[string]string) (int, string) {
		got = b
		return 201, `{"decision":"ALLOW"}`
	}, nil)
	if allow, _ := testHook(gw.URL).decide(context.Background(), []byte(bashInput)); !allow {
		t.Fatal("not allowed")
	}
	want := map[string]string{"taskId": "task-9", "toolId": "host.claude-code", "actionId": "bash", "resource": "rm -rf /tmp/x"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestHookAction(t *testing.T) {
	cases := []struct {
		tool  string
		input map[string]any
		act   string
		res   string
	}{
		{"Bash", map[string]any{"command": "ls"}, "bash", "ls"},
		{"Edit", map[string]any{"file_path": "/a/b"}, "edit", "/a/b"},
		{"Write", map[string]any{"file_path": "/a/c", "content": "secret"}, "write", "/a/c"},
		{"Read", map[string]any{"file_path": "/etc/passwd"}, "read", "/etc/passwd"},
		{"WebFetch", map[string]any{"url": "https://x.test/p", "prompt": "p"}, "webfetch", "https://x.test/p"},
		{"Glob", map[string]any{"pattern": "*"}, "glob", "Glob"},
		{"Bash", map[string]any{}, "bash", "Bash"},
	}
	for _, c := range cases {
		a, r := hookAction(hookInput{ToolName: c.tool, ToolInput: c.input})
		if a != c.act || r != c.res {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.tool, a, r, c.act, c.res)
		}
	}
	_, r := hookAction(hookInput{ToolName: "Bash", ToolInput: map[string]any{"command": strings.Repeat("é", 3000)}})
	if n := len([]rune(r)); n != maxResource {
		t.Errorf("resource truncated to %d runes, want %d", n, maxResource)
	}
	if got := truncateUTF16(strings.Repeat("😀", 1500), maxResource); len([]rune(got)) != 1024 {
		t.Errorf("astral truncation kept %d runes, want 1024", len([]rune(got)))
	}
}

func TestHookOutputShape(t *testing.T) {
	var out struct {
		HookSpecificOutput map[string]string `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(hookOutput(false, "Manar denied: x"), &out); err != nil {
		t.Fatal(err)
	}
	h := out.HookSpecificOutput
	if h["hookEventName"] != "PreToolUse" || h["permissionDecision"] != "deny" || h["permissionDecisionReason"] != "Manar denied: x" {
		t.Fatalf("%v", h)
	}
	_ = json.Unmarshal(hookOutput(true, "ok"), &out)
	if out.HookSpecificOutput["permissionDecision"] != "allow" {
		t.Fatal("allow not mapped")
	}
}

func TestClaudeSettingsMerge(t *testing.T) {
	existing := `{"permissions":{"deny":["Read(./.env)"]},"env":{"FOO":"1"},
	  "hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/other"}]},
	  {"matcher":"*","hooks":[{"type":"command","command":"/old/manar-edge","args":["hook","claude-code","old"]}]}]}}`
	b, err := claudeSettings([]byte(existing), "/usr/local/bin/manar-edge", "acme-soc-1")
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s["allowManagedHooksOnly"] != true {
		t.Error("allowManagedHooksOnly not set")
	}
	env := s["env"].(map[string]any)
	if env["ANTHROPIC_BASE_URL"] != gatewayURL || env["FOO"] != "1" {
		t.Errorf("env %v", env)
	}
	if s["permissions"] == nil {
		t.Error("existing keys dropped")
	}
	pre := s["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("want the other hook plus one Manar hook, got %d", len(pre))
	}
	h := pre[1].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if h["command"] != "/usr/local/bin/manar-edge" || h["onFailure"] != "block" || h["timeout"].(float64) != hookTimeoutSeconds {
		t.Errorf("hook %v", h)
	}
	if _, err := claudeSettings([]byte("{broken"), "/x", "a"); err == nil {
		t.Error("broken existing settings accepted")
	}
}
