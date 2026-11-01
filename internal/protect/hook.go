package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"

	"gitlab.vax.sh/manar/manar-edge/internal/undo"
)

// Hooks run as the user and cannot read the host key, so they ask the device service over a local
// socket (Linux: unix socket, caller from SO_PEERCRED; Windows: named pipe), which asks Manar over
// mTLS. See relay_linux.go and relay_windows.go.

// restoreHint ends every message that means Manar itself cannot answer, so a person stuck behind a
// hook that denies everything knows how to take it out.
const restoreHint = " If Manar was removed or this device was revoked, run: manar-edge protect restore"

const (
	maxResource = 2048
	maxActionID = 128
)

// Verdict is what a hook or MCP wrapper does with a call.
type Verdict struct {
	Allow  bool
	Reason string
}

// Classify maps a tool's own hook input to Manar's generic action id and resource. event is the
// hook event the command was installed for (Cursor, Windsurf: shell, read, mcp; others: tool).
// Anything that cannot be mapped with certainty is an error, which the caller turns into a deny.
func Classify(key, event string, raw []byte) (actionID, resource string, err error) {
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		return "", "", errors.New("cannot read the hook input")
	}
	str := func(m map[string]any, ks ...string) string {
		for _, k := range ks {
			if s, _ := m[k].(string); s != "" {
				return s
			}
		}
		return ""
	}
	switch key {
	case "cursor":
		switch event {
		case "shell":
			actionID, resource = "shell", str(in, "command")
		case "read":
			actionID, resource = "read", str(in, "file_path")
		case "mcp":
			actionID, resource = "mcp", str(in, "mcp_server_name")+"/"+str(in, "tool_name")
		}
	case "windsurf":
		info, _ := in["tool_info"].(map[string]any)
		if info == nil {
			info = in
		}
		switch event {
		case "shell":
			actionID, resource = "shell", str(info, "command_line", "command")
		case "read":
			actionID, resource = "read", str(info, "file_path")
		case "mcp":
			actionID, resource = "mcp", str(info, "mcp_server_name")+"/"+str(info, "mcp_tool_name")
		}
	default:
		name := str(in, "tool_name", "toolName")
		args, _ := in["tool_input"].(map[string]any)
		if args == nil {
			args, _ = in["tool_args"].(map[string]any)
		}
		if args == nil { // Copilot sends toolArgs as a JSON string
			if s, ok := in["toolArgs"].(string); ok {
				_ = json.Unmarshal([]byte(s), &args)
			} else {
				args, _ = in["toolArgs"].(map[string]any)
			}
		}
		actionID, resource = classifyName(name, args, str)
	}
	if actionID == "" || strings.Trim(resource, "/ ") == "" {
		return "", "", errors.New("the hook input has no action or resource Manar can check")
	}
	if utf16Len(actionID) > maxActionID {
		return "", "", errors.New("tool name longer than Manar accepts")
	}
	if utf16Len(resource) > maxResource {
		return "", "", fmt.Errorf("the input is longer than %d characters, which Manar cannot check as a whole; split it", maxResource)
	}
	return actionID, resource, nil
}

var (
	shellNames = set("bash", "shell", "run_shell_command", "run_command", "powershell", "exec_command", "terminal", "local_shell")
	readNames  = set("read", "read_file", "read_many_files", "view", "list_directory", "ls", "glob", "grep", "search_file_content", "cat", "open")
	editNames  = set("edit", "write", "write_file", "replace", "create", "multiedit", "str_replace", "apply_patch", "str_replace_editor", "notebookedit")
	webNames   = set("webfetch", "web_fetch", "fetch", "google_web_search", "websearch")
)

func set(ns ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range ns {
		m[n] = true
	}
	return m
}

func classifyName(name string, args map[string]any, str func(map[string]any, ...string) string) (string, string) {
	n := strings.ToLower(name)
	switch {
	case shellNames[n]:
		return "shell", str(args, "command", "cmd", "command_line")
	case readNames[n]:
		return "read", firstNonEmpty(str(args, "file_path", "absolute_path", "path", "filepath", "dir_path", "pattern"), name)
	case editNames[n]:
		return "edit", firstNonEmpty(str(args, "file_path", "absolute_path", "path", "filepath"), name)
	case webNames[n]:
		return "webfetch", firstNonEmpty(str(args, "url", "query"), name)
	case strings.HasPrefix(n, "mcp__"):
		return "mcp", strings.Replace(strings.TrimPrefix(name, "mcp__"), "__", "/", 1)
	}
	// An unknown tool is treated as an MCP-style call named after the tool: the most cautious
	// class that still has a risk score.
	return "mcp", name
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// Relay talks to the device service's local endpoint.
type Relay struct {
	Base string // http://127.0.0.1:8481
	HTTP *http.Client
	// PollMin and PollMax bound the wait between approval checks.
	PollMin, PollMax time.Duration
}

// NewRelay returns a client for the local service.
func NewRelay() *Relay {
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialRelay(ctx) }}
	return &Relay{Base: "http://manar-relay", HTTP: &http.Client{Timeout: 30 * time.Second, Transport: tr}, PollMin: 2 * time.Second, PollMax: 10 * time.Second}
}

type authorizeReply struct {
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	ApprovalID string `json:"approvalId"`
}

// Decide asks for a decision, waiting for an approval when one is needed. Every failure is a deny.
func (r *Relay) Decide(ctx context.Context, key, actionID, resource string, budget time.Duration) Verdict {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var dec authorizeReply
	body := map[string]string{"toolId": "host." + key, "actionId": actionID, "resource": resource}
	if err := r.call(ctx, http.MethodPost, "/v1/authorize", body, &dec); err != nil {
		return Verdict{false, "Manar: authorization failed: " + err.Error() + "." + restoreHint}
	}
	switch dec.Decision {
	case "ALLOW":
		return Verdict{true, "Manar: allowed"}
	case "DENY":
		return Verdict{false, "Manar denied: " + dec.Reason}
	case "APPROVAL_REQUIRED":
		if dec.ApprovalID == "" {
			return Verdict{false, "Manar requires approval (" + dec.Reason + ") and no approver is reachable yet"}
		}
		return r.wait(ctx, dec.ApprovalID)
	}
	return Verdict{false, fmt.Sprintf("Manar: unknown decision %q", dec.Decision)}
}

func (r *Relay) wait(ctx context.Context, id string) Verdict {
	wait := r.PollMin
	for {
		select {
		case <-ctx.Done():
			return Verdict{false, "Manar: approval " + id + " not decided in time"}
		case <-time.After(wait):
		}
		var ap struct {
			Status string `json:"status"`
		}
		if err := r.call(ctx, http.MethodGet, "/v1/approvals/"+id, nil, &ap); err != nil {
			return Verdict{false, "Manar: approval check failed: " + err.Error()}
		}
		switch ap.Status {
		case "APPROVED":
			return Verdict{true, "Manar: approved (" + id + ")"}
		case "PENDING":
		default:
			return Verdict{false, "Manar: approval " + id + " is " + ap.Status}
		}
		wait = min(wait*3/2, r.PollMax)
	}
}

func (r *Relay) call(ctx context.Context, method, path string, in, out any) error {
	var rd io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.Base+path, rd)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := r.HTTP.Do(req)
	if err != nil {
		return errors.New("the Manar device service is not reachable")
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return json.Unmarshal(b, out)
}

// Render turns a verdict into what the tool expects on stdout and as its exit code. A deny is
// always exit 2 with the reason on stderr, which every tool in the catalogue treats as a block.
func Render(key string, v Verdict) (stdout, stderr []byte, exit int) {
	if !v.Allow {
		return nil, []byte(v.Reason + "\n"), 2
	}
	switch key {
	case "cursor", "gemini-cli", "copilot-cli":
		// Valid JSON with no decision: Manar only ever asserts a deny, so the tool's own
		// permission prompts still apply to what Manar lets through.
		return []byte("{}\n"), nil, 0
	}
	return nil, nil, 0
}

// RunHook is `manar-edge hook-tool <key> <event>`: read the hook input, decide, answer.
func RunHook(key, event string, stdin io.Reader) (stdout, stderr []byte, exit int) {
	raw, err := io.ReadAll(io.LimitReader(stdin, 4<<20))
	if err != nil {
		return Render(key, Verdict{false, "Manar: cannot read the hook input"})
	}
	actionID, resource, err := Classify(key, event, raw)
	if err != nil {
		return Render(key, Verdict{false, "Manar: " + err.Error()})
	}
	budget := time.Duration(Budget(key)) * time.Second
	v := NewRelay().Decide(context.Background(), key, actionID, resource, budget)
	if v.Allow {
		SnapshotBeforeEdit(key, raw)
	}
	return Render(key, v)
}

// SnapshotBeforeEdit saves a copy of the file an editing tool is about to change when it lies
// outside the tool's project folder, and tells the device service (best effort: an edit is never
// blocked because a snapshot could not be taken). It runs as the user the hook runs as.
func SnapshotBeforeEdit(tool string, raw []byte) {
	defer func() { _ = recover() }()
	path, cwd, ok := undo.EditTarget(raw)
	if !ok || !undo.Outside(path, cwd) {
		return
	}
	s, err := undo.OpenDefault()
	if err != nil {
		return
	}
	rec, err := s.Snapshot(tool, path, time.Now())
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var ignore map[string]any
	_ = NewRelay().call(ctx, http.MethodPost, "/v1/changes", rec, &ignore)
}
