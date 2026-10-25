package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	hookToolID      = "host.claude-code"
	maxResource     = 2048
	approvalTimeout = 10 * time.Minute
	// hookTimeoutSeconds is the Claude Code hook timeout: the approval wait plus slack.
	hookTimeoutSeconds = 660
)

type hookInput struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

// hookAction maps a PreToolUse call to the authorize request's actionId and resource.
func hookAction(in hookInput) (actionID, resource string) {
	actionID = truncateUTF16(strings.ToLower(in.ToolName), 128)
	str := func(k string) string { s, _ := in.ToolInput[k].(string); return s }
	switch actionID {
	case "bash":
		resource = str("command")
	case "edit", "multiedit", "write", "read":
		resource = str("file_path")
	case "notebookedit":
		resource = str("notebook_path")
	case "webfetch":
		resource = str("url")
	}
	if resource == "" {
		resource = in.ToolName
	}
	return actionID, truncateUTF16(resource, maxResource)
}

// truncateUTF16 cuts s to at most n UTF-16 code units (manar-api validates lengths with zod,
// which counts in UTF-16), never splitting a character.
func truncateUTF16(s string, n int) string {
	units := 0
	for i, r := range s {
		units += len(utf16.Encode([]rune{r}))
		if units > n {
			return s[:i]
		}
	}
	return s
}

type hookClient struct {
	base     string // local gateway URL
	http     *http.Client
	pollMin  time.Duration
	pollMax  time.Duration
	deadline time.Duration
}

type authorizeResponse struct {
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	ApprovalID string `json:"approvalId"`
}

// decide returns the hook decision. Every error is a deny with the reason (fail closed).
func (h *hookClient) decide(ctx context.Context, raw []byte) (allow bool, reason string) {
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil || in.ToolName == "" {
		return false, "Manar: cannot read the hook input"
	}
	var health struct {
		TaskID string `json:"taskId"`
	}
	if err := h.getJSON(ctx, "/healthz", &health); err != nil {
		return false, "Manar: local gateway unavailable: " + err.Error()
	}
	if health.TaskID == "" {
		return false, "Manar: no task set for this agent (manar-edge up --task <taskId>)"
	}
	actionID, resource := hookAction(in)
	var dec authorizeResponse
	err := h.postJSON(ctx, "/agent/v1/authorize", map[string]string{
		"taskId": health.TaskID, "toolId": hookToolID, "actionId": actionID, "resource": resource,
	}, &dec)
	if err != nil {
		return false, "Manar: authorization failed: " + err.Error()
	}
	switch dec.Decision {
	case "ALLOW":
		return true, "Manar: allowed"
	case "DENY":
		return false, "Manar denied: " + dec.Reason
	case "APPROVAL_REQUIRED":
		if dec.ApprovalID == "" || !idPattern.MatchString(dec.ApprovalID) {
			return false, "Manar requires approval (" + dec.Reason + ") but returned no approval id to wait on"
		}
		return h.waitApproval(ctx, dec.ApprovalID)
	}
	return false, "Manar: unknown decision " + fmt.Sprintf("%q", dec.Decision)
}

func (h *hookClient) waitApproval(ctx context.Context, id string) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, h.deadline)
	defer cancel()
	wait := h.pollMin
	for {
		select {
		case <-ctx.Done():
			return false, "Manar: approval " + id + " not decided in time"
		case <-time.After(wait):
		}
		var ap struct {
			Status string `json:"status"`
		}
		if err := h.getJSON(ctx, "/agent/v1/approvals/"+id, &ap); err != nil {
			if ctx.Err() != nil {
				return false, "Manar: approval " + id + " not decided in time"
			}
			return false, "Manar: approval check failed: " + err.Error()
		}
		switch ap.Status {
		case "APPROVED":
			return true, "Manar: approved (" + id + ")"
		case "PENDING":
		default:
			return false, "Manar: approval " + id + " is " + ap.Status
		}
		wait = min(wait*3/2, h.pollMax)
	}
}

func (h *hookClient) getJSON(ctx context.Context, path string, out any) error {
	return h.do(ctx, http.MethodGet, path, nil, out)
}

func (h *hookClient) postJSON(ctx context.Context, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return h.do(ctx, http.MethodPost, path, b, out)
}

func (h *hookClient) do(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := h.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, serverMessage(b))
	}
	return json.Unmarshal(b, out)
}

func hookOutput(allow bool, reason string) []byte {
	d := "deny"
	if allow {
		d = "allow"
	}
	b, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]string{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       d,
		"permissionDecisionReason": reason,
	}})
	return b
}

// cmdHook always exits 0 with a JSON decision; anything that goes wrong is a deny.
func cmdHook(args []string) (code int) {
	allow, reason := false, "Manar: hook error"
	defer func() {
		if r := recover(); r != nil {
			allow, reason = false, "Manar: hook error"
		}
		os.Stdout.Write(append(hookOutput(allow, reason), '\n'))
		code = 0
	}()
	if len(args) != 2 || args[0] != "claude-code" {
		reason = "Manar: usage: manar-edge hook claude-code <agent>"
		return
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		reason = "Manar: cannot read the hook input"
		return
	}
	h := &hookClient{
		base:     gatewayURL,
		http:     &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}},
		pollMin:  2 * time.Second,
		pollMax:  15 * time.Second,
		deadline: approvalTimeout,
	}
	allow, reason = h.decide(context.Background(), raw)
	return
}

// claudeSettings returns the managed settings with the Manar hook merged in. Other keys and
// other hooks already in the file are kept; an older Manar entry is replaced.
func claudeSettings(existing []byte, exe, agent string) ([]byte, error) {
	s := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &s); err != nil {
			return nil, fmt.Errorf("existing managed settings are not valid JSON: %w", err)
		}
	}
	hooks, _ := s["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	var pre []any
	if list, ok := hooks["PreToolUse"].([]any); ok {
		for _, g := range list {
			if !isManarHookGroup(g) {
				pre = append(pre, g)
			}
		}
	}
	pre = append(pre, map[string]any{
		"matcher": "*",
		"hooks": []any{map[string]any{
			"type":      "command",
			"command":   exe,
			"args":      []string{"hook", "claude-code", agent},
			"timeout":   hookTimeoutSeconds,
			"onFailure": "block",
		}},
	})
	hooks["PreToolUse"] = pre
	s["hooks"] = hooks
	s["allowManagedHooksOnly"] = true
	env, _ := s["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
	}
	env["ANTHROPIC_BASE_URL"] = gatewayURL
	s["env"] = env
	b, err := json.MarshalIndent(s, "", "  ")
	return append(b, '\n'), err
}

func isManarHookGroup(g any) bool {
	m, _ := g.(map[string]any)
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		if args, ok := hm["args"].([]any); ok && len(args) >= 2 && args[0] == "hook" && args[1] == "claude-code" {
			return true
		}
	}
	return false
}

func cmdInstallClaudeCode(base string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: manar-edge install-claude-code <agent>")
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	_, st, err := resolveAgent(base, args[0])
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	existing, err := os.ReadFile(managedSettingsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	out, err := claudeSettings(existing, exe, st.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(managedSettingsPath), 0o755); err != nil {
		return err
	}
	tmp := managedSettingsPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, managedSettingsPath); err != nil {
		return err
	}
	fmt.Printf("wrote %s (PreToolUse hook for %s, managed hooks only)\n", managedSettingsPath, st.Name)
	return nil
}
