package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/manarhq/manar-edge/internal/protect"
)

const (
	hookToolID  = "host.claude-code"
	maxResource = 2048
	maxActionID = 128
	// hookBudget bounds one hook decision end to end (authorize plus the approval wait).
	hookBudget = 10 * time.Minute
	// noAnswerAfter is how long a person has to answer a prompt (founder decision, 1 Nov 2026).
	// The prompt shows and the phone is pushed at the same moment; after this the call is denied
	// and the agent is told "no answer".
	noAnswerAfter = 2 * time.Minute
	// hookTimeoutSeconds is the Claude Code hook timeout: the budget plus 90 s spare, so the hook
	// always answers before Claude Code gives up on it.
	hookTimeoutSeconds = 690
	// minClaudeCode is the oldest Claude Code that honours `onFailure: "block"`.
	minClaudeCode = "2.1.295"
)

type hookInput struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

// hookAction maps a PreToolUse call to the authorize request's actionId and resource. A value
// longer than manar-api accepts is an error: a truncated resource would get a decision about a
// different command than the one that runs.
func hookAction(in hookInput) (actionID, resource string, err error) {
	actionID = strings.ToLower(in.ToolName)
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
	if utf16Len(actionID) > maxActionID {
		return "", "", errors.New("tool name longer than Manar accepts")
	}
	if utf16Len(resource) > maxResource {
		return "", "", fmt.Errorf("the %s input is longer than %d characters, which Manar cannot check as a whole; split it (for long file content use the Write tool)", in.ToolName, maxResource)
	}
	return actionID, resource, nil
}

// utf16Len counts UTF-16 code units, as manar-api's zod limits do.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

type hookClient struct {
	base     string // local gateway URL (over the unix socket on Linux)
	http     *http.Client
	pollMin  time.Duration
	pollMax  time.Duration
	deadline time.Duration // whole decision
	noAnswer time.Duration // 0 means noAnswerAfter
}

type authorizeResponse struct {
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	ApprovalID string `json:"approvalId"`
}

// decide returns the hook decision. Every error is a deny with the reason (fail closed).
func (h *hookClient) decide(ctx context.Context, raw []byte) (allow bool, reason string) {
	ctx, cancel := context.WithTimeout(ctx, h.deadline)
	defer cancel()
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil || in.ToolName == "" {
		return false, "Manar: cannot read the hook input"
	}
	actionID, resource, err := hookAction(in)
	if err != nil {
		return false, "Manar: " + err.Error()
	}
	if reason, _, _ := protect.GuardInput("claude-code", "tool", raw); reason != "" {
		return false, reason
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
	var dec authorizeResponse
	err = h.postJSON(ctx, "/agent/v1/authorize", map[string]string{
		"taskId": health.TaskID, "toolId": hookToolID, "actionId": actionID, "resource": resource,
	}, &dec)
	if err != nil {
		return false, "Manar: authorization failed: " + err.Error()
	}
	switch dec.Decision {
	case "ALLOW":
		return true, "Manar: allowed"
	case "DENY":
		if dec.Reason == "paused" {
			return false, "Manar denied: paused (AI is paused for this workspace; resume it in the Manar console)"
		}
		return false, "Manar denied: " + dec.Reason
	case "APPROVAL_REQUIRED":
		if dec.ApprovalID == "" || !idPattern.MatchString(dec.ApprovalID) {
			return false, "Manar requires approval (" + dec.Reason + ") but returned no approval id to wait on"
		}
		return h.waitApproval(ctx, dec.ApprovalID)
	}
	return false, "Manar: unknown decision " + strconv.Quote(dec.Decision)
}

func (h *hookClient) waitApproval(ctx context.Context, id string) (bool, string) {
	wait := h.pollMin
	limit := h.noAnswer
	if limit == 0 {
		limit = noAnswerAfter
	}
	giveUp := time.After(limit)
	for {
		select {
		case <-ctx.Done():
			return false, "Manar: approval " + id + " not decided in time"
		case <-giveUp:
			// Tell Manar too, so the console cannot approve after the agent was told "denied".
			// Best effort: the 30-minute server expiry is the backstop.
			ectx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = h.do(ectx, http.MethodPost, "/agent/v1/approvals/"+id+"/expire", []byte("{}"), &struct{}{})
			cancel()
			return false, "Manar denied: no answer"
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
		case "PAUSED":
			return false, "Manar denied: paused (AI is paused for this workspace; resume it in the Manar console)"
		case "EXPIRED":
			return false, "Manar denied: no answer"
		case "REVOKED":
			return false, "Manar denied: approval revoked (a person withdrew it in the Manar console)"
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
	if len(args) != 2 || args[0] != "claude-code" || !slugPattern.MatchString(args[1]) {
		reason = "Manar: usage: manar-edge hook claude-code <name>"
		return
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		reason = "Manar: cannot read the hook input"
		return
	}
	tr, base := hookTransport(args[1])
	h := &hookClient{
		base: base,
		http: &http.Client{Timeout: 30 * time.Second, Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		pollMin:  2 * time.Second,
		pollMax:  15 * time.Second,
		deadline: hookBudget,
	}
	allow, reason = h.decide(context.Background(), raw)
	if allow {
		protect.SnapshotBeforeEdit("claude-code", raw)
	}
	return
}

// claudeSettings returns the managed settings with the Manar policy merged in. Other keys and
// other hooks already in the file are kept; an older Manar entry is replaced. The policy:
//   - the hook runs before every tool call, and a hook that fails, times out or cannot start
//     blocks the call (onFailure "block");
//   - only managed hooks run, so no other hook can answer "allow" first;
//   - dontAsk mode: anything that would prompt is denied unless the hook allowed it;
//   - bypass and auto modes are disabled, permission rules come from managed settings only;
//   - Claude Code older than the version that honours onFailure refuses to start.
func claudeSettings(existing []byte, exe, agent string) ([]byte, error) {
	s := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &s); err != nil {
			return nil, fmt.Errorf("existing managed settings are not valid JSON: %w", err)
		}
	}
	obj := func(k string) map[string]any {
		m, _ := s[k].(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		s[k] = m
		return m
	}
	hooks := obj("hooks")
	var pre []any
	if list, ok := hooks["PreToolUse"].([]any); ok {
		for _, g := range list {
			if !isManarHookGroup(g) {
				pre = append(pre, g)
			}
		}
	}
	hooks["PreToolUse"] = append(pre, map[string]any{
		"matcher": "*",
		"hooks": []any{map[string]any{
			"type":      "command",
			"command":   exe,
			"args":      []string{"hook", "claude-code", agent},
			"timeout":   hookTimeoutSeconds,
			"onFailure": "block",
		}},
	})
	s["allowManagedHooksOnly"] = true
	s["allowManagedPermissionRulesOnly"] = true
	perms := obj("permissions")
	perms["defaultMode"] = "dontAsk"
	perms["disableBypassPermissionsMode"] = "disable"
	perms["disableAutoMode"] = "disable"
	if v, _ := s["requiredMinimumVersion"].(string); versionLess(v, minClaudeCode) {
		s["requiredMinimumVersion"] = minClaudeCode
	}
	obj("env")["ANTHROPIC_BASE_URL"] = gatewayURL
	b, err := json.MarshalIndent(s, "", "  ")
	return append(b, '\n'), err
}

// removeClaudeSettings is the inverse of claudeSettings: it takes out the Manar hook and the
// keys claudeSettings set, only where they still hold the value Manar wrote. Anything else in the
// file stays. It reports whether anything changed and whether the file is now empty.
func removeClaudeSettings(existing []byte) (out []byte, changed, empty bool, err error) {
	s := map[string]any{}
	if err := json.Unmarshal(existing, &s); err != nil {
		return nil, false, false, fmt.Errorf("managed settings are not valid JSON: %w", err)
	}
	hooks, _ := s["hooks"].(map[string]any)
	ours := false
	if list, ok := hooks["PreToolUse"].([]any); ok {
		var keep []any
		for _, g := range list {
			if isManarHookGroup(g) {
				ours = true
			} else {
				keep = append(keep, g)
			}
		}
		if ours {
			if len(keep) == 0 {
				delete(hooks, "PreToolUse")
			} else {
				hooks["PreToolUse"] = keep
			}
		}
	}
	if !ours {
		return existing, false, false, nil // not ours: leave the file alone
	}
	if len(hooks) == 0 {
		delete(s, "hooks")
	}
	delete(s, "allowManagedHooksOnly")
	delete(s, "allowManagedPermissionRulesOnly")
	if perms, ok := s["permissions"].(map[string]any); ok {
		if perms["defaultMode"] == "dontAsk" {
			delete(perms, "defaultMode")
		}
		for _, k := range []string{"disableBypassPermissionsMode", "disableAutoMode"} {
			if perms[k] == "disable" {
				delete(perms, k)
			}
		}
		if len(perms) == 0 {
			delete(s, "permissions")
		}
	}
	if env, ok := s["env"].(map[string]any); ok {
		if env["ANTHROPIC_BASE_URL"] == gatewayURL {
			delete(env, "ANTHROPIC_BASE_URL")
		}
		if len(env) == 0 {
			delete(s, "env")
		}
	}
	if s["requiredMinimumVersion"] == minClaudeCode {
		delete(s, "requiredMinimumVersion")
	}
	if len(s) == 0 {
		return nil, true, true, nil
	}
	b, err := json.MarshalIndent(s, "", "  ")
	return append(b, '\n'), true, false, err
}

// uninstallClaudeCode takes Manar's policy out of the managed settings file (and the file if
// nothing else is in it).
func uninstallClaudeCode() error {
	b, err := os.ReadFile(managedSettingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	out, changed, empty, err := removeClaudeSettings(b)
	if err != nil || !changed {
		return err
	}
	if empty {
		return os.Remove(managedSettingsPath)
	}
	return writePrivateMode(managedSettingsPath, out, 0o644)
}

// versionLess compares dotted numeric versions; an empty or invalid a is less.
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range pb {
		if i >= len(pa) {
			return true
		}
		x, err := strconv.Atoi(pa[i])
		if err != nil {
			return true
		}
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
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

// policyConflicts lists managed policy sources that would win over, or merge into, our file:
// files in managed-settings.d (merged after managed-settings.json), the Windows HKLM policy, and
// any cached server-managed settings (~/.claude/remote-settings.json of a user).
func policyConflicts() []string {
	return append(settingsDFiles(filepath.Dir(managedSettingsPath)), osPolicyConflicts()...)
}

func settingsDFiles(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "managed-settings.d", "*.json"))
	return m
}

func cmdInstallClaudeCode(base string, args []string) error {
	fs := flag.NewFlagSet("install-claude-code", flag.ContinueOnError)
	force := fs.Bool("force-coexist", false, "install even when another managed policy source exists")
	agent, err := parseAgentFlags(fs, args)
	if err != nil {
		return err
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	_, st, err := resolveAgent(base, agent)
	if err != nil {
		return err
	}
	if c := policyConflicts(); len(c) > 0 {
		msg := "other managed Claude Code policy sources exist and could override or merge into this policy:\n  " +
			strings.Join(c, "\n  ")
		if !*force {
			return errors.New(msg + "\nremove them, or pass --force-coexist after checking they keep the hook, dontAsk and the locks")
		}
		fmt.Fprintln(os.Stderr, "warning: "+msg)
	}
	exe, err := installedBinary()
	if err != nil {
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
	fmt.Printf("wrote %s (hook %s, dontAsk, managed hooks and rules only, Claude Code >= %s)\n", managedSettingsPath, exe, minClaudeCode)
	fmt.Println("verify in Claude Code with /status: \"Setting sources\" must show the managed settings file " +
		"(not remote, HKLM or plist), and /hooks must list the manar-edge PreToolUse hook")
	return nil
}
