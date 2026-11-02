package protect

import (
	"encoding/json"
	"path/filepath"
	"runtime"

	"github.com/manarhq/manar-edge/internal/discovery"
)

// Role says what a planned edit contributes to a tool's protection.
type Role string

const (
	RoleHook    Role = "hook"
	RoleMCP     Role = "mcp"
	RoleGateway Role = "gateway"
	// RoleUntrusted is installed but does not count: the tool makes its owner review the hook
	// before it runs (Codex CLI: /hooks), and Manar cannot see that happen.
	RoleUntrusted Role = "untrusted"
)

// Item is one planned edit.
type Item struct {
	FileEdit
	Role Role
}

// Ctx is what plans need besides the user.
type Ctx struct {
	Exe        string // the installed manar-edge binary
	GatewayURL string // local LLM gateway base URL, e.g. http://127.0.0.1:848
	GatewayUp  bool   // answered /healthz just now: never route a tool to a gateway that is down
	GOOS       string // runtime.GOOS unless a test says otherwise
}

// Keys are the tool keys protect knows; the host tool id is "host." + key.
var Keys = []string{"claude-code", "cursor", "windsurf", "gemini-cli", "codex-cli", "copilot-cli", "vscode-copilot", "claude-desktop"}

// Budget is how long a hook may wait for a person to decide, below the tool's own hook timeout.
// Tools whose timeout we set (Cursor, Gemini, Copilot) get the long one.
func Budget(key string) (seconds int) {
	switch key {
	case "claude-code", "cursor", "gemini-cli", "copilot-cli":
		return 590
	}
	return 25
}

func hookCommand(exe, key, event string) string {
	return `"` + exe + `" hook-tool ` + key + ` ` + event
}

// Plan lists the edits that protect one tool for one user. Tools Manar can only see (ChatGPT
// desktop) have none.
func Plan(key string, u discovery.User, c Ctx) []Item {
	goos := c.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	h := u.Home
	appdata := filepath.Join(h, ".config")
	if goos == "windows" {
		appdata = filepath.Join(h, "AppData", "Roaming")
	}
	hook := func(path string, role Role, f func(map[string]any) error) Item {
		return Item{FileEdit{Path: path, Edit: jsonObject(f), Kind: KindJSON, Mode: 0o644}, role}
	}
	mcp := func(path, field string) Item {
		return Item{FileEdit{Path: path, Kind: KindJSON, Mode: 0o644, Edit: jsonObject(func(r map[string]any) error {
			_, _, err := wrapMCP(r, field, c.Exe, key)
			return err
		})}, RoleMCP}
	}
	switch key {
	case "claude-code":
		// The person's own settings, like Gemini CLI. A deny is exit 2 with the reason on stderr,
		// which Claude Code shows the model; the timeout (seconds) leaves room for an approval.
		return []Item{hook(filepath.Join(h, ".claude", "settings.json"), RoleHook, func(r map[string]any) error {
			return setNestedHook(r, "PreToolUse", map[string]any{"matcher": "*", "hooks": []any{map[string]any{
				"type": "command", "command": hookCommand(c.Exe, key, "tool"), "timeout": json.Number("600"),
			}}})
		})}
	case "cursor":
		cursorHook := func(event, arg string) func(map[string]any) error {
			return func(r map[string]any) error {
				if _, ok := r["version"]; !ok {
					r["version"] = json.Number("1")
				}
				return setFlatHook(r, event, map[string]any{
					"command": hookCommand(c.Exe, key, arg), "timeout": json.Number("600"), "failClosed": true,
				})
			}
		}
		p := filepath.Join(h, ".cursor", "hooks.json")
		return []Item{
			hook(p, RoleHook, chain(cursorHook("beforeShellExecution", "shell"), cursorHook("beforeReadFile", "read"), cursorHook("beforeMCPExecution", "mcp"))),
			mcp(filepath.Join(h, ".cursor", "mcp.json"), "mcpServers"),
		}
	case "windsurf":
		wh := func(event, arg string) func(map[string]any) error {
			return func(r map[string]any) error {
				cmd := hookCommand(c.Exe, key, arg)
				return setFlatHook(r, event, map[string]any{"command": cmd, "powershell": "& " + cmd, "show_output": false})
			}
		}
		dir := filepath.Join(h, ".codeium", "windsurf")
		return []Item{
			hook(filepath.Join(dir, "hooks.json"), RoleHook, chain(wh("pre_run_command", "shell"), wh("pre_read_code", "read"), wh("pre_mcp_tool_use", "mcp"))),
			mcp(filepath.Join(dir, "mcp_config.json"), "mcpServers"),
		}
	case "gemini-cli":
		p := filepath.Join(h, ".gemini", "settings.json")
		return []Item{
			hook(p, RoleHook, func(r map[string]any) error {
				return setNestedHook(r, "BeforeTool", map[string]any{"matcher": "*", "hooks": []any{map[string]any{
					"type": "command", "command": hookCommand(c.Exe, key, "tool"), "timeout": json.Number("600000"),
				}}})
			}),
			mcp(p, "mcpServers"),
		}
	case "codex-cli":
		items := []Item{hook(filepath.Join(h, ".codex", "hooks.json"), RoleUntrusted, func(r map[string]any) error {
			return setNestedHook(r, "PreToolUse", map[string]any{"matcher": "*", "hooks": []any{map[string]any{
				"type": "command", "command": hookCommand(c.Exe, key, "tool"),
			}}})
		})}
		cfg := filepath.Join(h, ".codex", "config.toml")
		if c.GatewayUp && c.GatewayURL != "" && goos != "windows" {
			items = append(items, Item{FileEdit{Path: cfg, Edit: codexBaseURL(c.GatewayURL + "/v1"), Kind: KindCodexTOML, Mode: 0o600}, RoleGateway})
		} else {
			// DOOR is not healthy (or cannot be trusted on this OS): take any route Manar wrote
			// earlier out again, so a program that grabs the port gets no API key. A no-op when
			// there is none. It does not count for the tool's protection mode.
			items = append(items, Item{FileEdit{Path: cfg, Edit: func(cur []byte, _ bool) ([]byte, error) { return undoCodexTOML(cur, true) }, Kind: KindCodexTOML, Mode: 0o600}, RoleUntrusted})
		}
		return items
	case "copilot-cli":
		return []Item{
			hook(filepath.Join(h, ".copilot", "hooks", "manar.json"), RoleHook, func(r map[string]any) error {
				if _, ok := r["version"]; !ok {
					r["version"] = json.Number("1")
				}
				return setFlatHook(r, "preToolUse", map[string]any{
					"type": "command", "command": hookCommand(c.Exe, key, "tool"), "timeoutSec": json.Number("600"),
				})
			}),
			mcp(filepath.Join(h, ".copilot", "mcp-config.json"), "mcpServers"),
		}
	case "vscode-copilot":
		return []Item{mcp(filepath.Join(appdata, "Code", "User", "mcp.json"), "servers")}
	case "claude-desktop":
		return []Item{mcp(filepath.Join(appdata, "Claude", "claude_desktop_config.json"), "mcpServers")}
	}
	return nil
}

func chain(fs ...func(map[string]any) error) func(map[string]any) error {
	return func(r map[string]any) error {
		for _, f := range fs {
			if err := f(r); err != nil {
				return err
			}
		}
		return nil
	}
}

// Mode is the strongest protection whose every edit went through without a warning.
func Mode(items []Item, outcomes []Outcome) (protected bool, mode string) {
	ok := map[Role]bool{}
	bad := map[Role]bool{}
	for i, it := range items {
		if outcomes[i].Warning != "" {
			bad[it.Role] = true
		} else {
			ok[it.Role] = true
		}
	}
	for _, r := range []Role{RoleHook, RoleGateway, RoleMCP} {
		if ok[r] && !bad[r] {
			return true, string(r)
		}
	}
	return false, "none"
}
