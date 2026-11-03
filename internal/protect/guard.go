package protect

import (
	"path"
	"regexp"
	"strings"
)

// The hook and settings files of the tools Manar protects. A project's own settings win over the
// user's (Claude Code: .claude/settings.json and settings.local.json can set disableAllHooks), so an
// AI tool that may edit files could switch its own checks off. Every hook refuses an edit to these
// files, in any folder, and a shell command that names them. Matching is on the last path
// elements, case-insensitive; '*' matches within one element.
var guardedFiles = []string{
	".claude/settings*.json", "managed-settings*.json", "managed-settings.d/*",
	".cursor/hooks.json", ".cursor/mcp.json",
	".codeium/windsurf/hooks.json", ".codeium/windsurf/mcp_config.json", ".windsurf/hooks.json",
	".gemini/settings.json",
	".codex/hooks.json", ".codex/config.toml",
	".copilot/hooks/*.json", ".copilot/mcp-config.json", ".github/hooks/*.json",
	"code/user/mcp.json", "claude/claude_desktop_config.json",
}

// guardedText are fragments that, in a shell command, name a guarded file or a way around the
// hooks (CLAUDE_CONFIG_DIR, --settings point Claude Code at other settings).
var guardedText = []string{
	".claude/settings", "settings.local.json", "managed-settings", "disableallhooks", "claude_config_dir",
	".cursor/hooks.json", ".cursor/mcp.json", "windsurf/hooks.json", "mcp_config.json", ".gemini/settings.json",
	".codex/hooks.json", ".codex/config.toml", ".copilot/hooks", ".copilot/mcp-config.json", ".github/hooks",
	"claude_desktop_config.json",
}

var (
	// A tool's settings folder named as a whole, with a command that could replace or remove it.
	guardedDir  = regexp.MustCompile(`(^|[\s/"'=~:])\.(claude|cursor|gemini|codex|copilot|windsurf|codeium)(/|\s|$|["';&|)])`)
	changeVerb  = regexp.MustCompile(`(^|[\s;&|(])(rm|rmdir|mv|cp|ln|unlink|install|rsync|tar|unzip|del|erase|rd|move|ren|rename|xcopy|robocopy|mklink|remove-item|move-item|rename-item|copy-item|new-item|set-content|add-content|out-file)(\s|$)|>`)
	claudeFlags = regexp.MustCompile(`\bclaude(\.exe)?\b[^;&|]*\s--settings\b`)
)

// GuardedPath reports whether p (absolute or relative, either separator) is a guarded file.
func GuardedPath(p string) bool {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	p = path.Clean(p)
	parts := strings.Split(p, "/")
	for _, g := range guardedFiles {
		gp := strings.Split(g, "/")
		if len(gp) > len(parts) {
			continue
		}
		tail := parts[len(parts)-len(gp):]
		ok := true
		for i := range gp {
			if m, _ := path.Match(gp[i], tail[i]); !m {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// GuardedCommand reports whether a shell command names a guarded file, points Claude Code at other
// settings, or changes a tool's settings folder as a whole. Best effort: a command can build a name
// the text does not show (variables, encodings, a script written first). Reading is refused too.
func GuardedCommand(cmd string) bool {
	c := strings.ToLower(strings.ReplaceAll(cmd, `\`, "/"))
	for _, t := range guardedText {
		if strings.Contains(c, t) {
			return true
		}
	}
	return claudeFlags.MatchString(c) || (guardedDir.MatchString(c) && changeVerb.MatchString(c))
}

// GuardReason is the deny message for a guarded edit or command.
const GuardReason = "Manar denied: AI tools may not change AI tool hook or settings files (they could switch off " +
	"Manar's checks). Change them yourself if you need to."

// Guard checks a classified action (shell, edit) before Manar is asked. blocked means deny with
// GuardReason; the call is never sent for approval.
func Guard(actionID, resource string) (blocked bool) {
	switch strings.ToLower(actionID) {
	case "edit", "write", "multiedit", "notebookedit":
		return GuardedPath(resource)
	case "shell", "bash":
		return GuardedCommand(resource)
	}
	return false
}
