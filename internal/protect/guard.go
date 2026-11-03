package protect

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
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
	// A tool's settings folder named as a whole.
	guardedDir = regexp.MustCompile(`(^|[\s/"'=~:(])\.(claude|cursor|gemini|codex|copilot|windsurf|codeium)(/|\s|$|["';&|)])`)
	// Something next to it that can replace, remove or write files: file commands, redirection,
	// and interpreters or tools that write files themselves.
	changeVerb  = regexp.MustCompile(`(^|[\s;&|(])(rm|rmdir|mv|cp|ln|unlink|install|rsync|tar|unzip|truncate|touch|tee|dd|awk|gawk|python[0-9.]*|node|nodejs|deno|bun|perl|ruby|php|lua|del|erase|rd|move|ren|rename|xcopy|robocopy|mklink|remove-item|move-item|rename-item|copy-item|new-item|set-content|add-content|out-file)(\s|$)|\bsed\s+(-[a-z]*\s+)*-[a-z]*i|>`)
	claudeFlags = regexp.MustCompile(`\bclaude(\.exe)?\b[^;&|]*\s--settings\b`)
	dotDot      = regexp.MustCompile(`[^/\s"'=]+/\.\./`)
)

// canonical lower-cases p, uses '/', drops Windows stream suffixes (name:stream, name::$DATA) and
// trailing dots and spaces (Windows ignores both), and collapses '.', '..' and repeated '/'.
func canonical(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	parts := strings.Split(p, "/")
	for i, s := range parts {
		if i == 0 && len(s) == 2 && s[1] == ':' { // drive letter
			continue
		}
		if j := strings.IndexByte(s, ':'); j >= 0 {
			s = s[:j]
		}
		if t := strings.TrimRight(s, ". "); t != "" && s != "." && s != ".." {
			s = t
		}
		parts[i] = s
	}
	return path.Clean(strings.Join(parts, "/"))
}

// GuardedPath reports whether p (absolute or relative, either separator) is a guarded file, by its
// text (see guardedTarget for links and short names).
func GuardedPath(p string) bool {
	parts := strings.Split(canonical(p), "/")
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

// guardedTarget is GuardedPath for a file a tool is about to write, also through what the path
// stands for on disk: links in the part that exists (the file itself, or the folders above it)
// are resolved, and so are Windows 8.3 short names (EvalSymlinks returns long names there).
// A relative path is taken from cwd, the tool's working folder.
func guardedTarget(p, cwd string) bool {
	if GuardedPath(p) {
		return true
	}
	abs := filepath.FromSlash(p)
	if !filepath.IsAbs(abs) {
		if cwd == "" {
			cwd, _ = os.Getwd()
		}
		abs = filepath.Join(cwd, abs)
	}
	abs = filepath.Clean(abs)
	rest := ""
	for dir := abs; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil {
			if r, err := filepath.EvalSymlinks(dir); err == nil {
				return GuardedPath(filepath.Join(r, rest))
			}
			return false
		}
		if filepath.Dir(dir) == dir {
			return false
		}
		rest = filepath.Join(filepath.Base(dir), rest)
	}
}

// GuardedCommand reports whether a shell command names a guarded file, points Claude Code at other
// settings, or names a tool's settings folder next to something that can write or remove files.
//
// This is best effort, not a security boundary: it reads the command's text, and a command can
// build a name the text does not show (variables, encodings, a script written first and run
// later). It narrows what an AI tool does by accident or on a planted instruction; the reports
// (tamper.go) and the console are what make the rest visible.
func GuardedCommand(cmd string) bool {
	c := strings.ToLower(strings.ReplaceAll(cmd, `\`, "/"))
	for prev := ""; prev != c; {
		prev = c
		c = strings.ReplaceAll(c, "//", "/")
		c = strings.ReplaceAll(c, "/./", "/")
		c = dotDot.ReplaceAllString(c, "")
	}
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

// GuardNoTarget is the deny message for an editing call whose files Manar cannot tell.
const GuardNoTarget = "Manar denied: cannot tell which files this edit changes, so it cannot check them."

// Keys that name a file an editing tool writes, moves or creates.
var targetKeys = map[string]bool{
	"file_path": true, "filepath": true, "absolute_path": true, "path": true, "notebook_path": true,
	"new_path": true, "old_path": true, "target_file": true, "target": true, "destination": true,
	"dest": true, "source": true, "new_name": true, "to": true, "from": true, "file": true,
	"filename": true, "paths": true, "files": true,
}

// Patch headers that name a file: the apply_patch format (*** Add/Update/Delete File, *** Move
// to) and unified and git diffs (---, +++, rename, copy).
var patchTargets = regexp.MustCompile(`(?m)^(?:\*\*\* (?:Add|Update|Delete) File: |\*\*\* Move to: |(?:\+\+\+|---) |rename (?:from|to) |copy (?:from|to) )(.+?)\s*$|^diff --git (\S+) (\S+)\s*$`)

// editTargets lists every file path in a tool's arguments: values of path-like keys (also in
// nested objects and lists) and the files named in any patch text.
func editTargets(args map[string]any) []string {
	var out []string
	var walk func(v any, key string, depth int)
	add := func(s string) {
		s = strings.TrimSpace(strings.SplitN(s, "\t", 2)[0]) // diff headers may carry a timestamp
		for _, pre := range []string{"a/", "b/"} {
			if strings.HasPrefix(s, pre) {
				out = append(out, strings.TrimPrefix(s, pre)) // git diff prefixes, kept both ways
			}
		}
		if s != "" && s != "/dev/null" {
			out = append(out, s)
		}
	}
	walk = func(v any, key string, depth int) {
		if depth > 4 {
			return
		}
		switch x := v.(type) {
		case string:
			if targetKeys[strings.ToLower(key)] {
				add(x)
			}
			for _, m := range patchTargets.FindAllStringSubmatch(x, -1) {
				for _, g := range m[1:] {
					add(g)
				}
			}
		case []any:
			for _, e := range x {
				walk(e, key, depth+1)
			}
		case map[string]any:
			for k, e := range x {
				walk(e, k, depth+1)
			}
		}
	}
	walk(args, "", 0)
	return out
}

// toolArgs returns a generic tool's arguments from its hook input (Claude Code, Gemini, Codex:
// tool_input or tool_args; Copilot: toolArgs, an object or a JSON string).
func toolArgs(in map[string]any) map[string]any {
	args, _ := in["tool_input"].(map[string]any)
	if args == nil {
		args, _ = in["tool_args"].(map[string]any)
	}
	if args == nil {
		if s, ok := in["toolArgs"].(string); ok {
			_ = json.Unmarshal([]byte(s), &args)
		} else {
			args, _ = in["toolArgs"].(map[string]any)
		}
	}
	return args
}

// GuardInput checks one hook call before Manar is asked; reason is empty when it may go on.
// path is what to report: a guarded file, or "" for a shell command (it can hold secrets).
//   - shell: GuardedCommand on the command;
//   - edit (any editing tool, apply_patch included): every target from the arguments and patch
//     headers is checked, and an edit with no target Manar can find is refused;
//   - anything else except read and fetch (MCP tools, unknown tools): any path-like argument or
//     patch header that is a guarded file is refused.
func GuardInput(key, event string, raw []byte) (reason, action, path string) {
	actionID, resource, err := Classify(key, event, raw)
	if err != nil {
		return "", "", "" // the caller refuses an input it cannot classify
	}
	var in map[string]any
	_ = json.Unmarshal(raw, &in)
	cwd, _ := in["cwd"].(string)
	switch actionID {
	case "shell":
		if GuardedCommand(resource) {
			return GuardReason, "shell", ""
		}
		for _, t := range editTargets(map[string]any{"": resource}) { // a patch piped to apply_patch
			if guardedTarget(t, cwd) {
				return GuardReason, "shell", ""
			}
		}
		return "", "", ""
	case "read", "webfetch":
		return "", "", ""
	}
	var targets []string
	if key == "cursor" || key == "windsurf" {
		targets = nil // their mcp events carry no file arguments Manar can see
	} else {
		targets = editTargets(toolArgs(in))
	}
	for _, t := range targets {
		if guardedTarget(t, cwd) {
			return GuardReason, "edit", t
		}
	}
	if actionID == "edit" && len(targets) == 0 {
		return GuardNoTarget, "", ""
	}
	return "", "", ""
}
