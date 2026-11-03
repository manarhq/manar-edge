package protect

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
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
	guardedDir = regexp.MustCompile(`(^|[\s/"'=~:(<>])\.(claude|cursor|gemini|codex|copilot|windsurf|codeium)(/|\s|$|["';&|)])`)
	// Something next to it that can replace, remove or write files: file commands, redirection,
	// and interpreters or tools that write files themselves.
	changeVerb  = regexp.MustCompile(`(^|[\s;&|(])(rm|rmdir|mv|cp|ln|unlink|install|rsync|tar|unzip|truncate|touch|tee|dd|awk|gawk|python[0-9.]*|node|nodejs|deno|bun|perl|ruby|php|lua|del|erase|rd|move|ren|rename|xcopy|robocopy|mklink|remove-item|move-item|rename-item|copy-item|new-item|set-content|add-content|out-file)(\s|$)|\bsed\s+(-[a-z]*\s+)*-[a-z]*i|>`)
	claudeFlags = regexp.MustCompile(`\bclaude(\.exe)?\b[^;&|]*\s--settings\b`)
	// Any mention of a tool's settings folder, and a '..' path element: together they are refused
	// whatever the shell would make of the rest, because collapsing '..' in text cannot follow
	// what variables or command substitution expand to.
	toolFolder = regexp.MustCompile(`\.(claude|cursor|gemini|codex|copilot|windsurf|codeium)\b`)
	parentElem = regexp.MustCompile(`/\.\.(/|\s|$|["';&|)<>` + "`" + `])`)
	dotDot     = regexp.MustCompile("(^|/)[^/\\s\"'=;&|<>()$`]+/\\.\\./")
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
// stands for on disk. A relative path is taken from cwd, the tool's working folder. The path is
// checked twice: as text (GuardedPath, which applies '..' to the text, as Windows does) and as the
// real target realPath finds (links first, as Linux does). It fails closed: when the path cannot
// be resolved, it counts as guarded.
func guardedTarget(p, cwd string) bool {
	if GuardedPath(p) {
		return true
	}
	abs := filepath.FromSlash(p)
	if !filepath.IsAbs(abs) {
		if cwd == "" {
			cwd, _ = os.Getwd()
		}
		abs = filepath.FromSlash(cwd) + string(filepath.Separator) + abs // not cleaned: links come first
	}
	if !filepath.IsAbs(abs) {
		return true // no folder to start from: cannot tell
	}
	real, err := realPath(abs)
	return err != nil || GuardedPath(real)
}

// maxHops bounds the links followed for one path (Linux's own limit is 40).
const maxHops = 40

// realPath resolves an absolute path the way the kernel walks it: one element at a time, each link
// (symbolic link, or junction on Windows) replaced by its target's elements, which are walked the
// same way from where the link is (or from the root, for an absolute target), so every '..' is
// applied only after the links before it. A link that cannot be read, points nowhere, or loops is
// an error, and so is an element made only of dots and spaces other than "." and ".." (Windows
// reads "..." or ". ." as other names). Once an element does not exist, the rest is a file or
// folder the tool would create: it may only be plain names (no "..", and no "~" 8.3-style name on
// Windows), else it is an error. On Windows the part that exists is given its long name.
// Every error means "cannot tell": the caller refuses.
func realPath(abs string) (string, error) {
	vol := filepath.VolumeName(abs)
	if vol == "" && runtime.GOOS == "windows" {
		return "", errors.New("no drive")
	}
	todo := splitPath(abs[len(vol):])
	cur := vol + string(filepath.Separator)
	hops := 0
	for len(todo) > 0 {
		e, err := element(todo[0])
		if err != nil {
			return "", err
		}
		todo = todo[1:]
		switch e {
		case ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, e)
		fi, err := os.Lstat(next)
		if os.IsNotExist(err) {
			long, err := longPath(cur)
			if err != nil {
				return "", err
			}
			out := []string{long}
			for _, r := range append([]string{e}, todo...) {
				n, err := element(r)
				if err != nil || n == ".." || n == "." || (runtime.GOOS == "windows" && strings.Contains(n, "~")) {
					return "", errors.New("only plain new names may follow a part that does not exist")
				}
				out = append(out, n)
			}
			return filepath.Join(out...), nil
		}
		if err != nil {
			return "", err
		}
		if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			cur = next
			continue
		}
		if hops++; hops > maxHops {
			return "", errors.New("too many links")
		}
		if _, err := os.Stat(next); err != nil {
			return "", errors.New("a link that points nowhere") // broken, or a loop
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		// The target's own elements go first in the queue, walked from the link's folder or from
		// the root: never joined (and so cleaned) as text.
		if tv := filepath.VolumeName(target); tv != "" {
			cur, target = tv+string(filepath.Separator), target[len(tv):]
		} else if strings.HasPrefix(target, "/") || strings.HasPrefix(target, string(filepath.Separator)) {
			cur = filepath.VolumeName(cur) + string(filepath.Separator)
		}
		todo = append(splitPath(target), todo...)
	}
	return longPath(cur)
}

// element returns a path element as the file system reads it: on Windows without trailing dots
// and spaces. An element made only of dots and spaces other than "." and ".." is an error.
func element(e string) (string, error) {
	if e == "." || e == ".." {
		return e, nil
	}
	if strings.Trim(e, ". ") == "" {
		return "", errors.New("a path element made only of dots and spaces")
	}
	if runtime.GOOS == "windows" {
		e = strings.TrimRight(e, ". ")
	}
	return e, nil
}

func splitPath(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == filepath.Separator })
}

// GuardedCommand reports whether a shell command names a guarded file, points Claude Code at other
// settings, or names a tool's settings folder next to something that can write or remove files.
//
// This is best effort, not a security boundary: it reads the command's text, and a command can
// build a name the text does not show (variables, encodings, a script written first and run
// later). It narrows what an AI tool does by accident or on a planted instruction; the reports
// (tamper.go) and the console are what make the rest visible.
func GuardedCommand(cmd string) bool {
	raw := strings.ToLower(strings.ReplaceAll(cmd, `\`, "/"))
	norm := raw
	for prev := ""; prev != norm; {
		prev = norm
		norm = strings.ReplaceAll(norm, "//", "/")
		norm = strings.ReplaceAll(norm, "/./", "/")
		norm = dotDot.ReplaceAllString(norm, "$1")
	}
	if toolFolder.MatchString(raw) && parentElem.MatchString(raw) {
		return true
	}
	// Normalising removes text, so the raw command is checked too: a match in either refuses.
	return guardedText1(raw) || guardedText1(norm)
}

func guardedText1(c string) bool {
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

// Limits of one argument scan. Past either, Manar cannot tell what the call names: refused.
const (
	maxArgDepth  = 32
	maxArgValues = 10000
)

var errTooDeep = errors.New("the arguments are nested too deeply or are too many to check")

// scanArgs walks a tool's arguments with no silent cut-off: it lists the file paths (values of
// path-like keys and the files named in any patch text) and every string, and fails when the
// arguments go deeper than maxArgDepth or hold more than maxArgValues values.
func scanArgs(args any) (targets, values []string, err error) {
	add := func(s string) {
		s = strings.TrimSpace(strings.SplitN(s, "\t", 2)[0]) // diff headers may carry a timestamp
		for _, pre := range []string{"a/", "b/"} {
			if strings.HasPrefix(s, pre) {
				targets = append(targets, strings.TrimPrefix(s, pre)) // git diff prefixes, kept both ways
			}
		}
		if s != "" && s != "/dev/null" {
			targets = append(targets, s)
		}
	}
	n := 0
	var walk func(v any, key string, depth int) error
	walk = func(v any, key string, depth int) error {
		if n++; depth > maxArgDepth || n > maxArgValues {
			return errTooDeep
		}
		switch x := v.(type) {
		case string:
			values = append(values, x)
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
				if err := walk(e, key, depth+1); err != nil {
					return err
				}
			}
		case map[string]any:
			for k, e := range x {
				if err := walk(e, k, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	err = walk(args, "", 0)
	return targets, values, err
}

// editTargets is scanArgs's file list (tests and the shell's patch check; no depth to speak of).
func editTargets(args map[string]any) []string {
	t, _, _ := scanArgs(args)
	return t
}

// guardedText reports a one-line string whose text is a guarded file: a file named under a key
// Manar does not know as a path (output_file, dst, ...).
func guardedValue(values []string) (string, bool) {
	for _, v := range values {
		if !strings.ContainsAny(v, "\n\r") && GuardedPath(v) {
			return v, true
		}
	}
	return "", false
}

// guardedNames are the file names in guardedFiles that are specific enough to stand for one on
// their own (not "*" or "*.json").
var guardedNames = []string{
	"settings*.json", "managed-settings*.json", "hooks.json", "mcp.json", "mcp_config.json",
	"mcp-config.json", "config.toml", "claude_desktop_config.json",
}

// namedLikeGuarded lists the one-line string values whose last element has the name of a guarded
// file (settings.json, hooks.json, mcp.json, ...): under a key Manar does not know as a path they
// are still treated as files, so a link or a relative path to one is resolved and checked.
func namedLikeGuarded(values []string) []string {
	var out []string
	for _, v := range values {
		if strings.ContainsAny(v, "\n\r") {
			continue
		}
		parts := strings.Split(canonical(v), "/")
		last := parts[len(parts)-1]
		for _, n := range guardedNames {
			if m, _ := path.Match(n, last); m {
				out = append(out, v)
				break
			}
		}
	}
	return out
}

// GuardNeedsFullPath is the deny message for an MCP call that names a file by a relative or ~
// path: Manar cannot know which folder the server resolves it from.
const GuardNeedsFullPath = "Manar denied: Manar needs a full file path for this tool."

// guardedArgs is the argument check for an MCP call through the wrapper; reason is empty when it
// may go on. Arguments that cannot be checked as a whole, and a one-line string whose text is a
// guarded file, are refused. A path-like argument must be absolute (relative, ~ and ~user paths
// are refused: the server resolves them from a folder Manar does not know), and an absolute one
// is refused when its real target is a guarded file.
func guardedArgs(args map[string]any) (reason string) {
	targets, values, err := scanArgs(args)
	if err != nil {
		return "Manar: " + err.Error()
	}
	if _, ok := guardedValue(values); ok {
		return GuardReason
	}
	for _, t := range append(targets, namedLikeGuarded(values)...) {
		if !filepath.IsAbs(filepath.FromSlash(t)) {
			return GuardNeedsFullPath
		}
		if guardedTarget(t, "") {
			return GuardReason
		}
	}
	return ""
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
		return "Manar: " + err.Error(), "", "" // what cannot be checked is refused
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
		var values []string
		var err error
		targets, values, err = scanArgs(toolArgs(in))
		if err != nil {
			return "Manar: " + err.Error(), "", ""
		}
		if v, ok := guardedValue(values); ok {
			return GuardReason, "edit", v
		}
		targets = append(targets, namedLikeGuarded(values)...)
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
