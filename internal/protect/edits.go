package protect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/manarhq/manar-edge/internal/lazyre"
)

// jsonObject parses cur as one JSON object (empty or absent is {}), runs fn, and returns the
// result in canonical form. Anything that is not a plain JSON object (comments, a list, a typo)
// is an error: the caller leaves the file alone. Unchanged output is returned as the original bytes.
func jsonObject(fn func(root map[string]any) error) Edit {
	return func(cur []byte, existed bool) ([]byte, error) {
		root := map[string]any{}
		if len(bytes.TrimSpace(cur)) > 0 {
			dec := json.NewDecoder(bytes.NewReader(cur))
			dec.UseNumber()
			if err := dec.Decode(&root); err != nil {
				return nil, fmt.Errorf("not valid JSON (%v)", err)
			}
			if dec.More() {
				return nil, errors.New("not valid JSON (text after the object)")
			}
		}
		before, err := json.Marshal(root)
		if err != nil {
			return nil, err
		}
		if err := fn(root); err != nil {
			return nil, err
		}
		after, _ := json.Marshal(root)
		if bytes.Equal(before, after) {
			return cur, nil
		}
		out, err := json.MarshalIndent(root, "", "  ")
		return append(out, '\n'), err
	}
}

// isOurs recognises a command Manar installed, by the subcommand and the program name.
// A command that runs Manar's hook subcommand for a known tool counts as ours whatever program
// it names, so an entry repointed at another program is found and put back.
var reHookTool = lazyre.New(`(?i)\bhook-tool\s+(claude-code|cursor|windsurf|gemini-cli|codex-cli|copilot-cli)\s+\w+`)

func isOurs(cmd string) bool {
	l := strings.ToLower(cmd)
	return reHookTool.MatchString(cmd) || strings.Contains(l, "manar-edge") && (strings.Contains(l, "hook-tool") || strings.Contains(l, "mcp-wrap"))
}

// commandExe is the program a hook command runs: the quoted first word (as hookCommand writes
// it), or the first word.
func commandExe(cmd string) string {
	cmd = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(cmd), "& "))
	if strings.HasPrefix(cmd, `"`) {
		if j := strings.Index(cmd[1:], `"`); j >= 0 {
			return cmd[1 : j+1]
		}
		return ""
	}
	if f := strings.Fields(cmd); len(f) > 0 {
		return f[0]
	}
	return ""
}

// guard knows this install's program and where to report tampering. This install owns every
// Manar-looking hook entry in a file: nothing but its own exact entry is allowed to stay.
type guard struct {
	exe    string
	report func(cmds []string)
}

// canonicalHook splits a command Manar writes: its program in quotes, hook-tool, the tool key and
// one event word (an optional "& " is the PowerShell form Windsurf uses).
var canonicalHook = lazyre.New(`^(& )?"([^"\x00-\x1f]+)" hook-tool ([a-z-]+) (tool|shell|read|mcp)$`)

// sameExe compares two program paths as cleaned text (case-folded on Windows). It never resolves
// symlinks: the path in the file is user-writable, so a link that points at the service's binary
// today can point at anything tomorrow. The service passes its own already-resolved path (exePath).
func sameExe(a, b string) bool {
	norm := func(p string) string {
		p = filepath.Clean(p)
		if runtime.GOOS == "windows" {
			p = strings.ToLower(p)
		}
		return p
	}
	return a != "" && b != "" && norm(a) == norm(b)
}

// withOwnExe returns e with every canonical hook command that runs this install's program (by
// sameExe, so only a case or clean-up difference) written with exactly want's text for the program.
// Commands that run anything else, including any link to this program, are left as they are.
func (g *guard) withOwnExe(e any) any {
	switch v := e.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[k] = g.withOwnExe(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = g.withOwnExe(x)
		}
		return out
	case string:
		if m := canonicalHook.FindStringSubmatch(v); m != nil && sameExe(m[2], g.exe) {
			return m[1] + `"` + g.exe + `" hook-tool ` + m[3] + ` ` + m[4]
		}
	}
	return e
}

// entryCommands lists the command strings of one hook entry (flat or nested).
func entryCommands(e any) []string {
	var out []string
	m, _ := e.(map[string]any)
	for _, k := range []string{"command", "powershell", "bash"} {
		if s, _ := m[k].(string); s != "" {
			out = append(out, s)
		}
	}
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		if s, _ := hm["command"].(string); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func objAt(m map[string]any, key string) (map[string]any, error) {
	v, ok := m[key]
	if !ok || v == nil {
		n := map[string]any{}
		m[key] = n
		return n, nil
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%q is not an object", key)
	}
	return o, nil
}

func listAt(m map[string]any, key string) ([]any, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%q is not a list", key)
	}
	return l, nil
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// setFlatHook puts entry in root.hooks[event] (a list of entries that each have "command"),
// replacing an older Manar entry, leaving everyone else's.
func setFlatHook(root map[string]any, event string, entry map[string]any, g *guard) error {
	hooks, err := objAt(root, "hooks")
	if err != nil {
		return err
	}
	list, err := listAt(hooks, event)
	if err != nil {
		return err
	}
	return putOurs(hooks, event, list, entry, g, func(e any) bool {
		m, _ := e.(map[string]any)
		for _, k := range []string{"command", "powershell", "bash"} {
			if s, _ := m[k].(string); isOurs(s) {
				return true
			}
		}
		return false
	})
}

// setNestedHook is the Claude-style shape: root.hooks[event] is a list of {matcher, hooks:[...]}.
func setNestedHook(root map[string]any, event string, group map[string]any, g *guard) error {
	hooks, err := objAt(root, "hooks")
	if err != nil {
		return err
	}
	list, err := listAt(hooks, event)
	if err != nil {
		return err
	}
	return putOurs(hooks, event, list, group, g, func(x any) bool {
		m, _ := x.(map[string]any)
		hs, _ := m["hooks"].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			if s, _ := hm["command"].(string); isOurs(s) {
				return true
			}
		}
		return false
	})
}

// putOurs makes want the only Manar entry in list. An existing entry that is exactly want (the
// program compared with sameExe) stays untouched; every other Manar-looking entry, a changed
// timeout, an extra hook or field, a duplicate, another program, is removed and reported, and want
// is put in. Entries that are not Manar's are left alone.
func putOurs(parent map[string]any, event string, list []any, want map[string]any, g *guard, ours func(any) bool) error {
	kept := make([]any, 0, len(list)+1)
	exact, tampered := 0, false
	for _, e := range list {
		switch {
		case !ours(e):
			kept = append(kept, e)
		case sameJSON(e, want) || (g != nil && sameJSON(g.withOwnExe(e), want)):
			exact++
			if exact > 1 { // a second copy is not ours to leave
				tampered = true
				if g != nil {
					g.report(entryCommands(e))
				}
			}
		default:
			tampered = true
			if g != nil {
				g.report(entryCommands(e))
			}
		}
	}
	if exact == 1 && !tampered {
		return nil // already there, exactly
	}
	parent[event] = append(kept, want)
	return nil
}

// wrapMCP rewrites each stdio server in root[key] to run through `manar-edge mcp-wrap`, which asks
// Manar before every tool call. Remote (url) servers cannot be wrapped this way and are left as
// they are; wrapped is how many are now behind the wrapper and skipped how many are not.
func wrapMCP(root map[string]any, key, exe, tool string) (wrapped, skipped int, err error) {
	v, ok := root[key]
	if !ok || v == nil {
		return 0, 0, nil
	}
	servers, ok := v.(map[string]any)
	if !ok {
		return 0, 0, fmt.Errorf("%q is not an object", key)
	}
	for name, raw := range servers {
		srv, ok := raw.(map[string]any)
		if !ok {
			skipped++
			continue
		}
		cmd, _ := srv["command"].(string)
		if cmd == "" {
			skipped++
			continue
		}
		args, _ := srv["args"].([]any)
		if strings.Contains(strings.ToLower(cmd), "manar-edge") && len(args) >= 4 && args[0] == "mcp-wrap" {
			srv["command"] = exe // keep it pointing at the installed binary
			wrapped++
			continue
		}
		next := append([]any{"mcp-wrap", tool, name, "--", cmd}, args...)
		srv["command"], srv["args"] = exe, next
		wrapped++
	}
	return wrapped, skipped, nil
}

var topLevelBaseURL = lazyre.New(`(?m)^\s*openai_base_url\s*=\s*(.*)$`)

// codexBaseURL sets openai_base_url in config.toml, only when the key is not there yet. It is
// added at the top of the file, where a top-level key must be. The file is not parsed as TOML
// (standard library only), so anything it cannot place with certainty is left alone.
func codexBaseURL(url string) Edit {
	line := `openai_base_url = "` + url + `"`
	return func(cur []byte, _ bool) ([]byte, error) {
		// A line Manar wrote on an earlier run (maybe for another port) is replaced, not kept.
		if codexAdded.Match(cur) {
			if bytes.Contains(cur, []byte("# Added by Manar: sends model calls through the local gateway.\n"+line+"\n")) {
				return cur, nil
			}
			cur = codexAdded.ReplaceAll(cur, nil)
		}
		if m := topLevelBaseURL.FindSubmatch(cur); m != nil {
			if strings.TrimSpace(string(m[1])) == `"`+url+`"` {
				return cur, nil
			}
			return nil, errors.New("openai_base_url is already set; not changed")
		}
		return append([]byte("# Added by Manar: sends model calls through the local gateway.\n"+line+"\n\n"), cur...), nil
	}
}
