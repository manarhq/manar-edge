package protect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
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
func isOurs(cmd string) bool {
	l := strings.ToLower(cmd)
	return strings.Contains(l, "manar-edge") && (strings.Contains(l, "hook-tool") || strings.Contains(l, "mcp-wrap"))
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
func setFlatHook(root map[string]any, event string, entry map[string]any) error {
	hooks, err := objAt(root, "hooks")
	if err != nil {
		return err
	}
	list, err := listAt(hooks, event)
	if err != nil {
		return err
	}
	return putOurs(hooks, event, list, entry, func(e any) bool {
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
func setNestedHook(root map[string]any, event string, group map[string]any) error {
	hooks, err := objAt(root, "hooks")
	if err != nil {
		return err
	}
	list, err := listAt(hooks, event)
	if err != nil {
		return err
	}
	return putOurs(hooks, event, list, group, func(g any) bool {
		m, _ := g.(map[string]any)
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

func putOurs(parent map[string]any, event string, list []any, want map[string]any, ours func(any) bool) error {
	for _, e := range list {
		if ours(e) && sameJSON(e, want) {
			return nil // already there, exactly
		}
	}
	kept := make([]any, 0, len(list)+1)
	for _, e := range list {
		if !ours(e) {
			kept = append(kept, e)
		}
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

var topLevelBaseURL = regexp.MustCompile(`(?m)^\s*openai_base_url\s*=\s*(.*)$`)

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
