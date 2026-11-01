package protect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Undo reverses what Manar added to the current content of a file, leaving everything else in it,
// including what the user changed after protection.
func undoFor(kind string) Edit {
	switch kind {
	case KindJSON:
		return jsonObject(undoJSON)
	case KindCodexTOML:
		return undoCodexTOML
	case KindJSONEnv:
		return jsonObject(undoJSONEnv)
	}
	return func([]byte, bool) ([]byte, error) { return nil, fmt.Errorf("unknown kind %q", kind) }
}

// File kinds, stored in the manifest.
const (
	KindJSON      = "json"
	KindCodexTOML = "codex-toml"
)

func undoJSON(root map[string]any) error {
	if v, ok := root["hooks"]; ok {
		hooks, isObj := v.(map[string]any)
		if !isObj {
			return fmt.Errorf(`"hooks" is not an object`)
		}
		for event, raw := range hooks {
			list, isList := raw.([]any)
			if !isList {
				continue
			}
			var kept []any
			for _, e := range list {
				if keep := stripOurs(e); keep != nil {
					kept = append(kept, keep)
				}
			}
			if len(kept) == 0 {
				delete(hooks, event)
			} else {
				hooks[event] = kept
			}
		}
		if len(hooks) == 0 {
			delete(root, "hooks")
		}
	}
	for _, field := range []string{"mcpServers", "servers"} {
		servers, ok := root[field].(map[string]any)
		if !ok {
			continue
		}
		for _, raw := range servers {
			if srv, ok := raw.(map[string]any); ok {
				unwrapServer(srv)
			}
		}
	}
	return nil
}

// stripOurs removes Manar's hook from an entry: a flat entry that is ours goes entirely; a
// Claude-style group loses only its Manar hooks and goes if none is left.
func stripOurs(e any) any {
	m, ok := e.(map[string]any)
	if !ok {
		return e
	}
	for _, k := range []string{"command", "powershell", "bash"} {
		if s, _ := m[k].(string); isOurs(s) {
			return nil
		}
	}
	hs, ok := m["hooks"].([]any)
	if !ok {
		return e
	}
	var kept []any
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		if s, _ := hm["command"].(string); isOurs(s) {
			continue
		}
		kept = append(kept, h)
	}
	if len(kept) == len(hs) {
		return e
	}
	if len(kept) == 0 {
		return nil
	}
	m["hooks"] = kept
	return m
}

// unwrapServer turns {command: manar-edge, args: [mcp-wrap, tool, name, --, cmd, args...]} back
// into {command: cmd, args: [...]}.
func unwrapServer(srv map[string]any) {
	cmd, _ := srv["command"].(string)
	args, _ := srv["args"].([]any)
	if !strings.Contains(strings.ToLower(cmd), "manar-edge") || len(args) < 5 || args[0] != "mcp-wrap" || args[3] != "--" {
		return
	}
	orig, ok := args[4].(string)
	if !ok {
		return
	}
	srv["command"] = orig
	if rest := args[5:]; len(rest) > 0 {
		srv["args"] = rest
	} else {
		delete(srv, "args")
	}
}

var codexAdded = regexp.MustCompile(`(?m)^# Added by Manar:[^\n]*\n\s*openai_base_url\s*=\s*"[^"\n]*"[ \t]*\n\n?`)

func undoCodexTOML(cur []byte, _ bool) ([]byte, error) {
	return codexAdded.ReplaceAll(cur, nil), nil
}

// emptyish says a JSON file has nothing of the user's in it any more: no keys, or only the
// "version" Manar may have written.
func emptyish(b []byte) bool {
	t := strings.TrimSpace(string(b))
	if t == "" {
		return true
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	delete(m, "version")
	return len(m) == 0
}
