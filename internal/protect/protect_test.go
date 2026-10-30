package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.vax.sh/manar/manar-edge/internal/discovery"
)

const exe = "/usr/local/bin/manar-edge"

func setup(t *testing.T) (*Store, discovery.User, Ctx) {
	t.Helper()
	root := t.TempDir()
	u := discovery.User{Name: "sam", Home: filepath.Join(root, "home"), UID: -1, GID: -1}
	if err := os.MkdirAll(u.Home, 0o755); err != nil {
		t.Fatal(err)
	}
	return NewStore(filepath.Join(root, "state")), u, Ctx{Exe: exe, GOOS: "linux", GatewayURL: "http://127.0.0.1:8480", GatewayUp: true}
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o640); err != nil {
		t.Fatal(err)
	}
}

func apply(t *testing.T, s *Store, key string, u discovery.User, c Ctx) ([]Item, []Outcome) {
	t.Helper()
	items := Plan(key, u, c)
	edits := make([]FileEdit, len(items))
	for i, it := range items {
		edits[i] = it.FileEdit
	}
	out, err := s.Apply(key, u.Name, Owner{-1, -1}, edits)
	if err != nil {
		t.Fatal(err)
	}
	return items, out
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const cursorMCP = "{\n  // a comment the user keeps\n}\n"

func TestBackupEditRestoreIsByteIdentical(t *testing.T) {
	s, u, c := setup(t)
	hooks := filepath.Join(u.Home, ".cursor", "hooks.json")
	mcp := filepath.Join(u.Home, ".cursor", "mcp.json")
	// Odd formatting, key order and a number the user wrote by hand: restore must give it all back.
	origHooks := "{\n\t\"version\":1,   \"hooks\":{\"afterFileEdit\":[{\"command\":\"./fmt.sh\"}]},\n\t\"z\": 1.50\n}"
	origMCP := `{"mcpServers":{"fs":{"command":"npx","args":["-y","server-fs","/tmp"],"env":{"K":"v"}},"remote":{"url":"https://x.example/mcp"}}}`
	write(t, hooks, origHooks)
	write(t, mcp, origMCP)

	items, out := apply(t, s, "cursor", u, c)
	if prot, mode := Mode(items, out); !prot || mode != "hook" {
		t.Fatalf("mode = %v %q, outcomes %+v", prot, mode, out)
	}
	h := read(t, hooks)
	for _, want := range []string{"beforeShellExecution", "beforeReadFile", "beforeMCPExecution", "afterFileEdit", "./fmt.sh", `"failClosed": true`, "1.50"} {
		if !strings.Contains(h, want) {
			t.Errorf("hooks.json lacks %q:\n%s", want, h)
		}
	}
	m := read(t, mcp)
	if !strings.Contains(m, `"mcp-wrap"`) || !strings.Contains(m, `https://x.example/mcp`) || strings.Contains(m, `"command": "npx"`) {
		t.Errorf("mcp.json not wrapped as expected:\n%s", m)
	}

	if err := s.Restore("cursor", u.Name); err != nil {
		t.Fatal(err)
	}
	if read(t, hooks) != origHooks || read(t, mcp) != origMCP {
		t.Fatal("restore is not byte for byte")
	}
	if st, _ := os.Stat(hooks); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode lost: %v", st.Mode())
	}
	if len(s.Tools()) != 0 {
		t.Fatalf("manifest still lists %v", s.Tools())
	}
}

func TestProtectIsIdempotent(t *testing.T) {
	s, u, c := setup(t)
	write(t, filepath.Join(u.Home, ".gemini", "settings.json"), `{"mcpServers":{"a":{"command":"node","args":["a.js"]}}}`)
	apply(t, s, "gemini-cli", u, c)
	p := filepath.Join(u.Home, ".gemini", "settings.json")
	first := read(t, p)
	backups := countFiles(t, filepath.Join(s.dir, "backups"))
	_, out := apply(t, s, "gemini-cli", u, c)
	for _, o := range out {
		if o.Changed || o.Warning != "" {
			t.Fatalf("second run changed something: %+v", o)
		}
	}
	if read(t, p) != first {
		t.Fatal("second run rewrote the file")
	}
	if countFiles(t, filepath.Join(s.dir, "backups")) != backups {
		t.Fatal("second run took another backup")
	}
	if strings.Count(first, "hook-tool") != 1 || strings.Count(first, `"mcp-wrap"`) != 1 {
		t.Fatalf("duplicated entries:\n%s", first)
	}
	// The first backup survives a later edit (a server the user adds afterwards gets wrapped too).
	write(t, p, strings.Replace(first, `"mcpServers": {`, `"mcpServers": {"b":{"command":"py"},`, 1))
	apply(t, s, "gemini-cli", u, c)
	if !strings.Contains(read(t, p), `"b"`) || strings.Count(read(t, p), `"mcp-wrap"`) != 2 {
		t.Fatalf("new server not wrapped:\n%s", read(t, p))
	}
	// The user edits the file after Manar's last edit; restoring must not lose that.
	write(t, p, read(t, p)+"\n")
	if err := s.Restore("gemini-cli", u.Name); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, p), `"command":"node"`) || strings.Contains(read(t, p), "hook-tool") {
		t.Fatal("restore did not bring back the very first original")
	}
	// The edit made after Manar's is kept beside the backup, not lost.
	found := false
	filepath.Walk(filepath.Join(s.dir, "backups"), func(p string, _ os.FileInfo, _ error) error {
		found = found || strings.Contains(p, ".edited-")
		return nil
	})
	if !found {
		t.Fatal("changes made after Manar's edit were not kept")
	}
}

func countFiles(t *testing.T, dir string) int {
	n := 0
	filepath.Walk(dir, func(_ string, i os.FileInfo, _ error) error {
		if i != nil && !i.IsDir() {
			n++
		}
		return nil
	})
	return n
}

func TestMalformedConfigIsLeftUntouched(t *testing.T) {
	s, u, c := setup(t)
	mcp := filepath.Join(u.Home, ".cursor", "mcp.json")
	write(t, mcp, cursorMCP) // JSON with a comment: not valid JSON, must not be rewritten
	hooks := filepath.Join(u.Home, ".cursor", "hooks.json")
	write(t, hooks, `{"hooks": [1,2]}`) // valid JSON, wrong shape
	items, out := apply(t, s, "cursor", u, c)
	if read(t, mcp) != cursorMCP || read(t, hooks) != `{"hooks": [1,2]}` {
		t.Fatal("a malformed config was modified")
	}
	for _, o := range out {
		if o.Warning == "" || o.Changed {
			t.Fatalf("expected a warning and no change: %+v", o)
		}
	}
	if prot, mode := Mode(items, out); prot || mode != "none" {
		t.Fatalf("claimed protection with nothing installed: %v %q", prot, mode)
	}
	if countFiles(t, filepath.Join(s.dir, "backups")) != 0 {
		t.Fatal("backed up a file it did not edit")
	}
}

func TestNewFileIsRemovedOnRestore(t *testing.T) {
	s, u, c := setup(t)
	items, out := apply(t, s, "copilot-cli", u, c)
	p := filepath.Join(u.Home, ".copilot", "hooks", "manar.json")
	var doc map[string]any
	if err := json.Unmarshal([]byte(read(t, p)), &doc); err != nil {
		t.Fatal(err)
	}
	if prot, mode := Mode(items, out); !prot || mode != "hook" {
		t.Fatalf("%v %q", prot, mode)
	}
	if _, err := os.Stat(filepath.Join(u.Home, ".copilot", "mcp-config.json")); err == nil {
		t.Fatal("created an MCP config nobody had")
	}
	if errs := s.RestoreAll(); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("file Manar created is still there")
	}
}

func TestCodexHookNeedsReviewSoOnlyTheGatewayCounts(t *testing.T) {
	s, u, c := setup(t)
	items, out := apply(t, s, "codex-cli", u, c)
	if _, mode := Mode(items, out); mode != "gateway" {
		t.Fatalf("mode %q", mode)
	}
	toml := filepath.Join(u.Home, ".codex", "config.toml")
	if !strings.HasPrefix(read(t, toml), "# Added by Manar") || !strings.Contains(read(t, toml), `openai_base_url = "http://127.0.0.1:8480/v1"`) {
		t.Fatal(read(t, toml))
	}
	// A gateway that is down is never routed to; a key the user set is never overwritten.
	c.GatewayUp = false
	items, out = apply(t, s, "codex-cli", u, c)
	if prot, _ := Mode(items, out); prot {
		t.Fatal("hook alone must not count: Codex asks its owner to review it")
	}
	write(t, toml, "openai_base_url = \"https://mine.example/v1\"\n")
	c.GatewayUp = true
	s2, _, _ := setup(t)
	_, out = apply(t, s2, "codex-cli", u, c)
	if out[len(out)-1].Warning == "" || read(t, toml) != "openai_base_url = \"https://mine.example/v1\"\n" {
		t.Fatal("overwrote a base URL the user set")
	}
}

func TestMCPWrapShape(t *testing.T) {
	root := map[string]any{"servers": map[string]any{"fs": map[string]any{"command": "npx", "args": []any{"-y", "x"}}}}
	w, sk, err := wrapMCP(root, "servers", exe, "vscode-copilot")
	if err != nil || w != 1 || sk != 0 {
		t.Fatal(w, sk, err)
	}
	b, _ := json.Marshal(root)
	if !bytes.Contains(b, []byte(`"args":["mcp-wrap","vscode-copilot","fs","--","npx","-y","x"]`)) {
		t.Fatal(string(b))
	}
}

func TestMCPWrapDeniesCallsAndPassesTheRest(t *testing.T) {
	deny := func(_ context.Context, _, res string) Verdict {
		if res == "fs/delete" {
			return Verdict{false, "Manar denied: policy_denied"}
		}
		return Verdict{true, ""}
	}
	f, r := screen([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete"}}`), "fs", deny)
	if f != nil || len(r) != 1 || !bytes.Contains(r[0], []byte("policy_denied")) || !bytes.Contains(r[0], []byte(`"id":1`)) {
		t.Fatalf("%s %s", f, r)
	}
	for _, l := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`not json`,
	} {
		if f, r := screen([]byte(l), "fs", deny); string(f) != l || r != nil {
			t.Fatalf("%q was not passed through: %s %s", l, f, r)
		}
	}
	// A batch cannot smuggle a denied call past the wrapper.
	f, r = screen([]byte(`[{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete"}},{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read"}}]`), "fs", deny)
	if bytes.Contains(f, []byte("delete")) || !bytes.Contains(f, []byte(`"id":5`)) || len(r) != 1 {
		t.Fatalf("%s %s", f, r)
	}
}

func TestMCPWrapEndToEnd(t *testing.T) {
	var out, errw bytes.Buffer
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete"}}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n")
	code := RunMCPWrap("cursor", "fs", []string{"cat"}, in, &out, &errw, func(context.Context, string, string) Verdict { return Verdict{false, "nope"} })
	if code != 0 {
		t.Fatal(code, errw.String())
	}
	if !strings.Contains(out.String(), `"nope"`) || !strings.Contains(out.String(), `"method":"ping"`) || strings.Contains(out.String(), "delete") {
		t.Fatal(out.String())
	}
}

func TestClassifyMapsEachToolsInput(t *testing.T) {
	cases := []struct{ key, event, in, action, res string }{
		{"cursor", "shell", `{"command":"ls -la","cwd":"/x"}`, "shell", "ls -la"},
		{"cursor", "read", `{"file_path":"/home/u/.ssh/id_rsa"}`, "read", "/home/u/.ssh/id_rsa"},
		{"cursor", "mcp", `{"mcp_server_name":"gh","tool_name":"create_issue"}`, "mcp", "gh/create_issue"},
		{"windsurf", "shell", `{"agent_action_name":"pre_run_command","tool_info":{"command_line":"git push"}}`, "shell", "git push"},
		{"gemini-cli", "tool", `{"tool_name":"run_shell_command","tool_input":{"command":"rm x"}}`, "shell", "rm x"},
		{"gemini-cli", "tool", `{"tool_name":"write_file","tool_input":{"file_path":"/a/b"}}`, "edit", "/a/b"},
		{"codex-cli", "tool", `{"tool_name":"Bash","tool_input":{"command":"make"}}`, "shell", "make"},
		{"codex-cli", "tool", `{"tool_name":"mcp__filesystem__read_file","tool_input":{}}`, "mcp", "filesystem/read_file"},
		{"copilot-cli", "tool", `{"toolName":"bash","toolArgs":"{\"command\":\"npm test\"}"}`, "shell", "npm test"},
		{"copilot-cli", "tool", `{"tool_name":"mystery","tool_input":{}}`, "mcp", "mystery"},
	}
	for _, c := range cases {
		a, r, err := Classify(c.key, c.event, []byte(c.in))
		if err != nil || a != c.action || r != c.res {
			t.Errorf("%s %s: got %q %q %v, want %q %q", c.key, c.event, a, r, err, c.action, c.res)
		}
	}
	for _, bad := range []string{`not json`, `{}`, `{"tool_name":"Bash","tool_input":{}}`, `{"tool_name":"Bash","tool_input":{"command":"` + strings.Repeat("a", 2049) + `"}}`} {
		if _, _, err := Classify("codex-cli", "tool", []byte(bad)); err == nil {
			t.Errorf("accepted %.40q", bad)
		}
	}
}

func TestRenderDeniesWithExitTwo(t *testing.T) {
	for _, k := range []string{"cursor", "windsurf", "gemini-cli", "codex-cli", "copilot-cli"} {
		out, errb, code := Render(k, Verdict{false, "Manar denied: x"})
		if code != 2 || len(out) != 0 || !strings.Contains(string(errb), "Manar denied") {
			t.Errorf("%s: %d %q %q", k, code, out, errb)
		}
		if _, _, code := Render(k, Verdict{true, ""}); code != 0 {
			t.Errorf("%s allow exit %d", k, code)
		}
	}
}
