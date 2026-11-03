package protect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/manarhq/manar-edge/internal/discovery"
)

const exe = "/usr/local/bin/manar-edge"

func setup(t *testing.T) (*Store, discovery.User, Ctx) {
	t.Helper()
	root := t.TempDir()
	u := discovery.User{Name: "sam", Home: filepath.Join(root, "home"), UID: -1, GID: -1}
	if err := os.MkdirAll(u.Home, 0o755); err != nil {
		t.Fatal(err)
	}
	return NewStore(filepath.Join(root, "state")), u, Ctx{Exe: exe, GOOS: "linux", GatewayURL: "http://127.0.0.1:848", GatewayUp: true}
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
	out, err := s.Apply(key, u.Name, Owner{UID: -1, GID: -1, Home: u.Home}, edits)
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
	write(t, p, strings.Replace(read(t, p), `"mcpServers": {`, `"mcpServers": {"c":{"command":"ruby","args":["c.rb"]},`, 1))
	if err := s.Restore("gemini-cli", u.Name); err != nil {
		t.Fatal(err)
	}
	got := read(t, p)
	if strings.Contains(got, "hook-tool") || strings.Contains(got, "mcp-wrap") || strings.Contains(got, "manar-edge") {
		t.Fatalf("Manar's entries are still there:\n%s", got)
	}
	for _, keep := range []string{`"a"`, `"command": "node"`, `"a.js"`, `"b"`, `"command": "py"`, `"c"`, `"command": "ruby"`, `"c.rb"`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("lost %s:\n%s", keep, got)
		}
	}
	// A copy of the file as the user left it is kept next to it.
	m, _ := filepath.Glob(p + ".manar-before-restore-*")
	if len(m) != 1 {
		t.Fatalf("no kept copy: %v", m)
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
	if !strings.HasPrefix(read(t, toml), "# Added by Manar") || !strings.Contains(read(t, toml), `openai_base_url = "http://127.0.0.1:848/v1"`) {
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
	// What is let through is the canonical form of what was parsed, not the client's line.
	for l, want := range map[string]string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read"}}`:                           `{"id":2,"jsonrpc":"2.0","method":"tools/call","params":{"name":"read"}}`,
		`{ "method" : "tools/list", "id":3, "jsonrpc":"2.0" }`:                                              `{"id":3,"jsonrpc":"2.0","method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"arguments":{"q":"<a&b>"},"name":"read"}}`: `{"id":4,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"q":"<a&b>"},"name":"read"}}`,
	} {
		if f, r := screen([]byte(l), "fs", deny); string(f) != want || r != nil {
			t.Fatalf("%q: forwarded %s, replies %s", l, f, r)
		}
	}
	// A line that is not JSON-RPC is answered with an error and never reaches the server.
	if f, r := screen([]byte(`not json`), "fs", deny); f != nil || len(r) != 1 || !bytes.Contains(r[0], []byte("-32700")) {
		t.Fatalf("%s %s", f, r)
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

func TestRestoreReversesCodexBaseURLAndKeepsTheUsersLines(t *testing.T) {
	s, u, c := setup(t)
	toml := filepath.Join(u.Home, ".codex", "config.toml")
	write(t, toml, "model = \"o4\"\n")
	apply(t, s, "codex-cli", u, c)
	write(t, toml, read(t, toml)+"approval = \"never\"\n")
	if err := s.Restore("codex-cli", u.Name); err != nil {
		t.Fatal(err)
	}
	if read(t, toml) != "model = \"o4\"\napproval = \"never\"\n" {
		t.Fatalf("%q", read(t, toml))
	}
}

func TestRestoreRemovesAFileManarCreatedOnceTheUserHasNothingInIt(t *testing.T) {
	s, u, c := setup(t)
	p := filepath.Join(u.Home, ".cursor", "hooks.json")
	apply(t, s, "cursor", u, c)
	write(t, p, read(t, p)+" ") // touched: the byte-for-byte shortcut no longer applies
	if err := s.Restore("cursor", u.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("left an empty file Manar created")
	}
}

func TestLinksAreRefused(t *testing.T) {
	s, u, c := setup(t)
	outside := t.TempDir()
	// A parent folder that is a link to somewhere else (~/.copilot -> a system folder).
	if err := os.Symlink(outside, filepath.Join(u.Home, ".copilot")); err != nil {
		t.Fatal(err)
	}
	_, out := apply(t, s, "copilot-cli", u, c)
	for _, o := range out {
		if o.Changed {
			t.Fatalf("wrote through a linked folder: %+v", o)
		}
	}
	if n := countFiles(t, outside); n != 0 {
		t.Fatalf("%d files appeared in the linked folder", n)
	}
	if out[0].Warning == "" || !strings.Contains(out[0].Warning, "link") {
		t.Fatalf("no warning about the link: %+v", out[0])
	}
	// The file itself is a link to a file elsewhere.
	target := filepath.Join(outside, "target.json")
	write(t, target, `{"mcpServers":{}}`)
	if err := os.MkdirAll(filepath.Join(u.Home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(u.Home, ".cursor", "hooks.json")); err != nil {
		t.Fatal(err)
	}
	_, out = apply(t, s, "cursor", u, c)
	if out[0].Changed || read(t, target) != `{"mcpServers":{}}` {
		t.Fatalf("followed a linked file: %+v", out[0])
	}
}

func TestRestoreRefusesALinkPlantedAfterProtection(t *testing.T) {
	s, u, c := setup(t)
	p := filepath.Join(u.Home, ".gemini", "settings.json")
	write(t, p, `{}`)
	apply(t, s, "gemini-cli", u, c)
	secret := filepath.Join(t.TempDir(), "victim")
	write(t, secret, "do not touch")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, p); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore("gemini-cli", u.Name); err == nil {
		t.Fatal("restored through a link")
	}
	if read(t, secret) != "do not touch" {
		t.Fatal("the link target was changed")
	}
	if !s.Has("gemini-cli", u.Name) {
		t.Fatal("dropped the way back after a failed restore")
	}
}

func TestServeUserFSRefusesLinksToo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the user-level helper is Linux only")
	}
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, "d")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	req := `{"op":"write","home":"` + home + `","path":"` + filepath.Join(home, "d", "x.json") + `","data":"e30=","mode":420}`
	if ServeUserFS(strings.NewReader(req), &out) != 0 || !strings.Contains(out.String(), "link") {
		t.Fatalf("%s", out.String())
	}
	if countFiles(t, outside) != 0 {
		t.Fatal("wrote through the link")
	}
}

func TestMCPWrapDoesNotHoldUpOtherMessagesWhileACallWaits(t *testing.T) {
	release := make(chan struct{})
	decide := func(ctx context.Context, _, _ string) Verdict {
		<-release
		return Verdict{true, ""}
	}
	pr, pw := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan int)
	go func() { done <- RunMCPWrap("cursor", "fs", []string{"cat"}, pr, outW, io.Discard, decide) }()
	go func() {
		io.WriteString(pw, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow"}}`+"\n")
		io.WriteString(pw, `{"jsonrpc":"2.0","id":2,"method":"ping"}`+"\n")
		io.WriteString(pw, "garbage\n")
	}()
	sc := bufio.NewScanner(outR)
	var got []string
	for len(got) < 2 && sc.Scan() {
		got = append(got, sc.Text())
	}
	all := strings.Join(got, "\n")
	if !strings.Contains(all, `"method":"ping"`) || !strings.Contains(all, "-32700") || strings.Contains(all, `"id":1`) {
		t.Fatalf("the ping or the garbage reply was held behind the pending call: %q", all)
	}
	close(release)
	if sc.Scan(); !strings.Contains(sc.Text(), `"id":1`) {
		t.Fatalf("the released call did not go through: %q", sc.Text())
	}
	pw.Close()
	<-done
}

func TestAsUserFSRunsTheHelperAsTheOwner(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux to become another user")
	}
	t.Skip("run by hand: build the binary, then asUserFS{UID: 65534, Exe: <binary>}.Write to a nobody-owned folder")
}

func TestCodexRouteIsTakenOutWhenDoorIsNotTrusted(t *testing.T) {
	s, u, c := setup(t)
	toml := filepath.Join(u.Home, ".codex", "config.toml")
	write(t, toml, "model = \"x\"\n")
	apply(t, s, "codex-cli", u, c)
	if !strings.Contains(read(t, toml), `openai_base_url = "http://127.0.0.1:848/v1"`) {
		t.Fatal("route not written while DOOR is healthy")
	}
	// DOOR went down: the next cycle plans without the route and the stale line goes.
	c.GatewayUp = false
	apply(t, s, "codex-cli", u, c)
	if got := read(t, toml); strings.Contains(got, "openai_base_url") || !strings.Contains(got, `model = "x"`) {
		t.Fatalf("route still there or user content lost: %q", got)
	}
	// Back up: it returns; and a line written for an older port is replaced.
	c.GatewayUp = true
	apply(t, s, "codex-cli", u, c)
	write(t, toml, "# Added by Manar: sends model calls through the local gateway.\nopenai_base_url = \"http://127.0.0.1:8480/v1\"\n\nmodel = \"x\"\n")
	apply(t, s, "codex-cli", u, c)
	got := read(t, toml)
	if strings.Contains(got, "8480") || !strings.Contains(got, "127.0.0.1:848/v1") || strings.Count(got, "openai_base_url") != 1 {
		t.Fatalf("stale port kept: %q", got)
	}
	// The original still comes back on restore.
	if err := s.Restore("codex-cli", u.Name); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read(t, toml), "openai_base_url") {
		t.Fatal("restore left the route")
	}
}

func TestNoCodexRouteOnWindows(t *testing.T) {
	_, u, c := setup(t)
	c.GOOS = "windows"
	for _, it := range Plan("codex-cli", u, c) {
		if it.Role == RoleGateway {
			t.Fatal("windows must not route Codex to a loopback port anyone can take")
		}
	}
}

func TestJailEnvEditKeepsOtherSettingsAndRestoresThem(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := `{"model":"opus","env":{"FOO":"bar"}}`
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	st := NewStore(filepath.Join(dir, "state"))
	vars := map[string]string{"HTTPS_PROXY": "http://127.0.0.1:8491", "HTTP_PROXY": "http://127.0.0.1:8491", "NO_PROXY": JailNoProxy}
	out, err := st.Apply("jail-claude-code", "sam", Owner{UID: -1, GID: -1, Home: home}, []FileEdit{JailEnvEdit(path, vars)})
	if err != nil || len(out) != 1 || !out[0].Changed {
		t.Fatalf("%+v %v", out, err)
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{`"HTTPS_PROXY": "http://127.0.0.1:8491"`, `"FOO": "bar"`, `"model": "opus"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	// untouched file: restored byte for byte
	if err := st.Restore("jail-claude-code", "sam"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != orig {
		t.Fatalf("not restored: %s", b)
	}

	// the user changed the file after protection: only our variables go, their change stays
	if _, err := st.Apply("jail-claude-code", "sam", Owner{UID: -1, GID: -1, Home: home}, []FileEdit{JailEnvEdit(path, vars)}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	changed := strings.Replace(string(b), `"model": "opus"`, `"model": "sonnet"`, 1)
	if err := os.WriteFile(path, []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := st.Restore("jail-claude-code", "sam"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "PROXY") || !strings.Contains(string(b), "sonnet") || !strings.Contains(string(b), `"FOO": "bar"`) {
		t.Fatalf("bad reverse: %s", b)
	}

	// a proxy the user set themselves is not ours
	own := `{"env":{"HTTPS_PROXY":"http://corp:3128"}}`
	os.WriteFile(path, []byte(own), 0o644)
	if _, err := st.Apply("jail-claude-code", "sam", Owner{UID: -1, GID: -1, Home: home}, []FileEdit{JailEnvEdit(path, vars)}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte(`{"env":{"HTTPS_PROXY":"http://corp:3128","X":"1"}}`), 0o644)
	if err := st.Restore("jail-claude-code", "sam"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "corp:3128") {
		t.Fatalf("user proxy lost: %s", b)
	}
}

func TestMCPWrapRefusesAmbiguousMessages(t *testing.T) {
	asked := 0
	allow := func(context.Context, string, string) Verdict { asked++; return Verdict{true, ""} }
	for _, l := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"ping","params":{"name":"delete"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"delete"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","name":"delete"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","NAME":"delete"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}} {"x":1}`,
		`{"jsonrpc":"2.0","id":1,"method":7}`,
		`{"jsonrpc":"2.0","id":2,"Method":"tools/call","params":{"name":"x"}}`,
		`{"jsonrpc":"2.0","id":2,"METHOD":"tools/call","params":{"name":"x"}}`,
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{},\"PARAMS\":{}}",
		// U+212A KELVIN SIGN folds to k: "\u212aey" and "key" are one key to a folding decoder.
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"\u212aey\":1,\"key\":2}}",
		// U+017F LONG S folds to s: a look-alike of "arguments".
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"argument\u017f\":{}}}",
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"Name":"x"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call"}`,
	} {
		if !needsDecision([]byte(l)) {
			t.Errorf("%s would be forwarded unchecked", l)
		}
		if f, r := screen([]byte(l), "fs", allow); f != nil || len(r) != 1 || !bytes.Contains(r[0], []byte("-32700")) {
			t.Errorf("%s: forwarded %s, replies %s", l, f, r)
		}
	}
	if asked != 0 {
		t.Fatalf("asked %d times about ambiguous messages", asked)
	}
}
