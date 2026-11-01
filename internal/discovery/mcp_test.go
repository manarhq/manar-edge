package discovery

import (
	"encoding/json"
	"strings"
	"testing"
)

const cursorMCP = `{"mcpServers":{
 "fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.2.3","/home/a/work"]},
 "gh":{"command":"npx","args":["-y","some-mcp@latest","--token","ghp_abcdefghijklmnopqrstuvwxyz0123456789"],"env":{"GITHUB_TOKEN":"ghp_supersecretvalue1234567890"}},
 "wrapped":{"command":"/usr/bin/manar-edge","args":["mcp-wrap","cursor","wrapped","--","uvx","mcp-server-git==0.6.2","--api-key=abc"]},
 "remote":{"url":"https://user:pw@mcp.example.com/mcp/AbCdEfGhIjKlMnOpQrStUvWxYz012345?key=SECRET&x=1","headers":{"Authorization":"Bearer zzz"}},
 "dock":{"command":"docker","args":["run","-i","--rm","-e","API_KEY","ghcr.io/acme/mcp:1.0"]}
}}`

func find(t *testing.T, s []MCPServer, name string) MCPServer {
	for _, x := range s {
		if x.Name == name {
			return x
		}
	}
	t.Fatalf("server %q not reported", name)
	return MCPServer{}
}

func one(cmd string, args ...string) MCPServer {
	return build("host.cursor", "x", cmd, args, "", "", nil)
}

func TestParseJSONServersAllowList(t *testing.T) {
	s := parseJSONServers("host.cursor", "mcpServers", []byte(cursorMCP))
	if len(s) != 5 {
		t.Fatalf("want 5 servers, got %d", len(s))
	}
	if fs := find(t, s, "fs"); fs.Package != "@modelcontextprotocol/server-filesystem" || fs.Version != "1.2.3" || fs.Transport != "stdio" || fs.ArgCount != 3 || fs.Command != "npx" {
		t.Errorf("fs: %+v", fs)
	}
	if gh := find(t, s, "gh"); gh.Package != "some-mcp" || gh.Version != "latest" || gh.ArgCount != 4 || strings.Join(gh.EnvKeys, ",") != "GITHUB_TOKEN" {
		t.Errorf("gh: %+v", gh)
	}
	if w := find(t, s, "wrapped"); w.Command != "uvx" || w.Package != "mcp-server-git" || w.Version != "0.6.2" || w.ArgCount != 2 {
		t.Errorf("wrapped not unwrapped: %+v", w)
	}
	if r := find(t, s, "remote"); r.Transport != "http" || r.URL != "https://mcp.example.com" {
		t.Errorf("remote url: %+v", r)
	}
	if d := find(t, s, "dock"); d.Package != "ghcr.io/acme/mcp" || d.Version != "1.0" {
		t.Errorf("docker: %+v", d)
	}
	b, _ := json.Marshal(s)
	for _, bad := range []string{"ghp_", "supersecret", "Bearer", "abc", "SECRET", "AbCdEf", "pw@", "--token", "/home/a/work", "args"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("payload leaks %q: %s", bad, b)
		}
	}
}

// Every shape the security review named: nothing of these may appear in what is sent.
func TestSecretShapesNeverLeave(t *testing.T) {
	const tok = "TOPSECRETVALUE9f8e7d6c5b4a3"
	cases := []MCPServer{
		one("npx", "-y", "pkg@1.0.0", "--header=Authorization: Bearer "+tok),
		one("npx", "-y", "pkg@1.0.0", "-H", "Authorization: "+tok),
		one("npx", "-y", "pkg@1.0.0", "--url=https://user:"+tok+"@host.example/x"),
		one("npx", "-y", "pkg@1.0.0", "-u=https://h/x?api_key="+tok),
		one("npx", "-y", "pkg@1.0.0", "--x=Basic "+tok),
		one("npx", "-y", "pkg@1.0.0", "--note=prefix Bearer "+tok+" suffix"),
		one("/home/alice/bin/run-"+"server.sh", "--api-key", tok),
		one("npx", "-y", "git+https://user:"+tok+"@github.com/o/r.git"),
		one("npx", "-y", tok),
		one("npx", "-y", "pkg@"+tok),
		one("env OPENAI_API_KEY="+tok+" node", "s.js"),
		build("host.cursor", "r", "", nil, "https://user:"+tok+"@h.example:8443/p/"+tok+"?k="+tok+"#f", "", nil),
	}
	for i, c := range cases {
		b, _ := json.Marshal(c)
		if strings.Contains(string(b), tok) || strings.Contains(string(b), "user:") || strings.Contains(string(b), "alice") {
			t.Errorf("case %d leaks: %s", i, b)
		}
	}
	if c := cases[7]; c.Package != "git+https://github.com" || c.Version != "" {
		t.Errorf("git spec: %+v", c)
	}
	if c := cases[8]; c.Package != "" {
		t.Errorf("token as package must be dropped: %+v", c)
	}
	if c := cases[9]; c.Package != "pkg" || c.Version != "" {
		t.Errorf("token as version must be dropped: %+v", c)
	}
	if c := cases[6]; c.Command != "run-server.sh" || c.ArgCount != 2 {
		t.Errorf("command base only: %+v", c)
	}
	if c := cases[10]; c.Command != "" {
		t.Errorf("command string with an inline key must not be sent: %+v", c)
	}
	if c := cases[11]; c.URL != "https://h.example:8443" {
		t.Errorf("url: %+v", c)
	}
}

func TestOutsideHome(t *testing.T) {
	for args, want := range map[string]bool{"/": true, "/etc": true, "C:\\": true, "/home": true, "--root=/var/lib": true, "/home/a/work": false, "/Users/b/x": false, "rel/dir": false} {
		if got := outsideHome([]string{args}); got != want {
			t.Errorf("%q: got %v", args, got)
		}
	}
}

func TestParseCodexTOML(t *testing.T) {
	s := parseCodexTOML("host.codex-cli", []byte(`model = "x"
[mcp_servers.docs]
command = "npx"
args = ["-y", "@upstash/context7-mcp@1.0.0"]
[mcp_servers.docs.env]
CONTEXT7_KEY = "supersecret"
[mcp_servers.tricky]
command = "node"
env = { A = "token=abc123", B = "sk_live_x=1", "C=D" = "v" }
[mcp_servers.web]
url = "http://10.0.0.5:8080/mcp"
`))
	if len(s) != 3 {
		t.Fatalf("got %+v", s)
	}
	tr := find(t, s, "tricky")
	if strings.Join(tr.EnvKeys, ",") != "A,B" {
		t.Errorf("env keys must be plain names only: %v", tr.EnvKeys)
	}
	if b, _ := json.Marshal(tr); strings.Contains(string(b), "token") || strings.Contains(string(b), "sk_live") || strings.Contains(string(b), "abc123") {
		t.Errorf("quoted value fragments leaked: %s", b)
	}
	d := find(t, s, "docs")
	if d.Package != "@upstash/context7-mcp" || d.Version != "1.0.0" || strings.Join(d.EnvKeys, "") != "CONTEXT7_KEY" {
		t.Errorf("docs: %+v", d)
	}
	if w := find(t, s, "web"); w.Transport != "http" || w.URL != "http://10.0.0.5:8080" {
		t.Errorf("web: %+v", w)
	}
	if b, _ := json.Marshal(s); strings.Contains(string(b), "supersecret") {
		t.Error("env value leaked")
	}
}

func TestMCPServersPerAccountAndFailClosed(t *testing.T) {
	u := User{Name: "a", Home: "/home/a", UID: 1000, GID: 1000}
	found := []Found{{Spec: Spec{ID: "host.cursor", Key: "cursor"}, Users: []User{u}}}
	read := func(_ User, p string) ([]byte, bool) {
		if p == "/home/a/.cursor/mcp.json" {
			return []byte(cursorMCP), true
		}
		return nil, false
	}
	if got := MCPServers(found, "linux", read); len(got) != 5 {
		t.Fatalf("want 5, got %d", len(got))
	}
	if got := MCPServers(found, "linux", func(User, string) ([]byte, bool) { return nil, false }); len(got) != 0 {
		t.Fatal("unreadable file must report nothing")
	}
	if got := MCPServers(found, "linux", func(User, string) ([]byte, bool) { return []byte("{not json"), true }); len(got) != 0 {
		t.Fatal("malformed config must report nothing")
	}
}

func TestPackageOnlyFromKnownLaunchShapes(t *testing.T) {
	const tok = "TOPSECRETVALUE9f8e7d6c5b4a3"
	for _, c := range []struct {
		cmd      string
		args     []string
		pkg, ver string
	}{
		{"npx", []string{"--token", tok, "pkg"}, "", ""},            // unknown option that takes a value
		{"npx", []string{"--token=" + tok, "pkg"}, "", ""},          // same, joined with =
		{"npx", []string{"-y", "-p", "SECRET", "tool"}, "tool", ""}, // known option: its value is skipped
		{"uvx", []string{"--from", "SECRET", "pkg"}, "pkg", ""},
		{"uvx", []string{"--from", tok, "pkg"}, "pkg", ""},
		{"uvx", []string{"--weird", "pkg"}, "", ""},
		{"docker", []string{"run", "-e", "K=V", "img"}, "img", ""},
		{"docker", []string{"run", "-e", "K=V", "ghcr.io/o/img:1.2"}, "ghcr.io/o/img", "1.2"},
		{"docker", []string{"run", "--secret-flag", "x", "img"}, "", ""},
		{"docker", []string{"ps"}, "", ""},
		{"pnpm", []string{"install", "left-pad"}, "", ""},
		{"pnpm", []string{"dlx", "pkg@2.0.0"}, "pkg", "2.0.0"},
		{"npx", []string{"-y", "Not A Name"}, "", ""},
		{"npx", []string{"-y", "UPPER_case!"}, "", ""},
		{"npx", []string{"-y", strings.Repeat("a", 300)}, "", ""},
	} {
		pkg, ver := packageOf(c.cmd, c.args)
		if pkg != c.pkg || ver != c.ver {
			t.Errorf("%s %v: got (%q,%q) want (%q,%q)", c.cmd, c.args, pkg, ver, c.pkg, c.ver)
		}
		if strings.Contains(pkg+ver, tok) {
			t.Errorf("%s %v leaks", c.cmd, c.args)
		}
	}
}

// A `command` entry is what runs, whatever else the entry says: a url next to it cannot make the
// server look remote (and so "known").
func TestTransportFollowsTypeThenCommand(t *testing.T) {
	s := parseJSONServers("host.cursor", "mcpServers", []byte(`{"mcpServers":{
	 "a":{"command":"bash","args":["-c","curl x | sh"],"url":"https://mcp.notion.com/mcp"},
	 "b":{"type":"http","url":"https://mcp.notion.com/mcp","command":"bash"},
	 "c":{"type":"sse","url":"https://h.example/sse"},
	 "d":{"url":"https://mcp.notion.com/mcp"}}}`))
	a, b, c, d := find(t, s, "a"), find(t, s, "b"), find(t, s, "c"), find(t, s, "d")
	if a.Transport != "stdio" || a.URL != "" || a.Command != "bash" {
		t.Errorf("command + url must be stdio: %+v", a)
	}
	if b.Transport != "http" || b.URL != "https://mcp.notion.com" || b.Command != "bash" {
		t.Errorf("typed remote keeps its command facts: %+v", b)
	}
	if c.Transport != "sse" || d.Transport != "http" {
		t.Errorf("c=%+v d=%+v", c, d)
	}
}

func TestSameNameServersAreAllKeptInStableOrder(t *testing.T) {
	u := User{Name: "a", Home: "/home/a"}
	found := []Found{{Spec: Spec{ID: "host.claude-code", Key: "claude-code"}, Users: []User{u}}}
	cfg := `{"projects":{"/p1":{"mcpServers":{"db":{"command":"npx","args":["-y","a@1.0.0"]}}},
	 "/p2":{"mcpServers":{"db":{"command":"bash","args":["-c","x"]}}}}}`
	read := func(_ User, p string) ([]byte, bool) {
		if strings.HasSuffix(p, ".claude.json") {
			return []byte(cfg), true
		}
		return nil, false
	}
	first := MCPServers(found, "linux", read)
	if len(first) != 2 {
		t.Fatalf("want both db servers, got %+v", first)
	}
	for i := 0; i < 20; i++ {
		again, _ := json.Marshal(MCPServers(found, "linux", read))
		want, _ := json.Marshal(first)
		if string(again) != string(want) {
			t.Fatal("order changed between scans")
		}
	}
}
