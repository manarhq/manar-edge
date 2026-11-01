package jail

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesetMatchesOnlyToolCgroups(t *testing.T) {
	r := Ruleset(map[string]int{"host.codex-cli": 4002, "host.claude-code": 4001}, []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fd00::1")})
	for _, want := range []string{
		"delete table inet manar_jail_tools",
		`socket cgroupv2 level 2 "manar-jail/claude-code" meta l4proto tcp redirect to :4001`,
		`socket cgroupv2 level 2 "manar-jail/codex-cli" meta l4proto tcp redirect to :4002`,
		`socket cgroupv2 level 2 "manar-jail/claude-code" jump jailed`,
		"ip daddr 127.0.0.0/8 return",
		"ip6 daddr ::1 return",
		"ip daddr { 192.168.1.1 } tcp dport 53 return",
		"ip6 daddr { fd00::1 } tcp dport 53 return",
		"ip daddr 127.0.0.0/8 accept",
		"ip6 daddr ::1 accept",
		"ip daddr { 192.168.1.1 } udp dport 53 accept",
		"ip6 daddr { fd00::1 } udp dport 53 accept",
		"meta l4proto tcp reject with tcp reset",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q in\n%s", want, r)
		}
	}
	// every rule that redirects or rejects is guarded by a cgroup match: nothing is unconditional
	for _, line := range strings.Split(r, "\n") {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "redirect to") && !strings.HasPrefix(l, "socket cgroupv2") {
			t.Errorf("unguarded redirect: %s", l)
		}
	}
	jailed := r[strings.Index(r, "chain jailed"):]
	if strings.Count(r, "chain ") != 3 || !strings.Contains(r, "chain jailed") || strings.Contains(r[:strings.Index(r, "chain jailed")], "reject") {
		t.Errorf("reject must live only in the chain only tools jump to:\n%s", jailed)
	}
	if !strings.Contains(Ruleset(nil, nil), "chain jailed") || strings.Contains(Ruleset(nil, nil), "cgroupv2") {
		t.Error("an empty set must match nothing")
	}
}

func TestMatchProc(t *testing.T) {
	all := Tools()
	argv := func(a ...string) func() []string { return func() []string { return a } }
	cases := []struct {
		name string
		comm string
		args []string
		want string
	}{
		{"native claude", "claude", nil, "host.claude-code"},
		{"codex", "codex", nil, "host.codex-cli"},
		{"node running the package", "node", []string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, "host.claude-code"},
		{"node via the bin shim", "node", []string{"node", "/usr/local/bin/gemini", "--yolo"}, "host.gemini-cli"},
		{"node with a flag first", "node", []string{"node", "--no-warnings", "/home/u/.npm/lib/node_modules/@github/copilot/index.js"}, "host.copilot-cli"},
		{"node running the user's server", "node", []string{"node", "/home/u/app/server.js"}, ""},
		{"npm installing the package", "node", []string{"node", "/usr/lib/node_modules/npm/bin/npm-cli.js", "i", "-g", "@anthropic-ai/claude-code"}, ""},
		{"the package name only as a later argument", "node", []string{"node", "/home/u/app.js", "@anthropic-ai/claude-code/x"}, ""},
		{"python", "python3", []string{"python3", "claude.py"}, ""},
		{"an editor", "code", nil, ""},
		{"curl", "curl", []string{"curl", "https://claude.ai"}, ""},
	}
	for _, c := range cases {
		if got := matchProc(c.comm, argv(c.args...), all); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	// a tool that is not wanted is not matched
	if got := matchProc("claude", argv(), []string{"host.codex-cli"}); got != "" {
		t.Errorf("unwanted tool matched: %s", got)
	}
}

func TestRulesetOpensDNSOnlyToTheConfiguredServers(t *testing.T) {
	r := Ruleset(map[string]int{claude: 4001}, nil)
	if strings.Contains(r, "dport 53") {
		t.Errorf("port 53 must not be open to every address:\n%s", r)
	}
	r = Ruleset(map[string]int{claude: 4001}, []netip.Addr{netip.MustParseAddr("10.0.0.2")})
	if strings.Count(r, "dport 53") != 3 { // tcp return in nat, udp and tcp accept in the filter
		t.Errorf("%s", r)
	}
}

func TestReadResolvers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(p, []byte("# comment\nsearch lan\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\nnameserver 0.0.0.0\nnameserver nonsense\nnameserver 127.0.0.53\n"), 0o644)
	got := readResolvers(p)
	if len(got) != 2 || got[0].String() != "127.0.0.53" || got[1].String() != "fe80::1" {
		t.Fatalf("%v", got)
	}
	if readResolvers(filepath.Join(t.TempDir(), "missing")) != nil {
		t.Fatal("a missing file has no resolvers")
	}
}
