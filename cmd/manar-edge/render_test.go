package main

import (
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var testEdge = Edge{
	Address: "100.88.0.17/32", GatewayPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	GatewayEndpoint: "edge.manar.test:51820", ManarAddress: "100.88.0.1:443",
	ManarServerName: "agents.manar.test", ProxyAddress: "100.88.0.1:3128", KeepaliveSeconds: 25,
}

func TestEdgeName(t *testing.T) {
	pairs := [][2]string{{"acme", "soc-1"}, {"a-b", "c"}, {"a", "b-c"}, {"contoso-bank", "incident-responder"},
		{"contoso-bank", "incident-reviewer"}, {"abcdefghi", "zzzzzzzzzz"}}
	seen := map[string]bool{}
	for _, p := range pairs {
		n := edgeName(p[0], p[1])
		if len(n) > maxNameLen || !slugPattern.MatchString(n) || strings.Contains(n, "--") {
			t.Errorf("%v: bad name %q", p, n)
		}
		if seen[n] {
			t.Errorf("%v: collides on %q", p, n)
		}
		seen[n] = true
		if edgeName(p[0], p[1]) != n {
			t.Error("not stable")
		}
	}
	if n := edgeName("acme", "soc-1"); !strings.HasPrefix(n, "acme-s-") || len(n) != 15 {
		t.Errorf("short pair: %q", n)
	}
}

func TestResolveAgent(t *testing.T) {
	base := t.TempDir()
	for _, p := range [][2]string{{"acme", "soc-1"}, {"globex", "soc-1"}, {"acme", "triage"}} {
		dir := agentDir(base, edgeName(p[0], p[1]))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := saveState(dir, &State{Name: edgeName(p[0], p[1]), TenantSlug: p[0], AgentSlug: p[1]}); err != nil {
			t.Fatal(err)
		}
	}
	if _, st, err := resolveAgent(base, "triage"); err != nil || st.Name != edgeName("acme", "triage") {
		t.Errorf("slug: %v %v", st, err)
	}
	if _, st, err := resolveAgent(base, "globex/soc-1"); err != nil || st.TenantSlug != "globex" {
		t.Errorf("pair: %v %v", st, err)
	}
	if _, _, err := resolveAgent(base, "soc-1"); err == nil {
		t.Error("ambiguous slug resolved")
	}
	if _, _, err := resolveAgent(base, "nope"); err == nil {
		t.Error("unknown agent resolved")
	}
	fi, err := os.Stat(filepath.Join(agentDir(base, edgeName("acme", "triage")), fileState))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("state.json mode %v %v", fi.Mode(), err)
	}
}

func TestJailRuleset(t *testing.T) {
	targets, err := overlayTargets(testEdge)
	if err != nil {
		t.Fatal(err)
	}
	want := `table inet manar_jail
delete table inet manar_jail
table inet manar_jail {
	chain output {
		type filter hook output priority filter; policy drop;
		oif "lo" accept
		oif "manar0" ip daddr 100.88.0.1 tcp dport 443 accept
		oif "manar0" ip daddr 100.88.0.1 tcp dport 3128 accept
		counter drop
	}
}
`
	if got := jailRuleset(targets); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if _, err := overlayTargets(Edge{ManarAddress: "[::1]:443", ProxyAddress: "100.88.0.1:3128"}); err == nil {
		t.Error("IPv6 overlay accepted")
	}
}

func TestRootRuleset(t *testing.T) {
	for _, s := range []string{"table inet manar_edge", "typeof meta skuid", "hook output", "policy accept", "meta skuid @agent_uids counter drop"} {
		if !strings.Contains(rootRuleset, s) {
			t.Errorf("root ruleset lacks %q", s)
		}
	}
	if got := strings.Join(rootElement("add", 998), " "); got != "add element inet manar_edge agent_uids { 998 }" {
		t.Errorf("element: %q", got)
	}
}

func TestComplementRanges(t *testing.T) {
	ip := netip.MustParseAddr
	got := complementRanges([]netip.Addr{ip("127.0.0.1"), ip("100.88.0.1"), ip("100.88.0.1")})
	want := []string{"0.0.0.0-100.88.0.0", "100.88.0.2-127.0.0.0", "127.0.0.2-255.255.255.255"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	if got := complementRanges([]netip.Addr{ip("0.0.0.0"), ip("255.255.255.255")}); !slices.Equal(got, []string{"0.0.0.1-255.255.255.254"}) {
		t.Errorf("edges: %v", got)
	}
	if got := complementRanges([]netip.Addr{ip("10.0.0.1"), ip("10.0.0.3")}); !slices.Contains(got, "10.0.0.2") {
		t.Errorf("single address gap: %v", got)
	}
	if got := complementRanges(nil); !slices.Equal(got, []string{"0.0.0.0-255.255.255.255"}) {
		t.Errorf("none allowed: %v", got)
	}
}

func TestComplementPorts(t *testing.T) {
	if got := complementPorts([]uint16{3128, 443, 443}); !slices.Equal(got, []string{"1-442", "444-3127", "3129-65535"}) {
		t.Errorf("got %v", got)
	}
	if got := complementPorts([]uint16{1, 2, 65535}); !slices.Equal(got, []string{"3-65534"}) {
		t.Errorf("edges: %v", got)
	}
	if got := complementPorts([]uint16{8480}); !slices.Equal(got, []string{"1-8479", "8481-65535"}) {
		t.Errorf("8480: %v", got)
	}
}

func TestPSQuote(t *testing.T) {
	for in, want := range map[string]string{
		`C:\x`:           `'C:\x'`,
		"it's":           "'it''s'",
		"a\u2018b":       "'a\u2018\u2018b'",
		"a\u201bb":       "'a\u201b\u201bb'",
		"\u2019;x\u201a": "'\u2019\u2019;x\u201a\u201a'",
	} {
		if got := psQuote(in); got != want {
			t.Errorf("psQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirewallScripts(t *testing.T) {
	progs := []string{`C:\Program Files\Agent\agent.exe`, `C:\it's\x.exe`}
	scripts := firewallScripts("acme-soc-1", progs, allowedTCP(testEdge))
	if len(scripts) != 1+len(progs) {
		t.Fatalf("%d scripts, want removal plus one per program", len(scripts))
	}
	if !strings.Contains(scripts[0], "Get-NetFirewallRule -Group 'Manar Edge acme-soc-1' -ErrorAction SilentlyContinue | Remove-NetFirewallRule") {
		t.Errorf("removal: %s", scripts[0])
	}
	s := strings.Join(scripts, "")
	for _, want := range []string{
		"-Program 'C:\\Program Files\\Agent\\agent.exe'",
		"-Program 'C:\\it''s\\x.exe'",
		"-RemoteAddress @('0.0.0.0-100.88.0.0','100.88.0.2-127.0.0.0','127.0.0.2-255.255.255.255','" + ipv6All + "')",
		"-Protocol TCP -RemoteAddress '100.88.0.1' -RemotePort @('1-442','444-3127','3129-65535')",
		"-Protocol TCP -RemoteAddress '127.0.0.1' -RemotePort @('1-8479','8481-65535')",
		"-Protocol UDP -RemoteAddress @('100.88.0.1','127.0.0.1')",
		"-Direction Outbound -Action Block",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("scripts lack %q:\n%s", want, s)
		}
	}
	per := rulesPerProgram(allowedTCP(testEdge))
	if n := strings.Count(s, "New-NetFirewallRule"); n != per*len(progs) || per != 4 {
		t.Errorf("%d rules (%d per program), want 4 per program", n, per)
	}
	// Each per-program command stays well under the Windows command line limit once encoded.
	for _, sc := range scripts {
		if l := len(psEncode(sc)); l > 16000 {
			t.Errorf("encoded script of %d characters", l)
		}
	}
}

func TestCheckRulePrograms(t *testing.T) {
	progs := []string{`C:\Programme\Agént\a.exe`, `C:\b.exe`}
	good := strings.Repeat(progs[0]+"\r\n", 4) + strings.Repeat(strings.ToUpper(progs[1])+"\n", 4)
	if err := checkRulePrograms(good, progs, 4); err != nil {
		t.Errorf("good read-back refused: %v", err)
	}
	mangled := strings.Repeat(`C:\Programme\AgÃ©nt\a.exe`+"\n", 4) + strings.Repeat(progs[1]+"\n", 4)
	if checkRulePrograms(mangled, progs, 4) == nil {
		t.Error("mangled path accepted")
	}
	if checkRulePrograms(good+"C:\\other.exe\n", progs, 4) == nil {
		t.Error("extra rule accepted")
	}
	if checkRulePrograms(strings.Repeat(progs[0]+"\n", 4), progs, 4) == nil {
		t.Error("missing program accepted")
	}
}

func TestPSEncode(t *testing.T) {
	// "é" is U+00E9: UTF-16LE e9 00.
	if got := psEncode("é'"); got != base64.StdEncoding.EncodeToString([]byte{0xe9, 0, '\'', 0}) {
		t.Errorf("psEncode = %q", got)
	}
}

func TestPipeSDDL(t *testing.T) {
	// Users must not get FILE_APPEND_DATA (0x4), the right to create a pipe instance, nor any
	// generic right (which would include it).
	for _, ace := range strings.Split(pipeSDDL, "(")[1:] {
		f := strings.Split(strings.TrimSuffix(ace, ")"), ";")
		if f[5] == "SY" {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || mask&0x4 != 0 || mask&0xf0000000 != 0 {
			t.Errorf("ACE %q grants instance creation or a generic right", ace)
		}
	}
	if !strings.HasPrefix(pipeSDDL, "D:P") {
		t.Error("DACL not protected")
	}
}

func TestWGConfig(t *testing.T) {
	targets, _ := overlayTargets(testEdge)
	c := wgConfig("PRIVATE", testEdge, targets)
	for _, want := range []string{"Address = 100.88.0.17/32", "AllowedIPs = 100.88.0.1/32\n", "Endpoint = edge.manar.test:51820", "PersistentKeepalive = 25"} {
		if !strings.Contains(c, want) {
			t.Errorf("config lacks %q", want)
		}
	}
	if strings.Contains(c, "DNS") {
		t.Error("config sets DNS")
	}
}

func TestAgentEnv(t *testing.T) {
	env := agentEnv([]string{"PATH=/bin", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1/bus", "SSH_AUTH_SOCK=/tmp/s", "XDG_RUNTIME_DIR=/run/user/1", "OPENAI_API_KEY=sk-real", "AWS_SECRET_ACCESS_KEY=x", "https_proxy=http://corp:8080", "SUDO_USER=bob", "LANG=C"}, "100.88.0.1:3128")
	joined := strings.Join(env, "\n")
	for _, bad := range []string{"sk-real", "AWS_SECRET", "corp:8080", "SUDO_USER", "DBUS_", "SSH_AUTH", "XDG_RUNTIME"} {
		if strings.Contains(joined, bad) {
			t.Errorf("leaked %q", bad)
		}
	}
	for _, want := range []string{"PATH=/bin", "LANG=C", "OPENAI_BASE_URL=http://127.0.0.1:8480/v1", "ANTHROPIC_BASE_URL=http://127.0.0.1:8480",
		"MANAR_MCP_URL=http://127.0.0.1:8480/mcp", "HTTPS_PROXY=http://100.88.0.1:3128", "NO_PROXY=127.0.0.1,localhost", "OPENAI_API_KEY=manar"} {
		if !slices.Contains(env, want) {
			t.Errorf("missing %q", want)
		}
	}
	if got := setEnv([]string{"HOME=/root", "A=1"}, "HOME=/nonexistent"); !slices.Equal(got, []string{"A=1", "HOME=/nonexistent"}) {
		t.Errorf("setEnv: %v", got)
	}
}
