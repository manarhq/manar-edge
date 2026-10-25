package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var testEdge = Edge{
	Address: "100.88.0.17/32", GatewayPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	GatewayEndpoint: "edge.manar.test:51820", ManarAddress: "100.88.0.1:443",
	ManarServerName: "agents.manar.test", ProxyAddress: "100.88.0.1:3128", KeepaliveSeconds: 25,
}

func TestEdgeName(t *testing.T) {
	if got := edgeName("acme", "soc-1"); got != "acme-soc-1" {
		t.Errorf("short: %q", got)
	}
	if got := edgeName("abcdefg", "1234567"); got != "abcdefg-1234567" { // exactly 15
		t.Errorf("15 chars: %q", got)
	}
	a := edgeName("contoso-bank", "incident-responder")
	b := edgeName("contoso-bank", "incident-reviewer")
	for _, n := range []string{a, b} {
		if len(n) > maxNameLen || !slugPattern.MatchString(n) {
			t.Errorf("long name %q: len %d", n, len(n))
		}
	}
	if a == b {
		t.Errorf("two long pairs with the same prefix collide: %q", a)
	}
	// The hash is of the pair, so a name ending in '-' before the hash is trimmed.
	if n := edgeName("abcdefghi", "-zzzzzzzzzz"); strings.Contains(n, "--") {
		t.Errorf("double dash in %q", n)
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
	if _, st, err := resolveAgent(base, "triage"); err != nil || st.Name != "acme-triage" {
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
	fi, err := os.Stat(filepath.Join(agentDir(base, "acme-triage"), fileState))
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

func TestFirewallScript(t *testing.T) {
	s := firewallScript("acme-soc-1", []string{`C:\Program Files\Agent\agent.exe`, `C:\it's\x.exe`}, allowedHosts(testEdge))
	for _, want := range []string{
		"Get-NetFirewallRule -Group 'Manar Edge acme-soc-1' -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
		"-Program 'C:\\Program Files\\Agent\\agent.exe'",
		"-Program 'C:\\it''s\\x.exe'",
		"'0.0.0.0-100.88.0.0','100.88.0.2-127.0.0.0','127.0.0.2-255.255.255.255','" + ipv6All + "'",
		"-Direction Outbound -Action Block",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Count(s, "New-NetFirewallRule") != 2 {
		t.Error("want one rule per program")
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
	env := agentEnv([]string{"PATH=/bin", "OPENAI_API_KEY=sk-real", "AWS_SECRET_ACCESS_KEY=x", "https_proxy=http://corp:8080", "SUDO_USER=bob", "LANG=C"}, "100.88.0.1:3128")
	joined := strings.Join(env, "\n")
	for _, bad := range []string{"sk-real", "AWS_SECRET", "corp:8080", "SUDO_USER"} {
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
