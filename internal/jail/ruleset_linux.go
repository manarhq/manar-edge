package jail

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
)

const (
	// cgParent is the cgroup (under the cgroup2 root) that holds one child per filtered tool.
	cgParent = "manar-jail"
	// nftTable is the nftables table JAIL owns in the root network namespace.
	nftTable = "manar_jail_tools"
)

// cgName is the cgroup directory name of a tool id: host.claude-code -> claude-code.
func cgName(tool string) string { return strings.TrimPrefix(tool, "host.") }

// readResolvers returns the nameserver addresses of a resolv.conf (zones stripped).
func readResolvers(path string) []netip.Addr {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		if a, err := netip.ParseAddr(strings.SplitN(f[1], "%", 2)[0]); err == nil && !a.IsUnspecified() {
			if a = a.Unmap(); !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

func addrSetText(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

// Ruleset builds the nftables ruleset. Only sockets created by processes in a tool's cgroup are
// matched, so every other program on the computer is outside it:
//
//   - nat output: TCP from a tool's cgroup, except to loopback and to the DNS servers in
//     resolv.conf, is redirected to that tool's proxy port (127.0.0.1 or ::1);
//   - filter output: a tool's sockets may reach loopback (that includes the proxy: after the
//     redirect the packet's destination is 127.0.0.1 although its output interface is still the
//     real one, so the address is what is matched) and port 53 of the configured DNS servers only;
//     the rest is rejected at once (UDP including QUIC, other protocols), so a tool fails fast and
//     falls back to TCP.
//
// The whole table is replaced in one transaction.
func Ruleset(ports map[string]int, resolvers []netip.Addr) string {
	tools := make([]string, 0, len(ports))
	for t := range ports {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	var v4, v6 []netip.Addr
	for _, a := range resolvers {
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %[1]s\ndelete table inet %[1]s\ntable inet %[1]s {\n", nftTable)
	b.WriteString("\tchain to_proxy {\n\t\ttype nat hook output priority -100; policy accept;\n")
	b.WriteString("\t\tip daddr 127.0.0.0/8 return\n\t\tip6 daddr ::1 return\n")
	if len(v4) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr { %s } tcp dport 53 return\n", addrSetText(v4))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "\t\tip6 daddr { %s } tcp dport 53 return\n", addrSetText(v6))
	}
	for _, t := range tools {
		fmt.Fprintf(&b, "\t\tsocket cgroupv2 level 2 \"%s/%s\" meta l4proto tcp redirect to :%d\n", cgParent, cgName(t), ports[t])
	}
	b.WriteString("\t}\n\tchain egress {\n\t\ttype filter hook output priority 0; policy accept;\n")
	for _, t := range tools {
		fmt.Fprintf(&b, "\t\tsocket cgroupv2 level 2 \"%s/%s\" jump jailed\n", cgParent, cgName(t))
	}
	b.WriteString("\t}\n\tchain jailed {\n\t\tip daddr 127.0.0.0/8 accept\n\t\tip6 daddr ::1 accept\n")
	if len(v4) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr { %s } udp dport 53 accept\n\t\tip daddr { %[1]s } tcp dport 53 accept\n", addrSetText(v4))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "\t\tip6 daddr { %s } udp dport 53 accept\n\t\tip6 daddr { %[1]s } tcp dport 53 accept\n", addrSetText(v6))
	}
	b.WriteString("\t\tmeta l4proto tcp reject with tcp reset\n\t\treject\n\t}\n}\n")
	return b.String()
}

// matcher says which processes belong to a tool.
type matcher struct {
	comm []string // /proc/<pid>/comm equals one of these
	cmd  []string // argv[1] or argv[2] of a node-like runtime has this base name or contains pkg
	pkg  []string // package path segments such as @anthropic-ai/claude-code/
}

// matchers are narrow on purpose: a generic runtime name (node, python, code) is never enough,
// so the user's own scripts and editors are not caught. IDE agents and desktop apps are not
// filtered at launch (their own backends need many hosts).
var matchers = map[string]matcher{
	"host.claude-code": {comm: []string{"claude"}, cmd: []string{"claude"}, pkg: []string{"@anthropic-ai/claude-code/"}},
	"host.codex-cli":   {comm: []string{"codex"}, cmd: []string{"codex"}, pkg: []string{"@openai/codex/"}},
	"host.gemini-cli":  {comm: []string{"gemini"}, cmd: []string{"gemini"}, pkg: []string{"@google/gemini-cli/"}},
	"host.copilot-cli": {comm: []string{"copilot"}, cmd: []string{"copilot"}, pkg: []string{"@github/copilot/"}},
}

var runtimes = []string{"node", "nodejs", "bun", "deno"}

// matchProc returns the tool a process belongs to among want, or "". argv is the process's
// command line (may be nil when comm already decides).
func matchProc(comm string, argv func() []string, want []string) string {
	for _, tool := range want {
		m, ok := matchers[tool]
		if !ok {
			continue
		}
		if slices.Contains(m.comm, comm) {
			return tool
		}
		if !slices.Contains(runtimes, comm) {
			continue
		}
		a := argv()
		for i := 1; i < len(a) && i <= 3; i++ {
			if strings.HasPrefix(a[i], "-") {
				continue
			}
			base := a[i][strings.LastIndex(a[i], "/")+1:]
			if slices.Contains(m.cmd, base) {
				return tool
			}
			for _, p := range m.pkg {
				if strings.Contains(a[i], "node_modules/"+p) {
					return tool
				}
			}
			break // the first non-flag argument is the script
		}
	}
	return ""
}
