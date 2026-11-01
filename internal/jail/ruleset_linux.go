package jail

import (
	"fmt"
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

// Ruleset builds the nftables ruleset. Only sockets created by processes in a tool's cgroup are
// matched, so every other program on the computer is outside it:
//
//   - nat output: TCP from a tool's cgroup, except to loopback and DNS, is redirected to that
//     tool's proxy port (127.0.0.1 or ::1);
//   - filter output: a tool's sockets may reach loopback and DNS, nothing else; the rest is
//     rejected at once (UDP including QUIC, other protocols), so a tool fails fast and falls back
//     to TCP.
//
// The whole table is replaced in one transaction.
func Ruleset(ports map[string]int) string {
	tools := make([]string, 0, len(ports))
	for t := range ports {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %[1]s\ndelete table inet %[1]s\ntable inet %[1]s {\n", nftTable)
	b.WriteString("\tchain to_proxy {\n\t\ttype nat hook output priority -100; policy accept;\n")
	b.WriteString("\t\tip daddr 127.0.0.0/8 return\n\t\tip6 daddr ::1 return\n\t\ttcp dport 53 return\n")
	for _, t := range tools {
		fmt.Fprintf(&b, "\t\tsocket cgroupv2 level 2 \"%s/%s\" meta l4proto tcp redirect to :%d\n", cgParent, cgName(t), ports[t])
	}
	b.WriteString("\t}\n\tchain egress {\n\t\ttype filter hook output priority 0; policy accept;\n")
	for _, t := range tools {
		fmt.Fprintf(&b, "\t\tsocket cgroupv2 level 2 \"%s/%s\" jump jailed\n", cgParent, cgName(t))
	}
	b.WriteString("\t}\n\tchain jailed {\n\t\toifname \"lo\" accept\n\t\tudp dport 53 accept\n\t\ttcp dport 53 accept\n")
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
