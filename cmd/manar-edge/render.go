package main

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// overlayTargets returns the overlay endpoints a jailed agent may reach: Manar's relay and the
// egress proxy, as host:port pairs parsed from the enrollment response.
func overlayTargets(e Edge) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, a := range []string{e.ManarAddress, e.ProxyAddress} {
		ap, err := netip.ParseAddrPort(a)
		if err != nil || !ap.Addr().Is4() {
			return nil, fmt.Errorf("overlay address %q must be IPv4 host:port", a)
		}
		if !slices.Contains(out, ap) {
			out = append(out, ap)
		}
	}
	return out, nil
}

// jailRuleset is the nftables ruleset inside the agent's netns: loopback and the overlay
// endpoints only, everything else (IPv6 included) dropped. It replaces any previous version in
// one transaction.
func jailRuleset(targets []netip.AddrPort) string {
	var b strings.Builder
	b.WriteString("table inet manar_jail\ndelete table inet manar_jail\ntable inet manar_jail {\n")
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority filter; policy drop;\n")
	b.WriteString("\t\toif \"lo\" accept\n")
	for _, t := range targets {
		fmt.Fprintf(&b, "\t\toif \"manar0\" ip daddr %s tcp dport %d accept\n", t.Addr(), t.Port())
	}
	b.WriteString("\t\tcounter drop\n\t}\n}\n")
	return b.String()
}

// rootRuleset is the root-namespace table: any socket owned by a jailed agent's user is dropped
// on output, so the user cannot reach anything when started outside its netns. Agents are
// elements of the agent_uids set; the table is created once and never re-applied.
const rootRuleset = `table inet manar_edge {
	set agent_uids {
		typeof meta skuid
	}
	chain output {
		type filter hook output priority filter; policy accept;
		meta skuid @agent_uids counter drop
	}
}
`

func rootElement(op string, uid int) []string {
	return []string{op, "element", "inet", "manar_edge", "agent_uids", "{ " + strconv.Itoa(uid) + " }"}
}

// complementRanges returns the IPv4 ranges that cover every address except allowed, as
// "a-b" (or "a" for a single address) strings for Windows firewall rules.
func complementRanges(allowed []netip.Addr) []string {
	var ips []netip.Addr
	for _, a := range allowed {
		a = a.Unmap()
		if a.Is4() && !slices.Contains(ips, a) {
			ips = append(ips, a)
		}
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	rng := func(a, b netip.Addr) string {
		if a == b {
			return a.String()
		}
		return a.String() + "-" + b.String()
	}
	var out []string
	cur := netip.IPv4Unspecified()
	for _, a := range ips {
		if !cur.IsValid() {
			break
		}
		if cur.Less(a) {
			out = append(out, rng(cur, a.Prev()))
		}
		cur = a.Next() // invalid after 255.255.255.255
	}
	if cur.IsValid() {
		out = append(out, rng(cur, netip.AddrFrom4([4]byte{255, 255, 255, 255})))
	}
	return out
}

const ipv6All = "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

func fwGroup(name string) string { return "Manar Edge " + name }

// psQuote makes a PowerShell single-quoted literal. PowerShell also treats U+2018 to U+201B as
// single quotes, so each of those is doubled as well.
func psQuote(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		b.WriteRune(r)
		switch r {
		case '\'', '\u2018', '\u2019', '\u201a', '\u201b':
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// complementPorts returns the port ranges 1-65535 without the given ports.
func complementPorts(ports []uint16) []string {
	ps := slices.Clone(ports)
	slices.Sort(ps)
	ps = slices.Compact(ps)
	var out []string
	next := 1
	add := func(a, b int) {
		if a == b {
			out = append(out, strconv.Itoa(a))
		} else if a < b {
			out = append(out, strconv.Itoa(a)+"-"+strconv.Itoa(b))
		}
	}
	for _, p := range ps {
		if int(p) >= next {
			add(next, int(p)-1)
			next = int(p) + 1
		}
	}
	add(next, 65535)
	return out
}

func psList(items []string) string {
	q := make([]string, len(items))
	for i, it := range items {
		q[i] = psQuote(it)
	}
	return "@(" + strings.Join(q, ",") + ")"
}

// firewallScript renders the PowerShell that replaces the agent's rule group. For each program:
// block every protocol to every address except the allowed ones, and all of IPv6; block TCP to
// an allowed address on any port it is not allowed on; block UDP to the allowed addresses.
func firewallScript(name string, programs []string, allowed map[netip.Addr][]uint16) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	fmt.Fprintf(&b, "Get-NetFirewallRule -Group %s -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n", psQuote(fwGroup(name)))
	addrs := slices.Collect(maps.Keys(allowed))
	slices.SortFunc(addrs, netip.Addr.Compare)
	var addrStrs []string
	for _, a := range addrs {
		addrStrs = append(addrStrs, a.String())
	}
	rule := func(i int, kind, extra string, p string) {
		fmt.Fprintf(&b, "New-NetFirewallRule -DisplayName %s -Group %s -Direction Outbound -Action Block -Profile Any -Program %s %s | Out-Null\n",
			psQuote(fmt.Sprintf("%s %d %s", fwGroup(name), i, kind)), psQuote(fwGroup(name)), psQuote(p), extra)
	}
	for i, p := range programs {
		rule(i+1, "other addresses", "-RemoteAddress "+psList(append(complementRanges(addrs), ipv6All)), p)
		for _, a := range addrs {
			rule(i+1, "tcp "+a.String(), "-Protocol TCP -RemoteAddress "+psQuote(a.String())+" -RemotePort "+psList(complementPorts(allowed[a])), p)
		}
		rule(i+1, "udp", "-Protocol UDP -RemoteAddress "+psList(addrStrs), p)
	}
	return b.String()
}

// allowedTCP is what a confined Windows program may still reach: the local gateway, Manar's
// relay and the egress proxy, each on its own TCP port only.
func allowedTCP(e Edge) map[netip.Addr][]uint16 {
	out := map[netip.Addr][]uint16{netip.MustParseAddr("127.0.0.1"): {8480}}
	for _, a := range []string{e.ManarAddress, e.ProxyAddress} {
		if ap, err := netip.ParseAddrPort(a); err == nil {
			out[ap.Addr()] = append(out[ap.Addr()], ap.Port())
		}
	}
	return out
}

// wgConfig renders a WireGuard for Windows tunnel config. No DNS line: the tunnel sets no resolver.
func wgConfig(privateKey string, e Edge, targets []netip.AddrPort) string {
	var allowed []string
	for _, t := range targets {
		p := netip.PrefixFrom(t.Addr(), 32).String()
		if !slices.Contains(allowed, p) {
			allowed = append(allowed, p)
		}
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = %d\n",
		privateKey, e.Address, e.GatewayPublicKey, strings.Join(allowed, ", "), e.GatewayEndpoint, e.KeepaliveSeconds)
}
