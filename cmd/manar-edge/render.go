package main

import (
	"fmt"
	"net"
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

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// firewallScript renders the PowerShell that replaces the agent's rule group: per program, block
// outbound to everything except the allowed IPv4 addresses, and all of IPv6.
func firewallScript(name string, programs []string, allowed []netip.Addr) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	fmt.Fprintf(&b, "Get-NetFirewallRule -Group %s -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n", psQuote(fwGroup(name)))
	var q []string
	for _, r := range append(complementRanges(allowed), ipv6All) {
		q = append(q, psQuote(r))
	}
	ranges := "@(" + strings.Join(q, ",") + ")"
	for i, p := range programs {
		fmt.Fprintf(&b, "New-NetFirewallRule -DisplayName %s -Group %s -Direction Outbound -Action Block -Profile Any -Program %s -RemoteAddress %s | Out-Null\n",
			psQuote(fmt.Sprintf("%s %d", fwGroup(name), i+1)), psQuote(fwGroup(name)), psQuote(p), ranges)
	}
	return b.String()
}

// allowedHosts are the addresses a covered program may still reach on Windows.
func allowedHosts(e Edge) []netip.Addr {
	out := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	for _, a := range []string{e.ManarAddress, e.ProxyAddress} {
		h, _, _ := net.SplitHostPort(a)
		if ip, err := netip.ParseAddr(h); err == nil {
			out = append(out, ip)
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
