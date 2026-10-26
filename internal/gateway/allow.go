// Package gateway is the Manar edge gateway: the WireGuard server agents reach Manar through, the
// relay to manar-api's agent listener and the hostname-filtered egress proxy (docs/design.md, 3).
package gateway

import (
	"net/netip"
	"strings"
)

// HostAllowed reports whether host matches one of the peer's allow rules: an exact name, or
// "*.suffix" for one label or more in front of suffix (never suffix itself). Case-insensitive.
// It returns the matching rule.
func HostAllowed(rules []string, host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", false
	}
	for _, r := range rules {
		rule := strings.ToLower(r)
		if suffix, ok := strings.CutPrefix(rule, "*."); ok {
			if suffix != "" && strings.HasSuffix(host, "."+suffix) {
				return r, true
			}
			continue
		}
		if rule == host {
			return r, true
		}
	}
	return "", false
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, includes the default overlay
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"), // reserved and broadcast
	// IPv6 forms that embed an IPv4 address the checks above would not see.
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// Blocked reports whether the proxy must refuse to dial a: private, loopback, link-local,
// multicast, unspecified, CGNAT, reserved or the overlay itself. IPv4-mapped IPv6 is unmapped
// first.
func Blocked(a netip.Addr, overlay netip.Prefix) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() ||
		a.IsUnspecified() || overlay.Contains(a) {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
