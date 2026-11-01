// Package jail is JAIL on a personal device: an egress filter for the processes of protected AI
// tools. Their connections are redirected to a local proxy (proxy.go) that reads the destination
// name from the TLS SNI or the HTTP Host header and asks the policy (policy.go). A new site raises a
// WARDEN prompt (ask.go). The user's own programs are never touched: the OS layer (enforce_*.go)
// selects only the tools' processes.
package jail

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/gateway"
)

// Verdict is what the policy says about one site for one tool.
type Verdict int

const (
	Allow Verdict = iota
	Ask
	Deny
)

// Rule is a remembered decision for one tool: an exact host, "*.suffix" or an IP literal. A zero
// Expires means always.
type Rule struct {
	Tool    string    `json:"toolId"`
	Site    string    `json:"site"`
	Allow   bool      `json:"-"`
	Mode    string    `json:"mode"` // ALLOW or DENY, as the API sends it
	Expires time.Time `json:"expiresAt"`
}

// providers are each tool's own AI provider; registries and code hosts are common to all tools
// (brief section 2).
var providers = map[string][]string{
	"host.claude-code": {"anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai", "claude.com", "*.claude.com"},
	"host.codex-cli":   {"openai.com", "*.openai.com", "chatgpt.com", "*.chatgpt.com"},
	"host.gemini-cli": {"generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com", "oauth2.googleapis.com",
		"www.googleapis.com", "aiplatform.googleapis.com", "*.aiplatform.googleapis.com", "accounts.google.com"},
	"host.copilot-cli": {"githubcopilot.com", "*.githubcopilot.com", "copilot-proxy.githubusercontent.com",
		"copilot-telemetry.githubusercontent.com", "api.github.com"},
}

var common = []string{
	// package registries: npm, PyPI, crates.io, Go proxy, Maven, NuGet, RubyGems
	"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
	"crates.io", "index.crates.io", "static.crates.io", "proxy.golang.org", "sum.golang.org",
	"repo.maven.apache.org", "repo1.maven.org", "api.nuget.org", "globalcdn.nuget.org",
	"rubygems.org", "index.rubygems.org", "*.rubygems.org",
	// code hosts
	"github.com", "*.github.com", "*.githubusercontent.com", "gitlab.com", "*.gitlab.com",
}

// Builtin is the allow list a tool has before anyone is asked.
func Builtin(tool string) []string {
	return append(append([]string(nil), providers[tool]...), common...)
}

// Tools is every tool id JAIL can filter on a device.
func Tools() []string {
	return []string{"host.claude-code", "host.codex-cli", "host.gemini-cli", "host.copilot-cli"}
}

type key struct{ tool, host string }

// Policy decides. Precedence: a live DENY rule, then a live ALLOW rule or a short "allow once"
// window, then the built-in list, then Ask. Safe for concurrent use.
type Policy struct {
	mu    sync.Mutex
	rules []Rule
	temp  map[key]tempEntry // "once" windows and short refusals
	now   func() time.Time

	// lookup resolves the built-in exact names, to recognise an IP literal of an allowed site
	// (git over ssh connects to an address, not a name).
	lookup   func(ctx context.Context, name string) ([]netip.Addr, error)
	addrs    map[string]addrSet
	addrTTL  time.Duration
	addrLast time.Time
}

type tempEntry struct {
	allow bool
	until time.Time
}

type addrSet map[netip.Addr]bool

// NewPolicy returns a policy with no rules.
func NewPolicy() *Policy {
	return &Policy{
		temp: map[key]tempEntry{}, now: time.Now, addrTTL: 5 * time.Minute,
		lookup: func(ctx context.Context, name string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		},
	}
}

// SetRules replaces the remembered rules with the API's list.
func (p *Policy) SetRules(rules []Rule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = p.rules[:0:0]
	for _, r := range rules {
		if r.Mode != "ALLOW" && r.Mode != "DENY" {
			continue // a mode we do not know says nothing
		}
		r.Site = strings.ToLower(r.Site)
		r.Allow = r.Mode == "ALLOW"
		p.rules = append(p.rules, r)
	}
}

// AddRule remembers a decision until the next SetRules.
func (p *Policy) AddRule(r Rule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r.Site = strings.ToLower(r.Site)
	p.rules = append(p.rules, r)
}

// AllowFor lets tool reach host for d without asking again (an "allow once" answer covers the
// connections the page or command opens next, not one TCP stream).
func (p *Policy) AllowFor(tool, host string, d time.Duration) { p.setTemp(tool, host, true, d) }

// DenyFor refuses tool/host for d, so a retrying agent does not raise a prompt every second.
func (p *Policy) DenyFor(tool, host string, d time.Duration) { p.setTemp(tool, host, false, d) }

func (p *Policy) setTemp(tool, host string, allow bool, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.temp[key{tool, strings.ToLower(host)}] = tempEntry{allow, p.now().Add(d)}
}

// Decide returns the verdict and where it came from ("rule", "once", "builtin", "new_site",
// "refused").
func (p *Policy) Decide(tool, host string) (Verdict, string) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	p.mu.Lock()
	now := p.now()
	var allowRule, denyRule bool
	for _, r := range p.rules {
		if r.Tool != tool || (!r.Expires.IsZero() && !r.Expires.After(now)) {
			continue
		}
		if _, ok := gateway.HostAllowed([]string{r.Site}, host); !ok {
			continue
		}
		if r.Allow {
			allowRule = true
		} else {
			denyRule = true
		}
	}
	t, hasTemp := p.temp[key{tool, host}]
	if hasTemp && !t.until.After(now) {
		delete(p.temp, key{tool, host})
		hasTemp = false
	}
	p.mu.Unlock()
	switch {
	case denyRule:
		return Deny, "rule"
	case allowRule:
		return Allow, "rule"
	case hasTemp && t.allow:
		return Allow, "once"
	case hasTemp:
		return Deny, "refused"
	}
	if _, ok := gateway.HostAllowed(Builtin(tool), host); ok {
		return Allow, "builtin"
	}
	return Ask, "new_site"
}

// IsUserRule reports whether host is allowed by a person's rule (not the built-in list): only then
// may a name resolve to a private address.
func (p *Policy) IsUserRule(tool, host string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for _, r := range p.rules {
		if r.Tool == tool && r.Allow && (r.Expires.IsZero() || r.Expires.After(now)) {
			if _, ok := gateway.HostAllowed([]string{r.Site}, host); ok {
				return true
			}
		}
	}
	return false
}

// sshHosts are the code hosts whose addresses are theirs alone (not a CDN shared with other
// sites), so a connection to one of those addresses that shows no name (git over ssh) can be
// recognised. Registries are never allowed by address: npm, PyPI and the Go proxy sit behind shared
// CDNs, where an address says nothing about the site.
var sshHosts = []string{"github.com", "ssh.github.com", "gitlab.com", "altssh.gitlab.com"}

// AllowedAddr reports whether ip is an address of github.com or gitlab.com. The proxy uses it only
// for a protocol that shows no name (ssh); a TLS connection without a name, an ECH hello or an odd
// HTTP request is asked about instead.
func (p *Policy) AllowedAddr(tool string, ip netip.Addr) bool {
	p.mu.Lock()
	stale := p.addrs == nil || p.now().Sub(p.addrLast) > p.addrTTL
	p.mu.Unlock()
	if stale {
		set := addrSet{}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, n := range sshHosts {
			if as, err := p.lookup(ctx, n); err == nil {
				for _, a := range as {
					set[a.Unmap()] = true
				}
			}
		}
		p.mu.Lock()
		p.addrs, p.addrLast = map[string]addrSet{"": set}, p.now()
		p.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addrs[""][ip.Unmap()]
}
