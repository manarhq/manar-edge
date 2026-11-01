package jail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const claude = "host.claude-code"

func TestPolicyPrecedence(t *testing.T) {
	p := NewPolicy()
	now := time.Now()
	p.now = func() time.Time { return now }
	p.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.121.3")}, nil
	}
	v := func(tool, h string) (Verdict, string) { return p.Decide(tool, h) }
	for _, h := range []string{"api.anthropic.com", "registry.npmjs.org", "pypi.org", "github.com", "api.github.com", "gitlab.com", "proxy.golang.org", "crates.io", "api.nuget.org", "rubygems.org", "repo.maven.apache.org"} {
		if got, why := v(claude, h); got != Allow || why != "builtin" {
			t.Errorf("%s: %v %s", h, got, why)
		}
	}
	if got, _ := v("host.codex-cli", "api.anthropic.com"); got != Ask {
		t.Error("another tool's provider must not be allowed")
	}
	for _, h := range []string{"evil.example", "anthropic.com.evil.example", "notgithub.com", "githubcom"} {
		if got, _ := v(claude, h); got != Ask {
			t.Errorf("%s should ask, got %v", h, got)
		}
	}
	// an address of an allowed code host (git over ssh)
	if got, _ := v(claude, "140.82.121.3"); got != Allow {
		t.Error("github address should be allowed")
	}
	if got, _ := v(claude, "203.0.113.5"); got != Ask {
		t.Error("unknown address should ask")
	}
	p.SetRules([]Rule{
		{Tool: claude, Site: "*.corp.example", Mode: "ALLOW"},
		{Tool: claude, Site: "bad.corp.example", Mode: "DENY"},
		{Tool: claude, Site: "old.example", Mode: "ALLOW", Expires: now.Add(-time.Second)},
		{Tool: claude, Site: "soon.example", Mode: "ALLOW", Expires: now.Add(time.Hour)},
		{Tool: claude, Site: "weird.example", Mode: "MAYBE"},
		{Tool: "host.codex-cli", Site: "codex-only.example", Mode: "ALLOW"},
	})
	cases := map[string]Verdict{"x.corp.example": Allow, "corp.example": Ask, "bad.corp.example": Deny, "old.example": Ask, "soon.example": Allow, "weird.example": Ask, "codex-only.example": Ask}
	for h, want := range cases {
		if got, _ := v(claude, h); got != want {
			t.Errorf("%s: got %v want %v", h, got, want)
		}
	}
	p.AllowFor(claude, "once.example", time.Minute)
	if got, why := v(claude, "once.example"); got != Allow || why != "once" {
		t.Error("once window")
	}
	now = now.Add(2 * time.Minute)
	if got, _ := v(claude, "once.example"); got != Ask {
		t.Error("once window must end")
	}
	p.DenyFor(claude, "no.example", time.Minute)
	if got, _ := v(claude, "no.example"); got != Deny {
		t.Error("refused window")
	}
	// a DENY rule beats the built-in list
	p.SetRules([]Rule{{Tool: claude, Site: "github.com", Mode: "DENY"}})
	if got, _ := v(claude, "github.com"); got != Deny {
		t.Error("deny beats built-in")
	}
}

type fakeAsker struct {
	calls atomic.Int32
	res   Result
	err   error
	block bool
}

func (f *fakeAsker) Ask(ctx context.Context, tool, site string) (Result, error) {
	f.calls.Add(1)
	if f.block {
		<-ctx.Done()
		return Result{}, ctx.Err()
	}
	time.Sleep(50 * time.Millisecond)
	return f.res, f.err
}

// echo listens and echoes lines prefixed with the name it was reached as.
func startEcho(t *testing.T, cfg *tls.Config) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		ln = tls.NewListener(ln, cfg)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

type env struct {
	p        *Proxy
	addr     string
	dialed   chan string
	askCalls *fakeAsker
}

func startProxy(t *testing.T, upstream net.Listener, ask *fakeAsker, rules []Rule, resolved ...string) *env {
	t.Helper()
	pol := NewPolicy()
	pol.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no dns in tests") }
	pol.SetRules(rules)
	dialed := make(chan string, 16)
	var addrs []netip.Addr
	for _, r := range resolved {
		addrs = append(addrs, netip.MustParseAddr(r))
	}
	p := &Proxy{
		Tool: claude, Policy: pol, Asker: ask, AskWait: 300 * time.Millisecond,
		OrigDst: func(net.Conn) (netip.AddrPort, error) { return netip.MustParseAddrPort("198.51.100.7:443"), nil },
		Resolve: func(context.Context, string) ([]netip.Addr, error) { return addrs, nil },
		Dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
			dialed <- addr
			return (&net.Dialer{}).DialContext(ctx, "tcp", upstream.Addr().String())
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return &env{p: p, addr: ln.Addr().String(), dialed: dialed, askCalls: ask}
}

func selfSigned(t *testing.T) *tls.Config {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
}

func tlsEcho(t *testing.T, addr, sni string) (string, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return "", err
	}
	b := make([]byte, 4)
	_, err = io.ReadFull(c, b)
	return string(b), err
}

func TestTLSAllowedByBuiltinPassesThroughAndDialsTheName(t *testing.T) {
	e := startProxy(t, startEcho(t, selfSigned(t)), &fakeAsker{}, nil, "160.79.104.10")
	got, err := tlsEcho(t, e.addr, "api.anthropic.com")
	if err != nil || got != "ping" {
		t.Fatalf("%q %v", got, err)
	}
	// it dialed the name's own address, not the 198.51.100.7 the client meant (no fronting)
	if d := <-e.dialed; d != "160.79.104.10:443" {
		t.Fatalf("dialed %s", d)
	}
	if e.askCalls.calls.Load() != 0 {
		t.Fatal("a built-in site must not be asked about")
	}
}

func TestTLSNewSiteAsksOncePerHostAndAllowOnceCoversTheBurst(t *testing.T) {
	ask := &fakeAsker{res: Result{Allow: true}}
	e := startProxy(t, startEcho(t, selfSigned(t)), ask, nil, "203.0.113.9")
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := tlsEcho(t, e.addr, "new.example"); err != nil || got != "ping" {
				t.Errorf("%q %v", got, err)
			}
		}()
	}
	wg.Wait()
	if n := ask.calls.Load(); n != 1 {
		t.Fatalf("asked %d times", n)
	}
	if _, err := tlsEcho(t, e.addr, "new.example"); err != nil || ask.calls.Load() != 1 {
		t.Fatal("the next connection inside the window must not ask again")
	}
}

func TestDenyAndNoAnswerCloseTheConnection(t *testing.T) {
	deny := &fakeAsker{res: Result{Reason: "denied"}}
	e := startProxy(t, startEcho(t, selfSigned(t)), deny, nil, "203.0.113.9")
	if _, err := tlsEcho(t, e.addr, "no.example"); err == nil {
		t.Fatal("denied site connected")
	}
	if _, err := tlsEcho(t, e.addr, "no.example"); err == nil || deny.calls.Load() != 1 {
		t.Fatalf("a refusal must be remembered for a minute (asked %d)", deny.calls.Load())
	}
	silent := &fakeAsker{block: true}
	e2 := startProxy(t, startEcho(t, selfSigned(t)), silent, nil, "203.0.113.9")
	start := time.Now()
	if _, err := tlsEcho(t, e2.addr, "silent.example"); err == nil {
		t.Fatal("no answer must deny")
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Fatal("did not wait for the answer")
	}
	// the API being unreachable is a refusal too
	broken := &fakeAsker{err: errors.New("offline")}
	e3 := startProxy(t, startEcho(t, selfSigned(t)), broken, nil, "203.0.113.9")
	if _, err := tlsEcho(t, e3.addr, "offline.example"); err == nil {
		t.Fatal("offline must deny")
	}
}

func TestRememberedAlwaysIsNotAskedAgain(t *testing.T) {
	ask := &fakeAsker{res: Result{Allow: true, Remember: -1}}
	e := startProxy(t, startEcho(t, selfSigned(t)), ask, nil, "203.0.113.9")
	for range 3 {
		if _, err := tlsEcho(t, e.addr, "always.example"); err != nil {
			t.Fatal(err)
		}
	}
	if ask.calls.Load() != 1 {
		t.Fatalf("asked %d", ask.calls.Load())
	}
}

func TestDenyRuleNeverAsks(t *testing.T) {
	ask := &fakeAsker{res: Result{Allow: true}}
	e := startProxy(t, startEcho(t, selfSigned(t)), ask, []Rule{{Tool: claude, Site: "*.blocked.example", Mode: "DENY"}}, "203.0.113.9")
	if _, err := tlsEcho(t, e.addr, "a.blocked.example"); err == nil || ask.calls.Load() != 0 {
		t.Fatal("deny rule must refuse without a prompt")
	}
}

func TestPrivateAndLocalAddressesByName(t *testing.T) {
	up := startEcho(t, selfSigned(t))
	// built-in site resolving to a private address: refused
	e := startProxy(t, up, &fakeAsker{}, nil, "10.1.2.3")
	if _, err := tlsEcho(t, e.addr, "api.anthropic.com"); err == nil {
		t.Fatal("rebinding to a private address must be refused")
	}
	// a person's rule may reach the LAN
	e = startProxy(t, up, &fakeAsker{}, []Rule{{Tool: claude, Site: "nas.home.example", Mode: "ALLOW"}}, "10.1.2.3")
	if _, err := tlsEcho(t, e.addr, "nas.home.example"); err != nil {
		t.Fatal(err)
	}
	// but never loopback or the metadata address
	for _, a := range []string{"127.0.0.1", "169.254.169.254"} {
		e = startProxy(t, up, &fakeAsker{}, []Rule{{Tool: claude, Site: "x.example", Mode: "ALLOW"}}, a)
		if _, err := tlsEcho(t, e.addr, "x.example"); err == nil {
			t.Fatalf("%s must be refused", a)
		}
	}
}

func httpGet(t *testing.T, addr, host string) string {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(400 * time.Millisecond)) // the echo upstream never closes
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	b, _ := io.ReadAll(c)
	return string(b)
}

func TestHTTPHostHeader(t *testing.T) {
	ask := &fakeAsker{res: Result{Reason: "denied"}}
	e := startProxy(t, startEcho(t, nil), ask, nil, "203.0.113.9")
	if got := httpGet(t, e.addr, "registry.npmjs.org:80"); !strings.HasPrefix(got, "GET / HTTP/1.1") {
		t.Fatalf("allowed request not forwarded intact: %q", got)
	}
	if got := httpGet(t, e.addr, "other.example"); !strings.HasPrefix(got, "HTTP/1.1 403") || !strings.Contains(got, "X-Manar-Reason: denied") {
		t.Fatalf("denied request: %q", got)
	}
}

func TestUnknownProtocolIsAskedAboutAsTheAddress(t *testing.T) {
	ask := &fakeAsker{res: Result{Reason: "denied"}}
	e := startProxy(t, startEcho(t, nil), ask, nil)
	c, _ := net.Dial("tcp", e.addr)
	defer c.Close()
	io.WriteString(c, "SSH-2.0-test\r\n")
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(c); err != nil && !strings.Contains(err.Error(), "reset") {
		t.Fatal(err)
	}
	if ask.calls.Load() != 1 {
		t.Fatal("an address with no name must be asked about")
	}
}

func TestHTTPHostParsing(t *testing.T) {
	cases := map[string]string{
		"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n":                          "example.com",
		"GET / HTTP/1.1\r\nhost: [::1]:80\r\n\r\n":                                  "::1",
		"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n":                                  "",
		"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n":                                     "",
		"SSH-2.0-OpenSSH_9\r\n":                                                     "",
		"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n": "",
		"GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n":           "",
		"OPTIONS * HTTP/1.1\r\nHost: x.example\r\n\r\n":                             "",
	}
	for in, want := range cases {
		if got := httpHost([]byte(in)); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}
