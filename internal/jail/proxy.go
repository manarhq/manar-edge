package jail

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"gitlab.vax.sh/manar/manar-edge/internal/telemetry"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/gateway"
)

// Proxy is the transparent proxy for one tool. The OS layer redirects the tool's TCP connections
// to it; it reads the destination name from the first bytes (TLS SNI or HTTP Host), asks Policy,
// raises a prompt for a new site and, when allowed, connects to the NAME it resolved itself, so a
// client cannot name one site and be sent to another address.
type Proxy struct {
	Tool   string
	Policy *Policy
	Asker  Asker
	// OrigDst returns where the client meant to connect (SO_ORIGINAL_DST on Linux).
	OrigDst func(c net.Conn) (netip.AddrPort, error)
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Log     func(format string, args ...any)

	// AskWait is how long a prompt waits for a person (2 minutes); sniffWait how long we wait for
	// the client's first bytes.
	AskWait   time.Duration
	sniffWait time.Duration

	mu     sync.Mutex
	asking map[string]*pending // one prompt per host, however many connections wait
}

type pending struct {
	done chan struct{}
	res  Result
}

// Result is a person's answer.
type Result struct {
	Allow bool
	// Remember is how long the answer holds: 0 means a short window for this action only, a
	// negative value means always.
	Remember time.Duration
	Reason   string
}

const (
	onceWindow    = 60 * time.Second
	refusedWindow = 60 * time.Second
	maxHeader     = 8 << 10
	maxConns      = 2048
)

// Serve accepts until ln is closed.
func (p *Proxy) Serve(ln net.Listener) error {
	sem := make(chan struct{}, maxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				p.handle(c)
			}()
		default:
			c.Close() // a flood must not exhaust the service
		}
	}
}

func (p *Proxy) logf(f string, a ...any) {
	if p.Log != nil {
		p.Log(f, a...)
	}
}

func (p *Proxy) handle(c net.Conn) {
	defer c.Close()
	dst, err := p.OrigDst(c)
	if err != nil {
		return // not a redirected connection: nothing to decide
	}
	sniff := p.sniffWait
	if sniff == 0 {
		sniff = 5 * time.Second
	}
	br := bufio.NewReaderSize(c, 16<<10)
	c.SetReadDeadline(time.Now().Add(sniff))
	host, replay, kind := p.classify(br, dst)
	c.SetReadDeadline(time.Time{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port := dst.Port()
	t0 := time.Now()
	v, why := p.Policy.Decide(p.Tool, host)
	recordDecision(p.Tool, host, v, time.Since(t0))
	if v == Ask && kind == "other" && port == 22 {
		if a, err := netip.ParseAddr(host); err == nil && p.Policy.AllowedAddr(p.Tool, a) {
			v, why = Allow, "builtin"
		}
	}
	if v == Ask {
		res := p.ask(host)
		if res.Allow {
			v, why = Allow, "asked"
		} else {
			v, why = Deny, res.Reason
		}
	}
	if v != Allow {
		p.logf("jail: %s denied %s:%d (%s)", p.Tool, host, port, why)
		if kind == "http" {
			io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\nX-Manar-Reason: "+safeReason(why)+"\r\n\r\n")
		}
		return
	}
	up, err := p.connect(ctx, host, dst, kind)
	if err != nil {
		p.logf("jail: %s %s:%d: %v", p.Tool, host, port, err)
		return
	}
	defer up.Close()
	p.logf("jail: %s allowed %s:%d (%s)", p.Tool, host, port, why)
	if kind == "http" {
		// Plain HTTP shows its site in every request, so every request is checked: a second
		// request on the same connection cannot name another site.
		relayHTTP(c, br, up, host)
		return
	}
	if len(replay) > 0 {
		if _, err := up.Write(replay); err != nil {
			return
		}
	}
	pipe(c, br, up)
}

func safeReason(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, s)
}

// connect dials the upstream. A host that is a name is resolved here; an IP literal (no name was
// visible: ssh, ECH, a bare address) goes to the address the client asked for.
func (p *Proxy) connect(ctx context.Context, host string, dst netip.AddrPort, kind string) (net.Conn, error) {
	dial := p.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second}
		dial = d.DialContext
	}
	if a, err := netip.ParseAddr(host); err == nil {
		// The proxy may run with more rights than the tool (root, SYSTEM): it never connects on
		// the tool's behalf to this computer's own services or the metadata address.
		if a = a.Unmap(); a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
			return nil, fmt.Errorf("refused: %s is a local address", a)
		}
		return dial(ctx, "tcp", netip.AddrPortFrom(a, dst.Port()).String())
	}
	resolve := p.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := resolve(rctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("dns failed")
	}
	userRule := p.Policy.IsUserRule(p.Tool, host)
	var ok []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		// Loopback, link-local (cloud metadata) and the like are never reachable by name. A
		// private LAN address is, but only for a site a person allowed by hand.
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
			return nil, fmt.Errorf("refused: %s resolves to a local address", host)
		}
		if gateway.Blocked(a, netip.Prefix{}) && !userRule {
			return nil, fmt.Errorf("refused: %s resolves to a private address", host)
		}
		ok = append(ok, a)
	}
	var last error
	for _, a := range ok {
		c, err := dial(ctx, "tcp", netip.AddrPortFrom(a, dst.Port()).String())
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// classify finds the site name from the client's first bytes. replay is what must be sent
// upstream first (bytes already consumed from br); kind is "tls", "http" or "other".
func (p *Proxy) classify(br *bufio.Reader, dst netip.AddrPort) (host string, replay []byte, kind string) {
	fallback := dst.Addr().Unmap().String()
	first, err := br.Peek(1)
	if err != nil {
		return fallback, nil, "other"
	}
	switch {
	case first[0] == 0x16: // TLS handshake record
		sni, ech, raw, err := gateway.PeekHello(br)
		if err != nil {
			return fallback, raw, "tls"
		}
		sni = strings.ToLower(strings.TrimSuffix(sni, "."))
		// With ECH the SNI is a cover name; without any SNI there is no name: both are asked
		// about as the address.
		if ech || sni == "" || !validName(sni) {
			return fallback, raw, "tls"
		}
		return sni, raw, "tls"
	case first[0] >= 'A' && first[0] <= 'Z':
		head := peekHeader(br)
		if h := httpHost(head); h != "" {
			return h, nil, "http"
		}
		return fallback, nil, "other"
	}
	return fallback, nil, "other"
}

// peekHeader returns the buffered start of the stream up to the end of the HTTP header, without
// consuming it.
func peekHeader(br *bufio.Reader) []byte {
	n := 1
	for {
		b, err := br.Peek(n)
		if bytes.Contains(b, []byte("\r\n\r\n")) || len(b) >= maxHeader || err != nil {
			return b
		}
		// A first line that is not an HTTP request line (ssh, smtp, ...) needs no more bytes.
		if i := bytes.Index(b, []byte("\r\n")); i >= 0 {
			if f := strings.Fields(string(b[:i])); len(f) != 3 || !strings.HasPrefix(f[2], "HTTP/") {
				return b
			}
		}
		if br.Buffered() > len(b) {
			n = br.Buffered()
		} else {
			n = len(b) + 1
		}
		if n > maxHeader {
			n = maxHeader
		}
	}
}

func httpHost(head []byte) string {
	lines := strings.Split(string(head), "\r\n")
	if len(lines) < 2 {
		return ""
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return ""
	}
	// A request to a forward proxy (CONNECT host:443, GET http://host/...) is addressed to the
	// proxy, not to the site in it: the site is then the address the client connected to.
	if parts[0] == "CONNECT" || !strings.HasPrefix(parts[1], "/") {
		return ""
	}
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "host") {
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if h, _, err := net.SplitHostPort(v); err == nil {
			v = h
		}
		v = strings.TrimSuffix(strings.Trim(v, "[]"), ".")
		if validName(v) {
			return v
		}
		return ""
	}
	return ""
}

func validName(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

// ask raises one prompt per host however many connections wait for it, then applies the answer.
func (p *Proxy) ask(host string) Result {
	p.mu.Lock()
	if p.asking == nil {
		p.asking = map[string]*pending{}
	}
	if w, ok := p.asking[host]; ok {
		p.mu.Unlock()
		<-w.done
		return w.res
	}
	w := &pending{done: make(chan struct{})}
	p.asking[host] = w
	p.mu.Unlock()

	wait := p.AskWait
	if wait == 0 {
		wait = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	res, err := p.Asker.Ask(ctx, p.Tool, host)
	timedOut := ctx.Err() != nil
	cancel()
	switch {
	case err != nil && timedOut:
		res = Result{Reason: "denied_no_answer"}
	case err != nil:
		res = Result{Reason: "denied_no_decision"} // fail closed: the API could not be asked
	}
	switch {
	case res.Allow && res.Remember < 0:
		p.Policy.AddRule(Rule{Tool: p.Tool, Site: host, Allow: true, Mode: "ALLOW"})
	case res.Allow && res.Remember > 0:
		p.Policy.AddRule(Rule{Tool: p.Tool, Site: host, Allow: true, Mode: "ALLOW", Expires: time.Now().Add(res.Remember)})
	case res.Allow:
		p.Policy.AllowFor(p.Tool, host, onceWindow)
	default:
		p.Policy.DenyFor(p.Tool, host, refusedWindow)
		if res.Reason == "" {
			res.Reason = "denied"
		}
	}
	w.res = res
	p.mu.Lock()
	delete(p.asking, host)
	p.mu.Unlock()
	close(w.done)
	return res
}

// pipe copies both ways until one side ends. br may hold bytes already read from c.
func pipe(c net.Conn, br *bufio.Reader, up net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, br)
		if t, ok := up.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(c, up)
		if t, ok := c.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	// One direction ended: give the other a moment to drain, then cut both.
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
}

// relayHTTP forwards plain HTTP request by request. Anything but an ordinary request for host
// (another Host, an absolute URL, CONNECT, an upgrade) ends the connection.
func relayHTTP(c net.Conn, br *bufio.Reader, up net.Conn, host string) {
	upBr := bufio.NewReader(up)
	deny := func(why string) {
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\nX-Manar-Reason: "+why+"\r\n\r\n")
	}
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		h := strings.ToLower(strings.TrimSuffix(req.Host, "."))
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = strings.Trim(hh, "[]")
		}
		if req.Method == http.MethodConnect || !strings.HasPrefix(req.RequestURI, "/") || h != host || req.Header.Get("Upgrade") != "" {
			deny("another_site")
			return
		}
		if err := req.Write(up); err != nil {
			return
		}
		resp, err := http.ReadResponse(upBr, req)
		if err != nil {
			return
		}
		err = resp.Write(c)
		resp.Body.Close()
		if err != nil || req.Close || resp.Close {
			return
		}
	}
}

// recordDecision hands a JAIL check to telemetry (non-blocking; a no-op while it is off).
func recordDecision(tool, host string, v Verdict, took time.Duration) {
	d := map[Verdict]string{Allow: "allow", Ask: "ask", Deny: "block"}[v]
	if d != "" {
		telemetry.Record("jail", tool, d, "domain", host, took)
	}
}
