package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// The tests use 127.0.0.0/8 as the overlay: the gateway is 127.0.0.1, the peer 127.0.0.2 and a
// stranger 127.0.0.3, so peer identity by source address is exercised on real sockets.
var (
	testOverlay = netip.MustParsePrefix("127.0.0.0/8")
	peerIP      = net.ParseIP("127.0.0.2")
	strangerIP  = net.ParseIP("127.0.0.3")
)

func testRegistry(t *testing.T, allow ...string) *Registry {
	reg := NewRegistry(testOverlay, discard)
	reg.Apply(PeerSet{Full: true, Peers: []Peer{{ID: "p1", PublicKey: newKey(t), Address: "127.0.0.2/32",
		State: "active", AllowHosts: allow}}})
	return reg
}

func listen(t *testing.T, serve func(net.Listener) error) string {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serve(ln)
	return ln.Addr().String()
}

func dialFrom(t *testing.T, src net.IP, addr string) net.Conn {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: src}, Timeout: 5 * time.Second}
	c, err := d.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

type proxyEnv struct {
	addr    string
	proxy   *Proxy
	pool    *x509.CertPool
	dialed  chan string
	resolve map[string][]netip.Addr
}

// newProxyEnv starts an upstream TLS server for example.com (httptest's certificate) and a proxy
// whose resolver answers from env.resolve and whose dialer reaches that upstream.
func newProxyEnv(t *testing.T, allow ...string) *proxyEnv {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from upstream")
	}))
	t.Cleanup(up.Close)
	env := &proxyEnv{pool: x509.NewCertPool(), dialed: make(chan string, 10), resolve: map[string][]netip.Addr{
		"example.com": {netip.MustParseAddr("203.0.113.7")},
	}}
	env.pool.AddCert(up.Certificate())
	env.proxy = &Proxy{
		Registry: testRegistry(t, allow...), Metrics: &Metrics{}, Log: discard, Ports: []int{443},
		Events:  &Events{Max: 100, Metrics: &Metrics{}},
		Overlay: netip.MustParsePrefix("100.88.0.0/16"),
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			if a, ok := env.resolve[host]; ok {
				return a, nil
			}
			return nil, fmt.Errorf("no such host %s", host)
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			env.dialed <- addr
			var d net.Dialer
			return d.DialContext(ctx, network, up.Listener.Addr().String())
		},
	}
	env.addr = listen(t, env.proxy.Serve)
	return env
}

func connect(t *testing.T, c net.Conn, target string) *http.Response {
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("CONNECT %s: %v", target, err)
	}
	return resp
}

func (e *proxyEnv) events(t *testing.T, n int) []Event {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		e.proxy.Events.mu.Lock()
		q := append([]Event(nil), e.proxy.Events.q...)
		e.proxy.Events.mu.Unlock()
		if len(q) >= n {
			return q
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d events", n)
	return nil
}

func TestProxyAllowedReplaysClientHello(t *testing.T) {
	env := newProxyEnv(t, "Example.com")
	c := dialFrom(t, peerIP, env.addr)
	if resp := connect(t, c, "EXAMPLE.com:443"); resp.StatusCode != 200 {
		t.Fatalf("CONNECT status %d", resp.StatusCode)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "example.com", RootCAs: env.pool})
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	body, err := io.ReadAll(tc)
	if err != nil || !strings.Contains(string(body), "hello from upstream") {
		t.Fatalf("through the proxy: %v %q", err, body)
	}
	if got := <-env.dialed; got != "203.0.113.7:443" {
		t.Fatalf("dialed %s, want the resolved address", got)
	}
	ev := env.events(t, 1)[0]
	if ev.Decision != "allowed" || ev.PeerID != "p1" || ev.Host != "example.com" || ev.Port != 443 ||
		ev.BytesUp == 0 || ev.BytesDown == 0 {
		t.Fatalf("event %+v", ev)
	}
}

func TestProxyDenials(t *testing.T) {
	cases := []struct {
		name, target, sni string
		resolve           []netip.Addr
		status            int
		reason            string
	}{
		{"host not allowed", "evil.com:443", "", nil, 403, "host_not_allowed"},
		{"port not allowed", "example.com:8443", "", nil, 403, "port_not_allowed"},
		{"private address", "example.com:443", "", []netip.Addr{netip.MustParseAddr("10.0.0.5")}, 403, "private_address"},
		{"mapped private", "example.com:443", "", []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("::ffff:169.254.169.254")}, 403, "private_address"},
		{"sni mismatch", "example.com:443", "other.example.org", nil, 200, "sni_mismatch"},
		{"not tls", "example.com:443", "-", nil, 200, "sni_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newProxyEnv(t, "example.com")
			if tc.resolve != nil {
				env.resolve["example.com"] = tc.resolve
			}
			c := dialFrom(t, peerIP, env.addr)
			resp := connect(t, c, tc.target)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
			switch tc.sni {
			case "":
			case "-":
				fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
			default:
				cfg := &tls.Config{ServerName: tc.sni, RootCAs: env.pool}
				if err := tls.Client(c, cfg).Handshake(); err == nil {
					t.Fatal("handshake through a mismatched CONNECT succeeded")
				}
			}
			ev := env.events(t, 1)[0]
			if ev.Decision != "denied" || ev.Reason != tc.reason {
				t.Fatalf("event %+v, want denied %s", ev, tc.reason)
			}
			select {
			case a := <-env.dialed:
				t.Fatalf("dialed %s on a denial", a)
			default:
			}
		})
	}
}

func TestProxyRefusesStranger(t *testing.T) {
	env := newProxyEnv(t, "example.com")
	c := dialFrom(t, strangerIP, env.addr)
	fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("a non-peer got a response")
	}
	env.proxy.Events.mu.Lock()
	defer env.proxy.Events.mu.Unlock()
	if len(env.proxy.Events.q) != 0 {
		t.Fatal("a non-peer produced an event")
	}
}

func TestPeekSNI(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go tls.Client(a, &tls.Config{ServerName: "Graph.Microsoft.com"}).Handshake()
	sni, hello, err := peekSNI(b)
	if err != nil || sni != "Graph.Microsoft.com" || len(hello) < 5 || hello[0] != 0x16 {
		t.Fatalf("sni %q, %d bytes, err %v", sni, len(hello), err)
	}
	if _, _, err := peekSNI(strings.NewReader("GET / HTTP/1.1\r\n\r\n")); err == nil {
		t.Fatal("plain HTTP accepted as a ClientHello")
	}
}

func TestRelay(t *testing.T) {
	var mu sync.Mutex
	accepted := 0
	echo := listen(t, func(ln net.Listener) error {
		for {
			c, err := ln.Accept()
			if err != nil {
				return err
			}
			mu.Lock()
			accepted++
			mu.Unlock()
			go io.Copy(c, c)
		}
	})
	reg := testRegistry(t)
	m := &Metrics{}
	var d net.Dialer
	r := &Relay{Registry: reg, Upstream: echo, Dial: d.DialContext, Metrics: m, Log: discard}
	addr := listen(t, r.Serve)

	// A stranger is closed without reaching the upstream.
	s := dialFrom(t, strangerIP, addr)
	s.Write([]byte("hi"))
	if n, _ := s.Read(make([]byte, 2)); n != 0 {
		t.Fatal("stranger got bytes back")
	}
	if m.RelayRefused.Load() != 1 {
		t.Fatalf("refused = %d", m.RelayRefused.Load())
	}

	// The peer is relayed.
	c := dialFrom(t, peerIP, addr)
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("relay echo %q %v", buf, err)
	}
	mu.Lock()
	if accepted != 1 {
		t.Fatalf("upstream accepted %d connections, want 1", accepted)
	}
	mu.Unlock()

	// A cut closes the open relay connection.
	_, closers, cuts := reg.Apply(PeerSet{Full: true})
	for _, cl := range closers {
		cl.Close()
	}
	if cuts != 1 || len(closers) != 1 {
		t.Fatalf("cuts %d closers %d", cuts, len(closers))
	}
	if n, err := c.Read(buf); n != 0 || err == nil {
		t.Fatalf("connection still open after the cut: %d %v", n, err)
	}
}
