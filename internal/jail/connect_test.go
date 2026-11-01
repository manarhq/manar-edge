package jail

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func startConnect(t *testing.T, up net.Listener, ask *fakeAsker, rules []Rule, resolved ...string) (*Proxy, string) {
	t.Helper()
	e := startProxy(t, up, ask, rules, resolved...) // reuses the setup; its transparent listener is unused
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.p.ServeConnect(ln)
	t.Cleanup(func() { ln.Close() })
	return e.p, ln.Addr().String()
}

// connectTLS asks the proxy for a tunnel to host:443 and then speaks TLS through it.
func connectTLS(t *testing.T, proxy, host string) (string, error) {
	c, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		return "", err
	}
	if res.StatusCode != 200 {
		return res.Status + " " + res.Header.Get("X-Manar-Reason"), fmt.Errorf("refused")
	}
	tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if _, err := tc.Write([]byte("ping")); err != nil {
		return "", err
	}
	b := make([]byte, 4)
	_, err = io.ReadFull(tc, b)
	return string(b), err
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestConnectProxyTunnelsAllowedAndAsksForNew(t *testing.T) {
	ask := &fakeAsker{res: Result{Reason: "denied"}}
	_, addr := startConnect(t, startEcho(t, selfSigned(t)), ask, nil, "160.79.104.10")
	if got, err := connectTLS(t, addr, "api.anthropic.com"); err != nil || got != "ping" {
		t.Fatalf("%q %v", got, err)
	}
	if ask.calls.Load() != 0 {
		t.Fatal("built-in site asked")
	}
	if got, err := connectTLS(t, addr, "new.example"); err == nil || !strings.Contains(got, "403") || !strings.Contains(got, "denied") {
		t.Fatalf("new site: %q %v", got, err)
	}
	if ask.calls.Load() != 1 {
		t.Fatalf("asked %d", ask.calls.Load())
	}
	allow := &fakeAsker{res: Result{Allow: true}}
	_, addr = startConnect(t, startEcho(t, selfSigned(t)), allow, nil, "203.0.113.9")
	if got, err := connectTLS(t, addr, "ok.example"); err != nil || got != "ping" {
		t.Fatalf("asked and allowed: %q %v", got, err)
	}
}

func TestConnectProxyRefusals(t *testing.T) {
	up := startEcho(t, selfSigned(t))
	_, addr := startConnect(t, up, &fakeAsker{}, []Rule{{Tool: claude, Site: "bad.example", Mode: "DENY"}}, "203.0.113.9")
	if got, err := connectTLS(t, addr, "bad.example"); err == nil || !strings.Contains(got, "403") {
		t.Fatalf("deny rule: %q %v", got, err)
	}
	for _, target := range []string{"127.0.0.1:445", "169.254.169.254:80", "[::1]:22"} {
		c, _ := net.Dial("tcp", addr)
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		c.SetDeadline(time.Now().Add(3 * time.Second))
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
		if err != nil || res.StatusCode == 200 {
			t.Errorf("%s was tunnelled: %v %v", target, res, err)
		}
	}
	// plain http through the proxy, and a malformed host
	for _, req := range []string{"GET http://x.example/ HTTP/1.1\r\nHost: x.example\r\n\r\n", "CONNECT bad host:443 HTTP/1.1\r\n\r\n", "CONNECT x.example:99999 HTTP/1.1\r\nHost: x.example:99999\r\n\r\n"} {
		c, _ := net.Dial("tcp", addr)
		io.WriteString(c, req)
		c.SetDeadline(time.Now().Add(3 * time.Second))
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
		if err == nil && res.StatusCode == 200 {
			t.Errorf("%q accepted", req)
		}
	}
}

func TestConnectProxyKeepsBytesSentRightAfterTheRequest(t *testing.T) {
	up := startEcho(t, nil) // plain echo
	_, addr := startConnect(t, up, &fakeAsker{}, nil, "160.79.104.10")
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\nhello-early")
	br := bufio.NewReader(c)
	if res, err := http.ReadResponse(br, nil); err != nil || res.StatusCode != 200 {
		t.Fatalf("%v %v", res, err)
	}
	b := make([]byte, len("hello-early"))
	if _, err := io.ReadFull(br, b); err != nil || string(b) != "hello-early" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestChallengeRejectsAnImpostor(t *testing.T) {
	_, addr := startConnect(t, startEcho(t, nil), &fakeAsker{}, nil)
	if err := Challenge(addr); err != nil {
		t.Fatalf("our proxy failed its own challenge: %v", err)
	}
	// a squatter that answers 200 without the proof
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Manar-Jail-Proof: deadbeef\r\n\r\n")
			c.Close()
		}
	}()
	if Challenge(ln.Addr().String()) == nil {
		t.Fatal("an impostor passed")
	}
	// a replayed proof for another nonce
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln2.Close()
	old := proof("an-earlier-nonce")
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Manar-Jail-Proof: %s\r\n\r\n", old)
			c.Close()
		}
	}()
	if Challenge(ln2.Addr().String()) == nil {
		t.Fatal("a replayed proof passed")
	}
	if Challenge("127.0.0.1:1") == nil {
		t.Fatal("nothing listening passed")
	}
}
