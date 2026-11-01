package jail

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// The CONNECT proxy is JAIL on Windows. There is no transparent redirect there, so the tool is
// pointed at this proxy through its own settings (HTTPS_PROXY) and the OS blocks everything else
// for the tool's exe (wfp_windows.go). The proxy sees only the host name and port of each
// tunnel: the TLS inside stays between the tool and the site. It is portable so it is tested on
// Linux too.

const (
	healthPath   = "/__manar_jail_health"
	challengeHdr = "X-Manar-Jail-Challenge"
	proofHdr     = "X-Manar-Jail-Proof"
)

// proofKey is a random per-process secret. Only this process can answer a health challenge, so a
// program that grabbed the proxy port while the service was down cannot pass for the proxy.
var proofKey = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("jail: no randomness: " + err.Error())
	}
	return k
}()

func proof(nonce string) string {
	m := hmac.New(sha256.New, proofKey)
	m.Write([]byte(nonce))
	return hex.EncodeToString(m.Sum(nil))
}

// Challenge asks whatever listens on addr to prove it is this process's proxy: a fresh nonce must
// come back signed. A squatter, or a proxy of an earlier run, fails.
func Challenge(addr string) error {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	n := hex.EncodeToString(nonce)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+healthPath, nil)
	req.Header.Set(challengeHdr, n)
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	res, err := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return fmt.Errorf("the proxy does not answer: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || !hmac.Equal([]byte(res.Header.Get(proofHdr)), []byte(proof(n))) {
		return fmt.Errorf("something other than Manar's proxy answers on %s", addr)
	}
	return nil
}

// ServeConnect accepts proxy connections until ln is closed.
func (p *Proxy) ServeConnect(ln net.Listener) error {
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
				p.handleConnect(c)
			}()
		default:
			c.Close()
		}
	}
}

func (p *Proxy) handleConnect(c net.Conn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(io.LimitReader(c, maxHeader), 4<<10)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	reply := func(code int, reason string) {
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\nX-Manar-Reason: %s\r\n\r\n", code, http.StatusText(code), safeReason(reason))
	}
	if req.Method == http.MethodGet && req.URL.Path == healthPath {
		if n := req.Header.Get(challengeHdr); n != "" && len(n) <= 64 {
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n%s: %s\r\n\r\n", proofHdr, proof(n))
			return
		}
	}
	if req.Method != http.MethodConnect {
		// ponytail: plain http through the proxy is refused; tools reach their providers over https.
		reply(http.StatusMethodNotAllowed, "https_only")
		return
	}
	host, portStr, err := net.SplitHostPort(req.Host)
	port, perr := strconv.Atoi(portStr)
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if err != nil || perr != nil || port < 1 || port > 65535 || !validName(host) {
		reply(http.StatusBadRequest, "invalid_host")
		return
	}
	v, why := p.Policy.Decide(p.Tool, host)
	if v == Ask {
		if res := p.ask(host); res.Allow {
			v, why = Allow, "asked"
		} else {
			v, why = Deny, res.Reason
		}
	}
	if v != Allow {
		p.logf("jail: %s denied %s:%d (%s)", p.Tool, host, port, why)
		reply(http.StatusForbidden, why)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up, err := p.connect(ctx, host, netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)), "tls")
	if err != nil {
		p.logf("jail: %s %s:%d: %v", p.Tool, host, port, err)
		reply(http.StatusBadGateway, "connect_failed")
		return
	}
	defer up.Close()
	p.logf("jail: %s allowed %s:%d (%s)", p.Tool, host, port, why)
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	// The request reader limited what it read; anything the client sent after the CONNECT line
	// and headers is in br's buffer and must go upstream first.
	rest := io.MultiReader(io.LimitReader(br, int64(br.Buffered())), c)
	pipeRaw(c, rest, up)
}

// pipeRaw copies both ways until one side ends.
func pipeRaw(c net.Conn, in io.Reader, up net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, in)
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
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
}
