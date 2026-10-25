package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Proxy is the HTTP CONNECT egress proxy. Every attempt from an active peer becomes an Event.
type Proxy struct {
	Registry *Registry
	Events   *Events
	Metrics  *Metrics
	Log      *slog.Logger
	Ports    []int        // CONNECT ports allowed
	Overlay  netip.Prefix // refused as a destination
	Resolve  func(ctx context.Context, host string) ([]netip.Addr, error)
	Dial     DialFunc
	Idle     time.Duration
	// DenyECH refuses ClientHellos carrying encrypted_client_hello. Off by default: GREASE ECH
	// from Chromium cannot be told apart from real ECH (docs/gateway.md).
	DenyECH bool
}

// Serve accepts until ln is closed.
func (p *Proxy) Serve(ln net.Listener) error { return serve(ln, p.handle) }

const (
	// handshakeTimeout bounds the CONNECT request, DNS, dial and ClientHello.
	handshakeTimeout = 15 * time.Second
	// maxRequest bounds the CONNECT line and headers.
	maxRequest = 8 << 10
	// maxHost is the longest DNS name.
	maxHost = 253
)

func (p *Proxy) handle(c net.Conn) {
	defer c.Close()
	start := time.Now()
	lease, err := p.Registry.Acquire(remoteAddr(c), c)
	if errors.Is(err, errTooMany) {
		p.Metrics.Decision("denied", "too_many_connections")
		p.Events.Add(Event{PeerID: lease.Peer.ID, At: start.UTC(), Decision: "denied", Reason: "too_many_connections"})
		return
	}
	if err != nil {
		p.Metrics.Decision("denied", "not_peer")
		return
	}
	defer lease.Release()
	c.SetDeadline(start.Add(handshakeTimeout))
	ctx, cancel := context.WithDeadline(lease.Ctx, start.Add(handshakeTimeout))
	defer cancel()

	ev := Event{PeerID: lease.Peer.ID, At: start.UTC()}
	deny := func(status int, reason string) {
		if status != 0 {
			fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\nX-Manar-Reason: %s\r\n\r\n",
				status, http.StatusText(status), reason)
		}
		ev.Decision, ev.Reason = "denied", reason
		ev.DurationMs = time.Since(start).Milliseconds()
		p.Metrics.Decision("denied", reason)
		p.Events.Add(ev)
	}
	// cut reports whether the peer was cut (or the host dropped from its list) meanwhile.
	cut := func() bool {
		if lease.Ctx.Err() != nil {
			deny(0, "peer_cut")
			return true
		}
		return false
	}

	lr := &io.LimitedReader{R: c, N: maxRequest}
	br := bufio.NewReader(lr)
	req, err := http.ReadRequest(br)
	if err != nil {
		deny(http.StatusBadRequest, "bad_request")
		return
	}
	if req.Method != http.MethodConnect {
		deny(http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	host, portStr, err := net.SplitHostPort(req.Host)
	port, perr := strconv.Atoi(portStr)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ev.Host, ev.Port = truncate(host, maxHost), port
	if err != nil || perr != nil || !validHost(host) {
		deny(http.StatusBadRequest, "invalid_host")
		return
	}
	if !slices.Contains(p.Ports, port) {
		deny(http.StatusForbidden, "port_not_allowed")
		return
	}
	if !lease.Allow(host) {
		if !cut() {
			deny(http.StatusForbidden, "host_not_allowed")
		}
		return
	}
	addrs, err := p.Resolve(ctx, host)
	if cut() {
		return
	}
	if err != nil || len(addrs) == 0 {
		deny(http.StatusBadGateway, "dns_failed")
		return
	}
	// Any private answer refuses the host: a mix is a rebinding attempt or a split-horizon name.
	for _, a := range addrs {
		if Blocked(a, p.Overlay) {
			deny(http.StatusForbidden, "private_address")
			return
		}
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	lr.N = maxHello
	hello, err := peekHello(br)
	ev.ECH = hello.ech
	switch {
	case err != nil || !strings.EqualFold(strings.TrimSuffix(hello.sni, "."), host):
		deny(0, "sni_mismatch")
		return
	case hello.ech && p.DenyECH:
		deny(0, "ech_not_allowed")
		return
	}
	dst := addrs[0]
	if i := slices.IndexFunc(addrs, func(a netip.Addr) bool { return a.Unmap().Is4() }); i >= 0 {
		dst = addrs[i].Unmap() // pod networks are usually IPv4 only
	}
	if cut() {
		return
	}
	up, err := p.Dial(ctx, "tcp", netip.AddrPortFrom(dst, uint16(port)).String())
	if cut() {
		if up != nil {
			up.Close()
		}
		return
	}
	if err != nil {
		deny(0, "dial_failed")
		return
	}
	defer up.Close()
	if _, err := up.Write(hello.raw); err != nil {
		deny(0, "dial_failed")
		return
	}
	c.SetDeadline(time.Time{})
	lr.N = math.MaxInt64
	p.Metrics.Decision("allowed", "allowed")
	bytesUp, bytesDown := pipe(c, br, up, p.Idle)
	ev.Decision, ev.Reason = "allowed", "allowed"
	ev.BytesUp, ev.BytesDown = bytesUp+int64(len(hello.raw)), bytesDown
	ev.DurationMs = time.Since(start).Milliseconds()
	p.Events.Add(ev)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// validHost accepts a lowercase DNS name: at most 253 characters, labels of 1 to 63 letters,
// digits or hyphens, no hyphen at either end of a label.
func validHost(h string) bool {
	if h == "" || len(h) > maxHost {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

// maxHello bounds the bytes read while looking for the ClientHello (post-quantum key shares make
// it a few KiB; a record is at most 16 KiB plus header).
const maxHello = 64 << 10

var errHelloRead = errors.New("client hello read")

// extensionECH is the encrypted_client_hello extension (RFC 9849). With it the outer SNI is only a
// cover name, so the SNI check would mean nothing.
const extensionECH = 0xfe0d

type clientHello struct {
	sni string
	ech bool
	raw []byte // every byte consumed, to be replayed upstream
}

// peekHello reads the TLS ClientHello from r with crypto/tls's own parser. Nothing is written back
// to the client.
func peekHello(r io.Reader) (clientHello, error) {
	var buf bytes.Buffer
	var h clientHello
	got := false
	conn := &helloConn{r: io.TeeReader(io.LimitReader(r, maxHello), &buf)}
	err := tls.Server(conn, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			h.sni, h.ech, got = chi.ServerName, slices.Contains(chi.Extensions, extensionECH), true
			return nil, errHelloRead
		},
	}).Handshake()
	if !got {
		return h, fmt.Errorf("no TLS ClientHello: %w", err)
	}
	h.raw = buf.Bytes()
	return h, nil
}

// helloConn is a read-only net.Conn for peekHello; writes (the alert after the abort) are dropped.
type helloConn struct{ r io.Reader }

func (h *helloConn) Read(b []byte) (int, error)       { return h.r.Read(b) }
func (h *helloConn) Write(b []byte) (int, error)      { return len(b), nil }
func (h *helloConn) Close() error                     { return nil }
func (h *helloConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (h *helloConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (h *helloConn) SetDeadline(time.Time) error      { return nil }
func (h *helloConn) SetReadDeadline(time.Time) error  { return nil }
func (h *helloConn) SetWriteDeadline(time.Time) error { return nil }
