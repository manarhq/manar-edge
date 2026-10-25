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
}

// Serve accepts until ln is closed.
func (p *Proxy) Serve(ln net.Listener) error { return serve(ln, p.handle) }

// handshakeTimeout bounds the CONNECT request, DNS, dial and ClientHello.
const handshakeTimeout = 15 * time.Second

func (p *Proxy) handle(c net.Conn) {
	defer c.Close()
	start := time.Now()
	peer, release, ok := p.Registry.Acquire(remoteAddr(c), c)
	if !ok {
		p.Metrics.Decision("denied", "not_peer")
		return
	}
	defer release()
	c.SetDeadline(start.Add(handshakeTimeout))
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(handshakeTimeout))
	defer cancel()

	ev := Event{PeerID: peer.ID, At: start.UTC()}
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

	br := bufio.NewReader(c)
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
	if err != nil || perr != nil {
		deny(http.StatusBadRequest, "bad_request")
		return
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ev.Host, ev.Port = host, port
	if !slices.Contains(p.Ports, port) {
		deny(http.StatusForbidden, "port_not_allowed")
		return
	}
	if _, ok := HostAllowed(peer.AllowHosts, host); !ok {
		deny(http.StatusForbidden, "host_not_allowed")
		return
	}
	addrs, err := p.Resolve(ctx, host)
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
	sni, hello, err := peekSNI(br)
	if err != nil || !strings.EqualFold(strings.TrimSuffix(sni, "."), host) {
		deny(0, "sni_mismatch")
		return
	}
	dst := addrs[0]
	if i := slices.IndexFunc(addrs, func(a netip.Addr) bool { return a.Unmap().Is4() }); i >= 0 {
		dst = addrs[i].Unmap() // pod networks are usually IPv4 only
	}
	up, err := p.Dial(ctx, "tcp", netip.AddrPortFrom(dst, uint16(port)).String())
	if err != nil {
		deny(0, "dial_failed")
		return
	}
	defer up.Close()
	c.SetDeadline(time.Time{})
	if _, err := up.Write(hello); err != nil {
		deny(0, "dial_failed")
		return
	}
	p.Metrics.Decision("allowed", "allowed")
	bytesUp, bytesDown := pipe(c, br, up)
	ev.Decision, ev.Reason = "allowed", "allowed"
	ev.BytesUp, ev.BytesDown = bytesUp+int64(len(hello)), bytesDown
	ev.DurationMs = time.Since(start).Milliseconds()
	p.Events.Add(ev)
}

// maxHello bounds the bytes read while looking for the ClientHello (post-quantum key shares make
// it a few KiB; a record is at most 16 KiB plus header).
const maxHello = 64 << 10

var errHelloRead = errors.New("client hello read")

// peekSNI reads the TLS ClientHello from r with crypto/tls's own parser and returns its SNI and
// every byte consumed, to be replayed upstream. Nothing is written back to the client.
func peekSNI(r io.Reader) (sni string, consumed []byte, err error) {
	var buf bytes.Buffer
	got := false
	conn := &helloConn{r: io.TeeReader(io.LimitReader(r, maxHello), &buf)}
	err = tls.Server(conn, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni, got = h.ServerName, true
			return nil, errHelloRead
		},
	}).Handshake()
	if !got {
		return "", nil, fmt.Errorf("no TLS ClientHello: %w", err)
	}
	return sni, buf.Bytes(), nil
}

// helloConn is a read-only net.Conn for peekSNI; writes (the alert after the abort) are dropped.
type helloConn struct{ r io.Reader }

func (h *helloConn) Read(b []byte) (int, error)       { return h.r.Read(b) }
func (h *helloConn) Write(b []byte) (int, error)      { return len(b), nil }
func (h *helloConn) Close() error                     { return nil }
func (h *helloConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (h *helloConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (h *helloConn) SetDeadline(time.Time) error      { return nil }
func (h *helloConn) SetReadDeadline(time.Time) error  { return nil }
func (h *helloConn) SetWriteDeadline(time.Time) error { return nil }
