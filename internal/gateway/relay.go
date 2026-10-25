package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DialFunc dials an upstream; net.Dialer.DialContext in production.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DefaultIdleTimeout closes a relayed or proxied connection with no traffic either way.
const DefaultIdleTimeout = 5 * time.Minute

// dialTimeout bounds the relay's upstream dial.
const dialTimeout = 10 * time.Second

// Relay passes TCP from active peers to manar-api's agent listener without terminating TLS.
type Relay struct {
	Registry *Registry
	Upstream string
	Dial     DialFunc
	Idle     time.Duration
	Metrics  *Metrics
	Log      *slog.Logger
}

// Serve accepts until ln is closed.
func (r *Relay) Serve(ln net.Listener) error { return serve(ln, r.handle) }

func (r *Relay) handle(c net.Conn) {
	defer c.Close()
	lease, err := r.Registry.Acquire(remoteAddr(c), c)
	if err != nil {
		r.Metrics.RelayRefused.Add(1)
		if errors.Is(err, errTooMany) {
			r.Log.Warn("relay connection refused", "peerId", lease.Peer.ID, "reason", "too_many_connections")
		}
		return
	}
	defer lease.Release()
	ctx, cancel := context.WithTimeout(lease.Ctx, dialTimeout)
	up, err := r.Dial(ctx, "tcp", r.Upstream)
	cancel()
	if err != nil {
		if lease.Ctx.Err() == nil {
			r.Log.Warn("relay upstream unreachable", "err", err)
		}
		return
	}
	defer up.Close()
	if lease.Ctx.Err() != nil { // cut while dialling
		return
	}
	pipe(c, c, up, r.Idle)
}

func remoteAddr(c net.Conn) netip.Addr {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

func serve(ln net.Listener, handle func(net.Conn)) error {
	for {
		c, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go handle(c)
	}
}

// copyBufs keeps per-connection memory small: two 8 KiB buffers per open tunnel.
var copyBufs = sync.Pool{New: func() any { b := make([]byte, 8<<10); return &b }}

// activity resets the idle timer on every read it passes through.
type activity struct {
	r     io.Reader
	timer *time.Timer
	idle  time.Duration
}

func (a *activity) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.timer.Reset(a.idle)
	}
	return n, err
}

// writerOnly hides ReadFrom so io.CopyBuffer uses the pooled buffer.
type writerOnly struct{ io.Writer }

// pipe copies client (read through cr) and up both ways until either side ends or no byte moves
// either way for idle, then closes both so a cut (which closes client) also ends the upstream
// side. It returns the bytes sent each way.
func pipe(client net.Conn, cr io.Reader, up net.Conn, idle time.Duration) (bytesUp, bytesDown int64) {
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	var once sync.Once
	done := func() { once.Do(func() { client.Close(); up.Close() }) }
	timer := time.AfterFunc(idle, done)
	defer timer.Stop()
	cp := func(dst io.Writer, src io.Reader) int64 {
		buf := copyBufs.Get().(*[]byte)
		defer copyBufs.Put(buf)
		n, _ := io.CopyBuffer(writerOnly{dst}, &activity{r: src, timer: timer, idle: idle}, *buf)
		done()
		return n
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bytesUp = cp(up, cr)
	}()
	bytesDown = cp(client, up)
	wg.Wait()
	return bytesUp, bytesDown
}
