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

// Relay passes TCP from active peers to manar-api's agent listener without terminating TLS.
type Relay struct {
	Registry *Registry
	Upstream string
	Dial     DialFunc
	Metrics  *Metrics
	Log      *slog.Logger
}

// Serve accepts until ln is closed.
func (r *Relay) Serve(ln net.Listener) error { return serve(ln, r.handle) }

func (r *Relay) handle(c net.Conn) {
	defer c.Close()
	_, release, ok := r.Registry.Acquire(remoteAddr(c), c)
	if !ok {
		r.Metrics.RelayRefused.Add(1)
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	up, err := r.Dial(ctx, "tcp", r.Upstream)
	cancel()
	if err != nil {
		r.Log.Warn("relay upstream unreachable", "err", err)
		return
	}
	defer up.Close()
	pipe(c, c, up)
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

// pipe copies client (read through cr) and up both ways until either side ends, then closes both
// so a cut (which closes client) also ends the upstream side. It returns the bytes sent each way.
func pipe(client net.Conn, cr io.Reader, up net.Conn) (bytesUp, bytesDown int64) {
	var once sync.Once
	done := func() { once.Do(func() { client.Close(); up.Close() }) }
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bytesUp, _ = io.Copy(up, cr)
		done()
	}()
	bytesDown, _ = io.Copy(client, up)
	done()
	wg.Wait()
	return bytesUp, bytesDown
}
