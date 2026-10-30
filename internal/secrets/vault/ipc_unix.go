//go:build !windows

package vault

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// SocketPath is where the daemon listens. The directory belongs to root; the socket is
// connectable by anyone, because the secret is released only after the person says yes.
const SocketPath = "/run/manar-edge/vault.sock"

func dialDaemon(timeout time.Duration) (io.ReadWriteCloser, error) {
	return net.DialTimeout("unix", SocketPath, timeout)
}

// Serve answers helper calls until ctx ends.
func Serve(ctx context.Context, b *Broker, env Env) error {
	if err := os.MkdirAll(filepath.Dir(SocketPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(SocketPath)
	l, err := net.Listen("unix", SocketPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(SocketPath, 0o666)
	go func() { <-ctx.Done(); l.Close(); _ = os.Remove(SocketPath) }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
			pid, uid := peerCred(c)
			if pid <= 0 {
				return
			}
			peer := Peer{PID: pid, Owner: "u" + itoa(uid), Admin: uid == 0}
			handleConn(ctx, c, peer, b, env)
		}()
	}
}
