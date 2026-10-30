//go:build linux

package warden

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// SocketPath is where the service listens. The directory is root-owned; the socket is openable by
// everyone, and the SO_PEERCRED check below decides who may talk.
const SocketPath = "/run/manar-edge/warden.sock"

func listen(base string) (net.Listener, PeerCheck, error) {
	if err := os.MkdirAll(filepath.Dir(SocketPath), 0o755); err != nil {
		return nil, nil, err
	}
	_ = os.Remove(SocketPath)
	l, err := net.Listen("unix", SocketPath)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(SocketPath, 0o666); err != nil {
		l.Close()
		return nil, nil, err
	}
	// The allowed users are read on every connection, so `allowed-uids` can change without a restart.
	return l, func(c net.Conn) error {
		uid, err := peerUID(c)
		if err != nil {
			return err
		}
		return CheckUID(uid, LoadAllowedUIDs(base))
	}, nil
}

// peerUID reads the connecting process's uid from the kernel (SO_PEERCRED), which the peer cannot forge.
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("warden: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, fmt.Errorf("warden: reading peer credentials: %w", serr)
	}
	return cred.Uid, nil
}

// Dial connects the helper to the service.
func Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", SocketPath)
}
