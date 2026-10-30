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
	want, err := installedExe()
	if err != nil {
		l.Close()
		return nil, nil, err
	}
	ops := procOps{
		exeOf: func(pid int) (string, error) { return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)) },
		stat: func(p string) (fileInfo, error) {
			var st unix.Stat_t
			if err := unix.Stat(p, &st); err != nil {
				return fileInfo{}, err
			}
			return fileInfo{OwnerUID: st.Uid, Mode: os.FileMode(st.Mode & 0o7777)}, nil
		},
	}
	// The allowed users are read on every connection, so `allowed-uids` can change without a restart.
	return l, func(c net.Conn) (string, error) {
		cred, err := peerCred(c)
		if err != nil {
			return "", err
		}
		if err := CheckUID(cred.Uid, LoadAllowedUIDs(base)); err != nil {
			return "", err
		}
		// Right user is not enough: any process of that user can open the socket. Only the
		// installed manar-edge binary may be the helper.
		if err := verifyHelperExe(ops, int(cred.Pid), want); err != nil {
			return "", err
		}
		return fmt.Sprintf("uid-%d", cred.Uid), nil
	}, nil
}

// installedExe is the service's own binary, resolved: the one the helper must be.
func installedExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// peerCred reads the connecting process's uid and pid from the kernel (SO_PEERCRED), which the peer cannot forge.
func peerCred(c net.Conn) (*unix.Ucred, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("warden: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, fmt.Errorf("warden: reading peer credentials: %w", serr)
	}
	return cred, nil
}

// Dial connects the helper to the service.
func Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", SocketPath)
}
