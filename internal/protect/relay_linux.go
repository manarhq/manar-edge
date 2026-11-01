package protect

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// The relay is a unix socket, not a loopback port: a web page or another user's process cannot
// reach a TCP port by accident or by DNS rebinding, and the service learns who is calling from
// the kernel (SO_PEERCRED). Anyone on the machine may ask for a decision; the caller's uid goes
// into the audit record.
var (
	relayDir  = "/run/manar-edge"
	relaySock = relayDir + "/relay.sock"
	// relayOwner is the uid the socket must belong to: root, the service.
	relayOwner = uint32(0)
)

func listenRelay() (net.Listener, error) {
	if err := os.MkdirAll(relayDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(relayDir, 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(relaySock)
	l, err := net.Listen("unix", relaySock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(relaySock, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// dialRelay connects only to a socket and a server that belong to the service.
func dialRelay(ctx context.Context) (net.Conn, error) {
	st, err := os.Lstat(relaySock)
	if err != nil {
		return nil, err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != relayOwner || st.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("the relay socket is not the service's")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", relaySock)
	if err != nil {
		return nil, err
	}
	if cred, err := peerCred(c); err != nil || cred.Uid != relayOwner {
		c.Close()
		return nil, errors.New("the relay socket is not served by the service")
	}
	return c, nil
}

func peerCred(c net.Conn) (*unix.Ucred, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix connection")
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, cerr
}

// callerOf names the process on the other end of an accepted connection.
func callerOf(c net.Conn) string {
	cred, err := peerCred(c)
	if err != nil {
		return "unknown"
	}
	return "uid:" + strconv.Itoa(int(cred.Uid))
}
