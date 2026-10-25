package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// The hook reaches the local gateway over a unix socket in a root-owned 0755 directory, not over
// TCP: inside the netns the agent user could bind 127.0.0.1:8480 while the gateway restarts and
// answer the hook itself. The agent can connect to the socket but cannot create or replace
// anything in the directory, and the hook checks the server's uid with SO_PEERCRED.
const runBase = "/run/manar-edge"

func sockDir(name string) string  { return runBase + "/" + name }
func sockPath(name string) string { return sockDir(name) + "/gw.sock" }

// hookListener serves the hook routes on the socket. Only the agent's uid and root may use it:
// the socket is root:<agent group> 0660 and every connection's SO_PEERCRED is checked, so no other
// local user can use the agent's identity through it.
func hookListener(st *State) (net.Listener, error) {
	uid, gid, err := lookupUser(userName(st))
	if err != nil {
		return nil, fmt.Errorf("agent user: %w", err)
	}
	if err := rootOnlyWritable(sockDir(st.Name), true); err != nil {
		return nil, err
	}
	p := sockPath(st.Name)
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	if err := os.Lchown(p, 0, gid); err != nil {
		ln.Close()
		return nil, err
	}
	if err := os.Chmod(p, 0o660); err != nil { // connect needs write permission on the socket
		ln.Close()
		return nil, err
	}
	return &peerListener{Listener: ln, allow: func(u uint32) bool { return u == 0 || u == uint32(uid) }}, nil
}

// peerListener drops connections whose peer uid is not allowed.
type peerListener struct {
	net.Listener
	allow func(uint32) bool
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if cred, err := peerCred(c); err == nil && l.allow(cred.Uid) {
			return c, nil
		}
		c.Close()
	}
}

func peerCred(c net.Conn) (*unix.Ucred, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, cerr
}

func hookTransport(name string) (*http.Transport, string) {
	return &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialUnixAs(ctx, sockPath(name), 0)
	}}, "http://manar-edge-gateway"
}

// dialUnixAs connects to a unix socket and refuses it unless the listening process runs as uid.
func dialUnixAs(ctx context.Context, path string, uid uint32) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if cred, err := peerCred(c); err != nil || cred.Uid != uid {
		c.Close()
		return nil, errors.New("the local gateway socket is not served by root")
	}
	return c, nil
}

// rootOnlyWritable checks that p is a real file or directory (not a symlink) owned by root and
// not writable by group or others.
func rootOnlyWritable(p string, dir bool) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || fi.Mode()&os.ModeSymlink != 0 || fi.IsDir() != dir || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must be owned by root and writable by root only", p)
	}
	return nil
}

// safeBinary checks the agent user can run p but cannot change it or anything on its path.
func safeBinary(p string) error {
	if err := rootOnlyWritable(p, false); err != nil {
		return err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o001 == 0 {
		return fmt.Errorf("%s is not executable by other users", p)
	}
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		if err := rootOnlyWritable(d, true); err != nil {
			return err
		}
		if fi, _ := os.Stat(d); fi.Mode().Perm()&0o001 == 0 {
			return fmt.Errorf("%s is not searchable by other users", d)
		}
		if d == "/" {
			return nil
		}
	}
}

// installedBinary returns a path to this binary that the agent user can run and cannot change,
// copying it to /usr/local/bin when the current location does not qualify. Units and the hook
// run that path.
func installedBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	if safeBinary(exe) == nil {
		return exe, nil
	}
	const dst = "/usr/local/bin/manar-edge"
	if err := copyFile(exe, dst, 0o755); err != nil {
		return "", err
	}
	if err := safeBinary(dst); err != nil {
		return "", fmt.Errorf("cannot place the binary where the agent user can run it but not change it: %w", err)
	}
	fmt.Fprintf(os.Stderr, "installed %s as %s\n", exe, dst)
	return dst, nil
}
