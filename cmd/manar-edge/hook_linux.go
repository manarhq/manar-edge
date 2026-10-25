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

func hookListener(st *State) (net.Listener, error) {
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
	if err := os.Chmod(p, 0o666); err != nil { // connect needs write permission on the socket
		ln.Close()
		return nil, err
	}
	return ln, nil
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
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		c.Close()
		return nil, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || cerr != nil || cred.Uid != uid {
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
