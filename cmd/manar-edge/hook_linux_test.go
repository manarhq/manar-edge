package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The hook refuses a gateway socket served by anyone but root: a socket the test process serves
// (not root, unless the tests run as root) must be refused when root is required.
func TestDialUnixAsChecksPeer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gw.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	me := uint32(os.Getuid())
	c, err := dialUnixAs(ctx, p, me)
	if err != nil {
		t.Fatalf("own socket refused: %v", err)
	}
	c.Close()
	if _, err := dialUnixAs(ctx, p, me+1); err == nil {
		t.Fatal("socket served by another uid accepted")
	}
}

func TestSafeBinary(t *testing.T) {
	f := filepath.Join(t.TempDir(), "manar-edge")
	if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 && safeBinary(f) == nil {
		t.Error("binary in a user-owned directory accepted")
	}
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	if err := safeBinary(sh); err != nil {
		t.Errorf("%s refused: %v", sh, err)
	}
}

// The agent gets a fresh pty as its controlling terminal.
func TestOpenPTY(t *testing.T) {
	m, s, err := openPTY()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	cmd := exec.Command("sh", "-c", "tty")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	buf := make([]byte, 256)
	_ = m.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := m.Read(buf)
	_ = cmd.Wait()
	if got := strings.TrimSpace(string(buf[:n])); !strings.HasPrefix(got, "/dev/pts/") {
		t.Fatalf("tty = %q", got)
	}
}

// The hook socket listener drops peers whose uid is not allowed.
func TestPeerListener(t *testing.T) {
	me := uint32(os.Getuid())
	get := func(allow func(uint32) bool) error {
		path := filepath.Join(t.TempDir(), "s")
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })}
		go srv.Serve(&peerListener{Listener: ln, allow: allow})
		defer srv.Close()
		hc := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			}}}
		res, err := hc.Get("http://gw/")
		if err == nil {
			res.Body.Close()
		}
		return err
	}
	if err := get(func(u uint32) bool { return u == me }); err != nil {
		t.Errorf("allowed peer refused: %v", err)
	}
	if err := get(func(u uint32) bool { return u == me+1 }); err == nil {
		t.Error("peer with another uid served")
	}
}
