//go:build linux

package warden

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The kernel reports who is on the other end of a unix socket; peerUID must return our own uid.
func TestPeerUIDIsTheKernelsAnswer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "w.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan uint32, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		uid, _ := peerUID(c)
		got <- uid
	}()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if uid := <-got; uid != uint32(os.Getuid()) {
		t.Fatalf("peerUID = %d, want %d", uid, os.Getuid())
	}
}
