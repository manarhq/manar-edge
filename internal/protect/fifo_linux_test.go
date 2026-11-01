package protect

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO where a config file should be must not hang the scan.
func TestReadDoesNotBlockOnAFifo(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, "mcp.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, _, _, err := (directFS{Home: home}).Read(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO is not a regular file: want an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read blocked on a FIFO")
	}
}
