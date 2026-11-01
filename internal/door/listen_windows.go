//go:build windows

package door

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// listen takes the port exclusively: on Windows another process may otherwise bind the same
// port with SO_REUSEADDR and receive part of the traffic (and the user's API keys).
func listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			// SO_EXCLUSIVEADDRUSE is ~SO_REUSEADDR.
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, ^windows.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp", addr)
}
