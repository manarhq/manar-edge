//go:build !linux && !windows

package protect

import (
	"context"
	"errors"
	"net"
)

func listenRelay() (net.Listener, error)          { return nil, errors.New("unsupported OS") }
func dialRelay(context.Context) (net.Conn, error) { return nil, errors.New("unsupported OS") }
func callerOf(net.Conn) string                    { return "unknown" }

func callerIsAdmin(net.Conn) bool { return false }
