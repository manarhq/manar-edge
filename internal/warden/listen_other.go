//go:build !linux && !windows

package warden

import (
	"context"
	"errors"
	"net"
)

func listen(string) (net.Listener, PeerCheck, error) {
	return nil, nil, errors.New("warden: this platform is not supported")
}

func Dial(context.Context) (net.Conn, error) {
	return nil, errors.New("warden: this platform is not supported")
}
