//go:build !windows

package door

import "net"

func listen(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }
