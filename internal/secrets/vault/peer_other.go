//go:build !linux && !windows

package vault

import "net"

func peerCred(net.Conn) (int, int) { return 0, -1 } // no helper channel on this OS
