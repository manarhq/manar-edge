//go:build !linux && !windows

package vault

import "net"

func peerPID(net.Conn) int { return 0 } // no helper channel on this OS
