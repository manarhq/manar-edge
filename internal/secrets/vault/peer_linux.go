//go:build linux

package vault

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCred is the process id and user id on the other end of a unix socket (SO_PEERCRED), taken
// by the kernel when the connection was made. 0, -1 when unknown.
func peerCred(c net.Conn) (pid, uid int) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, -1
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, -1
	}
	uid = -1
	_ = raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			pid, uid = int(cred.Pid), int(cred.Uid)
		}
	})
	return pid, uid
}
