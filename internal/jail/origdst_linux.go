package jail

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	soOriginalDst   = 80 // SO_ORIGINAL_DST and IP6T_SO_ORIGINAL_DST
	solIPv6         = 41
	sockaddrInSize  = 16
	sockaddrIn6Size = 28
)

// OrigDst returns where a redirected connection was going before the nat rule changed it. A
// connection that was not redirected (someone opened the proxy port by hand) has none: error.
func OrigDst(c net.Conn) (netip.AddrPort, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("not tcp")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	v6 := tc.LocalAddr().(*net.TCPAddr).IP.To4() == nil
	var out netip.AddrPort
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		var buf [sockaddrIn6Size]byte
		n := uint32(len(buf))
		level := unix.SOL_IP
		if v6 {
			level = solIPv6
		}
		_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(level), soOriginalDst,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
		if e != 0 {
			gerr = e
			return
		}
		port := binary.BigEndian.Uint16(buf[2:4])
		if v6 {
			out = netip.AddrPortFrom(netip.AddrFrom16([16]byte(buf[8:24])).Unmap(), port)
		} else {
			out = netip.AddrPortFrom(netip.AddrFrom4([4]byte(buf[4:8])), port)
		}
	}); err != nil {
		return netip.AddrPort{}, err
	}
	return out, gerr
}
