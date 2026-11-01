package jail

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	netlinkConnector  = 11 // NETLINK_CONNECTOR
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventExec     = 2
)

// watchExec calls fn with the pid of every process that finishes an exec, from the kernel's proc
// connector (needs root). It returns an error if the connector is not available, and when ctx ends.
func watchExec(ctx context.Context, fn func(pid int)) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, netlinkConnector)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}); err != nil {
		return err
	}
	// nlmsghdr (16) + cn_msg (20) + op (4)
	msg := make([]byte, 40)
	binary.NativeEndian.PutUint32(msg[0:], 40)
	binary.NativeEndian.PutUint16(msg[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint32(msg[12:], uint32(os.Getpid()))
	binary.NativeEndian.PutUint32(msg[16:], cnIdxProc)
	binary.NativeEndian.PutUint32(msg[20:], cnValProc)
	binary.NativeEndian.PutUint16(msg[32:], 4) // cn_msg.len
	binary.NativeEndian.PutUint32(msg[36:], procCnMcastListen)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	// Wake the blocking read when ctx ends.
	tv := unix.NsecToTimeval(500e6)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) {
				continue // ENOBUFS: events were lost; the periodic scan covers them
			}
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			// cn_msg (20 bytes) then proc_event: what u32, cpu u32, timestamp u64, then the
			// event data; for exec: process_pid u32, process_tgid u32.
			d := m.Data
			if len(d) < 20+16+8 || binary.NativeEndian.Uint32(d[20:]) != procEventExec {
				continue
			}
			fn(int(binary.NativeEndian.Uint32(d[20+16+4:])))
		}
	}
}
