//go:build linux

package watch

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// taintTracker follows fork and exit through the kernel's process connector (netlink, needs root)
// and remembers which processes descend from a blockable AI tool, so `setsid`, a double fork or a
// re-parent to init does not shake the attribution off. Without the connector (no CAP_NET_ADMIN, a
// kernel without it) it simply stays empty and attribution is by ancestry only.
type taintTracker struct {
	table taintTable
	procs ProcSource

	fd     int
	drainM sync.Mutex // events are applied one drain at a time, in order
	buf    [8192]byte

	mu    sync.Mutex
	tools map[int]*Tool // parent pid -> tool it runs as, cached until exec/exit of that pid
}

var (
	taintMu     sync.Mutex
	taintGlobal *taintTracker
)

// currentTaint is the tracker started by the watcher (nil before it runs or when unavailable).
func currentTaint() *taintTracker {
	taintMu.Lock()
	defer taintMu.Unlock()
	return taintGlobal
}

// taintedProcs is the /proc source plus the taint memory.
type taintedProcs struct {
	ProcSource
	t *taintTracker
}

// Sync brings the taint memory up to date before an attribution.
func (p taintedProcs) Sync() {
	if p.t != nil {
		p.t.drain()
	}
}

func (p taintedProcs) TaintOf(pid int) (Proc, string, bool) {
	if p.t == nil {
		return Proc{}, "", false
	}
	e, ok := p.t.table.get(pid)
	if !ok {
		return Proc{}, "", false
	}
	if cur, err := p.ProcSource.Get(pid); err != nil || (e.start != 0 && cur.Start != e.start) {
		p.t.table.drop(pid) // gone, or the pid belongs to someone else now
		return Proc{}, "", false
	}
	return e.tool, e.id, true
}

// procsWithTaint wraps the real /proc source with the running tracker.
func procsWithTaint(base ProcSource) ProcSource { return taintedProcs{base, currentTaint()} }

const (
	cnIdxProc     = 1
	cnValProc     = 1
	procCnListen  = 1
	procEventFork = 0x00000001
	procEventExec = 0x00000002
	procEventExit = 0x80000000
	nlHdr         = 16
	cnHdr         = 20
	evOff         = nlHdr + cnHdr + 16 // after what, cpu, timestamp
)

// startTaint opens the connector and processes events until ctx ends. It returns false when the
// connector cannot be used.
func startTaint(ctx context.Context, procs ProcSource) bool {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_CONNECTOR)
	if err != nil {
		log.Printf("manar-edge: process connector unavailable, attribution is by ancestry only: %v", err)
		return false
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}); err != nil {
		unix.Close(fd)
		log.Printf("manar-edge: process connector unavailable, attribution is by ancestry only: %v", err)
		return false
	}
	msg := make([]byte, nlHdr+cnHdr+4)
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint32(msg[12:], uint32(os.Getpid()))
	binary.NativeEndian.PutUint32(msg[nlHdr:], cnIdxProc)
	binary.NativeEndian.PutUint32(msg[nlHdr+4:], cnValProc)
	binary.NativeEndian.PutUint16(msg[nlHdr+16:], 4)
	binary.NativeEndian.PutUint32(msg[nlHdr+cnHdr:], procCnListen)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		log.Printf("manar-edge: process connector refused: %v", err)
		return false
	}
	t := &taintTracker{procs: procs, tools: map[int]*Tool{}, fd: fd}
	taintMu.Lock()
	taintGlobal = t
	taintMu.Unlock()
	go func() {
		defer unix.Close(fd)
		defer func() {
			taintMu.Lock()
			if taintGlobal == t {
				taintGlobal = nil
			}
			taintMu.Unlock()
		}()
		for ctx.Err() == nil {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, err := unix.Poll(fds, 500); err != nil && !errors.Is(err, unix.EINTR) {
				return
			} else if n > 0 && !t.drain() {
				return
			}
		}
	}()
	return true
}

// drain applies every event queued on the socket right now. Fork events are queued by the kernel
// while the fork happens, so a caller that drains before it looks has seen the fork of every
// process that already runs. It reports false when the socket is unusable.
func (t *taintTracker) drain() bool {
	t.drainM.Lock()
	defer t.drainM.Unlock()
	for {
		n, _, err := unix.Recvfrom(t.fd, t.buf[:], unix.MSG_DONTWAIT)
		switch {
		case err == nil:
			t.parse(t.buf[:n])
		case errors.Is(err, unix.EAGAIN):
			return true
		case errors.Is(err, unix.EINTR):
		case errors.Is(err, unix.ENOBUFS): // events were lost: what we know may be incomplete
			t.reset()
		default:
			return false
		}
	}
}

func (t *taintTracker) reset() {
	t.table.mu.Lock()
	t.table.m = nil
	t.table.mu.Unlock()
}

func (t *taintTracker) parse(b []byte) {
	for len(b) >= nlHdr {
		l := int(binary.NativeEndian.Uint32(b[0:]))
		if l < nlHdr || l > len(b) {
			return
		}
		m := b[:l]
		b = b[(l+3)&^3:]
		if len(m) < evOff+8 {
			continue
		}
		u := func(off int) int { return int(binary.NativeEndian.Uint32(m[off:])) }
		switch binary.NativeEndian.Uint32(m[nlHdr+cnHdr:]) {
		case procEventFork:
			parent, parentTgid, child, childTgid := u(evOff), u(evOff+4), u(evOff+8), u(evOff+12)
			if child == childTgid && parent == parentTgid { // processes, not threads
				t.fork(parent, child)
			}
		case procEventExec:
			pid := u(evOff)
			t.mu.Lock()
			delete(t.tools, pid)
			t.mu.Unlock()
		case procEventExit:
			pid := u(evOff)
			if pid == u(evOff+4) {
				t.table.drop(pid)
				t.mu.Lock()
				delete(t.tools, pid)
				t.mu.Unlock()
			}
		}
	}
}

// fork marks the child when the parent is a blockable tool or already marked.
func (t *taintTracker) fork(parent, child int) {
	var tool Proc
	var id string
	if e, ok := t.table.get(parent); ok {
		tool, id = e.tool, e.id
	} else {
		tl := t.toolOf(parent)
		if tl == nil {
			return
		}
		pr, err := t.procs.Get(parent)
		if err != nil {
			return
		}
		tool, id = pr, tl.ID
	}
	var start uint64
	if c, err := t.procs.Get(child); err == nil {
		start = c.Start
	}
	t.table.put(child, start, tool, id)
}

// toolOf says whether pid runs as a blockable catalogue tool (cached per pid until it execs).
func (t *taintTracker) toolOf(pid int) *Tool {
	t.mu.Lock()
	tl, ok := t.tools[pid]
	t.mu.Unlock()
	if ok {
		return tl
	}
	var found *Tool
	if pr, err := t.procs.Get(pid); err == nil {
		if m := match(pr); m != nil && m.Block {
			found = m
		}
	}
	t.mu.Lock()
	if len(t.tools) > 8192 {
		clear(t.tools)
	}
	t.tools[pid] = found
	t.mu.Unlock()
	return found
}
