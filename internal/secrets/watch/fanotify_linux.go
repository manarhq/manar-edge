//go:build linux

package watch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fanSource is a Source over one fanotify descriptor.
//
// Blocking mode (perm=true) uses FAN_CLASS_CONTENT with FAN_OPEN_PERM: the opener sleeps in the
// kernel until we answer. That is why the answer is policy-only and why Close matters: closing
// the descriptor makes the kernel allow every open still waiting and drops the marks.
// Alert mode uses FAN_CLASS_NOTIF with FAN_OPEN, which can never hold anything up.
type fanSource struct {
	mu      sync.RWMutex
	fd      int
	perm    bool
	closed  bool
	pending []unix.FanotifyEventMetadata
	buf     []byte
}

const (
	fanOpenFlags = unix.O_RDONLY | unix.O_LARGEFILE
	pollMillis   = 500
)

func newFanSource(perm bool) (*fanSource, error) {
	class := uint(unix.FAN_CLASS_NOTIF)
	if perm {
		class = unix.FAN_CLASS_CONTENT
	}
	fd, err := unix.FanotifyInit(class|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, fanOpenFlags)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	return &fanSource{fd: fd, perm: perm, buf: make([]byte, 8192)}, nil
}

func (f *fanSource) mask() uint64 {
	if f.perm {
		return unix.FAN_OPEN_PERM | unix.FAN_EVENT_ON_CHILD
	}
	return unix.FAN_OPEN | unix.FAN_EVENT_ON_CHILD
}

// Mark adds a directory (events for files directly in it) or a file. It returns an error the
// caller may ignore: a path on a filesystem fanotify cannot mark is simply not watched.
func (f *fanSource) Mark(path string, isDir bool) error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return ErrClosed
	}
	mask := f.mask()
	if !isDir {
		mask &^= unix.FAN_EVENT_ON_CHILD
	}
	return unix.FanotifyMark(f.fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, path)
}

func (f *fanSource) Next() (PermEvent, error) {
	for {
		if ev, ok := f.pop(); ok {
			return ev, nil
		}
		fds := []unix.PollFd{{Fd: int32(f.fd), Events: unix.POLLIN}}
		f.mu.RLock()
		closed := f.closed
		f.mu.RUnlock()
		if closed {
			return PermEvent{}, ErrClosed
		}
		n, err := unix.Poll(fds, pollMillis)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return PermEvent{}, ErrClosed
		}
		if n <= 0 {
			return PermEvent{}, ErrIdle
		}
		if fds[0].Revents&(unix.POLLNVAL|unix.POLLERR) != 0 {
			return PermEvent{}, ErrClosed
		}
		if err := f.fill(); err != nil {
			return PermEvent{}, err
		}
	}
}

func (f *fanSource) fill() error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return ErrClosed
	}
	n, err := unix.Read(f.fd, f.buf)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return nil
		}
		return ErrClosed
	}
	sz := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for off := 0; off+sz <= n; {
		m := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&f.buf[off]))
		if m.Event_len < uint32(sz) {
			break
		}
		if m.Vers != unix.FANOTIFY_METADATA_VERSION {
			return fmt.Errorf("fanotify metadata version %d", m.Vers)
		}
		f.pending = append(f.pending, m)
		off += int(m.Event_len)
	}
	return nil
}

func (f *fanSource) pop() (PermEvent, bool) {
	for len(f.pending) > 0 {
		m := f.pending[0]
		f.pending = f.pending[1:]
		if m.Fd < 0 { // queue overflow: nothing to answer
			continue
		}
		path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(m.Fd)))
		ev := PermEvent{PID: int(m.Pid), Path: path, Handle: uint64(m.Fd)}
		if err != nil {
			ev.Path = ""
		}
		if m.Mask&unix.FAN_OPEN_PERM == 0 { // alert mode: nothing to answer, close the fd now
			_ = unix.Close(int(m.Fd))
			ev.Handle = 0
		}
		return ev, true
	}
	return PermEvent{}, false
}

func (f *fanSource) Respond(ev PermEvent, allow bool) error {
	if !f.perm || ev.Handle == 0 {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	defer unix.Close(int(ev.Handle))
	if f.closed {
		return ErrClosed
	}
	resp := uint32(unix.FAN_ALLOW)
	if !allow {
		resp = unix.FAN_DENY
	}
	var b [8]byte
	binary.NativeEndian.PutUint32(b[0:], uint32(ev.Handle))
	binary.NativeEndian.PutUint32(b[4:], resp)
	_, err := unix.Write(f.fd, b[:])
	return err
}

func (f *fanSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return unix.Close(f.fd)
}

// markAll marks every existing target whose class want accepts and returns how many marks worked.
// A directory target covers the files directly inside it; a file target is covered through its
// parent directory.
func markAll(f *fanSource, targets []Target, envFiles []string, want func(class string) bool, envParents bool) int {
	ok := 0
	marked := map[string]bool{}
	mark := func(p string, dir bool) {
		if marked[p] {
			return
		}
		marked[p] = true
		if f.Mark(p, dir) == nil {
			ok++
		}
	}
	for _, t := range targets {
		if want != nil && !want(t.Class) {
			continue
		}
		st, err := os.Stat(t.Path)
		if err != nil {
			continue
		}
		if !st.IsDir() {
			// Mark the parent directory, not the file's inode: an editor or package manager that
			// replaces the file (write a temp file, rename it over) would otherwise drop the mark.
			// Events for the other files in that directory are answered at once (ClassOf is "").
			mark(filepath.Dir(t.Path), true)
			continue
		}
		dirs := []string{t.Path}
		if t.Recursive {
			_ = filepath.WalkDir(t.Path, func(p string, d os.DirEntry, err error) error {
				if err == nil && d.IsDir() && p != t.Path {
					dirs = append(dirs, p)
				}
				return nil
			})
		}
		for _, d := range dirs {
			mark(d, true)
		}
	}
	if want == nil || want(ClassEnv) {
		for _, p := range envFiles {
			if envParents { // blocked .env files get the same replace-safe parent mark
				mark(filepath.Dir(p), true)
			} else {
				mark(p, false)
			}
		}
	}
	return ok
}
