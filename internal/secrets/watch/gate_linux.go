//go:build linux

package watch

import (
	"os"
	"syscall"
)

func identify(f *os.File) (fileID, bool) {
	st, err := f.Stat()
	if err != nil {
		return fileID{}, false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{dev: uint64(sys.Dev), ino: sys.Ino, size: st.Size(), mtime: st.ModTime().UnixNano()}, true
}
