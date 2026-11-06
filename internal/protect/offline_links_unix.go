//go:build !windows

package protect

import (
	"os"
	"strconv"
	"syscall"
)

// linkCount is the number of hard links to a file (1 when it cannot be told).
func linkCount(_ string, fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}

// fileID names a file by device and inode, whatever its name.
func fileID(fi os.FileInfo) (string, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10), true
	}
	return "", false
}
