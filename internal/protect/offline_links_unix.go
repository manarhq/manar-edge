//go:build !windows

package protect

import (
	"os"
	"syscall"
)

// linkCount is the number of hard links to a file (1 when it cannot be told).
func linkCount(_ string, fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}
