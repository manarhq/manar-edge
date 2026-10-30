//go:build !windows

package vault

import (
	"os"
	"syscall"
)

func owner(st os.FileInfo) (int, int) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid), int(s.Gid)
	}
	return -1, -1
}

func chownFile(f *os.File, fi FileInfo) error {
	if fi.UID < 0 || os.Geteuid() != 0 {
		return nil // not root: the file is ours already
	}
	return f.Chown(fi.UID, fi.GID)
}
