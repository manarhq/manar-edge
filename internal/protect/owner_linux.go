package protect

import (
	"io/fs"
	"os"
	"syscall"
)

func chown(path string, o Owner) error {
	if o.UID < 0 || os.Geteuid() != 0 {
		return nil
	}
	return os.Chown(path, o.UID, o.GID)
}

func fileOwner(st fs.FileInfo, fallback Owner) (int, int) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid), int(s.Gid)
	}
	return fallback.UID, fallback.GID
}
