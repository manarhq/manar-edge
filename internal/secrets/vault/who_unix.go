//go:build !windows

package vault

import (
	"errors"
	"os"
	"syscall"
)

// WhoOfHome identifies the owner of a home folder (which must not be a link).
func WhoOfHome(home string) (Who, error) {
	st, err := os.Lstat(home)
	if err != nil {
		return Who{}, err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() {
		return Who{}, errors.New("the home folder is not a plain folder")
	}
	return Who{UID: int(s.Uid), GID: int(s.Gid)}, nil
}

func (w Who) owns(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == w.UID
}

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
