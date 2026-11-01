//go:build linux

package vault

import (
	"crypto/rand"
	"io"
	"os"
	"syscall"
)

func rand0() io.Reader { return rand.Reader }

// fileOwner is the owner of a unix socket (not following a final link).
func fileOwner(path string) (int, bool) {
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		return 0, false
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	return int(s.Uid), ok
}
