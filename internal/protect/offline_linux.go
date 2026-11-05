package protect

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// offlineDir is where the snapshot lives: a sibling of the state directory, so a user-readable
// directory can be root-owned without opening the (private) state directory itself.
func offlineDir(state string) string { return filepath.Clean(state) + "-policy" }

// trustedUID and trustedRoot say who must own the snapshot and its folders, and where the check of
// the folders above it stops. Tests change them; in the service they are root and "/".
var (
	trustedUID  uint32
	trustedRoot = "/"
)

var errUnprotected = errors.New("the saved policy is not protected")

func trustedInfo(fi os.FileInfo, dir bool) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode()&os.ModeSymlink == 0 && fi.IsDir() == dir && st.Uid == trustedUID && fi.Mode().Perm()&0o022 == 0
}

// readTrusted reads the snapshot only when every folder above it is a real folder (no links)
// owned by root and not writable by anyone else, and the file itself, opened without following a
// link and checked on the open handle, is a regular root-owned file nobody else can write. A user
// cannot create, replace or remove such a file, so what the hook reads is what the service wrote.
var readTrusted = func(state string) ([]byte, error) {
	f := offlineFile(state)
	for p := filepath.Dir(f); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if !trustedInfo(fi, true) {
			return nil, errUnprotected
		}
		if p == trustedRoot || filepath.Dir(p) == p {
			break
		}
	}
	fd, err := os.OpenFile(f, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	fi, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	if !trustedInfo(fi, false) {
		return nil, errUnprotected
	}
	return io.ReadAll(io.LimitReader(fd, 1<<20))
}

// writeOffline stores the snapshot (the service runs as root, so the folder and file are root's).
// It refuses a folder that already exists as a link, as a file, or owned by someone else.
func writeOffline(state string, b []byte) error {
	d := offlineDir(state)
	if fi, err := os.Lstat(d); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || st.Uid != uint32(os.Geteuid()) {
			return errUnprotected
		}
	} else if err := os.Mkdir(d, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(d, 0o755); err != nil {
		return err
	}
	tmp := offlineFile(state) + ".tmp"
	_ = os.Remove(tmp)
	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := fd.Write(b); err != nil {
		fd.Close()
		return err
	}
	if err := fd.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, offlineFile(state))
}

// localCaller names the account the hook runs as, in the form the service records ("uid:<n>").
var localCaller = func() string { return "uid:" + strconv.Itoa(os.Geteuid()) }
