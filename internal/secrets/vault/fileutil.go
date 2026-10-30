package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// FileInfo is what restore needs to put a file back exactly.
type FileInfo struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Who is the person whose home a secret lives in. Every read and write below the home is done as
// that person (Linux: filesystem uid on the thread; Windows: reparse points are refused), so the
// service, which runs as root or SYSTEM, can never be steered by a link in the user's folders
// into reading or writing something the user could not.
type Who struct {
	UID, GID int
	SID      string // Windows
}

// Key identifies the owner inside vault ids and grants.
func (w Who) Key() string {
	if w.SID != "" {
		return w.SID
	}
	return "u" + itoa(w.UID)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

var errLink = errors.New("a link or mount point is in the way")

// noLinks refuses a path whose final element, or the folders from home down to it, are links.
func noLinks(home, path string) error {
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return errLink
		}
		if p == home || filepath.Dir(p) == p {
			return nil
		}
	}
}

// Read returns a regular file's bytes and what is needed to recreate it. The file must belong to
// the home's owner.
func (w Who) Read(home, path string) ([]byte, FileInfo, error) {
	var b []byte
	var fi FileInfo
	err := w.do(func() error {
		if err := noLinks(home, path); err != nil {
			return err
		}
		f, err := openNoFollow(path)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return errors.New("not a regular file")
		}
		if !w.owns(st) {
			return errors.New("the file does not belong to the owner of this home")
		}
		b = make([]byte, 0, st.Size())
		buf := bytes.NewBuffer(b)
		if _, err := buf.ReadFrom(f); err != nil {
			return err
		}
		b = buf.Bytes()
		fi = FileInfo{Path: path, Mode: uint32(st.Mode().Perm())}
		return nil
	})
	return b, fi, err
}

// Write replaces the file: temp file in the same folder, sync, rename, with the recorded mode.
func (w Who) Write(fi FileInfo, data []byte) error {
	return w.do(func() error {
		dir := filepath.Dir(fi.Path)
		f, err := os.CreateTemp(dir, ".manar-*")
		if err != nil {
			return err
		}
		tmp := f.Name()
		fail := func(e error) error { _ = f.Close(); _ = os.Remove(tmp); return e }
		if err := f.Chmod(os.FileMode(fi.Mode)); err != nil {
			return fail(err)
		}
		if _, err := f.Write(data); err != nil {
			return fail(err)
		}
		if err := f.Sync(); err != nil {
			return fail(err)
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, fi.Path); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		return nil
	})
}

// MkdirAll creates folders as the owner with mode 0700.
func (w Who) MkdirAll(dir string) error {
	return w.do(func() error { return os.MkdirAll(dir, 0o700) })
}

func (w Who) Remove(path string) error {
	return w.do(func() error { return os.Remove(path) })
}

func (w Who) Exists(home, path string) bool {
	_, _, err := w.Read(home, path)
	return err == nil
}

// Same reports whether the file holds exactly want with the recorded mode.
func (w Who) Same(home string, fi FileInfo, want []byte) bool {
	got, cur, err := w.Read(home, fi.Path)
	return err == nil && bytes.Equal(got, want) && cur.Mode == fi.Mode
}
