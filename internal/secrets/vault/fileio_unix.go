//go:build !windows

package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

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
