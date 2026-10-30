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
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// readFile returns a file's bytes and what is needed to recreate it.
func readFile(path string) ([]byte, FileInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, FileInfo{}, err
	}
	if !st.Mode().IsRegular() {
		return nil, FileInfo{}, errors.New("not a regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, FileInfo{}, err
	}
	uid, gid := owner(st)
	return b, FileInfo{Path: path, Mode: uint32(st.Mode().Perm()), UID: uid, GID: gid}, nil
}

// writeFile writes data with the recorded mode and owner: temp file in the same directory, sync,
// rename. The file never exists with wider permissions than the original had.
func writeFile(fi FileInfo, data []byte) error {
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
	if err := chownFile(f, fi); err != nil {
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
}

// sameFile reports whether the file holds exactly want with the recorded mode.
func sameFile(fi FileInfo, want []byte) bool {
	got, cur, err := readFile(fi.Path)
	return err == nil && bytes.Equal(got, want) && cur.Mode == fi.Mode
}
