package protect

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FS is how Manar touches a user's files. On Linux, as root, every call runs in a child process
// that has become the file's owner (see userfs_linux.go), so a link the user plants can only
// reach what the user could already reach. Every implementation also refuses symbolic links and
// Windows reparse points anywhere below the user's home folder.
type FS interface {
	// Read returns the file; exists is false when it is not there. A path with a link in it is an error.
	Read(path string) (data []byte, exists bool, mode os.FileMode, err error)
	// Write replaces the file atomically (temp file in the same folder, renamed), creating missing
	// folders one at a time.
	Write(path string, data []byte, mode os.FileMode) error
	Remove(path string) error
}

// errLink is returned for a path that goes through a link.
var errLink = errors.New("a symbolic link or junction is in the path")

// directFS acts as the current process. Home is the folder the walk starts below.
type directFS struct{ Home string }

// checkPath walks from Home down to path, refusing links. A missing component ends the walk:
// everything below it will be created by us.
func (d directFS) checkPath(path string) error {
	if d.Home == "" || !filepath.IsAbs(path) || !filepath.IsAbs(d.Home) {
		return errors.New("path outside the user's home")
	}
	rel, err := filepath.Rel(d.Home, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("path outside the user's home")
	}
	cur := d.Home
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("%s: %w", cur, errLink)
		}
	}
	return nil
}

func (d directFS) Read(path string) ([]byte, bool, os.FileMode, error) {
	if err := d.checkPath(path); err != nil {
		return nil, false, 0, err
	}
	f, err := openRead(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, 0, nil
	}
	if err != nil {
		return nil, false, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, 0, err
	}
	if !st.Mode().IsRegular() {
		return nil, false, 0, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 32<<20))
	return b, true, st.Mode().Perm(), err
}

func (d directFS) Write(path string, data []byte, mode os.FileMode) error {
	if err := d.checkPath(path); err != nil {
		return err
	}
	if err := d.mkdirs(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".manar-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	// Through the open file, never the path: a swapped temp file cannot redirect these.
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (d directFS) mkdirs(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir && parent != d.Home {
		if err := d.mkdirs(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func (d directFS) Remove(path string) error {
	if err := d.checkPath(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
