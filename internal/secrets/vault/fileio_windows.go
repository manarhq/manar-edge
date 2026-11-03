package vault

import (
	"errors"
	"os"

	"github.com/manarhq/manar-edge/internal/safefs"
)

// On Windows the service runs as SYSTEM and cannot act as the user, so every file below the home
// is reached through handles opened one folder at a time from the drive's root, with no link
// followed and no path used twice (internal/safefs). The home folder comes from Who, never from
// the caller.

var errLink = safefs.ErrLink

func (w Who) home() (string, error) {
	if w.Home == "" {
		return "", errors.New("no home folder for this owner")
	}
	return w.Home, nil
}

// Read returns a regular file's bytes. The home argument must be the owner's own home.
func (w Who) Read(home, path string) ([]byte, FileInfo, error) {
	if w.Home != "" && home != w.Home {
		return nil, FileInfo{}, errors.New("the file is not in this owner's home")
	}
	b, exists, err := safefs.Read(home, path, 64<<20)
	if err != nil {
		return nil, FileInfo{}, err
	}
	if !exists {
		return nil, FileInfo{}, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
	}
	return b, FileInfo{Path: path, Mode: 0o600}, nil
}

// Write replaces the file (temporary file in the same folder, renamed over it).
func (w Who) Write(fi FileInfo, data []byte) error {
	h, err := w.home()
	if err != nil {
		return err
	}
	return safefs.Write(h, fi.Path, data)
}

// MkdirAll creates the folders below the home.
func (w Who) MkdirAll(dir string) error {
	h, err := w.home()
	if err != nil {
		return err
	}
	return safefs.MkdirAll(h, dir)
}

func (w Who) Remove(path string) error {
	h, err := w.home()
	if err != nil {
		return err
	}
	return safefs.Remove(h, path) // a missing file is not an error

}
