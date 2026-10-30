// Package vault is the Secret vault: AWS keys and ssh private keys move out of their files into
// a store only the Manar service can read, and programs get them back through Manar, which asks
// the person (spec 4.5 item 4).
//
// The rule that runs through all of it: a secret is written to the vault and read back before
// the original is touched, and "restore" puts the original bytes and permissions back.
package vault

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
)

// Store keeps named blobs. On Windows the bytes are DPAPI-protected; on Linux the directory is
// 0700 and the files 0600, owned by the service (root).
type Store interface {
	Put(name string, data []byte) error
	Get(name string) ([]byte, error)
	Delete(name string) error
	List() ([]string, error)
}

// ErrNotFound is returned by Store.Get for a name that does not exist.
var ErrNotFound = errors.New("not in the vault")

var nameOK = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)

// FileStore is a Store in one directory.
type FileStore struct{ Dir string }

func (s FileStore) path(name string) (string, error) {
	if !nameOK.MatchString(name) || name == "." || name == ".." {
		return "", errors.New("bad vault name")
	}
	return filepath.Join(s.Dir, name), nil
}

// Put writes atomically: temp file, fsync, rename.
func (s FileStore) Put(name string, data []byte) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	prot, err := protect(data)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(prot)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(p + ".tmp")
		return err
	}
	return os.Rename(p+".tmp", p)
}

func (s FileStore) Get(name string) ([]byte, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return unprotect(b)
}

func (s FileStore) Delete(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s FileStore) List() ([]string, error) {
	ents, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && nameOK.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out, err
}
