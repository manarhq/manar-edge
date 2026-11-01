//go:build !windows

package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// On Linux every blob is AES-256-GCM encrypted with a key that only the service (root) can read:
// <state>/vault.key, 0600, next to the 0700 vault folder. A copy of the vault folder alone (a
// backup, a disk image) holds no readable secret. Blobs written before this existed have no
// header and are read as they are, then encrypted at the next write.
const encMagic = "MV1\x00"

var keyMu sync.Mutex

func masterKey(dir string, create bool) ([]byte, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	p := filepath.Join(filepath.Dir(dir), "vault.key")
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		return b, nil
	} else if err == nil {
		return nil, errors.New("the vault key file is damaged")
	} else if !os.IsNotExist(err) || !create {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	_, werr := f.Write(k)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		_ = os.Remove(p)
		return nil, err
	}
	return k, nil
}

func protect(dir string, b []byte) ([]byte, error) {
	k, err := masterKey(dir, true)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	n := make([]byte, g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return g.Seal(append([]byte(encMagic), n...), n, b, nil), nil
}

func unprotect(dir string, b []byte) ([]byte, error) {
	if len(b) < len(encMagic) || string(b[:len(encMagic)]) != encMagic {
		return b, nil // written before encryption existed
	}
	k, err := masterKey(dir, false)
	if err != nil {
		return nil, errors.New("the vault key is missing: the vault cannot be read")
	}
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	b = b[len(encMagic):]
	if len(b) < g.NonceSize() {
		return nil, errors.New("the vault file is damaged")
	}
	return g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
}
