package vault

import (
	"bytes"
	"errors"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Keyring holds the decrypted ssh keys the Manar agent signs with, in memory, per user. They are
// loaded from the vault (never from the user's files) at start and after every change.
type Keyring struct {
	mu   sync.RWMutex
	keys map[string]*HeldKey
}

// HeldKey is one key the agent can sign with.
type HeldKey struct {
	Owner, Name, Fingerprint string
	Signer                   ssh.Signer
}

func NewKeyring() *Keyring { return &Keyring{keys: map[string]*HeldKey{}} }

func keyOf(owner, name string) string { return owner + "\x00" + name }

// ParseSSHKey reads an unencrypted private key. A key with a passphrase reports encrypted=true:
// it is already protected, so Manar leaves it where it is.
func ParseSSHKey(b []byte) (s ssh.Signer, fingerprint string, encrypted bool, err error) {
	raw, err := ssh.ParseRawPrivateKey(b)
	var miss *ssh.PassphraseMissingError
	if errors.As(err, &miss) {
		return nil, "", true, nil
	}
	if err != nil {
		return nil, "", false, errors.New("this is not a private key Manar can read")
	}
	s, err = ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, "", false, err
	}
	return s, ssh.FingerprintSHA256(s.PublicKey()), false, nil
}

// Add loads a key. It fails for an encrypted or unreadable key.
func (k *Keyring) Add(owner, name string, b []byte) (string, error) {
	s, fp, enc, err := ParseSSHKey(b)
	if err == nil && enc {
		err = errors.New("this key has a passphrase; it is already protected, so Manar leaves it where it is")
	}
	if err != nil {
		return "", err
	}
	k.mu.Lock()
	k.keys[keyOf(owner, name)] = &HeldKey{Owner: owner, Name: name, Fingerprint: fp, Signer: s}
	k.mu.Unlock()
	return fp, nil
}

func (k *Keyring) Remove(owner, name string) {
	k.mu.Lock()
	delete(k.keys, keyOf(owner, name))
	k.mu.Unlock()
}

func (k *Keyring) Has(owner, fp string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, h := range k.keys {
		if h.Owner == owner && h.Fingerprint == fp {
			return true
		}
	}
	return false
}

// HasBlob reports whether any user's vaulted key has this public key blob.
func (k *Keyring) HasBlob(blob []byte) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, h := range k.keys {
		if bytes.Equal(h.Signer.PublicKey().Marshal(), blob) {
			return true
		}
	}
	return false
}

// For lists one user's keys.
func (k *Keyring) For(owner string) []*HeldKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var out []*HeldKey
	for _, h := range k.keys {
		if h.Owner == owner {
			out = append(out, h)
		}
	}
	return out
}

// Owners lists users that hold at least one key.
func (k *Keyring) Owners() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, h := range k.keys {
		if !seen[h.Owner] {
			seen[h.Owner] = true
			out = append(out, h.Owner)
		}
	}
	return out
}

// Sync makes the keyring match the vault: keys that are in the vault are loaded, keys that are
// gone (restored by the CLI, by uninstall) are dropped.
func (k *Keyring) Sync(v *Vault) error {
	es, err := v.Entries()
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, e := range es {
		if e.Kind != "ssh" {
			continue
		}
		id := keyOf(e.Owner, e.Ref)
		want[id] = true
		k.mu.RLock()
		_, have := k.keys[id]
		k.mu.RUnlock()
		if have {
			continue
		}
		b, err := v.Store.Get("o-" + e.ID)
		if err != nil {
			continue
		}
		_, _ = k.Add(e.Owner, e.Ref, b)
	}
	k.mu.Lock()
	for id := range k.keys {
		if !want[id] {
			delete(k.keys, id)
		}
	}
	k.mu.Unlock()
	return nil
}

func ownerUID(owner string) (int, bool) {
	if !strings.HasPrefix(owner, "u") {
		return 0, false
	}
	n := 0
	for _, c := range owner[1:] {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, len(owner) > 1
}
