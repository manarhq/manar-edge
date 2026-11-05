package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/manarhq/manar-edge/internal/lazyre"
)

var keyNameRe = lazyre.New(`^[A-Za-z0-9._-]{1,100}$`)

// StoreSSH loads ~/.ssh/<name> into the ssh-agent and removes the file, but only after the
// vault holds an identical copy and the agent is seen to hold the key.
func (v *Vault) StoreSSH(name string) (*Entry, error) { return v.StoreSSHFor("", name) }

// StoreSSHFor is StoreSSH limited to one user's home (owner is a Who.Key(); "" means any single
// user who has that key). The command line uses it so a person can only move their own keys.
func (v *Vault) StoreSSHFor(owner, name string) (*Entry, error) {
	if v.Agent == nil && v.Keys == nil {
		return nil, errors.New("ssh keys cannot be protected on this computer yet")
	}
	if !keyNameRe.MatchString(name) || strings.HasSuffix(name, ".pub") {
		return nil, errors.New("bad key name")
	}
	var home, path string
	var who Who
	var orig []byte
	var fi FileInfo
	found := 0
	for _, h := range v.Homes() {
		w, err := WhoOfHome(h)
		if err != nil || (owner != "" && w.Key() != owner) {
			continue
		}
		p := filepath.Join(h, ".ssh", name)
		if b, f, err := w.Read(h, p); err == nil {
			home, path, who, orig, fi = h, p, w, b, f
			found++
		}
	}
	if found == 0 {
		return nil, ErrNoSuchSecret
	}
	if found > 1 {
		return nil, ErrAmbiguous
	}
	id := idOf("ssh", name, who.Key())
	if _, err := v.Store.Get("m-" + id); err == nil {
		return nil, ErrExists
	}
	if v.Keys != nil {
		return v.storeOwn(id, name, home, who, orig, fi)
	}
	fp, encrypted, err := v.Agent.Fingerprint(path)
	if err != nil {
		return nil, fmt.Errorf("reading the key: %w", err)
	}
	if encrypted {
		return nil, errors.New("this key has a passphrase; it is already protected, so Manar leaves it where it is")
	}
	e := &Entry{ID: id, Kind: "ssh", Ref: name, Owner: who.Key(), UID: who.UID, GID: who.GID, Home: home,
		File: fi, OrigSHA: sum(orig), Fingerprint: fp, StoredAt: time.Now().UTC()}
	if err := v.put(id, e, orig, []byte(fp)); err != nil {
		return nil, err
	}
	if err := v.Agent.Add(path); err != nil {
		v.drop(id)
		return nil, fmt.Errorf("loading the key into the ssh agent: %w", err)
	}
	if ok, err := v.Agent.Has(fp); err != nil || !ok {
		_ = v.Agent.Remove(path)
		v.drop(id)
		return nil, errors.New("the ssh agent does not hold the key: the file was kept")
	}
	if err := who.Remove(path); err != nil {
		return nil, fmt.Errorf("removing the key file: %w (the key is also in the agent and the vault)", err)
	}
	return e, nil
}

// RestoreSSH writes the exact key file back (bytes and mode) for every user who has it in the
// vault, checks it, then drops the key from the agent and the vault.
func (v *Vault) RestoreSSH(name string) error {
	es, err := v.entriesFor("ssh", name)
	errs := []error{err}
	for _, e := range es {
		errs = append(errs, v.restoreSSH(e))
	}
	return errors.Join(errs...)
}

func (v *Vault) restoreSSH(e *Entry) error {
	who := e.who()
	orig, err := v.Store.Get("o-" + e.ID)
	if err != nil {
		return fmt.Errorf("the vault has no original for this key: %w", err)
	}
	if cur, _, err := who.Read(e.Home, e.File.Path); err == nil && !bytes.Equal(cur, orig) {
		return errors.New("a different file now exists at the key's path: move it away first; the vault copy is kept")
	}
	if !who.Same(e.Home, e.File, orig) {
		if err := who.MkdirAll(filepath.Dir(e.File.Path)); err != nil {
			return err
		}
		if err := who.Write(e.File, orig); err != nil {
			return err
		}
	}
	if !who.Same(e.Home, e.File, orig) {
		return errors.New("the key file did not read back identically: the vault copy is kept")
	}
	if v.Keys != nil {
		v.Keys.Remove(e.Owner, e.Ref)
	} else if v.Agent != nil {
		_ = v.Agent.Remove(e.File.Path) // best effort: the file is back, which is what matters
	}
	v.drop(e.ID)
	v.profileAfterRestore(who, e)
	return nil
}

// storeOwn moves the key into the vault and into Manar's own agent. The order is the vault rule:
// vault copy written and read back, key loaded and seen, shell snippet written, only then the file
// removed. Any failure before the removal leaves the key file where it was.
func (v *Vault) storeOwn(id, name, home string, who Who, orig []byte, fi FileInfo) (*Entry, error) {
	_, fp, encrypted, err := ParseSSHKey(orig)
	if err != nil {
		return nil, err
	}
	if encrypted {
		return nil, errors.New("this key has a passphrase; it is already protected, so Manar leaves it where it is")
	}
	e := &Entry{ID: id, Kind: "ssh", Ref: name, Owner: who.Key(), UID: who.UID, GID: who.GID, Home: home,
		File: fi, OrigSHA: sum(orig), Fingerprint: fp, StoredAt: time.Now().UTC()}
	if err := v.put(id, e, orig, []byte(fp)); err != nil { // o-<id> is the encrypted backup of the exact bytes
		return nil, err
	}
	if _, err := v.Keys.Add(e.Owner, name, orig); err != nil || !v.Keys.Has(e.Owner, fp) {
		v.Keys.Remove(e.Owner, name)
		v.drop(id)
		return nil, errors.New("the agent does not hold the key: the file was kept")
	}
	if err := v.profileBefore(who, e); err != nil {
		v.Keys.Remove(e.Owner, name)
		v.drop(id)
		return nil, fmt.Errorf("setting up the shell snippet: %w (the key file was kept)", err)
	}
	if err := who.Remove(fi.Path); err != nil {
		return nil, fmt.Errorf("removing the key file: %w (the key is also in the agent and the vault)", err)
	}
	return e, nil
}

// RestoreSSHFor puts back one user's key (all of that user's keys when name is empty).
func (v *Vault) RestoreSSHFor(owner, name string) error {
	all, err := v.Entries()
	errs := []error{err}
	n := 0
	for _, e := range all {
		if e.Kind == "ssh" && e.Owner == owner && (name == "" || e.Ref == name) {
			n++
			errs = append(errs, v.restoreSSH(e))
		}
	}
	if n == 0 && name != "" {
		errs = append(errs, ErrNoSuchSecret)
	}
	return errors.Join(errs...)
}

// DetectSSH lists the unencrypted private keys in each user's ~/.ssh that are not in the vault yet:
// what the console offers to move. It reads names and key headers only; no key leaves the device.
func (v *Vault) DetectSSH() []string {
	have := map[string]bool{}
	if es, err := v.Entries(); err == nil {
		for _, e := range es {
			if e.Kind == "ssh" {
				have[e.Owner+"\x00"+e.Ref] = true
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, h := range v.Homes() {
		w, err := WhoOfHome(h)
		if err != nil {
			continue
		}
		var names []string
		_ = w.do(func() error {
			ents, err := os.ReadDir(filepath.Join(h, ".ssh"))
			for _, e := range ents {
				if !e.IsDir() && keyNameRe.MatchString(e.Name()) && !strings.HasSuffix(e.Name(), ".pub") {
					names = append(names, e.Name())
				}
			}
			return err
		})
		for _, n := range names {
			if len(out) >= 20 || have[w.Key()+"\x00"+n] || seen[n] {
				continue
			}
			b, _, err := w.Read(h, filepath.Join(h, ".ssh", n))
			if err != nil || len(b) > 16<<10 || !bytes.Contains(b[:min(len(b), 64)], []byte("PRIVATE KEY")) {
				continue
			}
			if _, _, enc, err := ParseSSHKey(b); err == nil && !enc {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// RestoreAll puts every vaulted secret back. Uninstall calls it before it changes anything else.
// It tries all of them and returns every failure.
func (v *Vault) RestoreAll() error {
	entries, err := v.Entries()
	errs := []error{err}
	for _, e := range entries {
		switch e.Kind {
		case "aws":
			errs = append(errs, wrap(e, v.RestoreAWS(e.Ref)))
		case "ssh":
			errs = append(errs, wrap(e, v.RestoreSSH(e.Ref)))
		}
	}
	if left, _ := v.Entries(); len(left) > 0 && errors.Join(errs...) == nil {
		errs = append(errs, fmt.Errorf("%d secrets are still in the vault", len(left)))
	}
	return errors.Join(errs...)
}

func wrap(e *Entry, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("restoring %s %s: %w", e.Kind, e.Ref, err)
}

// ExecAgent drives ssh-add and ssh-keygen. Sock is the agent socket (empty: the platform
// default, which on Windows is the OpenSSH Authentication Agent service).
type ExecAgent struct{ Sock string }

func (a ExecAgent) run(name string, args ...string) (string, error) {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command (callers pass ssh-add or ssh-keygen)
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	if a.Sock != "" {
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK="+a.Sock)
	}
	cmd.Env = append(cmd.Env, "SSH_ASKPASS=", "SSH_ASKPASS_REQUIRE=never")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

var fpRe = lazyre.New(`SHA256:[A-Za-z0-9+/=]+`)

func (a ExecAgent) Fingerprint(path string) (string, bool, error) {
	if _, err := a.run("ssh-keygen", "-y", "-P", "", "-f", path); err != nil {
		out, _ := a.run("ssh-keygen", "-y", "-P", "", "-f", path)
		if strings.Contains(out, "passphrase") {
			return "", true, nil
		}
		return "", false, fmt.Errorf("ssh-keygen: %s", strings.TrimSpace(out))
	}
	out, err := a.run("ssh-keygen", "-l", "-E", "sha256", "-f", path)
	fp := fpRe.FindString(out)
	if err != nil || fp == "" {
		return "", false, fmt.Errorf("ssh-keygen: %s", strings.TrimSpace(out))
	}
	return fp, false, nil
}

func (a ExecAgent) Add(path string) error {
	out, err := a.run("ssh-add", path)
	if err != nil {
		return fmt.Errorf("ssh-add: %s", strings.TrimSpace(out))
	}
	return nil
}

func (a ExecAgent) Has(fp string) (bool, error) {
	out, err := a.run("ssh-add", "-l", "-E", "sha256")
	if err != nil && !strings.Contains(out, "no identities") {
		return false, fmt.Errorf("ssh-add -l: %s", strings.TrimSpace(out))
	}
	return strings.Contains(out, fp), nil
}

func (a ExecAgent) Remove(path string) error {
	out, err := a.run("ssh-add", "-d", path)
	if err != nil {
		return fmt.Errorf("ssh-add -d: %s", strings.TrimSpace(out))
	}
	return nil
}
