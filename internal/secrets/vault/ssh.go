package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var keyNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// StoreSSH loads ~/.ssh/<name> into the ssh-agent and removes the file, but only after the
// vault holds an identical copy and the agent is seen to hold the key.
func (v *Vault) StoreSSH(name string) (*Entry, error) {
	if v.Agent == nil {
		return nil, errors.New("ssh keys cannot be protected on this computer yet")
	}
	if !keyNameRe.MatchString(name) || strings.HasSuffix(name, ".pub") {
		return nil, errors.New("bad key name")
	}
	id := idOf("ssh", name)
	if _, err := v.Store.Get("m-" + id); err == nil {
		return nil, ErrExists
	}
	var path string
	for _, h := range v.Homes() {
		if p := filepath.Join(h, ".ssh", name); fileExists(p) {
			path = p
			break
		}
	}
	if path == "" {
		return nil, ErrNoSuchSecret
	}
	orig, fi, err := readFile(path)
	if err != nil {
		return nil, err
	}
	fp, encrypted, err := v.Agent.Fingerprint(path)
	if err != nil {
		return nil, fmt.Errorf("reading the key: %w", err)
	}
	if encrypted {
		return nil, errors.New("this key has a passphrase; it is already protected, so Manar leaves it where it is")
	}
	e := &Entry{ID: id, Kind: "ssh", Ref: name, File: fi, OrigSHA: sum(orig), Fingerprint: fp, StoredAt: time.Now().UTC()}
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
	if err := os.Remove(path); err != nil {
		return nil, fmt.Errorf("removing the key file: %w (the key is also in the agent and the vault)", err)
	}
	return e, nil
}

// RestoreSSH writes the exact key file back (bytes and mode), checks it, then drops the key from
// the agent and the vault.
func (v *Vault) RestoreSSH(name string) error {
	e, err := v.Entry("ssh", name)
	if err != nil {
		return err
	}
	orig, err := v.Store.Get("o-" + e.ID)
	if err != nil {
		return fmt.Errorf("the vault has no original for this key: %w", err)
	}
	if cur, _, err := readFile(e.File.Path); err == nil && !bytes.Equal(cur, orig) {
		return errors.New("a different file now exists at the key's path: move it away first; the vault copy is kept")
	}
	if !sameFile(e.File, orig) {
		_ = os.MkdirAll(filepath.Dir(e.File.Path), 0o700)
		if err := writeFile(e.File, orig); err != nil {
			return err
		}
	}
	if !sameFile(e.File, orig) {
		return errors.New("the key file did not read back identically: the vault copy is kept")
	}
	if v.Agent != nil {
		_ = v.Agent.Remove(e.File.Path) // best effort: the file is back, which is what matters
	}
	v.drop(e.ID)
	return nil
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
	return errors.Join(errs...)
}

func wrap(e *Entry, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("restoring %s %s: %w", e.Kind, e.Ref, err)
}

func fileExists(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }

// ExecAgent drives ssh-add and ssh-keygen. Sock is the agent socket (empty: the platform
// default, which on Windows is the OpenSSH Authentication Agent service).
type ExecAgent struct{ Sock string }

func (a ExecAgent) run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	if a.Sock != "" {
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK="+a.Sock)
	}
	cmd.Env = append(cmd.Env, "SSH_ASKPASS=", "SSH_ASKPASS_REQUIRE=never")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

var fpRe = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`)

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
