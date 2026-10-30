package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeAgent struct {
	keys      map[string]string // path -> fingerprint
	encrypted bool
	addFails  bool
	lies      bool // Add succeeds but the agent does not hold the key
	fpOf      func(path string) string
}

func (f *fakeAgent) Fingerprint(p string) (string, bool, error) {
	return "SHA256:fp-" + filepath.Base(p), f.encrypted, nil
}
func (f *fakeAgent) Add(p string) error {
	if f.addFails {
		return errors.New("agent down")
	}
	if !f.lies {
		fp, _, _ := f.Fingerprint(p)
		f.keys[p] = fp
	}
	return nil
}
func (f *fakeAgent) Has(fp string) (bool, error) {
	for _, v := range f.keys {
		if v == fp {
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeAgent) Remove(p string) error { delete(f.keys, p); return nil }

const keyBytes = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"

func sshEnv(t *testing.T, ag *fakeAgent) (*Vault, string) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	p := filepath.Join(home, ".ssh", "id_ed25519")
	_ = os.WriteFile(p, []byte(keyBytes), 0o600)
	_ = os.Chmod(p, 0o600)
	return &Vault{Store: FileStore{Dir: filepath.Join(t.TempDir(), "v")}, Agent: ag, Homes: func() []string { return []string{home} }}, p
}

func TestSSHStoreRemovesTheFileOnlyAfterTheAgentHoldsTheKey(t *testing.T) {
	ag := &fakeAgent{keys: map[string]string{}}
	v, p := sshEnv(t, ag)
	if _, err := v.StoreSSH("id_ed25519"); err != nil {
		t.Fatal(err)
	}
	if fileExists(p) || len(ag.keys) != 1 {
		t.Fatal("key file should be gone and the agent should hold the key")
	}
	if err := v.RestoreSSH("id_ed25519"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	st, _ := os.Stat(p)
	if string(got) != keyBytes || st.Mode().Perm() != 0o600 || len(ag.keys) != 0 {
		t.Fatal("restore is not exact")
	}
	if n, _ := v.Store.List(); len(n) != 0 {
		t.Fatalf("vault not empty: %v", n)
	}
}

func TestSSHFileStaysWhenTheAgentCannotBeTrusted(t *testing.T) {
	for name, ag := range map[string]*fakeAgent{
		"add fails":        {keys: map[string]string{}, addFails: true},
		"agent lies":       {keys: map[string]string{}, lies: true},
		"has a passphrase": {keys: map[string]string{}, encrypted: true},
	} {
		v, p := sshEnv(t, ag)
		if _, err := v.StoreSSH("id_ed25519"); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if got, _ := os.ReadFile(p); string(got) != keyBytes {
			t.Fatalf("%s: the key file was lost", name)
		}
		if n, _ := v.Store.List(); len(n) != 0 {
			t.Fatalf("%s: vault entries left: %v", name, n)
		}
	}
}

func TestSSHRestoreDoesNotOverwriteADifferentFile(t *testing.T) {
	ag := &fakeAgent{keys: map[string]string{}}
	v, p := sshEnv(t, ag)
	if _, err := v.StoreSSH("id_ed25519"); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p, []byte("someone else's key"), 0o600)
	if err := v.RestoreSSH("id_ed25519"); err == nil {
		t.Fatal("must refuse")
	}
	if got, _ := os.ReadFile(p); string(got) != "someone else's key" {
		t.Fatal("overwritten")
	}
	if _, err := v.Entry("ssh", "id_ed25519"); err != nil {
		t.Fatal("vault copy must be kept")
	}
}

func TestRestoreAllRestoresEverythingAndReportsEveryFailure(t *testing.T) {
	ag := &fakeAgent{keys: map[string]string{}}
	e := newEnv(t, credsFile, 0o600)
	e.v.Agent = ag
	sshPath := filepath.Join(e.home, ".ssh", "id_rsa")
	_ = os.MkdirAll(filepath.Dir(sshPath), 0o700)
	_ = os.WriteFile(sshPath, []byte(keyBytes), 0o600)
	if _, err := e.v.StoreAWS("default"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.v.StoreAWS("work"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.v.StoreSSH("id_rsa"); err != nil {
		t.Fatal(err)
	}
	// Break one entry; the others must still come back.
	_ = os.WriteFile(e.path, []byte("[x]\n"), 0o600)
	err := e.v.RestoreAll()
	if err == nil {
		t.Fatal("the broken aws entries must be reported")
	}
	if got, _ := os.ReadFile(sshPath); string(got) != keyBytes {
		t.Fatal("ssh key was not restored although another entry failed")
	}
}
