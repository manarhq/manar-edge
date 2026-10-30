package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const credsFile = "# my keys\r\n[default]\r\naws_access_key_id = AKIAEXAMPLE1\r\naws_secret_access_key = secretOne/abc+def\r\nregion = eu-west-1\r\n\r\n[work]\r\naws_access_key_id = AKIAEXAMPLE2\r\naws_secret_access_key = secretTwo\r\naws_session_token = tok\r\n"

type env struct {
	v    *Vault
	home string
	path string
}

func newEnv(t *testing.T, content string, mode os.FileMode) env {
	t.Helper()
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	p := filepath.Join(home, ".aws", "credentials")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, mode)
	return env{&Vault{Store: FileStore{Dir: filepath.Join(t.TempDir(), "vault")}, Exe: "/usr/local/bin/manar-edge",
		Homes: func() []string { return []string{home} }}, home, p}
}

func TestAWSRoundTripIsByteIdenticalWithPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644} {
		e := newEnv(t, credsFile, mode)
		if _, err := e.v.StoreAWS("default"); err != nil {
			t.Fatal(err)
		}
		cur, _ := os.ReadFile(e.path)
		s := string(cur)
		if strings.Contains(s, "secretOne") || strings.Contains(s, "AKIAEXAMPLE1") {
			t.Fatalf("secret still in the file:\n%s", s)
		}
		if !strings.Contains(s, `credential_process = "/usr/local/bin/manar-edge" secret aws default`) ||
			!strings.Contains(s, "secretTwo") /* other profile untouched */ || !strings.Contains(s, "region = eu-west-1") {
			t.Fatalf("unexpected rewrite:\n%s", s)
		}
		out, err := e.v.AWSCredentialProcess("default")
		if err != nil || !bytes.Contains(out, []byte("secretOne/abc+def")) {
			t.Fatalf("credential_process output: %s %v", out, err)
		}
		if err := e.v.RestoreAWS("default"); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(e.path)
		st, _ := os.Stat(e.path)
		if string(got) != credsFile || st.Mode().Perm() != mode {
			t.Fatalf("mode %v: not identical (perm %v)", mode, st.Mode().Perm())
		}
		if names, _ := e.v.Store.List(); len(names) != 0 {
			t.Fatalf("vault not emptied: %v", names)
		}
	}
}

func TestAWSRestoreAfterTheFileWasEdited(t *testing.T) {
	e := newEnv(t, credsFile, 0o600)
	if _, err := e.v.StoreAWS("default"); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(e.path)
	edited := string(cur) + "[extra]\r\naws_access_key_id = NEW\r\naws_secret_access_key = newsecret\r\n"
	_ = os.WriteFile(e.path, []byte(edited), 0o600)
	if err := e.v.RestoreAWS("default"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(e.path)
	if !strings.Contains(string(got), "secretOne/abc+def") || !strings.Contains(string(got), "newsecret") || strings.Contains(string(got), "credential_process") {
		t.Fatalf("got:\n%s", got)
	}
}

func TestAWSRestoreRefusesWhenManarLinesAreGoneAndKeepsTheVaultCopy(t *testing.T) {
	e := newEnv(t, credsFile, 0o600)
	if _, err := e.v.StoreAWS("default"); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(e.path, []byte("[other]\r\nx=1\r\n"), 0o600)
	if err := e.v.RestoreAWS("default"); err == nil {
		t.Fatal("must not claim success")
	}
	if _, err := e.v.AWSCredentialProcess("default"); err != nil {
		t.Fatal("the secret must still be in the vault")
	}
}

// corruptStore returns different bytes than it was given, like a failing disk.
type corruptStore struct{ Store }

func (c corruptStore) Get(n string) ([]byte, error) {
	b, err := c.Store.Get(n)
	if err == nil && strings.HasPrefix(n, "s-") && len(b) > 0 {
		b = append([]byte{}, b...)
		b[0] ^= 0xff
	}
	return b, err
}

func TestAWSOriginalIsUntouchedWhenTheVaultCannotBeVerified(t *testing.T) {
	e := newEnv(t, credsFile, 0o600)
	e.v.Store = corruptStore{e.v.Store}
	if _, err := e.v.StoreAWS("default"); err == nil {
		t.Fatal("expected failure")
	}
	got, _ := os.ReadFile(e.path)
	if string(got) != credsFile {
		t.Fatal("the original file changed although the vault copy was not verified")
	}
	if names, _ := e.v.Store.List(); len(names) != 0 {
		t.Fatalf("partial vault entries left: %v", names)
	}
}

type failPut struct {
	Store
	after int
}

func (f *failPut) Put(n string, b []byte) error {
	if f.after--; f.after < 0 {
		return errors.New("disk full")
	}
	return f.Store.Put(n, b)
}

func TestAWSOriginalIsUntouchedWhenTheVaultWriteFails(t *testing.T) {
	e := newEnv(t, credsFile, 0o600)
	e.v.Store = &failPut{e.v.Store, 2}
	if _, err := e.v.StoreAWS("default"); err == nil {
		t.Fatal("expected failure")
	}
	if got, _ := os.ReadFile(e.path); string(got) != credsFile {
		t.Fatal("original changed")
	}
}

func TestAWSRefusals(t *testing.T) {
	e := newEnv(t, credsFile, 0o600)
	if _, err := e.v.StoreAWS("nope"); !errors.Is(err, ErrNoSuchSecret) {
		t.Fatal(err)
	}
	if _, err := e.v.StoreAWS("bad name; rm"); err == nil {
		t.Fatal("bad profile accepted")
	}
	if _, err := e.v.StoreAWS("work"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.v.StoreAWS("work"); !errors.Is(err, ErrExists) {
		t.Fatalf("second store: %v", err)
	}
	e2 := newEnv(t, "[p]\naws_access_key_id=A\naws_secret_access_key=B\ncredential_process = x\n", 0o600)
	if _, err := e2.v.StoreAWS("p"); err == nil {
		t.Fatal("a profile that already has credential_process must be left alone")
	}
}

func TestStoreNamesCannotEscapeTheDirectory(t *testing.T) {
	s := FileStore{Dir: t.TempDir()}
	for _, n := range []string{"../x", "a/b", "", "..", "."} {
		if s.Put(n, []byte("x")) == nil {
			t.Errorf("name %q accepted", n)
		}
	}
	if err := s.Put("ok-1", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(s.Dir, "ok-1")); st.Mode().Perm() != 0o600 {
		t.Fatal("vault files must be 0600")
	}
}
