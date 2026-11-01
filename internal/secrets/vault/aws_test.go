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
	v     *Vault
	home  string
	path  string
	owner string
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
	w, err := WhoOfHome(home)
	if err != nil {
		t.Fatal(err)
	}
	return env{&Vault{Store: FileStore{Dir: filepath.Join(t.TempDir(), "vault")}, Exe: "/usr/local/bin/manar-edge",
		Homes: func() []string { return []string{home} }}, home, p, w.Key()}
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
		out, err := e.v.AWSCredentialProcess(e.owner, "default")
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
	if _, err := e.v.AWSCredentialProcess(e.owner, "default"); err != nil {
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
	if _, err := e.v.StoreAWS("work"); !errors.Is(err, ErrNoSuchSecret) { // its keys are no longer in the file
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

// Two profiles in one file: restoring A must not touch B's lines, whatever the order.
func TestAWSRestoreSwapsOnlyItsOwnLines(t *testing.T) {
	for _, order := range [][]string{{"default", "work"}, {"work", "default"}} {
		e := newEnv(t, credsFile, 0o600)
		for _, p := range []string{"default", "work"} {
			if _, err := e.v.StoreAWS(p); err != nil {
				t.Fatal(err)
			}
		}
		// Someone edited the file, so restore must go through the line swap, not byte replace.
		cur, _ := os.ReadFile(e.path)
		_ = os.WriteFile(e.path, append(cur, []byte("# note\r\n")...), 0o600)
		if err := e.v.RestoreAWS(order[0]); err != nil {
			t.Fatal(err)
		}
		mid, _ := os.ReadFile(e.path)
		other := order[1]
		if !strings.Contains(string(mid), "secret aws "+other) {
			t.Fatalf("restoring %s removed %s's entry:\n%s", order[0], other, mid)
		}
		wantKey := map[string]string{"default": "secretOne/abc+def", "work": "secretTwo"}
		if !strings.Contains(string(mid), wantKey[order[0]]) || strings.Contains(string(mid), wantKey[other]) {
			t.Fatalf("wrong keys after restoring %s:\n%s", order[0], mid)
		}
		if err := e.v.RestoreAWS(other); err != nil {
			t.Fatal(err)
		}
		end, _ := os.ReadFile(e.path)
		if string(end) != credsFile+"# note\r\n" {
			t.Fatalf("final file differs:\n%q", end)
		}
	}
}

func TestRestoreAllOrderDoesNotMatter(t *testing.T) {
	e := newEnv(t, credsFile, 0o600)
	for _, p := range []string{"default", "work"} {
		if _, err := e.v.StoreAWS(p); err != nil {
			t.Fatal(err)
		}
	}
	cur, _ := os.ReadFile(e.path)
	_ = os.WriteFile(e.path, append(cur, []byte("# note\r\n")...), 0o600)
	if err := e.v.RestoreAll(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(e.path)
	if !strings.Contains(string(got), "secretOne/abc+def") || !strings.Contains(string(got), "secretTwo") || strings.Contains(string(got), "credential_process") {
		t.Fatalf("%s", got)
	}
}

func TestAWSRefusesLinksAndAmbiguousOwners(t *testing.T) {
	e := newEnv(t, credsFile, 0o600)
	real := filepath.Join(e.home, "elsewhere")
	_ = os.WriteFile(real, []byte(credsFile), 0o600)
	_ = os.Remove(e.path)
	_ = os.Symlink(real, e.path)
	if _, err := e.v.StoreAWS("default"); !errors.Is(err, ErrNoSuchSecret) {
		t.Fatalf("a credentials file that is a link must not be used: %v", err)
	}
	if got, _ := os.ReadFile(real); string(got) != credsFile {
		t.Fatal("the link target was changed")
	}

	a := newEnv(t, credsFile, 0o600)
	b := newEnv(t, credsFile, 0o600)
	a.v.Homes = func() []string { return []string{a.home, b.home} }
	if _, err := a.v.StoreAWS("default"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("two users with the same profile must not be guessed: %v", err)
	}
}

func TestRestoreRecreatesTheFolderPrivate(t *testing.T) {
	e := newEnv(t, credsFile, 0o600)
	if _, err := e.v.StoreAWS("default"); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(filepath.Join(e.home, ".aws"))
	if err := e.v.RestoreAWS("default"); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(e.home, ".aws"))
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("folder mode %v", st.Mode().Perm())
	}
}
