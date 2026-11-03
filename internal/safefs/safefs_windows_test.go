//go:build windows

package safefs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
}

func TestWriteReadRemove(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".claude", "sub", "settings.json")
	if _, exists, err := Read(home, p, 1<<20); err != nil || exists {
		t.Fatalf("Read missing = %v, %v", exists, err)
	}
	if err := Write(home, p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := Write(home, p, []byte("two")); err != nil { // replaces
		t.Fatal(err)
	}
	b, exists, err := Read(home, p, 1<<20)
	if err != nil || !exists || string(b) != "two" {
		t.Fatalf("Read = %q, %v, %v", b, exists, err)
	}
	if _, _, err := Read(home, p, 2); err == nil {
		t.Fatal("Read past max did not fail")
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("temporary files left behind: %v", ents)
	}
	if err := Remove(home, p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("still there: %v", err)
	}
	if err := Remove(home, p); err != nil {
		t.Fatalf("Remove of a missing file: %v", err)
	}
	if err := MkdirAll(home, filepath.Join(home, "a", "b")); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(home, "a", "b")); err != nil || !st.IsDir() {
		t.Fatalf("MkdirAll: %v", err)
	}
}

func TestJunctionIsRefused(t *testing.T) {
	home := t.TempDir()
	elsewhere := t.TempDir()
	victim := filepath.Join(elsewhere, "settings.json")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	junction(t, filepath.Join(home, ".claude"), elsewhere)
	p := filepath.Join(home, ".claude", "settings.json")
	if err := Write(home, p, []byte("evil")); !errors.Is(err, ErrLink) {
		t.Fatalf("Write through a junction = %v", err)
	}
	if _, _, err := Read(home, p, 1<<20); !errors.Is(err, ErrLink) {
		t.Fatalf("Read through a junction = %v", err)
	}
	if err := Remove(home, p); !errors.Is(err, ErrLink) {
		t.Fatalf("Remove through a junction = %v", err)
	}
	if err := MkdirAll(home, filepath.Join(home, ".claude", "x")); !errors.Is(err, ErrLink) {
		t.Fatalf("MkdirAll through a junction = %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "victim" {
		t.Fatalf("the junction target changed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "x")); err == nil {
		t.Fatal("a folder was made through the junction")
	}
	// A junction above the home is refused as well.
	up := filepath.Join(t.TempDir(), "j")
	junction(t, up, home)
	if err := Write(filepath.Join(up), filepath.Join(up, "f"), []byte("x")); !errors.Is(err, ErrLink) {
		t.Fatalf("Write below a junctioned home = %v", err)
	}
}

func TestHardLinkIsNotWrittenThrough(t *testing.T) {
	home := t.TempDir()
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, "settings.json")
	if err := os.Link(other, p); err != nil {
		t.Skipf("hard links not available here: %v", err)
	}
	if _, _, err := Read(home, p, 1<<20); err == nil {
		t.Fatal("Read of a hard link succeeded")
	}
	if err := Write(home, p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(other); string(b) != "other" {
		t.Fatalf("written through a hard link: %q", b)
	}
}

func TestOutsideHome(t *testing.T) {
	home := t.TempDir()
	for _, p := range []string{home, filepath.Join(home, "..", "x"), `relative\x`, filepath.Join(t.TempDir(), "x")} {
		if err := Write(home, p, nil); err == nil {
			t.Errorf("Write(%q) accepted", p)
		}
	}
	if _, err := openRel(0, `a\b`, 0, 0, 0, 0); err == nil {
		t.Error("a name with a separator was accepted")
	}
	if _, err := openRel(0, `a:stream`, 0, 0, 0, 0); err == nil {
		t.Error("a stream name was accepted")
	}
}
