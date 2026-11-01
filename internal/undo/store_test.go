package undo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func restore(s *Store, id, path string) error {
	_, err := s.Restore(id, path, "", now.Add(time.Second))
	return err
}

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "undo"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSnapshotAndRestoreExisting(t *testing.T) {
	s := open(t)
	f := filepath.Join(t.TempDir(), "a.conf")
	os.WriteFile(f, []byte("original"), 0o640)
	rec, err := s.Snapshot("claude-code", f, now)
	if err != nil || !rec.Exists || rec.Size != 8 {
		t.Fatalf("rec %+v err %v", rec, err)
	}
	os.WriteFile(f, []byte("agent wrote this"), 0o600)
	if err := restore(s, rec.ID, f); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f); string(b) != "original" {
		t.Fatalf("got %q", b)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(f); st.Mode().Perm() != 0o640 {
			t.Fatalf("mode %v", st.Mode())
		}
		if st, _ := os.Stat(s.dataPath(rec.ID)); st.Mode().Perm() != 0o600 {
			t.Fatalf("snapshot is readable by others: %v", st.Mode())
		}
	}
}

func TestRestoreRemovesFileTheToolCreated(t *testing.T) {
	s := open(t)
	f := filepath.Join(t.TempDir(), "new.txt")
	rec, err := s.Snapshot("claude-code", f, now)
	if err != nil || rec.Exists {
		t.Fatalf("rec %+v err %v", rec, err)
	}
	os.WriteFile(f, []byte("x"), 0o600)
	if err := restore(s, rec.ID, f); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("file should be gone")
	}
}

func TestRestoreRefusesAnotherPath(t *testing.T) {
	s := open(t)
	d := t.TempDir()
	f, other := filepath.Join(d, "a"), filepath.Join(d, "b")
	os.WriteFile(f, []byte("1"), 0o600)
	rec, _ := s.Snapshot("t", f, now)
	if err := restore(s, rec.ID, other); err == nil {
		t.Fatal("a restore must not be redirected to another path")
	}
}

func TestRestoreDetectsTamperedCopy(t *testing.T) {
	s := open(t)
	f := filepath.Join(t.TempDir(), "a")
	os.WriteFile(f, []byte("1"), 0o600)
	rec, _ := s.Snapshot("t", f, now)
	os.WriteFile(s.dataPath(rec.ID), []byte("evil"), 0o600)
	if err := restore(s, rec.ID, f); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("err %v", err)
	}
}

func TestSymlinksAreNeverFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs privileges on Windows")
	}
	s := open(t)
	d := t.TempDir()
	secret := filepath.Join(d, "secret")
	os.WriteFile(secret, []byte("s"), 0o600)
	link := filepath.Join(d, "link")
	os.Symlink(secret, link)
	if _, err := s.Snapshot("t", link, now); err != ErrNotRegular {
		t.Fatalf("snapshot of a link: %v", err)
	}
	f := filepath.Join(d, "f")
	os.WriteFile(f, []byte("1"), 0o600)
	rec, _ := s.Snapshot("t", f, now)
	os.Remove(f)
	os.Symlink(secret, f)
	if err := restore(s, rec.ID, f); err == nil {
		t.Fatal("restore wrote through a link")
	}
	if b, _ := os.ReadFile(secret); string(b) != "s" {
		t.Fatal("the link target changed")
	}
}

func TestSizeCapAndRetention(t *testing.T) {
	s := open(t)
	f := filepath.Join(t.TempDir(), "big")
	os.WriteFile(f, make([]byte, MaxFileSize+1), 0o600)
	if _, err := s.Snapshot("t", f, now); err != ErrTooLarge {
		t.Fatalf("err %v", err)
	}
	g := filepath.Join(t.TempDir(), "g")
	os.WriteFile(g, []byte("1"), 0o600)
	rec, _ := s.Snapshot("t", g, now)
	if len(s.List(now.Add(6*24*time.Hour))) != 1 {
		t.Fatal("kept at 6 days")
	}
	s.Prune(now.Add(Retention + time.Minute))
	if _, err := s.Load(rec.ID); err == nil {
		t.Fatal("expired snapshot kept")
	}
	if _, err := os.Stat(s.dataPath(rec.ID)); !os.IsNotExist(err) {
		t.Fatal("expired copy kept")
	}
}

func TestOpenRefusesALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	d := t.TempDir()
	os.Mkdir(filepath.Join(d, "real"), 0o700)
	os.Symlink(filepath.Join(d, "real"), filepath.Join(d, "undo"))
	if _, err := Open(filepath.Join(d, "undo")); err == nil {
		t.Fatal("opened a store that is a link")
	}
}

func TestEditTargetAndOutside(t *testing.T) {
	proj := t.TempDir()
	in := func(tool, p string) []byte {
		return []byte(`{"tool_name":"` + tool + `","cwd":"` + filepath.ToSlash(proj) + `","tool_input":{"file_path":"` + filepath.ToSlash(p) + `"}}`)
	}
	p, cwd, ok := EditTarget(in("Write", filepath.Join(proj, "src", "a.go")))
	if !ok || Outside(p, cwd) {
		t.Fatalf("inside project: %v %v %v", p, cwd, ok)
	}
	outside := filepath.Join(t.TempDir(), "x.conf")
	p, cwd, ok = EditTarget(in("Edit", outside))
	if !ok || !Outside(p, cwd) {
		t.Fatalf("outside project: %v %v %v", p, cwd, ok)
	}
	if _, _, ok := EditTarget(in("Bash", outside)); ok {
		t.Fatal("a shell command is not a file edit")
	}
	if _, _, ok := EditTarget([]byte(`nope`)); ok {
		t.Fatal("garbage")
	}
	if !Outside(filepath.Join(proj, "..", "x"), proj) || !Outside("/x", "") {
		t.Fatal("parent and unknown folders are outside")
	}
	if runtime.GOOS != "windows" {
		// a link inside the project that points out of it is outside
		link := filepath.Join(proj, "l")
		os.Symlink(t.TempDir(), link)
		p, cwd, _ = EditTarget(in("Write", filepath.Join(link, "f")))
		if !Outside(p, cwd) {
			t.Fatalf("link out of the project counted as inside: %s", p)
		}
	}
}

func TestRestoreSavesTheCurrentFileFirstAndSaysWhenItChanged(t *testing.T) {
	s := open(t)
	f := filepath.Join(t.TempDir(), "a.conf")
	os.WriteFile(f, []byte("original"), 0o600)
	rec, _ := s.Snapshot("claude-code", f, now)
	os.WriteFile(f, []byte("my later work"), 0o600)
	os.Chtimes(f, now.Add(time.Hour), now.Add(time.Hour))
	res, err := s.Restore(rec.ID, f, rec.SHA256, now.Add(2*time.Hour))
	if err != nil || res.Backup == "" || res.Note == "" {
		t.Fatalf("%+v %v", res, err)
	}
	if b, _ := os.ReadFile(f); string(b) != "original" {
		t.Fatalf("got %q", b)
	}
	// the restore is itself undoable
	if _, err := s.Restore(res.Backup, f, "", now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f); string(b) != "my later work" {
		t.Fatalf("backup restore gave %q", b)
	}
}

func TestRestoreWithoutLaterChangesHasNoNote(t *testing.T) {
	s := open(t)
	f := filepath.Join(t.TempDir(), "a")
	os.WriteFile(f, []byte("1"), 0o600)
	rec, _ := s.Snapshot("t", f, time.Now())
	res, err := s.Restore(rec.ID, f, "", time.Now())
	if err != nil || res.Note != "" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRestoreRefusesAHashTheServiceDidNotRecord(t *testing.T) {
	s := open(t)
	f := filepath.Join(t.TempDir(), "a")
	os.WriteFile(f, []byte("1"), 0o600)
	rec, _ := s.Snapshot("t", f, now)
	// the user swaps the copy AND its record so they agree with each other
	evil := []byte("evil")
	os.WriteFile(s.dataPath(rec.ID), evil, 0o600)
	meta, _ := os.ReadFile(s.metaPath(rec.ID))
	sum := sha256.Sum256(evil)
	forged := strings.Replace(string(meta), rec.SHA256, hex.EncodeToString(sum[:]), 1)
	os.WriteFile(s.metaPath(rec.ID), []byte(forged), 0o600)
	if _, err := s.Restore(rec.ID, f, rec.SHA256, now); err == nil {
		t.Fatal("restored content whose hash is not the one the service recorded")
	}
}

func TestHelperOnlyOpensManarStoreFolders(t *testing.T) {
	var out strings.Builder
	if Helper([]string{"purge", t.TempDir()}, &out) == 0 {
		t.Fatal("purged an arbitrary folder")
	}
	d := filepath.Join(t.TempDir(), "manar-edge", "undo")
	os.MkdirAll(d, 0o700)
	if Helper([]string{"purge", d}, &out) != 0 {
		t.Fatal(out.String())
	}
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Fatal("not purged")
	}
}
