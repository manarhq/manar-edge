// Package undo keeps copies of files an AI tool is about to change outside its project folder, so
// the owner can put them back. The copies live in the user's own folder, are written and read by
// the user (the hook runs as the user; the service restores through a child process that has
// become the user), are never uploaded, and expire after 7 days. Only a small record (path, size,
// hash, time) is reported to Manar.
package undo

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	// MaxFileSize is the largest file that is snapshotted; bigger ones are skipped.
	MaxFileSize = 10 << 20
	// MaxStoreSize bounds one user's store; the oldest snapshots go first.
	MaxStoreSize = 256 << 20
	// Retention is how long a snapshot is kept.
	Retention = 7 * 24 * time.Hour
)

// Errors that mean "no snapshot was taken" and must never block the edit.
var (
	ErrTooLarge   = errors.New("file is larger than the snapshot limit")
	ErrNotRegular = errors.New("not a regular file (link, folder or device)")
)

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// ValidID says whether s is a snapshot id this package made.
func ValidID(s string) bool { return idPattern.MatchString(s) }

// Record is the metadata of one snapshot: what is stored beside the copy and what is reported.
type Record struct {
	ID     string `json:"id"`
	Tool   string `json:"tool"`
	Path   string `json:"path"`
	Exists bool   `json:"existed"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
	// Store is the folder this snapshot lives in, so a restore uses the same one even if
	// XDG_STATE_HOME differs between the hook and the helper.
	Store string    `json:"store"`
	Taken time.Time `json:"takenAt"`
}

// Store is one user's snapshot folder.
type Store struct{ Dir string }

// DefaultDir is the current user's store: $XDG_STATE_HOME or ~/.local/state, or %LOCALAPPDATA%.
func DefaultDir() (string, error) {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "manar-edge", "undo"), nil
		}
	} else if d := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "manar-edge", "undo"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(h) {
		return "", errors.New("cannot find the user's home folder")
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(h, "AppData", "Local", "manar-edge", "undo"), nil
	}
	return filepath.Join(h, ".local", "state", "manar-edge", "undo"), nil
}

// OpenDefault opens (creating it, 0700) the current user's store.
func OpenDefault() (*Store, error) {
	d, err := DefaultDir()
	if err != nil {
		return nil, err
	}
	return Open(d)
}

// Open creates dir (0700) if needed and refuses a link or a folder others can write to.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("the snapshot folder is not a plain folder")
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) metaPath(id string) string { return filepath.Join(s.Dir, id+".json") }
func (s *Store) dataPath(id string) string { return filepath.Join(s.Dir, id+".snap") }

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// openNoFollow opens path read-only without following a final link, and checks it is a regular
// file with the same identity as the Lstat just before.
func openNoFollow(path string) (*os.File, os.FileInfo, error) {
	l, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !l.Mode().IsRegular() {
		return nil, nil, ErrNotRegular
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || !os.SameFile(l, st) {
		f.Close()
		return nil, nil, ErrNotRegular
	}
	return f, st, nil
}

// Snapshot copies path (if it exists) before a tool changes it. path must be absolute.
func (s *Store) Snapshot(tool, path string, now time.Time) (*Record, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("path must be absolute")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	rec := &Record{ID: id, Tool: tool, Path: filepath.Clean(path), Taken: now.UTC(), Store: s.Dir}
	f, st, err := openNoFollow(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		rec.SHA256 = hex.EncodeToString(sha256.New().Sum(nil))
	case err != nil:
		return nil, err
	default:
		defer f.Close()
		if st.Size() > MaxFileSize {
			return nil, ErrTooLarge
		}
		tmp, err := os.CreateTemp(s.Dir, ".snap-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(tmp.Name())
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(f, MaxFileSize+1))
		if err == nil && n > MaxFileSize {
			err = ErrTooLarge
		}
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(tmp.Name(), 0o600); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp.Name(), s.dataPath(id)); err != nil {
			return nil, err
		}
		rec.Exists, rec.Size, rec.Mode, rec.SHA256 = true, n, uint32(st.Mode().Perm()), hex.EncodeToString(h.Sum(nil))
	}
	meta, _ := json.Marshal(rec)
	if err := writeFile(s.metaPath(id), meta); err != nil {
		os.Remove(s.dataPath(id))
		return nil, err
	}
	s.Prune(now)
	return rec, nil
}

func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// List returns the snapshots that have not expired, newest first.
func (s *Store) List(now time.Time) []Record {
	entries, _ := os.ReadDir(s.Dir)
	var out []Record
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidID(id) {
			continue
		}
		if r, err := s.Load(id); err == nil && now.Sub(r.Taken) < Retention {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Taken.After(out[j].Taken) })
	return out
}

// Load reads one record.
func (s *Store) Load(id string) (*Record, error) {
	if !ValidID(id) {
		return nil, errors.New("not a snapshot id")
	}
	b, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil || r.ID != id {
		return nil, errors.New("unreadable snapshot record")
	}
	return &r, nil
}

func (s *Store) remove(id string) {
	os.Remove(s.dataPath(id))
	os.Remove(s.metaPath(id))
}

// Prune deletes snapshots past retention, then the oldest ones until the store fits its cap.
func (s *Store) Prune(now time.Time) {
	entries, _ := os.ReadDir(s.Dir)
	for _, e := range entries { // leftovers of an interrupted write
		if strings.HasPrefix(e.Name(), ".snap-") || strings.HasSuffix(e.Name(), ".tmp") {
			if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > time.Hour {
				os.Remove(filepath.Join(s.Dir, e.Name()))
			}
		}
	}
	var live []Record
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidID(id) {
			continue
		}
		r, err := s.Load(id)
		if err != nil || now.Sub(r.Taken) >= Retention {
			s.remove(id)
			continue
		}
		live = append(live, *r)
	}
	sort.Slice(live, func(i, j int) bool { return live[i].Taken.After(live[j].Taken) })
	var total int64
	for _, r := range live {
		if total += r.Size; total > MaxStoreSize {
			s.remove(r.ID)
		}
	}
}

// Purge removes every snapshot (uninstall).
func (s *Store) Purge() error { return os.RemoveAll(s.Dir) }

// RestoreResult says what a restore did besides putting the file back.
type RestoreResult struct {
	// Backup is the snapshot taken of the file as it was just before the restore, so the restore
	// can itself be undone (`manar-edge undo restore <Backup>`). Empty when there was no file.
	Backup string `json:"backup,omitempty"`
	// Note is set when the file looks changed after the AI tool edited it.
	Note string `json:"note,omitempty"`
}

// changedAfter is how long after the snapshot a modification counts as later work: the snapshot
// is taken just before the tool writes.
const changedAfter = time.Minute

// Restore puts the file at path back as it was when snapshot id was taken. path must be the path
// the snapshot recorded: a request cannot redirect it. expectSHA, when given, must equal the
// content hash recorded for the snapshot (the device service passes the hash it keeps in a place
// the user cannot edit). The current file is saved first, so the restore can be undone. A file
// the tool created (it did not exist before) is removed. A link at the target is refused.
func (s *Store) Restore(id, path, expectSHA string, now time.Time) (*RestoreResult, error) {
	r, err := s.Load(id)
	if err != nil {
		return nil, fmt.Errorf("snapshot not found: %w", err)
	}
	if r.Path != filepath.Clean(path) || !filepath.IsAbs(r.Path) {
		return nil, errors.New("the path does not match the snapshot")
	}
	if expectSHA != "" && r.SHA256 != expectSHA {
		return nil, errors.New("the saved copy does not match what the device recorded")
	}
	var data []byte
	if r.Exists {
		f, _, err := openNoFollow(s.dataPath(id))
		if err != nil {
			return nil, fmt.Errorf("the saved copy is missing: %w", err)
		}
		data, err = io.ReadAll(io.LimitReader(f, MaxFileSize+1))
		f.Close()
		if err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != r.SHA256 {
			return nil, errors.New("the saved copy was changed and is not restored")
		}
	}
	res := &RestoreResult{}
	l, lerr := os.Lstat(r.Path)
	switch {
	case lerr == nil && !l.Mode().IsRegular():
		return nil, ErrNotRegular
	case lerr != nil && !errors.Is(lerr, os.ErrNotExist):
		return nil, lerr
	case lerr == nil:
		if l.ModTime().After(r.Taken.Add(changedAfter)) {
			res.Note = "The file was changed after the AI tool edited it."
		}
		b, err := s.Snapshot("undo-backup", r.Path, now)
		if err != nil {
			return nil, fmt.Errorf("cannot save the current file first, so nothing was changed: %w", err)
		}
		res.Backup = b.ID
		if res.Note != "" {
			res.Note += " Your later version was saved first: manar-edge undo restore " + b.ID
		}
	}
	if !r.Exists {
		if lerr == nil {
			return res, os.Remove(r.Path)
		}
		return res, nil
	}
	dir := filepath.Dir(r.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".manar-undo-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Chmod(os.FileMode(r.Mode)); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	return res, os.Rename(tmp.Name(), r.Path)
}
