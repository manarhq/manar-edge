// Package protect installs Manar's protection into other AI tools (hooks, MCP wrapping, base-URL
// routing) and can undo every change. Every file is backed up byte for byte before its first edit;
// a file that cannot be parsed is never touched. The service runs as root, so every access to a
// user's files goes through an FS that acts as that user (fs.go).
package protect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Owner is whose files an operation touches: the account and the home folder below which links
// are refused. UID and GID are -1 where the OS has no such notion.
type Owner struct {
	UID, GID int
	Home     string
}

// Edit turns the current file content into the protected content. existed is false when the file
// is not there yet. Returning an error means "cannot be edited safely": the file is left alone.
type Edit func(cur []byte, existed bool) (out []byte, err error)

// FileEdit is one file a tool's protection touches.
type FileEdit struct {
	Path string
	Edit Edit
	// Kind says how to reverse the edit on content the user changed since (KindJSON, KindCodexTOML).
	Kind string
	// Mode is used when the file is created; an existing file keeps its own.
	Mode os.FileMode
}

// Outcome of one FileEdit.
type Outcome struct {
	Path    string
	Changed bool
	// Warning is set when the file was left untouched (malformed, a link, unreadable, unwritable).
	Warning string
	// Repaired: Manar had edited this file before, and everything of Manar's had been taken out of
	// it since; Apply put it back.
	Repaired bool
}

type entry struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Existed  bool   `json:"existed"`
	Backup   string `json:"backup,omitempty"` // absolute path of the byte-for-byte copy, in the state dir
	Mode     uint32 `json:"mode"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	Home     string `json:"home"`
	AfterSHA string `json:"afterSha"`
	At       string `json:"at"`
}

func (e entry) owner() Owner { return Owner{UID: e.UID, GID: e.GID, Home: e.Home} }

type manifest struct {
	// Key is "<tool>|<user>".
	Tools map[string][]entry `json:"tools"`
}

// Store keeps the manifest and the backups under the device state directory.
type Store struct {
	mu  sync.Mutex
	dir string // <state>
	now func() time.Time
	// fs is replaced by tests; the default acts as the file's owner.
	fs func(Owner) FS
}

// NewStore returns a store rooted at the device state directory.
func NewStore(stateDir string) *Store {
	return &Store{dir: stateDir, now: time.Now, fs: newUserFS}
}

func (s *Store) manifestPath() string { return filepath.Join(s.dir, "protect", "manifest.json") }

func (s *Store) load() (*manifest, error) {
	m := &manifest{Tools: map[string][]entry{}}
	b, err := os.ReadFile(s.manifestPath())
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("protect manifest is damaged (backups are in %s): %w", filepath.Join(s.dir, "backups"), err)
	}
	if m.Tools == nil {
		m.Tools = map[string][]entry{}
	}
	return m, nil
}

func (s *Store) save(m *manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeState(s.manifestPath(), b, 0o600)
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Apply runs the edits for one tool and user. Idempotent: an edit that changes nothing writes
// nothing and takes no backup. The backup and the manifest are written before the file is.
func (s *Store) Apply(tool, user string, owner Owner, edits []FileEdit) ([]Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return nil, err
	}
	fsys := s.fs(owner)
	key := tool + "|" + user
	var out []Outcome
	for _, fe := range edits {
		oc := Outcome{Path: fe.Path}
		cur, existed, curMode, rerr := fsys.Read(fe.Path)
		if rerr != nil {
			oc.Warning = "left untouched: " + rerr.Error()
			out = append(out, oc)
			continue
		}
		next, eerr := fe.Edit(cur, existed)
		if eerr != nil {
			oc.Warning = "left untouched: " + eerr.Error()
			out = append(out, oc)
			continue
		}
		if bytes.Equal(next, cur) || (!existed && len(next) == 0) {
			out = append(out, oc)
			continue
		}
		ent := findEntry(m.Tools[key], fe.Path)
		// Every edit Manar makes names its own binary (hook command, MCP wrapper).
		oc.Repaired = ent != nil && !bytes.Contains(cur, []byte("manar-edge"))
		if ent == nil {
			e, berr := s.backup(tool, fe, cur, existed, curMode, owner)
			if berr != nil {
				oc.Warning = "left untouched, cannot back up: " + berr.Error()
				out = append(out, oc)
				continue
			}
			m.Tools[key] = append(m.Tools[key], e)
			ent = &m.Tools[key][len(m.Tools[key])-1]
			if err := s.save(m); err != nil { // the way back is on disk before the edit is
				m.Tools[key] = m.Tools[key][:len(m.Tools[key])-1]
				oc.Warning = "left untouched, cannot record the backup: " + err.Error()
				out = append(out, oc)
				continue
			}
		}
		if err := fsys.Write(fe.Path, next, os.FileMode(ent.Mode)); err != nil {
			oc.Warning = "cannot write: " + err.Error()
			out = append(out, oc)
			continue
		}
		ent.AfterSHA = sha(next)
		if err := s.save(m); err != nil {
			return out, err
		}
		oc.Changed = true
		out = append(out, oc)
	}
	return out, nil
}

func findEntry(es []entry, path string) *entry {
	for i := range es {
		if es[i].Path == path {
			return &es[i]
		}
	}
	return nil
}

func (s *Store) backup(tool string, fe FileEdit, cur []byte, existed bool, curMode os.FileMode, owner Owner) (entry, error) {
	ts := s.now().UTC().Format("20060102T150405.000000000Z")
	e := entry{Path: fe.Path, Kind: fe.Kind, Existed: existed, Mode: uint32(fe.Mode), UID: owner.UID, GID: owner.GID, Home: owner.Home, At: ts}
	if e.Mode == 0 {
		e.Mode = 0o644
	}
	if existed {
		e.Mode = uint32(curMode)
		dir := filepath.Join(s.dir, "backups", tool, ts)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return e, err
		}
		e.Backup = filepath.Join(dir, sha([]byte(fe.Path))[:12]+".bak")
		if err := writeState(e.Backup, cur, 0o600); err != nil {
			return e, err
		}
	}
	return e, nil
}

// Restore undoes Manar's changes for one tool and user.
func (s *Store) Restore(tool, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	return s.restoreKey(m, tool+"|"+user)
}

// RestoreAll restores everything (uninstall). It does not stop at the first failure.
func (s *Store) RestoreAll() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return []error{err}
	}
	var errs []error
	for key := range m.Tools {
		if err := s.restoreKey(m, key); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", key, err))
		}
	}
	return errs
}

func (s *Store) restoreKey(m *manifest, key string) error {
	var failed []error
	var left []entry
	for _, e := range m.Tools[key] {
		if err := s.restoreEntry(e); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", e.Path, err))
			left = append(left, e) // keep the way back for a retry
		}
	}
	if len(left) == 0 {
		delete(m.Tools, key)
	} else {
		m.Tools[key] = left
	}
	if err := s.save(m); err != nil {
		failed = append(failed, err)
	}
	return errors.Join(failed...)
}

// restoreEntry puts a file back. If it is exactly what Manar last wrote, the original backup
// goes back byte for byte. If the user changed it since, Manar's own edits are reversed on the
// current content instead, so nothing the user did is lost, and a copy of the file as it was is
// kept beside it, owned by the user.
func (s *Store) restoreEntry(e entry) error {
	fsys := s.fs(e.owner())
	cur, exists, curMode, err := fsys.Read(e.Path)
	if err != nil {
		return err
	}
	if !exists {
		return nil // the user removed it; nothing of ours is left there
	}
	if sha(cur) == e.AfterSHA {
		if !e.Existed {
			return fsys.Remove(e.Path)
		}
		orig, err := os.ReadFile(e.Backup)
		if err != nil {
			return fmt.Errorf("backup unreadable: %w", err)
		}
		return fsys.Write(e.Path, orig, os.FileMode(e.Mode))
	}
	next, err := undoFor(e.Kind)(cur, true)
	if err != nil {
		return fmt.Errorf("changed since Manar edited it and cannot be reversed automatically (%v); the original is in %s", err, e.Backup)
	}
	keep := e.Path + ".manar-before-restore-" + strconv.FormatInt(s.now().Unix(), 10)
	if err := fsys.Write(keep, cur, 0o600); err != nil {
		return fmt.Errorf("cannot keep a copy of the changed file: %w", err)
	}
	if !e.Existed && emptyish(next) {
		return fsys.Remove(e.Path)
	}
	return fsys.Write(e.Path, next, curMode)
}

// Files lists the files Manar currently changes for a tool and user (for the install report).
func (s *Store) Files(tool, user string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range m.Tools[tool+"|"+user] {
		out = append(out, e.Path)
	}
	return out
}

// Tools lists the "<tool>|<user>" keys that have changes.
func (s *Store) Tools() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return nil
	}
	var out []string
	for k := range m.Tools {
		out = append(out, k)
	}
	return out
}

// writeState writes a file in the device state directory, which only root can reach.
func writeState(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".manar-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// HasUID reports whether Manar changes any file for the account with this uid.
func (s *Store) HasUID(uid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return false
	}
	for _, es := range m.Tools {
		for _, e := range es {
			if strconv.Itoa(e.UID) == uid {
				return true
			}
		}
	}
	return false
}

// Has reports whether Manar currently changes anything for this tool and user.
func (s *Store) Has(tool, user string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	return err == nil && len(m.Tools[tool+"|"+user]) > 0
}

// Describe lists what Manar changed for a tool and user, one line per file, for the install
// report and the console's AI tools page.
func (s *Store) Describe(tool, user string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range m.Tools[tool+"|"+user] {
		if e.Existed {
			out = append(out, e.Path+" (edited; the original is backed up and comes back when protection is turned off)")
		} else {
			out = append(out, e.Path+" (created by Manar; removed when protection is turned off)")
		}
	}
	return out
}
