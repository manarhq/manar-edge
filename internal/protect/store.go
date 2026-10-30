// Package protect installs Manar's protection into other AI tools (hooks, MCP wrapping, base-URL
// routing) and can undo every change. Every file is backed up byte for byte before its first edit;
// a file that cannot be parsed is never touched.
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

// Owner is who a written file belongs to (Linux: the user whose tool it is; Windows: ignored,
// the new file inherits the folder's ACL).
type Owner struct{ UID, GID int }

// Edit turns the current file content into the protected content. existed is false when the file
// is not there yet. Returning an error means "cannot be edited safely": the file is left alone.
type Edit func(cur []byte, existed bool) (out []byte, err error)

// FileEdit is one file a tool's protection touches.
type FileEdit struct {
	Path string
	Edit Edit
	// Mode is used when the file is created; an existing file keeps its own.
	Mode os.FileMode
}

// Outcome of one FileEdit.
type Outcome struct {
	Path    string
	Changed bool
	// Warning is set when the file was left untouched (malformed, unreadable, unwritable).
	Warning string
}

type entry struct {
	Path     string `json:"path"`
	Existed  bool   `json:"existed"`
	Backup   string `json:"backup,omitempty"` // absolute path of the byte-for-byte copy
	Mode     uint32 `json:"mode"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	AfterSHA string `json:"afterSha"`
	At       string `json:"at"`
}

type manifest struct {
	// Key is "<tool>|<user>".
	Tools map[string][]entry `json:"tools"`
}

// Store keeps the manifest and the backups under the device state directory.
type Store struct {
	mu  sync.Mutex
	dir string // <state>
	now func() time.Time
}

// NewStore returns a store rooted at the device state directory.
func NewStore(stateDir string) *Store { return &Store{dir: stateDir, now: time.Now} }

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
	return writeAtomic(s.manifestPath(), b, 0o600, nil, 0o700)
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
	key := tool + "|" + user
	var out []Outcome
	for _, fe := range edits {
		oc := Outcome{Path: fe.Path}
		cur, rerr := os.ReadFile(fe.Path)
		existed := rerr == nil
		if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			oc.Warning = "cannot read: " + rerr.Error()
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
		if ent == nil {
			e, berr := s.backup(tool, fe, cur, existed, owner)
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
		mode := os.FileMode(ent.Mode)
		if err := writeAtomic(fe.Path, next, mode, &owner, 0o755); err != nil {
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

func (s *Store) backup(tool string, fe FileEdit, cur []byte, existed bool, owner Owner) (entry, error) {
	ts := s.now().UTC().Format("20060102T150405.000000000Z")
	e := entry{Path: fe.Path, Existed: existed, Mode: uint32(fe.Mode), UID: owner.UID, GID: owner.GID, At: ts}
	if e.Mode == 0 {
		e.Mode = 0o644
	}
	if existed {
		if st, err := os.Stat(fe.Path); err == nil {
			e.Mode = uint32(st.Mode().Perm())
			e.UID, e.GID = fileOwner(st, owner)
		}
		dir := filepath.Join(s.dir, "backups", tool, ts)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return e, err
		}
		e.Backup = filepath.Join(dir, sha(append([]byte(fe.Path), 0))[:12]+".bak")
		if err := writeAtomic(e.Backup, cur, 0o600, nil, 0o700); err != nil {
			return e, err
		}
	}
	return e, nil
}

// Restore puts back every file of one tool and user exactly as it was. A file the user changed
// after Manar edited it is kept next to its backup before it is replaced.
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

func (s *Store) restoreEntry(e entry) error {
	cur, rerr := os.ReadFile(e.Path)
	if rerr == nil && sha(cur) != e.AfterSHA {
		keep := e.Path
		if e.Backup != "" {
			keep = e.Backup
		}
		if err := writeAtomic(keep+".edited-"+strconv.FormatInt(s.now().Unix(), 10), cur, 0o600, nil, 0o700); err != nil {
			return fmt.Errorf("cannot keep the changes made since: %w", err)
		}
	}
	if !e.Existed {
		if err := os.Remove(e.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	orig, err := os.ReadFile(e.Backup)
	if err != nil {
		return fmt.Errorf("backup unreadable: %w", err)
	}
	return writeAtomic(e.Path, orig, os.FileMode(e.Mode), &Owner{e.UID, e.GID}, 0o755)
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

// writeAtomic writes through a temp file in the same folder and renames it over the target, so a
// crash leaves the old or the new file, never half of one. A new parent folder gets dirMode.
func writeAtomic(path string, data []byte, mode os.FileMode, owner *Owner, dirMode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := mkdirOwned(dir, dirMode, owner); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".manar-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if owner != nil {
		if err := chown(tmp, *owner); err != nil {
			return err
		}
	}
	return os.Rename(tmp, path)
}

// mkdirOwned creates missing folders one by one so each belongs to the user, not to root.
func mkdirOwned(dir string, mode os.FileMode, owner *Owner) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := mkdirOwned(parent, mode, owner); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if owner != nil {
		return chown(dir, *owner)
	}
	return nil
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
