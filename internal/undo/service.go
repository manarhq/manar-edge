package undo

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/daemon"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

// The device service side. Hooks (running as the user) take snapshots and tell the service over
// the local relay; the service queues a small record for Manar, and carries out restores that
// the console asked for, each in a child process that has become the user who owns the snapshot.

// Default is the one service instance; protect's relay hands it the records hooks send.
var Default = &Service{index: map[string]entry{}, rate: map[string][]time.Time{}, runAs: RunAs, pollEvery: 15 * time.Second, now: time.Now}

func init() { daemon.Register(Default) }

// entry is what the service (root) remembers about one snapshot. The user cannot edit it: a
// restore trusts this, not the user's folder, for the content hash, the path and the store.
type entry struct {
	ID      string    `json:"id"`
	Caller  string    `json:"caller"`
	At      time.Time `json:"at"`
	SHA     string    `json:"sha"` // SHA-256 of the saved content, when the hook reported it
	Store   string    `json:"store"`
	Path    string    `json:"path"`
	Existed bool      `json:"existed"`
}

// Service is the daemon module "undo".
type Service struct {
	mu        sync.Mutex
	stateDir  string
	exe       string
	key       []byte // per-device key: Manar only ever sees HMAC(key, content hash)
	queue     []wireChange
	index     map[string]entry // snapshot id -> entry
	rate      map[string][]time.Time
	runAs     func(uid int, exe string, args ...string) ([]byte, error)
	pollEvery time.Duration
	lastPrune time.Time
	now       func() time.Time
}

// Limits that keep a local caller from filling the index or the queue.
const (
	maxPerCaller   = 1000
	reportsPerMin  = 120
	maxQueuedItems = 500
)

// Configure sets the device state dir (index, key) and the binary used for helpers.
func Configure(stateDir, exe string) {
	Default.mu.Lock()
	defer Default.mu.Unlock()
	Default.stateDir, Default.exe = stateDir, exe
	Default.loadKey()
	Default.loadIndex()
}

func (s *Service) Name() string { return "undo" }

var (
	toolPattern = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	shaPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Report accepts one record from a hook. caller is the kernel's view of who sent it. An id that
// already belongs to another caller is refused, so nobody can take over a snapshot.
func (s *Service) Report(caller string, r Record) error {
	if !ValidID(r.ID) || !toolPattern.MatchString(r.Tool) || !shaPattern.MatchString(r.SHA256) ||
		!filepath.IsAbs(r.Path) || len(r.Path) > 1024 || r.Size < 0 || strings.ContainsRune(r.Path, 0) ||
		!filepath.IsAbs(r.Store) || len(r.Store) > 1024 || strings.ContainsRune(r.Store, 0) {
		return errors.New("bad record")
	}
	if _, ok := callerUID(caller); !ok && !strings.HasPrefix(caller, "sid:") {
		return errors.New("unknown caller")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	recent := s.rate[caller][:0]
	for _, t := range s.rate[caller] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= reportsPerMin {
		s.rate[caller] = recent
		return errors.New("too many reports")
	}
	s.rate[caller] = append(recent, now)
	if old, ok := s.index[r.ID]; ok {
		if old.Caller != caller {
			return errors.New("that snapshot belongs to someone else")
		}
		return nil // the same caller sent it twice
	}
	n := 0
	for _, e := range s.index {
		if e.Caller == caller {
			n++
		}
	}
	if n >= maxPerCaller {
		return errors.New("too many saved copies for this account")
	}
	e := entry{ID: r.ID, Caller: caller, At: now, SHA: r.SHA256, Store: filepath.Clean(r.Store), Path: filepath.Clean(r.Path), Existed: r.Exists}
	s.index[r.ID] = e
	s.appendIndex(e)
	s.queue = append(s.queue, wireChange{
		SnapshotID: r.ID, Tool: r.Tool, Path: e.Path, Existed: r.Exists, SizeBytes: r.Size,
		SHA256: s.mac(r.SHA256), TakenAt: r.Taken.UTC().Format(time.RFC3339),
	})
	if len(s.queue) > maxQueuedItems {
		s.queue = s.queue[len(s.queue)-maxQueuedItems:]
	}
	return nil
}

func callerUID(c string) (int, bool) {
	v, ok := strings.CutPrefix(c, "uid:")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 0
}

// mac is what Manar sees instead of a hash of the user's file content.
func (s *Service) mac(contentSHA string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(contentSHA))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Service) loadKey() {
	if s.stateDir == "" {
		s.key = make([]byte, 32)
		_, _ = rand.Read(s.key)
		return
	}
	p := filepath.Join(s.stateDir, "undo-key")
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		s.key = b
		return
	}
	s.key = make([]byte, 32)
	_, _ = rand.Read(s.key)
	_ = os.MkdirAll(s.stateDir, 0o700)
	_ = os.WriteFile(p, s.key, 0o600)
}

func (s *Service) indexPath() string { return filepath.Join(s.stateDir, "undo-index.jsonl") }

// loadIndex replays the append-only index file, dropping what is past retention.
func (s *Service) loadIndex() {
	s.index = map[string]entry{}
	if s.stateDir == "" {
		return
	}
	f, err := os.Open(s.indexPath())
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		var e entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && ValidID(e.ID) && s.now().Sub(e.At) < Retention {
			s.index[e.ID] = e
		}
	}
}

// appendIndex adds one line: a report never rewrites the file.
func (s *Service) appendIndex(e entry) {
	if s.stateDir == "" {
		return
	}
	f, err := os.OpenFile(s.indexPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	_, _ = f.Write(append(b, '\n'))
}

// compactIndex rewrites the file from memory (once an hour, after expired entries are dropped).
func (s *Service) compactIndex() {
	if s.stateDir == "" {
		return
	}
	var b []byte
	for _, e := range s.index {
		line, _ := json.Marshal(e)
		b = append(append(b, line...), '\n')
	}
	tmp := s.indexPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.indexPath())
	}
}

type wireChange struct {
	SnapshotID string `json:"snapshotId"`
	Tool       string `json:"tool"`
	Path       string `json:"path"`
	Existed    bool   `json:"existed"`
	SizeBytes  int64  `json:"sizeBytes"`
	SHA256     string `json:"sha256"`
	TakenAt    string `json:"takenAt"`
}

type restoreItem struct {
	ID         string `json:"id"`
	SnapshotID string `json:"snapshotId"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"` // Manar's copy: HMAC of the content hash, not the hash
}

func (s *Service) Start(ctx context.Context, c *hostclient.Client) error {
	t := time.NewTicker(s.pollEvery)
	defer t.Stop()
	for {
		s.tick(ctx, c)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// api is what tick needs from the Manar client.
type api interface {
	Config(ctx context.Context) (*hostclient.Config, error)
	Do(ctx context.Context, method, path string, in, out any) error
}

func (s *Service) tick(ctx context.Context, c api) {
	cfg, err := c.Config(ctx)
	if err != nil || cfg.Status != "APPROVED" || !slices.Contains(cfg.Features, "undo") {
		return
	}
	s.flush(ctx, c)
	var pending struct {
		Items []restoreItem `json:"items"`
	}
	if err := c.Do(ctx, "GET", "/undo/restores", nil, &pending); err != nil {
		log.Printf("manar-edge: undo: restores: %v", err)
		return
	}
	for _, it := range pending.Items {
		res := map[string]string{"status": "RESTORED"}
		note, err := s.restore(it)
		if err != nil {
			res = map[string]string{"status": "FAILED", "error": truncate(err.Error(), 280)}
		} else if note != "" {
			res["note"] = truncate(note, 280)
		}
		if err := c.Do(ctx, "POST", "/undo/restores/"+it.ID+"/result", res, nil); err != nil {
			log.Printf("manar-edge: undo: result: %v", err)
		}
	}
	s.maybePrune()
}

func (s *Service) flush(ctx context.Context, c api) {
	s.mu.Lock()
	n := min(len(s.queue), 50)
	body := slices.Clone(s.queue[:n])
	s.mu.Unlock()
	if n == 0 {
		return
	}
	if err := c.Do(ctx, "POST", "/undo/changes", map[string]any{"changes": body}, nil); err != nil {
		log.Printf("manar-edge: undo: report: %v", err)
		return
	}
	s.mu.Lock()
	s.queue = s.queue[min(n, len(s.queue)):]
	s.mu.Unlock()
}

// restore runs one restore the console asked for. What it acts on comes from the service's own
// index (path, store, content hash), and Manar's record must agree with it.
func (s *Service) restore(it restoreItem) (note string, err error) {
	if !ValidID(it.SnapshotID) || !filepath.IsAbs(it.Path) {
		return "", errors.New("the request is not valid")
	}
	s.mu.Lock()
	e, ok := s.index[it.SnapshotID]
	exe := s.exe
	macOK := ok && hmac.Equal([]byte(s.mac(e.SHA)), []byte(it.SHA256))
	s.mu.Unlock()
	switch {
	case !ok:
		return "", errors.New("this device does not know that saved copy")
	case filepath.Clean(it.Path) != e.Path || !macOK:
		return "", errors.New("the request does not match what this device recorded")
	}
	uid, ok := callerUID(e.Caller)
	if !ok {
		return "", ErrNoRunAsMsg()
	}
	out, rerr := s.runAs(uid, exe, "__undo", "restore", it.SnapshotID, e.Path, e.Store, e.SHA)
	var r struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		Note   string `json:"note"`
		Backup string `json:"backup"`
	}
	if jerr := json.Unmarshal(out, &r); jerr == nil && !r.OK && r.Error != "" {
		return "", errors.New(r.Error)
	}
	if rerr != nil {
		return "", rerr
	}
	if !r.OK {
		return "", errors.New("the restore did not report success")
	}
	return r.Note, nil
}

// ErrNoRunAsMsg is the failure for a snapshot taken by an account the service cannot act as.
func ErrNoRunAsMsg() error {
	return errors.New("restoring from the console is not available for this account: run `manar-edge undo restore <id>` on the device")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type userStore struct {
	uid   int
	store string
}

// stores lists every (account, store folder) the index knows. Callers hold s.mu.
func (s *Service) stores() map[userStore]bool {
	m := map[userStore]bool{}
	for _, e := range s.index {
		if uid, ok := callerUID(e.Caller); ok {
			m[userStore{uid, e.Store}] = true
		}
	}
	return m
}

// maybePrune asks each known store's helper to drop expired snapshots, once an hour, forgets
// index entries past retention and rewrites the index file.
func (s *Service) maybePrune() {
	s.mu.Lock()
	if s.now().Sub(s.lastPrune) < time.Hour {
		s.mu.Unlock()
		return
	}
	s.lastPrune = s.now()
	for id, e := range s.index {
		if s.now().Sub(e.At) > Retention {
			delete(s.index, id)
		}
	}
	s.compactIndex()
	stores := s.stores()
	exe := s.exe
	s.mu.Unlock()
	for st := range stores {
		_, _ = s.runAs(st.uid, exe, "__undo", "prune", st.store)
	}
}

// Cleanup (uninstall) deletes the saved copies of every account the service knows about.
func (s *Service) Cleanup(context.Context) error {
	s.mu.Lock()
	stores := s.stores()
	exe := s.exe
	s.mu.Unlock()
	var errs []error
	for st := range stores {
		if _, err := s.runAs(st.uid, exe, "__undo", "purge", st.store); err != nil && !errors.Is(err, ErrNoUser) {
			errs = append(errs, err)
		}
	}
	if s.stateDir != "" {
		_ = os.Remove(s.indexPath())
		_ = os.Remove(filepath.Join(s.stateDir, "undo-key"))
	}
	return errors.Join(errs...)
}
