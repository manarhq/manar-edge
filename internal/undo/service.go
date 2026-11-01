package undo

import (
	"context"
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
var Default = &Service{owners: map[string]owner{}, runAs: RunAs, pollEvery: 15 * time.Second}

func init() { daemon.Register(Default) }

type owner struct {
	Caller string    `json:"caller"`
	At     time.Time `json:"at"`
}

// Service is the daemon module "undo".
type Service struct {
	mu        sync.Mutex
	stateDir  string
	exe       string
	queue     []Record
	owners    map[string]owner // snapshot id -> who took it ("uid:1000")
	runAs     func(uid int, exe string, args ...string) ([]byte, error)
	pollEvery time.Duration
	lastPrune time.Time
}

// Configure sets the device state dir (owner index) and the binary used for helpers.
func Configure(stateDir, exe string) {
	Default.mu.Lock()
	defer Default.mu.Unlock()
	Default.stateDir, Default.exe = stateDir, exe
	Default.loadOwners()
}

func (s *Service) Name() string { return "undo" }

var (
	toolPattern = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	shaPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

const maxQueue = 500

// Report accepts one record from a hook. caller is the kernel's view of who sent it.
func (s *Service) Report(caller string, r Record) error {
	if !ValidID(r.ID) || !toolPattern.MatchString(r.Tool) || !shaPattern.MatchString(r.SHA256) ||
		!filepath.IsAbs(r.Path) || len(r.Path) > 1024 || r.Size < 0 || strings.ContainsRune(r.Path, 0) {
		return errors.New("bad record")
	}
	if _, ok := callerUID(caller); !ok && !strings.HasPrefix(caller, "sid:") {
		return errors.New("unknown caller")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.owners[r.ID] = owner{Caller: caller, At: time.Now()}
	s.saveOwners()
	s.queue = append(s.queue, r)
	if len(s.queue) > maxQueue {
		s.queue = s.queue[len(s.queue)-maxQueue:]
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

func (s *Service) ownersPath() string { return filepath.Join(s.stateDir, "undo-owners.json") }

func (s *Service) loadOwners() {
	if s.stateDir == "" {
		return
	}
	b, err := os.ReadFile(s.ownersPath())
	if err != nil {
		return
	}
	m := map[string]owner{}
	if json.Unmarshal(b, &m) == nil {
		s.owners = m
	}
}

func (s *Service) saveOwners() {
	if s.stateDir == "" {
		return
	}
	b, _ := json.Marshal(s.owners)
	tmp := s.ownersPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.ownersPath())
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
		if err := s.restore(it); err != nil {
			res = map[string]string{"status": "FAILED", "error": truncate(err.Error(), 280)}
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
	batch := slices.Clone(s.queue[:n])
	s.mu.Unlock()
	if n == 0 {
		return
	}
	body := make([]wireChange, n)
	for i, r := range batch {
		body[i] = wireChange{r.ID, r.Tool, r.Path, r.Exists, r.Size, r.SHA256, r.Taken.Format(time.RFC3339)}
	}
	if err := c.Do(ctx, "POST", "/undo/changes", map[string]any{"changes": body}, nil); err != nil {
		log.Printf("manar-edge: undo: report: %v", err)
		return
	}
	s.mu.Lock()
	s.queue = s.queue[min(n, len(s.queue)):]
	s.mu.Unlock()
}

func (s *Service) restore(it restoreItem) error {
	if !ValidID(it.SnapshotID) || !filepath.IsAbs(it.Path) {
		return errors.New("the request is not valid")
	}
	s.mu.Lock()
	o, ok := s.owners[it.SnapshotID]
	exe := s.exe
	s.mu.Unlock()
	if !ok {
		return errors.New("this device does not know that saved copy")
	}
	uid, ok := callerUID(o.Caller)
	if !ok {
		return ErrNoRunAsMsg()
	}
	out, err := s.runAs(uid, exe, "__undo", "restore", it.SnapshotID, it.Path)
	var r struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if jerr := json.Unmarshal(out, &r); jerr == nil && !r.OK && r.Error != "" {
		return errors.New(r.Error)
	}
	if err != nil {
		return err
	}
	if !r.OK {
		return errors.New("the restore did not report success")
	}
	return nil
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

// maybePrune asks each known user's helper to drop expired snapshots, once an hour, and forgets
// owners past retention.
func (s *Service) maybePrune() {
	s.mu.Lock()
	if time.Since(s.lastPrune) < time.Hour {
		s.mu.Unlock()
		return
	}
	s.lastPrune = time.Now()
	uids := map[int]bool{}
	for id, o := range s.owners {
		if time.Since(o.At) > Retention {
			delete(s.owners, id)
		} else if uid, ok := callerUID(o.Caller); ok {
			uids[uid] = true
		}
	}
	s.saveOwners()
	exe := s.exe
	s.mu.Unlock()
	for uid := range uids {
		_, _ = s.runAs(uid, exe, "__undo", "prune")
	}
}

// Cleanup (uninstall) deletes the saved copies of every user the service knows about.
func (s *Service) Cleanup(context.Context) error {
	s.mu.Lock()
	uids := map[int]bool{}
	for _, o := range s.owners {
		if uid, ok := callerUID(o.Caller); ok {
			uids[uid] = true
		}
	}
	exe := s.exe
	s.mu.Unlock()
	var errs []error
	for uid := range uids {
		if _, err := s.runAs(uid, exe, "__undo", "purge"); err != nil && !errors.Is(err, ErrNoUser) {
			errs = append(errs, err)
		}
	}
	if s.stateDir != "" {
		_ = os.Remove(s.ownersPath())
	}
	return errors.Join(errs...)
}
