package protect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/manarhq/manar-edge/internal/lazyre"
	"github.com/manarhq/manar-edge/internal/pause"
	"github.com/manarhq/manar-edge/internal/secrets/watch"
)

// When the device service cannot be reached (it is restarting), a hook must not stop a person's
// work that Manar's last answers allowed. The service keeps a snapshot of what it last saw; the
// hook reads it and decides locally. The snapshot is a convenience for allowed work, never a
// bypass:
//   - only the service writes it, into a directory and file owned by root (SYSTEM) that a user
//     cannot write; the hook refuses a snapshot that is not so owned, is edited (checksum), is
//     missing, unreadable or older than offlineMaxAge, and then fails closed as before;
//   - it holds only actions Manar ALLOWed (reads of non-secret files, and exact commands or
//     resources allowed before); anything else, including everything that needed approval, waits
//     with "try again in a moment";
//   - secrets and destructive commands are never decided offline.

const (
	// offlineMaxAge is a working day: a snapshot older than this is not used and hooks fail closed.
	offlineMaxAge  = 8 * time.Hour
	offlineKeep    = 400 // exact allowed actions kept per tool
	offlineFlush   = 5 * time.Second
	offlineVersion = 1
)

// RestartingText is what the person sees while the service is restarting.
const RestartingText = "Manar is restarting. Try again in a moment."

// unreachableHint ends a message when there is no usable snapshot (fail closed).
const unreachableHint = " The Manar device service is not running. The person using this computer should restart it or contact their administrator."

type offlineTool struct {
	// Allowed holds, oldest first, a hash of each exact (caller, action, resource) Manar ALLOWed.
	Allowed []string `json:"allowed,omitempty"`
}

type offlineSnapshot struct {
	Version int       `json:"version"`
	SavedAt time.Time `json:"savedAt"`
	// ReadsAllowed is the workspace policy "reads of ordinary files keep working while Manar
	// restarts" (offlineReadsAllowed in GET /host/v1/config). Sensitive paths never qualify.
	ReadsAllowed bool `json:"readsAllowed"`
	// ReadDeny are the workspace's read-deny path patterns (offlineReadDeny in the config).
	ReadDeny []string `json:"readDeny,omitempty"`
	// Roots are the project folders in which Manar allowed a file action in the last
	// offlineMaxAge. An offline read must lie inside one, after symlinks are resolved.
	Roots []offlineRoot          `json:"roots,omitempty"`
	Tools map[string]offlineTool `json:"tools"`
	Sum   string                 `json:"sum"`
}

type offlineRoot struct {
	Caller string    `json:"caller"`
	Tool   string    `json:"tool"`
	Path   string    `json:"path"`
	At     time.Time `json:"at"`
}

const maxRoots = 20

func (s *offlineSnapshot) sum() string {
	c := *s
	c.Sum = ""
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func offlineFile(state string) string { return filepath.Join(offlineDir(state), "last-policy.json") }

// actionKey binds an allowed action to the person (caller, without the session part) who made it.
func actionKey(caller, action, resource string) string {
	h := sha256.Sum256([]byte(callerID(caller) + "\x00" + action + "\x00" + resource))
	return hex.EncodeToString(h[:16])
}

// --- service side ---

var rec struct {
	mu    sync.Mutex
	snap  offlineSnapshot
	dirty bool
	timer *time.Timer
}

func callerID(caller string) string {
	if i := strings.Index(caller, "|"); i >= 0 {
		return caller[:i]
	}
	return caller
}

// setOfflineReadsPolicy records the workspace's offline-reads setting and read-deny rules from the
// config poll.
func setOfflineReadsPolicy(on bool, deny []string) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.snap.ReadsAllowed == on && slicesEqual(rec.snap.ReadDeny, deny) && !rec.snap.SavedAt.IsZero() {
		return
	}
	rec.snap.ReadsAllowed, rec.snap.ReadDeny, rec.dirty = on, append([]string(nil), deny...), true
	rec.snap.SavedAt = time.Now()
	if rec.timer == nil {
		rec.timer = time.AfterFunc(offlineFlush, flushOffline)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// pathActions are the actions whose resource is a file path.
var pathActions = map[string]bool{"read": true, "edit": true, "write": true, "multiedit": true, "notebookedit": true}

// noteRoot remembers cwd as a project folder where a file action was allowed just now. The folder
// must be absolute, at least two levels deep and contain the resource; the hook resolves symlinks
// when it uses it.
func noteRoot(snap *offlineSnapshot, toolID, caller, action, resource, cwd string, now time.Time) {
	if !pathActions[action] || !filepath.IsAbs(cwd) || len(cwd) > 1024 || strings.ContainsRune(cwd, 0) {
		return
	}
	cwd = filepath.Clean(cwd)
	if len(strings.FieldsFunc(cwd, func(r rune) bool { return r == '/' || r == '\\' })) < 2 {
		return // "/", "/home", "C:\": far too wide to be a project
	}
	if !within(cwd, filepath.Clean(resource)) {
		return
	}
	id := callerID(caller)
	kept := snap.Roots[:0:0]
	for _, r := range snap.Roots {
		if now.Sub(r.At) <= offlineMaxAge && !(r.Caller == id && r.Tool == toolID && r.Path == cwd) {
			kept = append(kept, r)
		}
	}
	kept = append(kept, offlineRoot{Caller: id, Tool: toolID, Path: cwd, At: now})
	if len(kept) > maxRoots {
		kept = kept[len(kept)-maxRoots:]
	}
	snap.Roots = kept
}

// within is true when p is root or lies below it.
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// recordOfflineDecision remembers what Manar answered, for the offline snapshot. Only the service calls it.
func recordOfflineDecision(toolID, caller, action, resource, cwd, decision string) {
	if action == "" || resource == "" {
		return
	}
	k := actionKey(caller, action, resource)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.snap.Tools == nil {
		rec.snap.Tools = map[string]offlineTool{}
	}
	if decision == "ALLOW" && !sensitive(action, resource) {
		noteRoot(&rec.snap, toolID, caller, action, resource, cwd, time.Now())
	}
	t := rec.snap.Tools[toolID]
	t.Allowed = removeKey(t.Allowed, k)
	switch {
	case decision == "ALLOW" && !sensitive(action, resource):
		t.Allowed = append(t.Allowed, k)
		if len(t.Allowed) > offlineKeep {
			t.Allowed = t.Allowed[len(t.Allowed)-offlineKeep:]
		}
	}
	rec.snap.Tools[toolID] = t
	rec.dirty = true
	if rec.timer == nil {
		rec.timer = time.AfterFunc(offlineFlush, flushOffline)
	}
}

func removeKey(l []string, k string) []string {
	out := l[:0]
	for _, v := range l {
		if v != k {
			out = append(out, v)
		}
	}
	return out
}

func flushOffline() {
	rec.mu.Lock()
	rec.timer = nil
	if !rec.dirty {
		rec.mu.Unlock()
		return
	}
	s := rec.snap
	s.Tools = make(map[string]offlineTool, len(rec.snap.Tools))
	for k, v := range rec.snap.Tools {
		v.Allowed = append([]string(nil), v.Allowed...)
		s.Tools[k] = v
	}
	rec.dirty = false
	rec.mu.Unlock()
	s.Version, s.SavedAt = offlineVersion, time.Now().UTC() // saved now: it is only as old as the last answer it holds
	s.Sum = s.sum()
	b, _ := json.Marshal(&s)
	if err := writeOffline(stateDirNow(), b); err != nil {
		logOnce("offline policy not saved: " + err.Error())
	}
}

// --- sensitivity: never decided offline ---

var destructive = lazyre.New(`(?i)(^|[\s;&|(])(rm\s+-[a-z]*[rf]|rmdir\s|shred\s|mkfs|dd\s+.*\bof=|truncate\s|chmod\s+-R|chown\s+-R|git\s+(push\s+.*(--force|-f\b)|reset\s+--hard|clean\s+-[a-z]*f)|drop\s+(table|database)|del\s+/[sq]|rd\s+/s|format\s|remove-item\s+.*-recurse)`)

// secretName matches files that hold secrets, keys and credentials whatever folder they are in.
var secretName = lazyre.New(`(?i)(^|[/\\])(\.env[^/\\]*|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.pgpass|\.kube[/\\]config|kubeconfig|id_(rsa|dsa|ecdsa|ed25519)[^/\\]*|[^/\\]*\.(pem|key|p12|pfx|kdbx|jks|keystore|gpg|asc)|[^/\\]*(secret|credential|password|passwd|token|apikey|api_key)[^/\\]*)$|[/\\]\.(ssh|aws|azure|gnupg|docker)[/\\]`)

// sensitive is true for an action that touches a secret or can destroy data. The service never
// records such an action as allowed, and the hook never decides one offline.
func sensitive(action, resource string) bool {
	switch action {
	case "read", "edit", "write", "multiedit", "notebookedit":
		return watch.ClassOf(resource) != "" || secretName.MatchString(resource)
	case "shell", "bash":
		if destructive.MatchString(resource) || GuardedCommand(resource) {
			return true
		}
		for _, f := range strings.Fields(resource) {
			if watch.ClassOf(strings.Trim(f, `"'`)) != "" || strings.Contains(strings.ToLower(f), ".env") {
				return true
			}
		}
		return false
	}
	return false
}

// --- hook side ---

// offlineVerdict decides without the service. ok is false when there is no usable snapshot: the
// caller then fails closed.
func offlineVerdict(key, action, resource string) (v Verdict, ok bool) {
	state := stateDirNow()
	if state == "" {
		return Verdict{}, false
	}
	b, err := readTrusted(state)
	if err != nil {
		return Verdict{}, false
	}
	var s offlineSnapshot
	if json.Unmarshal(b, &s) != nil || s.Version != offlineVersion || s.Sum != s.sum() ||
		time.Since(s.SavedAt) > offlineMaxAge || s.SavedAt.After(time.Now().Add(5*time.Minute)) {
		return Verdict{}, false
	}
	if pause.Paused(state) {
		return Verdict{false, "Manar denied: paused (AI is paused for this workspace; resume it in the Manar console)"}, true
	}
	if lockedReason() != "" {
		return Verdict{}, false
	}
	if sensitive(action, resource) {
		return Verdict{false, "Manar: this touches a secret or can delete data, so it needs a live check and Manar is restarting. Try again in a moment."}, true
	}
	if action == "read" && readDenied(&s, resource) {
		return Verdict{false, "Manar denied: this file is protected by your workspace's rules."}, true
	}
	if action == "read" && s.ReadsAllowed && readInsideAllowedRoot(&s, "host."+key, resource) {
		return Verdict{true, "Manar: allowed (last policy)"}, true
	}
	k := actionKey(localCaller(), action, resource)
	for _, a := range s.Tools["host."+key].Allowed {
		if a == k {
			return Verdict{true, "Manar: allowed (last policy)"}, true
		}
	}
	return Verdict{false, "Manar: " + RestartingText}, true
}

// readInsideAllowedRoot is true when resource, after symlinks are resolved, lies inside a project
// folder where Manar allowed a file action for this person and tool within offlineMaxAge, and is
// neither sensitive nor matched by a read-deny rule (checked on the path as given and as resolved).
func readInsideAllowedRoot(s *offlineSnapshot, toolID, resource string) bool {
	real, err := filepath.EvalSymlinks(resource)
	if err != nil || !filepath.IsAbs(real) {
		return false
	}
	for _, p := range []string{resource, real} {
		if sensitive("read", p) {
			return false
		}
	}
	me := callerID(localCaller())
	for _, r := range s.Roots {
		if r.Caller != me || r.Tool != toolID || time.Since(r.At) > offlineMaxAge {
			continue
		}
		if root, err := filepath.EvalSymlinks(r.Path); err == nil && within(root, real) {
			return true
		}
	}
	return false
}

// readDenied is true when a workspace read-deny rule matches the path as given or as resolved.
func readDenied(s *offlineSnapshot, resource string) bool {
	if deniedRead(s.ReadDeny, resource) {
		return true
	}
	real, err := filepath.EvalSymlinks(resource)
	return err == nil && deniedRead(s.ReadDeny, real)
}

// deniedRead matches the workspace's read-deny patterns: a glob on the whole path or the file
// name, or a folder prefix when the pattern ends in a slash.
func deniedRead(patterns []string, p string) bool {
	base := filepath.Base(p)
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, p); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
		if strings.HasSuffix(pat, "/") && strings.HasPrefix(p, pat) {
			return true
		}
	}
	return false
}
