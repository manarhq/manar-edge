package protect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/manarhq/manar-edge/internal/lazyre"
	"github.com/manarhq/manar-edge/internal/secrets/watch"
)

// When the device service cannot be reached (it is restarting), a hook must not stop a person's
// work that Manar's last answers allowed. The service keeps a snapshot of what it last saw; the
// hook reads it and decides locally. The snapshot is a convenience for allowed work, never a
// bypass:
//   - only the service writes it, into a directory and file owned by root (SYSTEM) that a user
//     cannot write; the hook refuses a snapshot that is not so owned, is edited (checksum), is
//     missing, unreadable or older than offlineMaxAge, and then fails closed as before;
//   - everything the hook needs, including "paused" and "locked", is in that one file: the hook
//     never reads the service's private state directory;
//   - it holds only actions Manar ALLOWed: exact (person, tool, action, resource) answers with the
//     path resolved first, and, when the workspace allows it, reads inside project folders where a
//     file action was allowed recently. Project folders are stored as hashes, so a shared file
//     does not list anyone's paths. A project folder must lie inside the person's home, below it
//     by at least one folder that does not start with a dot;
//   - anything else, including everything that needed approval, waits with "try again in a
//     moment"; secrets and destructive commands are never decided offline; a symlink is resolved
//     before any check, and one that leaves the project or reaches a sensitive path is refused.

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
	// Allowed holds, oldest first, a hash of each exact (caller, action, resolved resource) Manar ALLOWed.
	Allowed []string `json:"allowed,omitempty"`
}

type offlineSnapshot struct {
	Version int       `json:"version"`
	SavedAt time.Time `json:"savedAt"`
	// Paused and Locked are the service's view of "Pause all AI" and of a locked device (423); the
	// hook reads them here and nowhere else.
	Paused bool   `json:"paused"`
	Locked string `json:"locked,omitempty"`
	// ReadsAllowed is the workspace policy "reads of ordinary files keep working while Manar
	// restarts" (offlineReadsAllowed in GET /host/v1/config). Sensitive paths never qualify.
	ReadsAllowed bool `json:"readsAllowed"`
	// ReadDeny are the workspace's read-deny path patterns (offlineReadDeny in the config).
	ReadDeny []string `json:"readDeny,omitempty"`
	// Roots are hashes of project folders (resolved) in which Manar allowed a file action in the
	// last offlineMaxAge, per person and tool.
	Roots []offlineRoot          `json:"roots,omitempty"`
	Tools map[string]offlineTool `json:"tools"`
	Sum   string                 `json:"sum"`
}

type offlineRoot struct {
	Caller string    `json:"caller"`
	Tool   string    `json:"tool"`
	Hash   string    `json:"hash"`
	At     time.Time `json:"at"`
}

const maxRoots = 40

func (s *offlineSnapshot) sum() string {
	c := *s
	c.Sum = ""
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func offlineFile(state string) string { return filepath.Join(offlineDir(state), "last-policy.json") }

// fold normalises a path for comparing and hashing (separators, and case on Windows).
func fold(p string) string {
	p = filepath.ToSlash(p)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

func hashOf(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}

// actionKey binds an allowed action to the person (caller, without the session part) who made it.
func actionKey(caller, action, resource string) string {
	return hashOf(callerID(caller), action, fold(resource))
}

func rootHash(caller, tool, root string) string {
	return hashOf("root", callerID(caller), tool, fold(root))
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

func markDirty() {
	rec.dirty = true
	if rec.timer == nil {
		rec.timer = time.AfterFunc(offlineFlush, flushOffline)
	}
}

// setOfflineReadsPolicy records the workspace's offline-reads setting and read-deny rules from the
// config poll.
func setOfflineReadsPolicy(on bool, deny []string) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.snap.ReadsAllowed == on && slicesEqual(rec.snap.ReadDeny, deny) && !rec.snap.SavedAt.IsZero() {
		return
	}
	rec.snap.ReadsAllowed, rec.snap.ReadDeny = on, append([]string(nil), deny...)
	rec.snap.SavedAt = time.Now()
	markDirty()
}

// setOfflineState records "Pause all AI" and a lock (the reason code, "" when not locked).
func setOfflineState(paused bool, locked string) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.snap.Paused == paused && rec.snap.Locked == locked && !rec.snap.SavedAt.IsZero() {
		return
	}
	rec.snap.Paused, rec.snap.Locked = paused, locked
	rec.snap.SavedAt = time.Now()
	markDirty()
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

// resolveTarget resolves symlinks in a path. A file that does not exist yet (a write) resolves
// through its folder. ok is false when it cannot be resolved or is not absolute.
func resolveTarget(p string) (string, bool) {
	if !filepath.IsAbs(p) || strings.ContainsRune(p, 0) {
		return "", false
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r, true
	}
	d, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return "", false
	}
	return filepath.Join(d, filepath.Base(p)), true
}

// noteRoot remembers the resolved project folder cwd where a file action was allowed just now: it
// must contain the resolved resource. The hook decides at use whether it is a usable folder (inside
// the person's home, deep enough).
func noteRoot(snap *offlineSnapshot, toolID, caller, realResource, cwd string, now time.Time) {
	if !filepath.IsAbs(cwd) || len(cwd) > 1024 {
		return
	}
	root, ok := resolveTarget(cwd)
	if !ok || !within(root, realResource) {
		return
	}
	h := rootHash(caller, toolID, root)
	kept := snap.Roots[:0:0]
	for _, r := range snap.Roots {
		if now.Sub(r.At) <= offlineMaxAge && r.Hash != h {
			kept = append(kept, r)
		}
	}
	kept = append(kept, offlineRoot{Caller: callerID(caller), Tool: toolID, Hash: h, At: now})
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

// recordOfflineDecision remembers what Manar answered, for the offline snapshot. Only the service
// calls it. A path is resolved first; an action on a sensitive path (as given or resolved) is never
// recorded.
func recordOfflineDecision(toolID, caller, action, resource, cwd, decision string) {
	if action == "" || resource == "" {
		return
	}
	target := resource
	real, resolved := "", false
	if pathActions[action] {
		if real, resolved = resolveTarget(resource); resolved {
			target = real
		}
	}
	ok := decision == "ALLOW" && !sensitive(action, resource) && !sensitive(action, target)
	k := actionKey(caller, action, target)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.snap.Tools == nil {
		rec.snap.Tools = map[string]offlineTool{}
	}
	t := rec.snap.Tools[toolID]
	t.Allowed = removeKey(t.Allowed, k)
	if ok {
		if pathActions[action] && resolved {
			noteRoot(&rec.snap, toolID, caller, real, cwd, time.Now())
		}
		t.Allowed = append(t.Allowed, k)
		if len(t.Allowed) > offlineKeep {
			t.Allowed = t.Allowed[len(t.Allowed)-offlineKeep:]
		}
	}
	rec.snap.Tools[toolID] = t
	markDirty()
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
	s.Roots = append([]offlineRoot(nil), rec.snap.Roots...)
	rec.dirty = false
	rec.mu.Unlock()
	s.Version, s.SavedAt = offlineVersion, time.Now().UTC() // saved now: it is only as old as the last answer it holds
	s.Sum = s.sum()
	b, _ := json.Marshal(&s)
	state := stateDirNow()
	if state == "" {
		return // not configured (a test, or a command that never runs the service)
	}
	if err := writeOffline(state, b); err != nil {
		logOnce("offline policy not saved: " + err.Error())
	}
}

// --- sensitivity: never decided offline ---

var destructive = lazyre.New(`(?i)(^|[\s;&|(])(rm\s+-[a-z]*[rf]|rmdir\s|shred\s|mkfs|dd\s+.*\bof=|truncate\s|chmod\s+-R|chown\s+-R|git\s+(push\s+.*(--force|-f\b)|reset\s+--hard|clean\s+-[a-z]*f)|drop\s+(table|database)|del\s+/[sq]|rd\s+/s|format\s|remove-item\s+.*-recurse)`)

// secretName matches files that hold secrets, keys and credentials whatever folder they are in:
// env files, key and certificate files, cloud and tool credentials, shell histories, Terraform
// state and variables, key rings.
var secretName = lazyre.New(`(?i)(^|[/\\])(` +
	`\.env[^/\\]*|\.dev\.vars|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.pgpass|\.s3cfg|rclone\.conf|\.claude\.json|` +
	`\.kube[/\\]config|kubeconfig|id_(rsa|dsa|ecdsa|ed25519)[^/\\]*|` +
	`\.codex[/\\]auth\.json|\.gemini[/\\]oauth_creds\.json|github-copilot[/\\](apps|hosts)\.json|\.m2[/\\]settings(-security)?\.xml|` +
	`[^/\\]*_history|[^/\\]*\.(pem|key|p12|pfx|ppk|kdbx|jks|keystore|gpg|asc|tfstate|tfvars)(\.backup|\.json)?|terraform\.tfstate[^/\\]*|` +
	`[^/\\]*(secret|credential|password|passwd|token|apikey|api_key)[^/\\]*)$` +
	`|[/\\]\.(ssh|aws|azure|gnupg|docker)[/\\]|[/\\](\.local[/\\]share[/\\])?keyrings?[/\\]|[/\\]Keychains[/\\]`)

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
			f = strings.Trim(f, `"'`)
			if watch.ClassOf(f) != "" || secretName.MatchString(f) {
				return true
			}
		}
		return false
	}
	return false
}

// commandTouchesSecretViaLink resolves every word of a command that names an existing path and
// reports whether any resolves to a sensitive one (a link to a secret hidden behind an ordinary name).
func commandTouchesSecretViaLink(cmd, home string) bool {
	n := 0
	for _, f := range strings.Fields(cmd) {
		if n++; n > 64 {
			break
		}
		f = strings.Trim(f, `"';&|()<>`)
		if strings.HasPrefix(f, "~/") && home != "" {
			f = filepath.Join(home, f[2:])
		}
		if f == "" || !strings.ContainsAny(f, `/\.`) {
			continue
		}
		if _, err := os.Lstat(f); err != nil {
			continue
		}
		if r, err := filepath.EvalSymlinks(f); err == nil {
			if abs, err := filepath.Abs(r); err == nil && (watch.ClassOf(abs) != "" || secretName.MatchString(abs)) {
				return true
			}
		}
	}
	return false
}

// --- hook side ---

// userHome is the person's resolved home folder ("" when unknown); a var so tests can set it.
var userHome = func() string {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		return ""
	}
	if r, err := filepath.EvalSymlinks(u.HomeDir); err == nil {
		return r
	}
	return u.HomeDir
}

// rootUsable says whether dir may serve as a project folder for this person: strictly inside home,
// and below it by a first folder that does not start with a dot (/home/sam/proj, never /home/sam,
// /home/sam/.config or anything above home). On Windows a drive letter is not a folder.
func rootUsable(home, dir string) bool {
	if home == "" || !within(home, dir) || filepath.Clean(home) == filepath.Clean(dir) {
		return false
	}
	rel, err := filepath.Rel(home, dir)
	if err != nil {
		return false
	}
	first := strings.Split(filepath.ToSlash(rel), "/")[0]
	return first != "" && !strings.HasPrefix(first, ".")
}

// insideRecordedRoot is true when an ancestor of the resolved path is a usable project folder that
// Manar recorded, for this person and tool, within offlineMaxAge.
func insideRecordedRoot(s *offlineSnapshot, toolID, real string) bool {
	home := userHome()
	me := callerID(localCaller())
	have := map[string]bool{}
	for _, r := range s.Roots {
		if r.Caller == me && r.Tool == toolID && time.Since(r.At) <= offlineMaxAge {
			have[r.Hash] = true
		}
	}
	for d := filepath.Dir(real); within(home, d) && filepath.Clean(d) != filepath.Clean(home); d = filepath.Dir(d) {
		if rootUsable(home, d) && have[rootHash(me, toolID, d)] {
			return true
		}
	}
	return false
}

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
	if s.Locked != "" {
		return Verdict{}, false
	}
	if s.Paused {
		return Verdict{false, "Manar denied: paused (AI is paused for this workspace; resume it in the Manar console)"}, true
	}
	tool := "host." + key
	refuse := Verdict{false, "Manar: this touches a secret or can delete data, so it needs a live check and Manar is restarting. Try again in a moment."}
	wait := Verdict{false, "Manar: " + RestartingText}
	if sensitive(action, resource) {
		return refuse, true
	}
	allowed := func(target string) bool {
		k := actionKey(localCaller(), action, target)
		for _, a := range s.Tools[tool].Allowed {
			if a == k {
				return true
			}
		}
		return false
	}
	yes := Verdict{true, "Manar: allowed (last policy)"}
	if !pathActions[action] {
		if commandTouchesSecretViaLink(resource, userHome()) {
			return refuse, true
		}
		if allowed(resource) {
			return yes, true
		}
		return wait, true
	}
	// A path: resolve it first. Everything below judges the real target, never the name.
	real, resolved := resolveTarget(resource)
	if !resolved {
		return wait, true
	}
	if sensitive(action, real) {
		return refuse, true
	}
	if action == "read" && (denyRule(s.ReadDeny, resource) || denyRule(s.ReadDeny, real)) {
		return Verdict{false, "Manar denied: this file is protected by your workspace's rules."}, true
	}
	if !insideRecordedRoot(&s, tool, real) {
		return wait, true
	}
	if action == "read" && s.ReadsAllowed {
		return yes, true
	}
	if allowed(real) {
		return yes, true
	}
	return wait, true
}

// denyRule matches the workspace's read-deny patterns against a path: "**" crosses folders, "*" and
// "?" do not, separators and (on Windows) case are normalised, a pattern without a slash matches the
// file name, one ending in a slash is a folder prefix, and a pattern that cannot be parsed denies.
func denyRule(patterns []string, p string) bool {
	p = fold(p)
	for _, pat := range patterns {
		pat = fold(pat)
		switch {
		case strings.HasSuffix(pat, "/"):
			if strings.HasPrefix(p, pat) {
				return true
			}
			continue
		case !strings.Contains(pat, "/"):
			ok, err := path.Match(pat, path.Base(p))
			if err != nil || ok {
				return true
			}
			continue
		case !strings.HasPrefix(pat, "/"):
			pat = "**/" + pat
		}
		parts := strings.Split(strings.Trim(pat, "/"), "/")
		bad := false
		for _, q := range parts { // a malformed segment denies, even after an earlier mismatch
			if _, err := path.Match(q, ""); err != nil {
				bad = true
			}
		}
		if bad {
			return true
		}
		ok, err := globMatch(parts, strings.Split(strings.Trim(p, "/"), "/"))
		if err != nil || ok {
			return true
		}
	}
	return false
}

// globMatch matches path segments against pattern segments, "**" standing for any number of segments.
func globMatch(pat, segs []string) (bool, error) {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for len(pat) > 1 && pat[1] == "**" {
				pat = pat[1:]
			}
			if len(pat) == 1 {
				return true, nil
			}
			for i := 0; i <= len(segs); i++ {
				ok, err := globMatch(pat[1:], segs[i:])
				if err != nil || ok {
					return ok, err
				}
			}
			return false, nil
		}
		if len(segs) == 0 {
			// still validate the rest of the pattern so a malformed one is never skipped
			for _, q := range pat {
				if _, err := path.Match(q, ""); err != nil {
					return false, err
				}
			}
			return false, nil
		}
		ok, err := path.Match(pat[0], segs[0])
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0, nil
}
