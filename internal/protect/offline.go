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
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

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
	offlineMaxAge = 8 * time.Hour
	offlineKeep   = 400 // exact allowed actions kept per tool (oldest dropped: safe, it only asks again)
	// offlineRefusedKeep is how many refusals are kept per tool. They are never evicted and never
	// age out: a refusal must outlive the project folder rule that would otherwise allow the file.
	// When the list is full the project-folder read rule is turned off (RefusedFull).
	offlineRefusedKeep = 1000
	offlineFlush       = 5 * time.Second
	offlineTouch       = 30 * time.Minute // how often an unchanged policy refreshes the snapshot's age
	offlineVersion     = 2
)

// RestartingText is what the person sees while the service is restarting.
const RestartingText = "Manar is restarting. Try again in a moment."

// unreachableHint ends a message when there is no usable snapshot (fail closed).
const unreachableHint = " The Manar device service is not running. The person using this computer should restart it or contact their administrator."

// offlineEntry is the hash of one exact answer and when Manar gave it; the hook ignores an entry
// older than offlineMaxAge whatever the age of the snapshot.
type offlineEntry struct {
	H  string `json:"h"`
	At int64  `json:"t"` // unix seconds (cheap to read: the hook parses every entry)
}

// entryList is a list of entries as one string, "hash:unix hash:unix", oldest first: the hook reads
// the whole snapshot on every call while the service is away, and one string decodes far faster
// than hundreds of objects.
type entryList string

func splitEntries(l entryList) []offlineEntry {
	var out []offlineEntry
	for _, f := range strings.Fields(string(l)) {
		if h, ts, ok := strings.Cut(f, ":"); ok {
			if t, err := strconv.ParseInt(ts, 10, 64); err == nil {
				out = append(out, offlineEntry{h, t})
			}
		}
	}
	return out
}

func joinEntries(es []offlineEntry) entryList {
	var b strings.Builder
	for i, e := range es {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(e.H + ":" + strconv.FormatInt(e.At, 10))
	}
	return entryList(b.String())
}

type offlineTool struct {
	// Allowed holds each exact (caller, action, resolved resource or folder+command) Manar ALLOWed
	// and that may be replayed.
	Allowed entryList `json:"allowed,omitempty"`
	// Denied holds what Manar answered with a DENY or an approval request. It has no age and is
	// never evicted; it is checked before any project-folder rule, so a refusal is never undone
	// offline. An ALLOW that must not be cached is stored nowhere.
	Denied entryList `json:"denied,omitempty"`
}

type offlineSnapshot struct {
	Version int       `json:"version"`
	SavedAt time.Time `json:"savedAt"`
	// Paused and Locked are the service's view of "Pause all AI" and of a locked device (423); the
	// hook reads them here and nowhere else.
	Paused bool   `json:"paused"`
	Locked string `json:"locked,omitempty"`
	// RefusedFull: a tool's refusal list overflowed, so reads in project folders are not allowed
	// offline (an unrecorded refusal could be covered by the folder rule).
	RefusedFull bool `json:"refusedFull,omitempty"`
	// PolicyVersion is the workspace policy version the answers below were given under; a new one
	// drops every allow and project folder.
	PolicyVersion string `json:"policyVersion,omitempty"`
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

// actionKey binds an allowed file action to the person (caller, without the session part) who made
// it; resource is the resolved path.
func actionKey(caller, action, resource string) string {
	return hashOf(callerID(caller), action, fold(resource))
}

// shellKey binds a command (or MCP call) to the person and the folder it ran in; the command text
// is hashed byte for byte (a command is not a path: case and separators matter).
func shellKey(caller, action, cwd, resource string) string {
	return hashOf("sh", callerID(caller), action, fold(cwd), resource)
}

// canonCwd is a working folder resolved the same way on both sides ("" when it cannot be).
func canonCwd(cwd string) string {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if r, ok := resolveTarget(cwd); ok {
		return r
	}
	return ""
}

func rootHash(caller, tool, root string) string {
	return hashOf("root", callerID(caller), tool, fold(root))
}

// --- service side ---

var rec struct {
	mu     sync.Mutex
	snap   offlineSnapshot
	dirty  bool
	timer  *time.Timer
	loaded bool
}

// loadSaved (rec.mu held) reads the snapshot the service saved before it last stopped, through the
// same ownership and checksum checks the hook uses, the first time anything is recorded. Refusals
// (and the folders and allows, still subject to their expiry) survive a restart: a restarted
// service must not forget what Manar refused.
func loadSaved() {
	if rec.loaded {
		return
	}
	rec.loaded = true
	state := stateDirNow()
	if state == "" {
		return
	}
	b, err := readTrusted(state)
	if err != nil {
		return
	}
	var s offlineSnapshot
	if json.Unmarshal(b, &s) != nil || s.Version != offlineVersion || s.Sum != s.sum() {
		return
	}
	now := time.Now()
	for k, t := range s.Tools {
		t.Allowed = joinEntries(pruneEntries(splitEntries(t.Allowed), now))
		s.Tools[k] = t
	}
	kept := s.Roots[:0:0]
	for _, r := range s.Roots {
		if now.Sub(r.At) <= offlineMaxAge {
			kept = append(kept, r)
		}
	}
	s.Roots = kept
	rec.snap = s
}

func callerID(caller string) string {
	if i := strings.Index(caller, "|"); i >= 0 {
		return caller[:i]
	}
	return caller
}

func markDirty() {
	rec.snap.SavedAt = time.Now()
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
	loadSaved()
	if rec.snap.ReadsAllowed == on && slicesEqual(rec.snap.ReadDeny, deny) && !rec.snap.SavedAt.IsZero() {
		// The config poll confirmed the policy again: keep the snapshot's age honest without a
		// write on every poll.
		if time.Since(rec.snap.SavedAt) > offlineTouch {
			markDirty()
		}
		return
	}
	rec.snap.ReadsAllowed, rec.snap.ReadDeny = on, append([]string(nil), deny...)
	markDirty()
}

// setOfflinePolicyVersion records the workspace policy version; a different one than before drops
// every allow and project folder (what was allowed under the old policy may not be now).
func setOfflinePolicyVersion(v string) {
	if v == "" {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	loadSaved()
	if rec.snap.PolicyVersion == v {
		return
	}
	if rec.snap.PolicyVersion != "" {
		for k, t := range rec.snap.Tools {
			t.Allowed, t.Denied = "", ""
			rec.snap.Tools[k] = t
		}
		rec.snap.Roots, rec.snap.RefusedFull = nil, false
	}
	rec.snap.PolicyVersion = v
	markDirty()
}

// setOfflineState records "Pause all AI" and a lock (the reason code, "" when not locked).
func setOfflineState(paused bool, locked string) {
	rec.mu.Lock()
	loadSaved()
	if rec.snap.Paused == paused && rec.snap.Locked == locked && !rec.snap.SavedAt.IsZero() {
		rec.mu.Unlock()
		return
	}
	rec.snap.Paused, rec.snap.Locked = paused, locked
	markDirty()
	rec.mu.Unlock()
	flushOffline() // a pause or a lock reaches the hooks now, not at the next timer
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

// resolveTarget resolves a path the way the kernel walks it (realPath): a link that points nowhere,
// loops or is a magic link is "cannot tell". A file that does not exist yet (a write) is judged by
// its folder, which must exist. ok is false when it cannot be resolved or is not absolute.
func resolveTarget(p string) (string, bool) {
	if !filepath.IsAbs(p) || strings.ContainsRune(p, 0) {
		return "", false
	}
	r, err := realPath(p)
	if err != nil {
		return "", false
	}
	if _, err := os.Lstat(r); err != nil {
		if fi, err := os.Stat(filepath.Dir(r)); err != nil || !fi.IsDir() {
			return "", false
		}
	}
	return r, true
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
// recorded as allowed. decision is ALLOW only for an answer that may be replayed; every other answer
// (DENY, an approval request, an ALLOW that must not be cached) is remembered as a refusal, which
// the hook checks before any project-folder rule.
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
	sens := sensitive(action, resource) || sensitive(action, target)
	// An answer about a link's name says nothing about its target: an ALLOW is recorded (and a
	// refusal dropped) only when the requested path already is the resolved target.
	direct := !pathActions[action] || (resolved && filepath.Clean(resource) == real)
	var k string
	if pathActions[action] {
		k = actionKey(caller, action, target)
	} else {
		k = shellKey(caller, action, canonCwd(cwd), resource)
	}
	now := time.Now()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	loadSaved()
	if rec.snap.Tools == nil {
		rec.snap.Tools = map[string]offlineTool{}
	}
	t := rec.snap.Tools[toolID]
	allowed := dropEntry(pruneEntries(splitEntries(t.Allowed), now), k)
	denied := splitEntries(t.Denied)
	switch {
	case decision == "ALLOW" && !sens && !direct:
		// judged by name only: nothing recorded
	case decision == "ALLOW" && !sens:
		if pathActions[action] && resolved {
			noteRoot(&rec.snap, toolID, caller, real, cwd, now)
		}
		allowed = capEntries(append(allowed, offlineEntry{k, now.Unix()}))
		denied = dropEntry(denied, k) // a later plain ALLOW is a change of policy
	case decision == "ALLOW_NOT_CACHEABLE":
		// Allowed now, but never replayed: stored nowhere, and an older refusal stays.
	case decision != "ALLOW" && !sens:
		if !hasEntryAny(t.Denied, k) {
			if len(denied) < offlineRefusedKeep {
				denied = append(denied, offlineEntry{k, now.Unix()})
			} else {
				rec.snap.RefusedFull = true
			}
		}
	}
	t.Allowed, t.Denied = joinEntries(allowed), joinEntries(denied)
	rec.snap.Tools[toolID] = t
	markDirty()
}

func capEntries(l []offlineEntry) []offlineEntry {
	if len(l) > offlineKeep {
		l = l[len(l)-offlineKeep:]
	}
	return l
}

// pruneEntries drops entries older than offlineMaxAge.
func pruneEntries(l []offlineEntry, now time.Time) []offlineEntry {
	out := l[:0:0]
	for _, e := range l {
		if now.Unix()-e.At <= int64(offlineMaxAge/time.Second) {
			out = append(out, e)
		}
	}
	return out
}

func dropEntry(l []offlineEntry, k string) []offlineEntry {
	out := l[:0:0]
	for _, e := range l {
		if e.H != k {
			out = append(out, e)
		}
	}
	return out
}

// entryTime finds k in l without allocating: its time, and whether it is there.
func entryTime(l entryList, k string) (int64, bool) {
	s, key := string(l), k+":"
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], key)
		if j < 0 {
			return 0, false
		}
		j += i
		if j == 0 || s[j-1] == ' ' {
			end := strings.IndexByte(s[j:], ' ')
			if end < 0 {
				end = len(s) - j
			}
			t, err := strconv.ParseInt(s[j+len(key):j+end], 10, 64)
			return t, err == nil
		}
		i = j + 1
	}
	return 0, false
}

// hasEntry is true when l holds k, given within offlineMaxAge (and not from the future).
func hasEntry(l entryList, k string) bool {
	at, ok := entryTime(l, k)
	now := time.Now().Unix()
	return ok && now-at <= int64(offlineMaxAge/time.Second) && at <= now+300
}

// hasEntryAny is true when l holds k, whatever its age (refusals do not expire).
func hasEntryAny(l entryList, k string) bool {
	_, ok := entryTime(l, k)
	return ok
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
		s.Tools[k] = v
	}
	s.Roots = append([]offlineRoot(nil), rec.snap.Roots...)
	rec.dirty = false
	rec.mu.Unlock()
	s.Version = offlineVersion // SavedAt stays what the last change set: a flush does not make old answers young
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

// commandSeparators split a command into words the way a shell does before it opens any file:
// white space, redirections, pipes, lists, subshells, backquotes and "=" (so --config=path and
// FOO=path give the path as a word). `echo hi>out.txt` has the word out.txt.
func isCommandSeparator(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune("<>|;&()`=", r)
}

// commandTouchesSecretViaLink resolves every word of a command that names an existing path (a bare
// word is taken relative to the working folder) and reports whether the command may reach a secret:
//   - a word that exists but cannot be resolved (a link that points nowhere, a loop, a magic link)
//     is refused: the command could write through it;
//   - a word that resolves to a sensitive path is refused (a link to a secret behind an ordinary name);
//   - a hard-linked file is refused when it is a credential file (same device and inode) or is not
//     a package file (see packageFile): package managers hard-link every file of node_modules, and
//     nothing else is let through on the strength of a folder.
func commandTouchesSecretViaLink(cmd, home, cwd string, inRoot func(realPath string) bool) bool {
	n := 0
	for _, f := range strings.FieldsFunc(cmd, isCommandSeparator) {
		if n++; n > 64 {
			break
		}
		f = strings.Trim(f, `"'`)
		if strings.HasPrefix(f, "~/") && home != "" {
			f = filepath.Join(home, f[2:])
		}
		if f == "" || strings.HasPrefix(f, "-") {
			continue
		}
		if !filepath.IsAbs(f) {
			if cwd == "" {
				continue
			}
			f = filepath.Join(cwd, f)
		}
		if _, err := os.Lstat(f); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return true // exists but cannot be looked at
		}
		r, err := realPath(f)
		if err != nil {
			return true
		}
		if watch.ClassOf(r) != "" || secretName.MatchString(r) {
			return true
		}
		if fi, err := os.Lstat(r); err == nil && fi.Mode().IsRegular() && linkCount(r, fi) > 1 {
			if hardLinkedCredential(fi, home) || !packageFile(r, inRoot) {
				return true
			}
		}
	}
	return false
}

// packageFile is true for a file under a node_modules folder (inside a recorded project folder,
// when inRoot is given) or in a known package-manager store: the only places where a hard-linked
// file is ordinary. Everywhere else a file with several names needs an exact allow.
func packageFile(p string, inRoot func(string) bool) bool {
	segs := strings.Split(fold(p), "/")
	has := func(want ...string) bool {
		for i := 0; i+len(want) <= len(segs); i++ {
			ok := true
			for j, w := range want {
				ok = ok && segs[i+j] == w
			}
			if ok {
				return true
			}
		}
		return false
	}
	if has(".pnpm-store") || has(".yarn", "cache") || has(".bun", "install", "cache") || has(".local", "share", "pnpm") {
		return true
	}
	return has("node_modules") && (inRoot == nil || inRoot(p))
}

// hardLinkedCredential is true when fi is (another name for) a credential file of the person, or
// when that cannot be told (Windows has no inode here: fail safe).
func hardLinkedCredential(fi os.FileInfo, home string) bool {
	id, ok := fileID(fi)
	if !ok {
		return true
	}
	ids, complete := credentialIDs(home)
	return !complete || ids[id]
}

var credCache struct {
	mu       sync.Mutex
	home     string
	ids      map[string]bool
	complete bool
	at       time.Time
}

// credentialTTL is how long the list is trusted: mcp-wrap and other long-lived programs call this
// for hours.
const credentialTTL = 3 * time.Minute

// resetCredentialIDs forgets the cached list (tests, and a changed home).
func resetCredentialIDs() {
	credCache.mu.Lock()
	credCache.home, credCache.ids, credCache.complete = "", nil, false
	credCache.mu.Unlock()
}

// credentialFolderBudget is how many entries one watched folder may cost.
const credentialFolderBudget = 1500

// skipCredentialDir: folders of logs and caches never hold the credentials themselves and can be huge.
var skipCredentialDir = map[string]bool{"logs": true, "log": true, "cache": true, ".cache": true, "tmp": true, "node_modules": true, "cached": true}

// credentialIDs is the set of (device, inode) of the person's credential files, and whether it is
// complete. Fixed credential files come first; then each watched folder (.ssh, .aws, .kube, ...)
// is walked with its own budget (recursively only where the watcher says so), skipping log and cache
// folders. A folder whose budget runs out makes the list incomplete: the caller then cannot tell
// and treats the file as a credential. Rebuilt when older than credentialTTL; built only when a
// hard-linked file shows up, so the common offline path never pays for it.
func credentialIDs(home string) (map[string]bool, bool) {
	credCache.mu.Lock()
	defer credCache.mu.Unlock()
	if credCache.ids != nil && credCache.home == home && time.Since(credCache.at) < credentialTTL {
		return credCache.ids, credCache.complete
	}
	ids := map[string]bool{}
	complete := true
	add := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			if id, ok := fileID(fi); ok {
				ids[id] = true
			}
		}
	}
	for _, rel := range []string{".kube/config", ".aws/credentials", ".aws/config", ".docker/config.json", ".netrc", ".pgpass", ".npmrc", ".pypirc",
		".git-credentials", ".s3cfg", ".claude.json", ".codex/auth.json", ".gemini/oauth_creds.json", ".config/gh/hosts.yml",
		".config/rclone/rclone.conf", ".m2/settings.xml", ".m2/settings-security.xml", ".config/github-copilot/apps.json", ".config/github-copilot/hosts.json"} {
		add(filepath.Join(home, filepath.FromSlash(rel)))
	}
	var walk func(dir string, recursive bool, depth int, budget *int)
	walk = func(dir string, recursive bool, depth int, budget *int) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			if *budget--; *budget < 0 {
				complete = false
				return
			}
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				if recursive && depth < 3 && !skipCredentialDir[strings.ToLower(e.Name())] {
					walk(p, true, depth+1, budget)
				}
				continue
			}
			add(p)
		}
	}
	for _, t := range watch.Targets(home) {
		if t.Dir {
			budget := credentialFolderBudget
			walk(t.Path, t.Recursive, 0, &budget)
		} else {
			add(t.Path)
		}
	}
	credCache.home, credCache.ids, credCache.complete, credCache.at = home, ids, complete, time.Now()
	return ids, complete
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

// plainCommand is true for a command made only of plain words, quotes around plain words, and the
// known separators. Offline, nothing else is replayed: a quote around a space, a backslash, a
// variable, a glob, a brace, a backquote or a cd (which changes what later words name) makes a word
// name something this check cannot see.
func plainCommand(cmd string) bool {
	plain := func(r rune) bool {
		return r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/+-:@%,=", r))
	}
	var quote rune
	for _, r := range cmd {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else if !plain(r) {
				return false
			}
		case r == '"' || r == '\'':
			quote = r
		case plain(r), unicode.IsSpace(r), strings.ContainsRune("<>|;&()", r):
		default:
			return false
		}
	}
	if quote != 0 {
		return false
	}
	for _, w := range strings.FieldsFunc(cmd, isCommandSeparator) {
		switch strings.Trim(w, `"'`) {
		case "cd", "pushd", "popd":
			return false
		}
	}
	return true
}

// offlineVerdict decides without the service, in the hook's own working folder.
func offlineVerdict(key, action, resource string) (Verdict, bool) {
	return offlineVerdictIn(key, action, resource, "")
}

// offlineVerdictIn decides without the service. cwd is the tool's working folder ("" for this
// process's). ok is false when there is no usable snapshot: the caller then fails closed.
func offlineVerdictIn(key, action, resource, cwd string) (v Verdict, ok bool) {
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
	notBefore := Verdict{false, "Manar: this was not allowed the last time Manar checked it, and Manar is restarting. Try again in a moment."}
	if sensitive(action, resource) {
		return refuse, true
	}
	yes := Verdict{true, "Manar: allowed (last policy)"}
	t := s.Tools[tool]
	if !pathActions[action] {
		if !plainCommand(resource) {
			return wait, true // quoting, escapes, variables, globs, cd: what a word names cannot be told
		}
		wd := canonCwd(cwd)
		inRoot := func(r string) bool { return insideRecordedRoot(&s, tool, r) }
		if commandTouchesSecretViaLink(resource, userHome(), wd, inRoot) {
			return refuse, true
		}
		k := shellKey(localCaller(), action, wd, resource)
		if hasEntryAny(t.Denied, k) {
			return notBefore, true
		}
		if hasEntry(t.Allowed, k) {
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
	if fi, err := os.Lstat(real); err == nil && fi.Mode().IsRegular() && linkCount(real, fi) > 1 && hardLinkedCredential(fi, userHome()) {
		return refuse, true // another name for a credential file (or Windows, where that cannot be told)
	}
	if action == "read" && (denyRule(s.ReadDeny, resource) || denyRule(s.ReadDeny, real)) {
		return Verdict{false, "Manar denied: this file is protected by your workspace's rules."}, true
	}
	k := actionKey(localCaller(), action, real)
	if hasEntryAny(t.Denied, k) {
		return notBefore, true
	}
	if fi, err := os.Lstat(real); err == nil && fi.Mode().IsRegular() && linkCount(real, fi) > 1 {
		// A file with several names is keyed by none of them: refusals and deny rules written for
		// another name do not apply. Only a package file may ride on the folder rule; anything else
		// needs an exact allow of this very path.
		if packageFile(real, func(p string) bool { return insideRecordedRoot(&s, tool, p) }) {
			if action == "read" && s.ReadsAllowed && !s.RefusedFull && insideRecordedRoot(&s, tool, real) {
				return yes, true
			}
		}
		if hasEntry(t.Allowed, k) {
			return yes, true
		}
		return wait, true
	}
	if !insideRecordedRoot(&s, tool, real) {
		return wait, true
	}
	if action == "read" && s.ReadsAllowed && !s.RefusedFull {
		return yes, true
	}
	if hasEntry(t.Allowed, k) {
		return yes, true
	}
	return wait, true
}

// denyRule matches the workspace's read-deny patterns against a path: "**" crosses folders, "*" and
// "?" do not, separators and (on Windows) case are normalised, a pattern without a slash matches the
// file name, one ending in a slash is that folder and everything below it, and a pattern that cannot be parsed denies.
func denyRule(patterns []string, p string) bool {
	p = fold(p)
	for _, pat := range patterns {
		pat = fold(pat)
		if strings.HasSuffix(pat, "/") {
			pat += "**" // a folder: everything below it, through the same glob
		}
		switch {
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
