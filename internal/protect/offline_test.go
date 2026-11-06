package protect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/pause"
)

func offlineRig(t *testing.T) string {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	Configure(state)
	saveRead := readTrusted
	readTrusted = func(s string) ([]byte, error) { return os.ReadFile(offlineFile(s)) } // tests are not root
	saveCaller, saveHome := localCaller, userHome
	localCaller = func() string { return me }
	home := filepath.Join(t.TempDir(), "home", "sam")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if r, err := filepath.EvalSymlinks(home); err == nil {
		home = r
	}
	userHome = func() string { return home }
	rec.mu.Lock()
	rec.snap, rec.dirty = offlineSnapshot{}, false
	rec.mu.Unlock()
	t.Cleanup(func() { readTrusted, localCaller, userHome = saveRead, saveCaller, saveHome })
	return state
}

func resetRec() {
	rec.mu.Lock()
	rec.snap, rec.dirty = offlineSnapshot{}, false
	rec.mu.Unlock()
}

func save(t *testing.T) {
	t.Helper()
	rec.mu.Lock()
	rec.dirty = true
	rec.mu.Unlock()
	flushOffline()
}

// realReadTrusted is the real ownership check; offlineRig swaps readTrusted for a plain read.
var realReadTrusted = readTrusted

const me = "uid:1000" // the test's caller; localCaller is set to it in offlineRig

// project makes a project folder under the user's home-like temp dir, with a few files.
func project(t *testing.T) string {
	t.Helper()
	root := filepath.Join(userHome(), "proj")
	for _, f := range []string{"a.go", "other.go", "sub/deep.go", ".env.production", "config/db_password.txt", "server.pem"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestOfflineAllowsExactAllowedActionsAndReadsInsideAllowedRootsOnly(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.claude-code", me+"|s:abc", "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	recordOfflineDecision("host.claude-code", me+"|s:abc", "bash", "go test ./...", proj, "ALLOW")
	recordOfflineDecision("host.claude-code", me, "bash", "git push", proj, "APPROVAL_REQUIRED")
	save(t)
	for _, c := range []struct {
		action, res string
		allow       bool
		want        string
	}{
		{"read", filepath.Join(proj, "other.go"), true, "last policy"},    // inside the allowed project
		{"read", filepath.Join(proj, "sub/deep.go"), true, "last policy"}, // below it
		{"read", "/etc/hostname", false, RestartingText},                  // outside every project
		{"bash", "go test ./...", true, "last policy"},                    // exact, same caller (session ignored)
		{"bash", "git push", false, RestartingText},
		{"bash", "go vet ./...", false, RestartingText},
		{"read", filepath.Join(proj, ".env.production"), false, "secret"},
		{"read", filepath.Join(proj, "server.pem"), false, "secret"},
		{"read", filepath.Join(proj, "config/db_password.txt"), false, "secret"},
		{"read", "/home/x/.aws/credentials", false, "secret"},
		{"bash", "rm -rf /work", false, "secret or can delete"},
		{"bash", "cat ~/.ssh/id_ed25519", false, "secret or can delete"},
	} {
		v, ok := offlineVerdictIn("claude-code", c.action, c.res, proj)
		if !ok || v.Allow != c.allow || !strings.Contains(v.Reason, c.want) {
			t.Errorf("%s %q: %+v ok=%v", c.action, c.res, v, ok)
		}
	}
}

func TestOfflineReadsStayInsideTheRootsAfterSymlinksAreResolved(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "private.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(proj, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip(err)
	}
	inner := filepath.Join(proj, "inner-link.go")
	_ = os.Symlink(filepath.Join(proj, "a.go"), inner)
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	save(t)
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(link, "private.txt")); v.Allow {
		t.Fatal("a link that leaves the project root was followed")
	}
	if v, _ := offlineVerdict("claude-code", "read", inner); !v.Allow {
		t.Fatal("a link that stays inside should be fine")
	}
	// a file that does not exist yet resolves through its folder: nothing to leak, and a link
	// folder that leaves the project is still refused
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "missing.go")); !v.Allow {
		t.Fatal("a missing file inside the project should resolve through its folder")
	}
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(link, "missing.txt")); v.Allow {
		t.Fatal("a missing file behind a link that leaves the project was allowed")
	}
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "nodir", "missing.go")); v.Allow {
		t.Fatal("a path whose folder cannot be resolved was allowed")
	}
}

func TestOfflineReadRootsExpireAndBelongToOnePersonAndTool(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	recordOfflineDecision("host.cursor", "uid:2000", "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	save(t)
	f := filepath.Join(proj, "other.go")
	if v, _ := offlineVerdict("claude-code", "read", f); !v.Allow {
		t.Fatal("setup")
	}
	if v, _ := offlineVerdict("cursor", "read", f); v.Allow {
		t.Fatal("another person's root allowed my read")
	}
	// age every root past the limit and re-sign
	rec.mu.Lock()
	for i := range rec.snap.Roots {
		rec.snap.Roots[i].At = time.Now().Add(-offlineMaxAge - time.Minute)
	}
	rec.mu.Unlock()
	save(t)
	if v, _ := offlineVerdict("claude-code", "read", f); v.Allow {
		t.Fatal("an expired root still allowed reads")
	}
}

func TestOfflineReadDenyRules(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	setOfflineReadsPolicy(true, []string{"*.go", proj + "/sub/"})
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	save(t)
	for _, f := range []string{"a.go", "other.go", "sub/deep.go"} {
		if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, f)); v.Allow {
			t.Errorf("read-deny rule ignored for %s", f)
		}
	}
}

func TestDenyRuleMatching(t *testing.T) {
	for _, c := range []struct {
		pats []string
		path string
		deny bool
	}{
		{[]string{"**/secrets/**"}, "/home/sam/proj/secrets/a/b.txt", true},
		{[]string{"**/secrets/**"}, "/home/sam/proj/public/b.txt", false},
		{[]string{"/home/*/proj/**/*.pem"}, "/home/sam/proj/a/b/c.pem", true},
		{[]string{"/home/*/proj/*.pem"}, "/home/sam/proj/a/c.pem", false}, // * does not cross folders
		{[]string{"config/*.yml"}, "/home/sam/proj/config/db.yml", true},  // relative: anywhere
		{[]string{"*.tfvars"}, "/home/sam/proj/prod.tfvars", true},
		{[]string{"/home/sam/private/"}, "/home/sam/private/x", true},
		{[]string{"[bad"}, "/home/sam/anything", true},       // malformed: deny
		{[]string{"**/[bad/**"}, "/home/sam/anything", true}, // malformed inside a ** pattern: deny
		{[]string{"/a/[bad"}, "/home/sam/anything", true},    // malformed after a mismatch: still deny
		{nil, "/home/sam/anything", false},
	} {
		if got := denyRule(c.pats, c.path); got != c.deny {
			t.Errorf("%v on %s: %v want %v", c.pats, c.path, got, c.deny)
		}
	}
	if runtime.GOOS == "windows" && !denyRule([]string{`C:\Users\Sam\Secrets\**`}, `c:/users/sam/secrets/a.txt`) {
		t.Error("separators and case must be normalised on Windows")
	}
}

// A project folder must be inside the person's home and below it by a folder that is not a dot
// folder; the home itself, anything above it, and "/" never serve, whatever the client claims.
func TestOfflineRootsMustBeInsideHomeAndDeepEnough(t *testing.T) {
	offlineRig(t)
	home := userHome()
	proj := project(t)
	f := filepath.Join(proj, "a.go")
	dot := filepath.Join(home, ".config", "tool")
	_ = os.MkdirAll(dot, 0o755)
	_ = os.WriteFile(filepath.Join(dot, "x.txt"), []byte("x"), 0o644)
	setOfflineReadsPolicy(true, nil)
	for name, cwd := range map[string]string{"home": home, "above home": filepath.Dir(home), "slash": "/", "dot folder": filepath.Join(home, ".config")} {
		resetRec() // fresh snapshot each time, same home
		setOfflineReadsPolicy(true, nil)
		recordOfflineDecision("host.claude-code", me, "read", f, cwd, "ALLOW")
		recordOfflineDecision("host.claude-code", me, "read", filepath.Join(dot, "x.txt"), cwd, "ALLOW")
		save(t)
		other := filepath.Join(proj, "other.go")
		if v, _ := offlineVerdict("claude-code", "read", other); v.Allow {
			t.Errorf("%s served as a project folder", name)
		}
	}
	// the legitimate shape
	resetRec()
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.claude-code", me, "read", f, proj, "ALLOW")
	save(t)
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); !v.Allow {
		t.Fatal("a normal project folder should serve")
	}
	// a person whose "project" lies outside their home gets nothing
	home2 := t.TempDir()
	save2 := userHome
	userHome = func() string { return home2 }
	defer func() { userHome = save2 }()
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); v.Allow {
		t.Fatal("a folder outside the person's home served")
	}
}

// The root is stored resolved: a folder swapped for a link to somewhere else loses its allowance,
// and a link inside the project to a secret or to the outside is refused for reads, edits and writes.
func TestOfflineResolvesLinksBeforeAnyCheck(t *testing.T) {
	offlineRig(t)
	home := userHome()
	proj := project(t)
	secretDir := filepath.Join(home, ".aws")
	_ = os.MkdirAll(secretDir, 0o700)
	_ = os.WriteFile(filepath.Join(secretDir, "credentials"), []byte("k"), 0o600)
	outside := filepath.Join(home, "elsewhere")
	_ = os.MkdirAll(outside, 0o755)
	_ = os.WriteFile(filepath.Join(outside, "o.txt"), []byte("x"), 0o644)
	linkSecret := filepath.Join(proj, "notes.txt")
	linkOut := filepath.Join(proj, "out.txt")
	if err := os.Symlink(filepath.Join(secretDir, "credentials"), linkSecret); err != nil {
		t.Skip(err)
	}
	_ = os.Symlink(filepath.Join(outside, "o.txt"), linkOut)
	setOfflineReadsPolicy(true, nil)
	f := filepath.Join(proj, "a.go")
	recordOfflineDecision("host.claude-code", me, "read", f, proj, "ALLOW")
	// the service is told the link was allowed: it must not remember a secret under an ordinary name
	recordOfflineDecision("host.claude-code", me, "read", linkSecret, proj, "ALLOW")
	recordOfflineDecision("host.claude-code", me, "edit", linkSecret, proj, "ALLOW")
	save(t)
	for _, act := range []string{"read", "edit", "write"} {
		if v, _ := offlineVerdict("claude-code", act, linkSecret); v.Allow {
			t.Errorf("%s through a link to a credentials file", act)
		}
		if v, _ := offlineVerdict("claude-code", act, linkOut); v.Allow {
			t.Errorf("%s through a link that leaves the project", act)
		}
	}
	// a shell command naming the link
	recordOfflineDecision("host.claude-code", me, "bash", "cat "+linkSecret, "", "ALLOW")
	save(t)
	if v, _ := offlineVerdict("claude-code", "bash", "cat "+linkSecret); v.Allow {
		t.Error("a command reading a credentials file through a link was replayed")
	}
	// the project folder swapped for a link to somewhere else
	moved := proj + ".real"
	if err := os.Rename(proj, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, proj); err != nil {
		t.Fatal(err)
	}
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "o.txt")); v.Allow {
		t.Error("a swapped project folder kept its allowance")
	}
}

// The reviewer's list of credential files is never decided offline.
func TestOfflineNeverDecidesCredentialFiles(t *testing.T) {
	for _, p := range []string{
		"/home/sam/.codex/auth.json", "/home/sam/.gemini/oauth_creds.json", "/home/sam/.config/github-copilot/apps.json",
		"/home/sam/.claude.json", "/home/sam/.bash_history", "/home/sam/.zsh_history", "/home/sam/.s3cfg",
		"/home/sam/.config/rclone/rclone.conf", "/home/sam/.m2/settings.xml", "/home/sam/proj/terraform.tfstate",
		"/home/sam/proj/prod.tfvars", "/home/sam/keys/id.ppk", "/home/sam/.local/share/keyrings/login.keyring",
		"/home/sam/proj/.dev.vars", "/home/sam/proj/.env", "/home/sam/proj/server.pem",
	} {
		if !sensitive("read", p) {
			t.Errorf("%s is not treated as sensitive", p)
		}
	}
	if sensitive("read", "/home/sam/proj/main.go") || sensitive("read", "/home/sam/proj/README.md") {
		t.Error("ordinary files are sensitive")
	}
}

// One allowed read allows nothing else: not another file outside its project, not another person's
// or tool's action, and without the workspace policy no read passes beyond the exact one.
func TestOfflineDoesNotGeneraliseOneAllowedRead(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	recordOfflineDecision("host.claude-code", "uid:2000", "bash", "make", "", "ALLOW")
	save(t) // reads policy is off
	for _, c := range []struct{ action, res string }{
		{"read", filepath.Join(proj, "other.go")}, {"bash", "make"}, {"read", "/etc/shadow"},
	} {
		if v, ok := offlineVerdictIn("claude-code", c.action, c.res, proj); !ok || v.Allow {
			t.Errorf("%s %q allowed offline: %+v", c.action, c.res, v)
		}
	}
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "a.go")); !v.Allow {
		t.Error("the exact read that was allowed should still pass")
	}
	if v, _ := offlineVerdict("cursor", "read", filepath.Join(proj, "a.go")); v.Allow {
		t.Error("another tool's allowed read passed")
	}
}

func TestServiceNeverRecordsSecretsOrDestructiveAsAllowed(t *testing.T) {
	state := offlineRig(t)
	recordOfflineDecision("host.cursor", me, "bash", "rm -rf build", "", "ALLOW")
	recordOfflineDecision("host.cursor", me, "read", "/home/x/.aws/credentials", "", "ALLOW")
	save(t)
	b, _ := os.ReadFile(offlineFile(state))
	var s offlineSnapshot
	_ = json.Unmarshal(b, &s)
	if len(s.Tools["host.cursor"].Allowed) != 0 {
		t.Fatalf("%+v", s.Tools)
	}
}

// A user who edits or deletes the snapshot, or swaps in one they wrote, gets fail-closed, never allow-all.
func TestOfflineSnapshotTamperingFailsClosed(t *testing.T) {
	state := offlineRig(t)
	proj := project(t)
	f0 := filepath.Join(proj, "a.go")
	recordOfflineDecision("host.claude-code", me, "read", f0, proj, "ALLOW")
	save(t)
	if v, ok := offlineVerdict("claude-code", "read", f0); !ok || !v.Allow {
		t.Fatal("setup")
	}
	f := offlineFile(state)
	good, _ := os.ReadFile(f)

	// edited: grants everything for another tool
	var s offlineSnapshot
	_ = json.Unmarshal(good, &s)
	s.Tools["host.cursor"] = offlineTool{Allowed: joinEntries([]offlineEntry{{H: actionKey(me, "read", f0), At: time.Now().Unix()}})}
	edited, _ := json.Marshal(s)
	_ = os.WriteFile(f, edited, 0o644)
	if _, ok := offlineVerdict("cursor", "read", f0); ok {
		t.Fatal("trusted an edited snapshot")
	}
	// edited and re-summed by a user who knows the format: still only as trustworthy as the file's
	// owner, which readTrusted checks (below); here the checksum alone is not the defence.
	s.Sum = s.sum()
	// garbage, empty, missing, stale
	for name, content := range map[string][]byte{"garbage": []byte("{"), "empty": nil} {
		_ = os.WriteFile(f, content, 0o644)
		if _, ok := offlineVerdict("claude-code", "read", f0); ok {
			t.Fatalf("%s snapshot trusted", name)
		}
	}
	_ = os.Remove(f)
	if v, ok := offlineVerdict("claude-code", "read", f0); ok {
		t.Fatalf("deleted snapshot allowed: %+v", v)
	}
	s2 := offlineSnapshot{Version: offlineVersion, SavedAt: time.Now().Add(-48 * time.Hour), ReadsAllowed: true, Tools: map[string]offlineTool{}}
	s2.Sum = s2.sum()
	b, _ := json.Marshal(s2)
	_ = os.WriteFile(f, b, 0o644)
	if _, ok := offlineVerdict("claude-code", "read", f0); ok {
		t.Fatal("trusted a stale snapshot")
	}
}

// The real ownership check refuses a snapshot the user could have written (not root-owned).
func TestOfflineSnapshotNotOwnedByRootIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	state := filepath.Join(t.TempDir(), "state")
	Configure(state)
	recordOfflineDecision("host.claude-code", me, "read", "/work/a.go", "", "ALLOW")
	rec.mu.Lock()
	rec.dirty = true
	rec.mu.Unlock()
	flushOffline()
	if _, err := os.Stat(offlineFile(state)); err != nil {
		t.Fatal(err)
	}
	if _, ok := offlineVerdict("claude-code", "read", "/x"); ok {
		t.Fatal("a user-owned snapshot was trusted")
	}
}

// Paused and locked come from the snapshot, the only thing the hook reads: it never touches the
// service's private state directory.
func TestPausedAndLockedComeFromTheSnapshot(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	f := filepath.Join(proj, "a.go")
	recordOfflineDecision("host.claude-code", me, "read", f, proj, "ALLOW")
	save(t)
	if v, ok := offlineVerdict("claude-code", "read", f); !ok || !v.Allow {
		t.Fatal("setup")
	}
	setOfflineState(true, "")
	save(t)
	if v, ok := offlineVerdict("claude-code", "read", f); !ok || v.Allow || !strings.Contains(v.Reason, "paused") {
		t.Fatalf("paused: %+v", v)
	}
	setOfflineState(false, "device_revoked")
	save(t)
	if v, ok := offlineVerdict("claude-code", "read", f); ok || v.Allow {
		t.Fatalf("a locked device must fail closed: %+v ok=%v", v, ok)
	}
	setOfflineState(false, "")
	save(t)
	if v, _ := offlineVerdict("claude-code", "read", f); !v.Allow {
		t.Fatal("unpaused again")
	}
	_ = pause.Paused // the pause flag file is read by the service only
}

// The server's explicit offlineReadsAllowed reaches the snapshot; an older API that sends nothing
// means no offline reads.
func TestOfflineReadsPolicyComesFromTheServer(t *testing.T) {
	state := offlineRig(t)
	yes, no := true, false
	for _, c := range []struct {
		v    *bool
		want bool
	}{{&yes, true}, {nil, false}, {&no, false}} {
		reconcile(context.Background(), nil, &hostclient.Config{Status: "APPROVED", OfflineReadsAllowed: c.v})
		rec.mu.Lock()
		rec.dirty = true
		rec.mu.Unlock()
		flushOffline()
		b, _ := os.ReadFile(offlineFile(state))
		var s offlineSnapshot
		_ = json.Unmarshal(b, &s)
		if s.ReadsAllowed != c.want {
			t.Fatalf("policy %v: snapshot says %v", c.v, s.ReadsAllowed)
		}
	}
}

// An ALLOW served because of learning mode or a grant (cacheable false, or a reason that is not a
// plain policy allow) is never kept, and it drops an older cached allow of the same action.
func TestOfflineNeverKeepsUncacheableAllows(t *testing.T) {
	state := offlineRig(t)
	yes, no := true, false
	for name, res := range map[string]*hostclient.AuthorizeResult{
		"field and reason absent": {Decision: "ALLOW"},
		"explicit false":          {Decision: "ALLOW", Cacheable: &no},
		"learning mode":           {Decision: "ALLOW", Reason: "learning_mode"},
		"grant":                   {Decision: "ALLOW", Reason: "grant"},
		"approval":                {Decision: "ALLOW", Reason: "approved"},
		"false beats policy":      {Decision: "ALLOW", Reason: "policy_allow", Cacheable: &no},
	} {
		if d := offlineDecision(res); d == "ALLOW" {
			t.Errorf("%s would be cached", name)
		}
	}
	for name, res := range map[string]*hostclient.AuthorizeResult{
		"policy reason":          {Decision: "ALLOW", Reason: "policy_allow"},
		"explicit true":          {Decision: "ALLOW", Reason: "x", Cacheable: &yes},
		"denial is not an ALLOW": {Decision: "DENY", Reason: "no"},
	} {
		d := offlineDecision(res)
		if (d == "ALLOW") != (res.Decision == "ALLOW") {
			t.Errorf("%s: recorded as %s", name, d)
		}
	}

	// end to end through the recorder: a cached allow, then the same action allowed by learning mode
	recordOfflineDecision("host.cursor", me, "bash", "make test", "", offlineDecision(&hostclient.AuthorizeResult{Decision: "ALLOW", Reason: "policy_allow"}))
	save(t)
	if v, _ := offlineVerdict("cursor", "bash", "make test"); !v.Allow {
		t.Fatal("setup: a plain allow should be cached")
	}
	recordOfflineDecision("host.cursor", me, "bash", "make test", "", offlineDecision(&hostclient.AuthorizeResult{Decision: "ALLOW", Reason: "learning_mode"}))
	recordOfflineDecision("host.cursor", me, "bash", "make lint", "", offlineDecision(&hostclient.AuthorizeResult{Decision: "ALLOW", Reason: "learning_mode"}))
	save(t)
	for _, c := range []string{"make test", "make lint"} {
		if v, _ := offlineVerdict("cursor", "bash", c); v.Allow {
			t.Errorf("%q outlived the learning-mode window", c)
		}
	}
	_ = state
}

// The wire shape from POST /host/v1/authorize: `cacheable:false` is never kept; a missing field is
// kept only for a policy allow with a policy reason.
func TestCacheableFieldOnTheWire(t *testing.T) {
	for body, want := range map[string]string{
		`{"decision":"ALLOW","cacheable":false}`:                               "ALLOW_NOT_CACHEABLE",
		`{"decision":"ALLOW","reason":"policy_allow","cacheable":false}`:       "ALLOW_NOT_CACHEABLE",
		`{"decision":"ALLOW","reason":"learning_mode"}`:                        "ALLOW_NOT_CACHEABLE",
		`{"decision":"ALLOW","reason":"grant_8h"}`:                             "ALLOW_NOT_CACHEABLE",
		`{"decision":"ALLOW"}`:                                                 "ALLOW_NOT_CACHEABLE",
		`{"decision":"ALLOW","reason":"policy_allow"}`:                         "ALLOW",
		`{"decision":"ALLOW","cacheable":true}`:                                "ALLOW",
		`{"decision":"DENY","reason":"policy_deny","cacheable":false}`:         "DENY",
		`{"decision":"APPROVAL_REQUIRED","reason":"policy_requires_approval"}`: "APPROVAL_REQUIRED",
	} {
		var res hostclient.AuthorizeResult
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			t.Fatal(err)
		}
		if got := offlineDecision(&res); got != want {
			t.Errorf("%s: recorded as %s, want %s", body, got, want)
		}
	}
}
