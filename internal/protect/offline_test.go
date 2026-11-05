package protect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	saveCaller := localCaller
	localCaller = func() string { return me }
	rec.mu.Lock()
	rec.snap, rec.dirty = offlineSnapshot{}, false
	rec.mu.Unlock()
	t.Cleanup(func() { readTrusted, localCaller = saveRead, saveCaller })
	return state
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
	root := filepath.Join(t.TempDir(), "home", "sam", "proj")
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
		v, ok := offlineVerdict("claude-code", c.action, c.res)
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
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "missing.go")); v.Allow {
		t.Fatal("a path that cannot be resolved was allowed")
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

func TestOfflineReadDenyRulesAndTooWideRoots(t *testing.T) {
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
	// a client claiming "/" or "/home" as its project folder does not widen anything
	offlineRig(t)
	setOfflineReadsPolicy(true, nil)
	for _, wide := range []string{"/", "/home", "relative/dir"} {
		recordOfflineDecision("host.claude-code", me, "read", filepath.Join(wide, "x"), wide, "ALLOW")
	}
	save(t)
	if v, _ := offlineVerdict("claude-code", "read", "/etc/hostname"); v.Allow {
		t.Fatal("a too-wide root allowed a read")
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
		if v, ok := offlineVerdict("claude-code", c.action, c.res); !ok || v.Allow {
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
	recordOfflineDecision("host.claude-code", me, "read", "/work/a.go", "", "ALLOW")
	save(t)
	if v, ok := offlineVerdict("claude-code", "read", "/work/a.go"); !ok || !v.Allow {
		t.Fatal("setup")
	}
	f := offlineFile(state)
	good, _ := os.ReadFile(f)

	// edited: grants everything for another tool
	var s offlineSnapshot
	_ = json.Unmarshal(good, &s)
	s.Tools["host.cursor"] = offlineTool{Allowed: []string{actionKey(me, "read", "/work/a.go")}}
	edited, _ := json.Marshal(s)
	_ = os.WriteFile(f, edited, 0o644)
	if _, ok := offlineVerdict("cursor", "read", "/work/a.go"); ok {
		t.Fatal("trusted an edited snapshot")
	}
	// edited and re-summed by a user who knows the format: still only as trustworthy as the file's
	// owner, which readTrusted checks (below); here the checksum alone is not the defence.
	s.Sum = s.sum()
	// garbage, empty, missing, stale
	for name, content := range map[string][]byte{"garbage": []byte("{"), "empty": nil} {
		_ = os.WriteFile(f, content, 0o644)
		if _, ok := offlineVerdict("claude-code", "read", "/work/a.go"); ok {
			t.Fatalf("%s snapshot trusted", name)
		}
	}
	_ = os.Remove(f)
	if v, ok := offlineVerdict("claude-code", "read", "/work/a.go"); ok {
		t.Fatalf("deleted snapshot allowed: %+v", v)
	}
	s2 := offlineSnapshot{Version: offlineVersion, SavedAt: time.Now().Add(-48 * time.Hour), ReadsAllowed: true, Tools: map[string]offlineTool{}}
	s2.Sum = s2.sum()
	b, _ := json.Marshal(s2)
	_ = os.WriteFile(f, b, 0o644)
	if _, ok := offlineVerdict("claude-code", "read", "/work/a.go"); ok {
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

func TestPausedStillDeniesOffline(t *testing.T) {
	state := offlineRig(t)
	recordOfflineDecision("host.claude-code", me, "read", "/work/a.go", "", "ALLOW")
	save(t)
	if err := pause.Set(state, true); err != nil {
		t.Fatal(err)
	}
	if v, ok := offlineVerdict("claude-code", "read", "/work/a.go"); !ok || v.Allow || !strings.Contains(v.Reason, "paused") {
		t.Fatalf("%+v", v)
	}
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
		"explicit false":     {Decision: "ALLOW", Cacheable: &no},
		"learning mode":      {Decision: "ALLOW", Reason: "learning_mode"},
		"grant":              {Decision: "ALLOW", Reason: "grant"},
		"approval":           {Decision: "ALLOW", Reason: "approved"},
		"false beats policy": {Decision: "ALLOW", Reason: "policy_allow", Cacheable: &no},
	} {
		if d := offlineDecision(res); d == "ALLOW" {
			t.Errorf("%s would be cached", name)
		}
	}
	for name, res := range map[string]*hostclient.AuthorizeResult{
		"plain, field absent":    {Decision: "ALLOW"},
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
	recordOfflineDecision("host.cursor", me, "bash", "make test", "", offlineDecision(&hostclient.AuthorizeResult{Decision: "ALLOW"}))
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
