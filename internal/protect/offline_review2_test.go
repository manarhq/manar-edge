package protect

// Regression tests for the third review of PR #36 (A1, A2, B1, B2, B3 and the hard-link rule).

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// A1: a refusal never ages out, so it cannot be forgotten while the project folder stays fresh.
func TestOfflineRefusalOutlivesTheEightHourWindow(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "other.go"), proj, "DENY")
	rec.mu.Lock()
	tl := rec.snap.Tools["host.claude-code"]
	es := splitEntries(tl.Denied)
	for i := range es {
		es[i].At -= int64(9 * 3600) // the refusal was given 9 hours ago
	}
	tl.Denied = joinEntries(es)
	rec.snap.Tools["host.claude-code"] = tl
	rec.mu.Unlock()
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW") // root fresh now
	save(t)
	if v, ok := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); ok && v.Allow {
		t.Errorf("a refusal older than 8 h was forgotten while the root is fresh: %+v", v)
	}
}

// A2: neither a flood of uncacheable allows nor of other refusals evicts a real refusal; a full
// refusal list turns the project-folder read rule off; an uncacheable allow is stored nowhere.
func TestOfflineRefusalsAreNotEvicted(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "other.go"), proj, "DENY")
	for i := 0; i < offlineKeep+10; i++ {
		recordOfflineDecision("host.claude-code", me, "bash", "echo "+strconv.Itoa(i), proj, "ALLOW_NOT_CACHEABLE")
	}
	save(t)
	if v, ok := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); ok && v.Allow {
		t.Errorf("a refusal was evicted by uncacheable answers: %+v", v)
	}
	tl := rec.snap.Tools["host.claude-code"]
	if len(splitEntries(tl.Allowed)) != 1 || len(splitEntries(tl.Denied)) != 1 {
		t.Errorf("uncacheable answers were stored: allowed %d, denied %d", len(splitEntries(tl.Allowed)), len(splitEntries(tl.Denied)))
	}
	// an uncacheable allow does not make offline say "not allowed last time"
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "sub/deep.go"), proj, "ALLOW_NOT_CACHEABLE")
	save(t)
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "sub/deep.go")); !v.Allow || v.Reason != "Manar: allowed (last policy)" {
		t.Errorf("a file allowed online (uncacheable) should be readable by the folder rule: %+v", v)
	}

	// overflow: the refusal list is full, so the folder rule is off rather than leaky
	for i := 0; i < offlineRefusedKeep+5; i++ {
		recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "r"+strconv.Itoa(i)+".go"), proj, "DENY")
	}
	save(t)
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); v.Allow {
		t.Error("the first refusal was lost")
	}
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "sub/deep.go")); v.Allow {
		t.Error("the folder read rule stayed on after the refusal list overflowed")
	}
	// a new policy version clears the refusals and the overflow
	setOfflinePolicyVersion("v1")
	setOfflinePolicyVersion("v2")
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	save(t)
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); !v.Allow {
		t.Errorf("refusals survived a new policy version: %+v", v)
	}
}

func shellRig(t *testing.T, cmd string) (proj string) {
	t.Helper()
	offlineRig(t)
	proj = project(t)
	recordOfflineDecision("host.claude-code", me, "bash", cmd, proj, "ALLOW")
	save(t)
	wd, _ := os.Getwd()
	os.Chdir(proj)
	t.Cleanup(func() { os.Chdir(wd) })
	return proj
}

// B1: a redirect glued to its word writes through a link to a secret.
func TestOfflineShellRedirectWithoutSpaceThroughLink(t *testing.T) {
	proj := shellRig(t, "echo hi>out.txt")
	aws := filepath.Join(userHome(), ".aws")
	os.MkdirAll(aws, 0o700)
	os.WriteFile(filepath.Join(aws, "credentials"), []byte("k"), 0o600)
	os.Symlink(filepath.Join(aws, "credentials"), filepath.Join(proj, "out.txt"))
	if v, ok := offlineVerdict("claude-code", "bash", "echo hi>out.txt"); ok && v.Allow {
		t.Errorf("'echo hi>out.txt' with out.txt -> ~/.aws/credentials allowed offline: %+v", v)
	}
	for _, c := range []string{"cat<out.txt", "echo x|tee out.txt", "(cat out.txt)", "cat `echo out.txt`", "cmd --out=out.txt"} {
		if !commandTouchesSecretViaLink(c, userHome(), proj) {
			t.Errorf("%q: the word out.txt was not seen", c)
		}
	}
}

// B2: a dangling link (EvalSymlinks fails) is refused, not skipped.
func TestOfflineShellDanglingLinkIsRefused(t *testing.T) {
	proj := shellRig(t, "echo hi > out.txt")
	os.MkdirAll(filepath.Join(userHome(), ".ssh"), 0o700)
	os.Symlink(filepath.Join(userHome(), ".ssh", "authorized_keys"), filepath.Join(proj, "out.txt"))
	if v, ok := offlineVerdict("claude-code", "bash", "echo hi > out.txt"); ok && v.Allow {
		t.Errorf("'echo hi > out.txt' with out.txt -> missing ~/.ssh/authorized_keys allowed offline: %+v", v)
	}
}

// B3: a command word that is a hard link waits, whatever the folder (credential file, node_modules,
// or outside every recorded folder).
func TestOfflineShellHardLinks(t *testing.T) {
	proj := shellRig(t, "cat notes.txt")
	os.MkdirAll(filepath.Join(userHome(), ".ssh"), 0o700)
	key := filepath.Join(userHome(), ".ssh", "id_ed25519")
	os.WriteFile(key, []byte("PRIVATE"), 0o600)
	if err := os.Link(key, filepath.Join(proj, "notes.txt")); err != nil {
		t.Skip(err)
	}
	if v, ok := offlineVerdict("claude-code", "bash", "cat notes.txt"); ok && v.Allow {
		t.Errorf("'cat notes.txt' (hard link to ~/.ssh/id_ed25519) allowed offline: %+v", v)
	}
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW") // the project folder is recorded
	recordOfflineDecision("host.claude-code", me, "bash", "cat node_modules/pkg.js", proj, "ALLOW")
	save(t)
	store := filepath.Join(userHome(), ".pnpm-store")
	os.MkdirAll(store, 0o755)
	os.WriteFile(filepath.Join(store, "pkg.js"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(proj, "node_modules"), 0o755)
	os.Link(filepath.Join(store, "pkg.js"), filepath.Join(proj, "node_modules", "pkg.js"))
	if v, ok := offlineVerdict("claude-code", "bash", "cat node_modules/pkg.js"); ok && v.Allow {
		t.Errorf("a command naming a hard-linked package file was replayed offline: %+v", v)
	}
	// a hard link to a file outside every recorded folder, named by an absolute path
	elsewhere := filepath.Join(userHome(), "elsewhere")
	os.MkdirAll(elsewhere, 0o755)
	f := filepath.Join(elsewhere, "data.csv")
	os.WriteFile(f, []byte("x"), 0o644)
	os.Link(f, filepath.Join(elsewhere, "data2.csv"))
	cmd := "cat " + f
	recordOfflineDecision("host.claude-code", me, "bash", cmd, proj, "ALLOW")
	save(t)
	if v, ok := offlineVerdict("claude-code", "bash", cmd); ok && v.Allow {
		t.Errorf("a hard-linked file outside the recorded folders allowed offline: %+v", v)
	}
}
