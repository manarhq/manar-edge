package protect

// Regression tests for the second review of PR #36 (findings F1 to F6, F10, F11). Each asserts the
// safe behaviour.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// F2: a previously-allowed file replaced by a dangling link to a path outside the project is judged
// by where the link leads, not by its own name; a magic link is not followed either.
func TestOfflineDanglingLinkWriteEscapesNothing(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	setOfflineReadsPolicy(true, nil)
	out := filepath.Join(proj, "out.txt")
	os.WriteFile(out, []byte("x"), 0o644)
	recordOfflineDecision("host.claude-code", me, "write", out, proj, "ALLOW")
	save(t)
	if v, _ := offlineVerdict("claude-code", "write", out); !v.Allow {
		t.Fatalf("baseline: write should be allowed offline: %+v", v)
	}
	ssh := filepath.Join(userHome(), ".ssh")
	os.MkdirAll(ssh, 0o700)
	os.Remove(out)
	if err := os.Symlink(filepath.Join(ssh, "authorized_keys"), out); err != nil {
		t.Skip(err)
	}
	if v, ok := offlineVerdict("claude-code", "write", out); ok && v.Allow {
		t.Errorf("write through a dangling link to ~/.ssh/authorized_keys allowed offline: %+v", v)
	}
	fdLink := filepath.Join(proj, "fd.txt")
	os.Symlink("/proc/self/fd/77", fdLink)
	if v, ok := offlineVerdict("claude-code", "read", fdLink); ok && v.Allow {
		t.Errorf("read through /proc/self/fd/77 link allowed offline: %+v", v)
	}
}

// F3: a hard link to a secret, or to a file of another project, looks like an ordinary file.
func TestOfflineHardLinkedFilesAreNotAllowed(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	save(t)
	ssh := filepath.Join(userHome(), ".ssh")
	os.MkdirAll(ssh, 0o700)
	key := filepath.Join(ssh, "id_ed25519")
	os.WriteFile(key, []byte("PRIVATE"), 0o600)
	notes := filepath.Join(proj, "notes.txt")
	if err := os.Link(key, notes); err != nil {
		t.Skip(err)
	}
	if v, ok := offlineVerdict("claude-code", "read", notes); ok && v.Allow {
		t.Errorf("read of a hard link to ~/.ssh/id_ed25519 allowed offline: %+v", v)
	}
	other := filepath.Join(userHome(), "other-proj")
	os.MkdirAll(other, 0o755)
	os.WriteFile(filepath.Join(other, "customers.csv"), []byte("x"), 0o644)
	cl := filepath.Join(proj, "c.csv")
	os.Link(filepath.Join(other, "customers.csv"), cl)
	if v, ok := offlineVerdict("claude-code", "read", cl); ok && v.Allow {
		t.Errorf("read of a hard link to a file outside every root allowed offline: %+v", v)
	}
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); !v.Allow {
		t.Error("an ordinary file of the project should still be readable")
	}
}

// F4: "cat config" allowed in a project is not replayed from ~/.kube, and a bare word that names a
// secret next to the working folder is refused.
func TestOfflineShellAllowIsBoundToItsWorkingFolder(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	os.WriteFile(filepath.Join(proj, "config"), []byte("x"), 0o644)
	recordOfflineDecision("host.claude-code", me, "bash", "cat config", proj, "ALLOW")
	save(t)
	if v, _ := offlineVerdictIn("claude-code", "bash", "cat config", proj); !v.Allow {
		t.Fatalf("the same command in the same folder should be allowed: %+v", v)
	}
	kube := filepath.Join(userHome(), ".kube")
	os.MkdirAll(kube, 0o700)
	os.WriteFile(filepath.Join(kube, "config"), []byte("token: s3cr3t"), 0o600)
	if v, ok := offlineVerdictIn("claude-code", "bash", "cat config", kube); ok && v.Allow {
		t.Errorf("'cat config' allowed offline from ~/.kube: %+v", v)
	}
	wd, _ := os.Getwd()
	os.Chdir(kube)
	defer os.Chdir(wd)
	if v, ok := offlineVerdict("claude-code", "bash", "cat config"); ok && v.Allow {
		t.Errorf("'cat config' allowed offline from the hook's own cwd ~/.kube: %+v", v)
	}
	if !commandTouchesSecretViaLink("cat config", userHome(), kube) {
		t.Error("a bare word naming ~/.kube/config was not seen")
	}
}

// F5: every allow carries its own age; a flush does not make old answers young; a new policy
// version drops allows and project folders.
func TestOfflineAllowsExpireAndAPolicyChangeDropsThem(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.claude-code", me, "bash", "make deploy", proj, "ALLOW")
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	save(t)
	var s offlineSnapshot
	b, _ := os.ReadFile(offlineFile(stateDirNow()))
	_ = json.Unmarshal(b, &s)
	for _, e := range splitEntries(s.Tools["host.claude-code"].Allowed) {
		if e.At == 0 {
			t.Fatal("a stored allow has no time")
		}
	}
	// age the allow past the limit, keep the snapshot itself fresh, flush again
	rec.mu.Lock()
	tl := rec.snap.Tools["host.claude-code"]
	old := splitEntries(tl.Allowed)
	for i := range old {
		old[i].At = time.Now().Add(-offlineMaxAge - time.Minute).Unix()
	}
	tl.Allowed = joinEntries(old)
	rec.snap.Tools["host.claude-code"] = tl
	for i := range rec.snap.Roots {
		rec.snap.Roots[i].At = time.Now()
	}
	rec.mu.Unlock()
	saved := rec.snap.SavedAt
	save(t)
	if !rec.snap.SavedAt.Equal(saved) {
		t.Error("a flush reset the snapshot's saved time")
	}
	if v, _ := offlineVerdictIn("claude-code", "bash", "make deploy", proj); v.Allow {
		t.Error("an allow older than 8 h was replayed")
	}

	// a new policy version
	resetRec()
	setOfflineReadsPolicy(true, nil)
	setOfflinePolicyVersion("v1")
	recordOfflineDecision("host.claude-code", me, "bash", "make test", proj, "ALLOW")
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	save(t)
	if v, _ := offlineVerdictIn("claude-code", "bash", "make test", proj); !v.Allow {
		t.Fatal("setup")
	}
	setOfflinePolicyVersion("v1") // same version: nothing dropped
	save(t)
	if v, _ := offlineVerdictIn("claude-code", "bash", "make test", proj); !v.Allow {
		t.Fatal("the same policy version dropped an allow")
	}
	setOfflinePolicyVersion("v2")
	save(t)
	if v, _ := offlineVerdictIn("claude-code", "bash", "make test", proj); v.Allow {
		t.Error("an allow survived a new policy version")
	}
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); v.Allow {
		t.Error("a project folder survived a new policy version")
	}
}

// F4/F11: the key of a command is its text byte for byte; only paths are normalised.
func TestOfflineCommandsAreHashedExactly(t *testing.T) {
	if shellKey(me, "bash", "/p", "Cat X") == shellKey(me, "bash", "/p", "cat x") {
		t.Error("two commands that differ in case share a key")
	}
	if shellKey(me, "bash", "/p", "ls") == shellKey(me, "bash", "/q", "ls") {
		t.Error("the same command in two folders shares a key")
	}
	if shellKey(me, "bash", "/p", `a\b`) == shellKey(me, "bash", "/p", "a/b") {
		t.Error("separators in a command were normalised")
	}
}

// F1: a read Manar DENIED, or sent for approval, inside a recorded project folder is not allowed
// offline by the "reads in project folders" rule; a later ALLOW of it undoes the refusal.
func TestOfflineRefusedReadInsideARootStaysRefused(t *testing.T) {
	offlineRig(t)
	proj := project(t)
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "other.go"), proj, "DENY")
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "sub/deep.go"), proj, "APPROVAL_REQUIRED")
	save(t)
	for _, f := range []string{"other.go", "sub/deep.go"} {
		if v, ok := offlineVerdict("claude-code", "read", filepath.Join(proj, f)); !ok || v.Allow {
			t.Errorf("%s was refused online but is allowed offline: %+v", f, v)
		}
	}
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "other.go"), proj, "ALLOW")
	save(t)
	if v, _ := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); !v.Allow {
		t.Error("a later ALLOW should undo the refusal")
	}
	// and the other way round: an ALLOW then a DENY
	recordOfflineDecision("host.claude-code", me, "bash", "make x", proj, "ALLOW")
	recordOfflineDecision("host.claude-code", me, "bash", "make x", proj, "DENY")
	save(t)
	if v, _ := offlineVerdictIn("claude-code", "bash", "make x", proj); v.Allow {
		t.Error("a later DENY should undo the allow")
	}
}

// F6: folder deny rules written with a trailing slash match through the same glob.
func TestDenyRuleFolderPatternsWithATrailingSlash(t *testing.T) {
	p := "/home/sam/proj/secrets/prod.yaml"
	for _, pat := range []string{"secrets/", "**/secrets/", "proj/secrets/", "/home/sam/proj/secrets/", "secrets/**", "**/secrets/**"} {
		if !denyRule([]string{pat}, p) {
			t.Errorf("deny pattern %q does not match %q", pat, p)
		}
	}
	for _, pat := range []string{"other/", "/home/sam/other/", "proj/sec/"} {
		if denyRule([]string{pat}, p) {
			t.Errorf("deny pattern %q matches %q", pat, p)
		}
	}
}

// Pause and lock reach the saved policy at once, not at the next timer.
func TestPauseIsWrittenToTheSnapshotImmediately(t *testing.T) {
	state := offlineRig(t)
	setOfflineReadsPolicy(true, nil)
	save(t)
	setOfflineState(true, "")
	b, err := os.ReadFile(offlineFile(state))
	if err != nil {
		t.Fatal(err)
	}
	var s offlineSnapshot
	_ = json.Unmarshal(b, &s)
	if !s.Paused {
		t.Error("the pause was not written straight away")
	}
}
