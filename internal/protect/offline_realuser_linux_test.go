package protect

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The real layout: the service writes the saved policy as root next to a private (0700) state
// directory, and the hook reads it as an ordinary user (uid 1000) with the real ownership checks,
// the real home lookup and no access to the state directory. It runs only in a throwaway container
// (MANAR_TEST_CONTAINER=1, root), because it creates /var/lib/manar-edge and a user.
func TestRealLayoutServiceWritesAsRootHookReadsAsUser1000(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("MANAR_TEST_CONTAINER") != "1" {
		t.Skip("needs root in a throwaway container (MANAR_TEST_CONTAINER=1)")
	}
	const uid = 1000
	state := "/var/lib/manar-edge"
	home := "/home/tester"
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	pw, _ := os.ReadFile("/etc/passwd")
	if !strings.Contains(string(pw), "tester:x:1000") {
		f, err := os.OpenFile("/etc/passwd", os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("tester:x:1000:1000::" + home + ":/bin/sh\n")
		f.Close()
	}
	proj := filepath.Join(home, "proj")
	for _, d := range []string{proj, filepath.Join(home, ".aws")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(proj, "a.go"), filepath.Join(proj, "b.go"), filepath.Join(home, ".aws", "credentials")} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Chown(home, uid, uid)
	_ = os.Chown(proj, uid, uid)

	// service side (root): the real writer, the real folder
	Configure(state)
	rec.mu.Lock()
	rec.snap, rec.dirty = offlineSnapshot{}, false
	rec.mu.Unlock()
	setOfflineReadsPolicy(true, nil)
	setOfflineState(false, "")
	recordOfflineDecision("host.cursor", "uid:1000", "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	flushOffline()
	if fi, err := os.Stat(offlineDir(state)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("snapshot folder: %v %v", fi, err)
	}

	// the test binary sits in a root-only build folder: give uid 1000 a copy it can run
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	bin := "/tmp/hooktest-bin"
	if err := os.WriteFile(bin, self, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(bin)
	ask := func(action, res string) map[string]any {
		cmd := exec.Command(bin, "-test.run=^TestHelperHookAsUser$")
		cmd.Env = append(os.Environ(), "MANAR_HOOK_HELPER=1", "MANAR_HOOK_STATE="+state, "MANAR_HOOK_ACTION="+action, "MANAR_HOOK_RES="+res, "HOME="+home)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helper: %v\n%s", err, out)
		}
		var res2 map[string]any
		i := strings.Index(string(out), "{")
		if i < 0 || json.Unmarshal([]byte(string(out)[i:strings.LastIndex(string(out), "}")+1]), &res2) != nil {
			t.Fatalf("helper output: %s", out)
		}
		return res2
	}
	if r := ask("read", filepath.Join(proj, "b.go")); r["ok"] != true || r["allow"] != true {
		t.Fatalf("a user could not read the root-written snapshot, or it did not allow a read in the project: %v", r)
	}
	if r := ask("read", filepath.Join(home, ".aws", "credentials")); r["allow"] == true {
		t.Fatalf("credentials allowed offline: %v", r)
	}
	if r := ask("bash", "go build ./..."); r["allow"] == true {
		t.Fatalf("an action never allowed was allowed: %v", r)
	}
	if r := ask("read", filepath.Join(proj, "b.go")); r["stateReadable"] == true {
		t.Fatalf("the hook can read the service's private state directory: %v", r)
	}
	// paused is carried by the snapshot alone
	setOfflineState(true, "")
	flushOffline()
	if r := ask("read", filepath.Join(proj, "b.go")); r["allow"] == true {
		t.Fatalf("paused, but the hook allowed: %v", r)
	}
}

// TestHelperHookAsUser is the hook side of the test above, run as uid 1000.
func TestHelperHookAsUser(t *testing.T) {
	if os.Getenv("MANAR_HOOK_HELPER") != "1" {
		t.Skip("helper")
	}
	state := os.Getenv("MANAR_HOOK_STATE")
	Configure(state)
	v, ok := offlineVerdict("cursor", os.Getenv("MANAR_HOOK_ACTION"), os.Getenv("MANAR_HOOK_RES"))
	_, serr := os.ReadDir(state)
	b, _ := json.Marshal(map[string]any{"ok": ok, "allow": v.Allow, "reason": v.Reason, "stateReadable": serr == nil})
	os.Stdout.Write(append(b, '\n'))
}
