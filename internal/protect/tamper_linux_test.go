package protect

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/manarhq/manar-edge/internal/discovery"
)

func captureTamper(t *testing.T) *[]map[string]any {
	t.Helper()
	var got []map[string]any
	tamper.mu.Lock()
	old := tamper.send
	tamper.send = func(ev map[string]any) { got = append(got, ev) }
	tamper.seen = nil
	tamper.mu.Unlock()
	t.Cleanup(func() { tamper.mu.Lock(); tamper.send = old; tamper.seen = nil; tamper.mu.Unlock() })
	return &got
}

func TestScanReportsClaudeCodeOverrides(t *testing.T) {
	got := captureTamper(t)
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	for _, d := range []string{filepath.Join(proj, ".git"), filepath.Join(proj, ".claude"), filepath.Join(proj, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(proj, ".claude", "settings.local.json"), []byte(`{"disableAllHooks": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Above the project's root: not read.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	procRoot = t.TempDir()
	defer func() { procRoot = "/proc" }()
	pd := filepath.Join(procRoot, "4242")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"comm":    "claude\n",
		"cmdline": "claude\x00--settings\x00/tmp/other.json\x00",
		"environ": "HOME=" + home + "\x00CLAUDE_CONFIG_DIR=/tmp/cfg\x00",
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(pd, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(proj, "sub"), filepath.Join(pd, "cwd")); err != nil {
		t.Fatal(err)
	}
	// Another program of the same person is ignored.
	od := filepath.Join(procRoot, "4243")
	_ = os.MkdirAll(od, 0o755)
	_ = os.WriteFile(filepath.Join(od, "comm"), []byte("bash\n"), 0o644)
	_ = os.WriteFile(filepath.Join(od, "cmdline"), []byte("bash\x00--settings\x00x\x00"), 0o644)

	found := []discovery.Found{{Spec: discovery.Spec{Key: "claude-code"}, Users: []discovery.User{{Name: "sam", Home: home, UID: os.Getuid(), GID: os.Getgid()}}}}
	scanClaudeOverrides(found)
	scanClaudeOverrides(found) // the same thing again is not reported again
	var kinds []string
	for _, ev := range *got {
		kinds = append(kinds, ev["type"].(string))
		if ev["toolId"] != "host.claude-code" || ev["blocked"] != false {
			t.Errorf("event %v", ev)
		}
	}
	sort.Strings(kinds)
	want := []string{TamperConfigDir, TamperHooksDisabled, TamperSettingsFlag}
	if len(kinds) != len(want) || kinds[0] != want[0] || kinds[1] != want[1] || kinds[2] != want[2] {
		t.Fatalf("reported %v, want %v", kinds, want)
	}
}

func TestApplyReportsARemovedHook(t *testing.T) {
	home := t.TempDir()
	st := NewStore(t.TempDir())
	p := filepath.Join(home, ".claude", "settings.json")
	items := Plan("claude-code", discovery.User{Name: "sam", Home: home}, Ctx{Exe: "/usr/bin/manar-edge", GOOS: "linux"})
	edits := []FileEdit{items[0].FileEdit}
	owner := Owner{UID: -1, GID: -1, Home: home}
	st.fs = func(o Owner) FS { return directFS{Home: o.Home} }
	out, err := st.Apply("claude-code", "sam", owner, edits)
	if err != nil || !out[0].Changed || out[0].Repaired {
		t.Fatalf("first apply: %+v %v", out, err)
	}
	if err := os.WriteFile(p, []byte(`{"theme":"dark"}`), 0o644); err != nil { // the person took the hook out
		t.Fatal(err)
	}
	out, err = st.Apply("claude-code", "sam", owner, edits)
	if err != nil || !out[0].Changed || !out[0].Repaired {
		t.Fatalf("repair: %+v %v", out, err)
	}
	out, _ = st.Apply("claude-code", "sam", owner, edits)
	if out[0].Changed || out[0].Repaired {
		t.Fatalf("steady state: %+v", out)
	}
}
