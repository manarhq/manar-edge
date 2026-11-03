package protect

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/manarhq/manar-edge/internal/discovery"
)

// procRoot is /proc; tests point it elsewhere.
var procRoot = "/proc"

// scanClaudeOverrides looks at every running Claude Code of a person Manar protects it for, and
// reports what would take Manar's hook out of play: --settings on its command line,
// CLAUDE_CONFIG_DIR in its environment, or disableAllHooks in the settings of the project it runs
// in (its working folder and the folders above it, up to the project's root or the home). Project
// files are read as their owner (readUserFile), never following a link.
func scanClaudeOverrides(found []discovery.Found) {
	users := map[int]discovery.User{}
	for _, f := range found {
		if f.Key == "claude-code" {
			for _, u := range f.Users {
				users[u.UID] = u
			}
		}
	}
	if len(users) == 0 {
		return
	}
	dirs, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*"))
	for _, d := range dirs {
		st, err := os.Stat(d)
		if err != nil {
			continue
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		u, ok := users[int(sys.Uid)]
		if !ok {
			continue
		}
		args := nulFields(d, "cmdline")
		comm, _ := os.ReadFile(filepath.Join(d, "comm"))
		if strings.TrimSpace(string(comm)) != "claude" && !strings.Contains(strings.Join(args, " "), "@anthropic-ai/claude-code") {
			continue
		}
		checkClaudeProcess(d, u, args)
	}
}

func nulFields(dir, name string) []string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range bytes.Split(b, []byte{0}) {
		if len(f) > 0 {
			out = append(out, string(f))
		}
	}
	return out
}

func checkClaudeProcess(dir string, u discovery.User, args []string) {
	const tool = "host.claude-code"
	for i, a := range args {
		if a == "--settings" || strings.HasPrefix(a, "--settings=") {
			v := strings.TrimPrefix(a, "--settings=")
			if a == "--settings" && i+1 < len(args) {
				v = args[i+1]
			}
			if strings.HasPrefix(strings.TrimSpace(v), "{") {
				v = "(inline JSON)"
			}
			reportTamper(TamperSettingsFlag, tool, "claude", v, false)
		}
	}
	for _, e := range nulFields(dir, "environ") {
		if v, ok := strings.CutPrefix(e, "CLAUDE_CONFIG_DIR="); ok && filepath.Clean(v) != filepath.Join(u.Home, ".claude") {
			reportTamper(TamperConfigDir, tool, "claude", v, false)
		}
	}
	cwd, err := os.Readlink(filepath.Join(dir, "cwd"))
	if err != nil || !strings.HasPrefix(cwd, u.Home+"/") {
		return
	}
	for d, n := cwd, 0; d != u.Home && d != "/" && n < 32; d, n = filepath.Dir(d), n+1 {
		for _, name := range []string{"settings.json", "settings.local.json"} {
			p := filepath.Join(d, ".claude", name)
			if _, err := os.Lstat(p); err != nil { // cheap check first: reading spawns a helper
				continue
			}
			if b, ok := readUserFile(u, p); ok && disablesHooks(b) {
				reportTamper(TamperHooksDisabled, tool, "claude", p, false)
			}
		}
		if st, err := os.Lstat(filepath.Join(d, ".git")); err == nil && (st.IsDir() || st.Mode().IsRegular()) {
			return // the project's root
		}
	}
}

// disablesHooks is true for settings with "disableAllHooks": true.
func disablesHooks(b []byte) bool {
	var s map[string]any
	return json.Unmarshal(b, &s) == nil && s["disableAllHooks"] == true
}
