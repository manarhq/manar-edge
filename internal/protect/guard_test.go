package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardedPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/home/sam/app/.claude/settings.json":             true,
		"/home/sam/app/.claude/settings.local.json":       true,
		".claude/settings.local.json":                     true,
		`C:\Users\Sam\app\.CLAUDE\Settings.Local.JSON`:    true,
		"/home/sam/app/.claude/./settings.json":           true,
		"/home/sam/app/x/../.claude/settings.json":        true,
		"/home/sam/.cursor/hooks.json":                    true,
		"/home/sam/proj/.cursor/hooks.json":               true,
		"/home/sam/.codeium/windsurf/hooks.json":          true,
		"/home/sam/.gemini/settings.json":                 true,
		"/home/sam/.codex/config.toml":                    true,
		"/home/sam/.copilot/hooks/manar.json":             true,
		"/home/sam/proj/.github/hooks/pre.json":           true,
		"/etc/claude-code/managed-settings.json":          true,
		"/etc/claude-code/managed-settings.d/10-x.json":   true,
		`C:\Users\Sam\AppData\Roaming\Code\User\mcp.json`: true,
		"/home/sam/app/.claude/commands/review.md":        false,
		"/home/sam/app/settings.json":                     false,
		"/home/sam/app/README.md":                         false,
		"/home/sam/app/.claude/agents/settings-helper.md": false,
		"/home/sam/app/src/claude/settings.json":          false,
		"/home/sam/.config/Code/User/settings.json":       false,
	} {
		if GuardedPath(p) != want {
			t.Errorf("GuardedPath(%q) != %v", p, want)
		}
	}
}

func TestGuardedCommand(t *testing.T) {
	for c, want := range map[string]bool{
		`echo '{"disableAllHooks":true}' > .claude/settings.local.json`: true,
		`cat ~/.claude/settings.json`:                                   true,
		`python3 -c "open('.claude/settings.local.json','w')"`:          true,
		`rm -rf ~/.claude`:                      true,
		`mv .cursor .cursor.bak`:                true,
		`cp -r /tmp/x ~/.gemini`:                true,
		`cd .claude && cat > x.json`:            true,
		`CLAUDE_CONFIG_DIR=/tmp/c claude -p hi`: true,
		`claude --settings /tmp/s.json -p hi`:   true,
		`Remove-Item -Recurse $HOME\.claude`:    true,
		`git status`:                            false,
		`ls -la .claude`:                        false,
		`npm test`:                              false,
		`grep -r settings src/`:                 false,
		`cat README.md > out.txt`:               false,
	} {
		if GuardedCommand(c) != want {
			t.Errorf("GuardedCommand(%q) != %v", c, want)
		}
	}
}

func TestRunHookRefusesGuardedChangesWithoutAskingManar(t *testing.T) {
	old := reportGuarded
	defer func() { reportGuarded = old }()
	var reported []string
	reportGuarded = func(key, action, res string) { reported = append(reported, action) }
	for _, in := range []string{
		`{"tool_name":"Write","tool_input":{"file_path":"/home/sam/app/.claude/settings.local.json","content":"{}"}}`,
		`{"tool_name":"Bash","tool_input":{"command":"echo x > .claude/settings.json"}}`,
	} {
		_, stderr, code := RunHook("claude-code", "tool", strings.NewReader(in))
		if code != 2 || !strings.Contains(string(stderr), "may not change AI tool hook or settings files") {
			t.Fatalf("%s: exit %d, %s", in, code, stderr)
		}
	}
	if strings.Join(reported, ",") != "edit,shell" {
		t.Fatalf("reported %v", reported)
	}
}

func guardIn(t *testing.T, key, event, in string) string {
	t.Helper()
	r, _, _ := GuardInput(key, event, []byte(in))
	return r
}

func TestEveryEditTargetIsChecked(t *testing.T) {
	refused := []string{
		// Codex apply_patch: the patch names the files.
		`{"tool_name":"apply_patch","tool_input":{"input":"*** Begin Patch\n*** Update File: src/main.go\n@@\n-a\n+b\n*** Add File: .claude/settings.local.json\n+{}\n*** End Patch"}}`,
		`{"tool_name":"apply_patch","tool_input":{"command":["apply_patch","*** Begin Patch\n*** Update File: notes.md\n*** Move to: .cursor/hooks.json\n*** End Patch"]}}`,
		`{"tool_name":"apply_patch","tool_input":{"patch":"diff --git a/x b/.gemini/settings.json\n--- a/x\n+++ b/.gemini/settings.json\n"}}`,
		`{"tool_name":"apply_patch","tool_input":{"patch":"rename from a.json\nrename to .codex/hooks.json\n"}}`,
		// Editors with other argument names.
		`{"tool_name":"str_replace_editor","tool_input":{"command":"create","path":".claude/settings.json","file_text":"{}"}}`,
		`{"tool_name":"move_file","tool_input":{"source":"x.json","destination":".claude/settings.local.json"}}`,
		// An MCP tool that writes a guarded file.
		`{"tool_name":"mcp__fs__write_file","tool_input":{"path":"/home/sam/app/.claude/settings.json","content":"{}"}}`,
		// Copilot's arguments as a JSON string.
		`{"toolName":"edit","toolArgs":"{\"path\":\".github/hooks/x.json\"}"}`,
		// apply_patch through the shell.
		`{"tool_name":"Bash","tool_input":{"command":"apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: .claude/settings.json\n*** End Patch\nEOF"}}`,
	}
	for _, in := range refused {
		if guardIn(t, "codex-cli", "tool", in) != GuardReason {
			t.Errorf("not refused: %s", in)
		}
	}
	// An editing call with no file Manar can find is refused; one with only ordinary files is not.
	if guardIn(t, "codex-cli", "tool", `{"tool_name":"apply_patch","tool_input":{"input":"*** Begin Patch\n*** End Patch"}}`) != GuardNoTarget {
		t.Error("an edit without a target was not refused")
	}
	for _, in := range []string{
		`{"tool_name":"apply_patch","tool_input":{"input":"*** Begin Patch\n*** Update File: src/main.go\n*** End Patch"}}`,
		`{"tool_name":"Write","tool_input":{"file_path":"/home/sam/app/README.md","content":"x"}}`,
		`{"tool_name":"mcp__fs__read_file","tool_input":{"path":"/home/sam/app/main.go"}}`,
		`{"tool_name":"Read","tool_input":{"file_path":"/home/sam/app/.claude/settings.json"}}`,
	} {
		if r := guardIn(t, "codex-cli", "tool", in); r != "" {
			t.Errorf("refused (%s): %s", r, in)
		}
	}
}

func TestPathCanonicalisation(t *testing.T) {
	for _, p := range []string{
		`C:\Users\sam\app\.claude\settings.json.`,
		`C:\Users\sam\app\.claude\settings.json. . `,
		`C:\Users\sam\app\.claude.\settings.json`,
		`C:\Users\sam\app\.claude\settings.json::$DATA`,
		`C:\Users\sam\app\.claude\settings.json:alt`,
		`/home/sam/app//.claude/./x/../settings.json`,
	} {
		if !GuardedPath(p) {
			t.Errorf("GuardedPath(%q) = false", p)
		}
	}
	if GuardedPath(`C:\Users\sam\app\notes:2026.txt`) || GuardedPath("/tmp/a:b/file.txt") {
		t.Error("a colon in an ordinary path made it guarded")
	}
}

func TestLinksToGuardedFilesAreFollowed(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, ".claude", "settings.json")
	if err := os.WriteFile(real, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "notes.json")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, ".claude"), filepath.Join(dir, "cfg")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"notes.json", "cfg/settings.local.json", filepath.Join(dir, "cfg", "settings.json")} {
		if !guardedTarget(p, dir) {
			t.Errorf("guardedTarget(%q) = false", p)
		}
	}
	if guardedTarget("other.json", dir) {
		t.Error("an ordinary new file was guarded")
	}
	in := `{"tool_name":"Write","cwd":"` + filepath.ToSlash(dir) + `","tool_input":{"file_path":"notes.json","content":"{}"}}`
	if guardIn(t, "claude-code", "tool", in) != GuardReason {
		t.Error("a write through a link was not refused")
	}
}

func TestShellTextIsNormalised(t *testing.T) {
	for _, c := range []string{
		`echo x > ~/app//.claude//settings.json`,
		`echo x > .claude/./settings.json`,
		`echo x > .claude/sub/../settings.json`,
		`python3 -c "import json; open('.claude/'+'s.json','w')"`,
		`cd .claude && node -e "require('fs').writeFileSync('x','y')"`,
		`perl -pi -e 's/a/b/' .cursor/x`,
		`echo '{}' | tee .gemini/x.json`,
		`dd if=/tmp/x of=.codex/y`,
		`sed -i 's/true/false/' .claude/x.json`,
		`sed -E -i '' .claude/x.json`,
	} {
		if !GuardedCommand(c) {
			t.Errorf("GuardedCommand(%q) = false", c)
		}
	}
	for _, c := range []string{`ls .claude`, `cat .claude/commands/review.md`, `python3 -m pytest`, `sed -n 1p README.md`} {
		if GuardedCommand(c) {
			t.Errorf("GuardedCommand(%q) = true", c)
		}
	}
}

func TestGuardResolvesTheRealTarget(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app")
	for _, d := range []string{filepath.Join(dir, ".claude"), filepath.Join(root, "deep", "x"), filepath.Join(root, "deep", ".claude")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A broken link to the settings file, and a broken link to somewhere harmless.
	if err := os.Symlink(filepath.Join(dir, ".claude", "settings.json"), filepath.Join(dir, "notes.json")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "nowhere", "x"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	// link -> deep/x, so link/../.claude is deep/.claude on disk (links before '..').
	if err := os.Symlink(filepath.Join(root, "deep", "x"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	// A relative link and a loop.
	if err := os.Symlink("../deep", filepath.Join(dir, "rel")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop", filepath.Join(dir, "loop")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"notes.json",                    // broken link to the settings file
		"dangling",                      // broken link
		"dangling/sub/file.txt",         // below a broken link
		"loop/x",                        // a link loop
		"link/../.claude/settings.json", // the link is followed before '..'
		"a/../.claude/settings.json",    // '..' in a path that does not exist
		"rel/.claude/settings.local.json",
		"../app/.claude/settings.json",
	} {
		if !guardedTarget(p, dir) {
			t.Errorf("guardedTarget(%q) = false", p)
		}
	}
	for _, p := range []string{
		"../README.md",
		"../deep/x/notes.txt",
		"link/../README.md",
		"new/folder/../file.txt",
		"src/main.go",
		filepath.Join(root, "deep", "x", "a.txt"),
	} {
		if guardedTarget(p, dir) {
			t.Errorf("guardedTarget(%q) = true", p)
		}
	}
	in := `{"tool_name":"Write","cwd":"` + filepath.ToSlash(dir) + `","tool_input":{"file_path":"../README.md","content":"x"}}`
	if r := guardIn(t, "claude-code", "tool", in); r != "" {
		t.Errorf("an edit of ../README.md was refused: %s", r)
	}
	in = `{"tool_name":"Write","cwd":"` + filepath.ToSlash(dir) + `","tool_input":{"file_path":"notes.json","content":"{}"}}`
	if guardIn(t, "claude-code", "tool", in) != GuardReason {
		t.Error("a write through a broken link to the settings file was not refused")
	}
}

func TestShellNormalisingCannotHideAName(t *testing.T) {
	for _, c := range []string{
		`echo x > a/../.claude/settings.json`,
		`echo x >a/../.claude/x`,
		`cat <.claude/x >y`,
		// The '..' rule would drop text here; the raw command still matches.
		`echo x > .claude/settings$(x)/../y`,
		"echo x > `.claude/settings`/../y",
		`echo x >.cursor/a`,
	} {
		if !GuardedCommand(c) {
			t.Errorf("GuardedCommand(%q) = false", c)
		}
	}
}

func TestShellParentElementNextToAToolFolder(t *testing.T) {
	for _, c := range []string{
		`echo x > $var/../.claude/settings.json`,
		`echo x > a$b/../.claude/settings.json`,
		"echo x > `pwd`/../.claude/settings.json",
		"cp y \"$(dirname x)\"/../.cursor/hooks.json",
		`cd .gemini && cd x/..`,
		`cat .codex/x ../y/..`,
	} {
		if !GuardedCommand(c) {
			t.Errorf("GuardedCommand(%q) = false", c)
		}
	}
	for _, c := range []string{`cd ../app && git status`, `ls .claude`, `cat ../README.md`} {
		if GuardedCommand(c) {
			t.Errorf("GuardedCommand(%q) = true", c)
		}
	}
}
