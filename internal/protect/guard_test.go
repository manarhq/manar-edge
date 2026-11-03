package protect

import (
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
	if !Guard("edit", "/x/.claude/settings.json") || Guard("read", "/x/.claude/settings.json") {
		t.Fatal("Guard: edits are refused, reads are not")
	}
}
