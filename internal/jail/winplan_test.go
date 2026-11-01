package jail

import (
	"path/filepath"
	"reflect"
	"testing"

	"gitlab.vax.sh/manar/manar-edge/internal/discovery"
)

func TestPlanWindowsOnlyNativeClaudeAndOnlyThatUsersFiles(t *testing.T) {
	sam := discovery.User{Name: "sam", Home: filepath.Join("C:", "Users", "sam")}
	lee := discovery.User{Name: "lee", Home: filepath.Join("C:", "Users", "lee")}
	npm := discovery.User{Name: "npm-only", Home: filepath.Join("C:", "Users", "npm-only")}
	files := map[string][]string{
		filepath.Join(sam.Home, ".local", "bin", "claude.exe"):                {filepath.Join(sam.Home, ".local", "bin", "claude.exe")},
		filepath.Join(sam.Home, ".local", "share", "claude", "versions", "*"): {filepath.Join(sam.Home, ".local", "share", "claude", "versions", "2.1.0"), filepath.Join(sam.Home, ".local", "share", "claude", "versions", "notes.txt")},
	}
	glob := func(p string) []string { return files[p] }
	running := []string{
		filepath.Join(lee.Home, "tools", "Claude.EXE"),          // lee runs a native copy from elsewhere in the profile
		filepath.Join("C:", "Program Files", "x", "claude.exe"), // not in any profile: left alone
		filepath.Join(npm.Home, "node.exe"),                     // a runtime, never matched
	}
	plans := planWindows([]discovery.User{sam, lee, npm}, running, glob)
	if len(plans) != 2 {
		t.Fatalf("%+v", plans)
	}
	if !reflect.DeepEqual(plans[0].Exes, []string{
		filepath.Join(sam.Home, ".local", "bin", "claude.exe"),
		filepath.Join(sam.Home, ".local", "share", "claude", "versions", "2.1.0"),
	}) {
		t.Errorf("sam: %v", plans[0].Exes)
	}
	if plans[0].Settings != filepath.Join(sam.Home, ".claude", "settings.json") {
		t.Errorf("settings %s", plans[0].Settings)
	}
	if len(plans[1].Exes) != 1 || plans[1].User.Name != "lee" {
		t.Errorf("lee: %+v", plans[1])
	}
}

func TestWindowsScopeIsClaudeCodeOnly(t *testing.T) {
	if got := WindowsTools(); len(got) != 1 || got[0] != "host.claude-code" {
		t.Fatal(got)
	}
	for _, tool := range []string{"host.codex-cli", "host.gemini-cli", "host.copilot-cli", "host.cursor"} {
		if winPort(tool) != 0 {
			t.Errorf("%s has a Windows proxy port", tool)
		}
	}
	env := proxyEnv(8491)
	if env["HTTPS_PROXY"] != "http://127.0.0.1:8491" || env["HTTP_PROXY"] != env["HTTPS_PROXY"] || env["NO_PROXY"] != "localhost,127.0.0.1" {
		t.Fatalf("%v", env)
	}
}
