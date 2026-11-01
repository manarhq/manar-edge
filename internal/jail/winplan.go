package jail

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gitlab.vax.sh/manar/manar-edge/internal/discovery"
	"gitlab.vax.sh/manar/manar-edge/internal/protect"
)

// Windows scope. A tool is filtered on Windows only when two things are verified: the tool honours
// a proxy set in its own settings file, and its executable is a program of its own (so a per-app
// block does not also block every other program that runs on the same runtime).
//
//   - Claude Code, native install (claude.exe): settings.json "env" (code.claude.com network-config:
//     "All environment variables shown on this page can also be configured in settings.json").
//   - Codex CLI, Gemini CLI, Copilot CLI: no documented setting for their own proxy, so they are
//     not filtered on Windows. Claude Code installed through npm runs as node.exe and is not
//     filtered either.
const winTool = "host.claude-code"

// winPort is the fixed loopback port of a tool's proxy on Windows. It is fixed because the tool's
// own settings file names it; a program that holds the port while the service is down is caught
// by Challenge before anything is blocked.
func winPort(tool string) int {
	if tool == winTool {
		return 8491
	}
	return 0
}

// WindowsTools are the tool ids JAIL filters on Windows.
func WindowsTools() []string { return []string{winTool} }

func proxyEnv(port int) map[string]string {
	u := "http://127.0.0.1:" + itoa(port)
	return map[string]string{"HTTPS_PROXY": u, "HTTP_PROXY": u, "NO_PROXY": protect.JailNoProxy}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// userPlan is what JAIL does for one account.
type userPlan struct {
	User     discovery.User
	Settings string   // the settings file that gets the proxy variables
	Exes     []string // the native Claude Code executables to block except through the proxy
}

// planWindows works out, per account, the settings file and executables. An account without a
// native claude.exe is left out completely: no settings change and no block.
func planWindows(users []discovery.User, running []string, glob func(pattern string) []string) []userPlan {
	var out []userPlan
	for _, u := range users {
		set := map[string]bool{}
		for _, pat := range []string{
			filepath.Join(u.Home, ".local", "bin", "claude.exe"),
			filepath.Join(u.Home, ".local", "share", "claude", "versions", "*"),
		} {
			for _, p := range glob(pat) {
				if isExe(p) {
					set[p] = true
				}
			}
		}
		home := strings.ToLower(filepath.Clean(u.Home)) + string(filepath.Separator)
		for _, p := range running {
			if strings.HasPrefix(strings.ToLower(filepath.Clean(p)), home) && strings.EqualFold(filepath.Base(p), "claude.exe") {
				set[p] = true
			}
		}
		if len(set) == 0 {
			continue
		}
		exes := make([]string, 0, len(set))
		for p := range set {
			exes = append(exes, p)
		}
		sort.Strings(exes)
		out = append(out, userPlan{User: u, Settings: filepath.Join(u.Home, ".claude", "settings.json"), Exes: exes})
	}
	return out
}

var versionName = regexp.MustCompile(`^\d+(\.\d+)+$`)

// isExe: a program file (name.exe, or a bare version number as the native installer names the
// files in its versions folder), not a text file that happens to sit beside them.
func isExe(p string) bool {
	b := strings.ToLower(filepath.Base(p))
	return strings.HasSuffix(b, ".exe") || versionName.MatchString(b)
}
