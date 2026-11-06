package protect

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// M1: a hard link under node_modules to a refused file, a deny-rule file, another project's secret
// or a key in a sub-folder of ~/.ssh is not read offline: no folder name makes a file with several
// names ordinary.
func TestOfflineHardLinkUnderNodeModulesIsNotACarveOut(t *testing.T) {
	proj := allowedRoot(t)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "other.go"), proj, "DENY")
	save(t)
	nm := filepath.Join(proj, "node_modules", "left-pad")
	os.MkdirAll(nm, 0o755)
	cases := map[string]string{
		"refused file":         filepath.Join(proj, "other.go"),
		"deny-rule file":       filepath.Join(proj, "secrets", "prod.yaml"),
		"other project's .env": filepath.Join(userHome(), "other-proj", ".env.production"),
		"key in ~/.ssh/keys/":  filepath.Join(userHome(), ".ssh", "keys", "work_ed25519"),
		"AWS SSO token cache":  filepath.Join(userHome(), ".aws", "sso", "cache", "abc.json"),
		"top-level ~/.ssh key": filepath.Join(userHome(), ".ssh", "id_ed25519"),
	}
	i := 0
	for name, target := range cases {
		i++
		link := filepath.Join(nm, "f"+strconv.Itoa(i)+".js")
		hardTo(t, target, link)
		resetCredentialIDs()
		if v, ok := offlineVerdict("claude-code", "read", link); ok && v.Allow {
			t.Errorf("hard link under node_modules to %s allowed offline: %+v", name, v)
		}
	}
}

// Commands that change folder or compute names without a cd wait (env -C, git -C, make -C, xargs,
// find, -exec, --chdir); the plain ones still run.
func TestPlainCommandRefusesFolderChangingAndNameComputingCommands(t *testing.T) {
	for _, c := range []string{"env -C sub cat x.txt", "find sub -name x.txt | xargs cat", "git -C sub show HEAD:x.txt",
		"make -C sub all", "tar --directory=sub -xf a.tar", "env --chdir sub cat x", "find . -exec cat {} ;", "xargs cat"} {
		if plainCommand(c) {
			t.Errorf("%q counted as plain", c)
		}
	}
	for _, c := range []string{"go test ./...", "make test", "git status", "cat src/a.go", "echo hi>out.txt", `git log "--oneline"`} {
		if !plainCommand(c) {
			t.Errorf("%q should be plain", c)
		}
	}
	if plainCommand("echo 100%") == (runtime.GOOS == "windows") {
		t.Error("% must be a plain character everywhere except Windows, where it starts a variable")
	}
}
