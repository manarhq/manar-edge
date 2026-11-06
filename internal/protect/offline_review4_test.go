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

// Commands that change folder, run another program or compute names wait; the plain ones replay.
func TestPlainCommandTable(t *testing.T) {
	wait := []string{
		"env -C sub cat x.txt", "env --chdir sub cat x", "find sub -name x.txt | xargs cat", "git -C sub show HEAD:x.txt",
		"make -C sub all", "make -Csub all", "tar -xC dir -f a.tar", "tar --directory=sub -xf a.tar", "git -xC sub status",
		"git --git-dir=other/.git log", "git --work-tree=other status", "terraform -chdir=infra plan", "ninja -C build",
		"make -f other/Makefile all", "make -kf other/Makefile", "make --file=other/Makefile", "make --makefile other/Makefile",
		"find . -exec cat {} ;", "xargs cat",
		"env FOO=1 cat x", "sudo cat x", "doas cat x", "sh -c ls", "bash script.sh", "zsh x", "dash x", "fish x", "nohup make",
		"timeout 5 make", "nice make", "watch ls", "eval ls", "exec ls", "command ls", "builtin cd", "source env.sh", ". env.sh",
		"/usr/bin/env cat x", "/bin/bash x", "cd sub", "pushd sub", "echo hi && bash x", "ls | xargs cat", "FOO=1 bash x",
		// found by the reviewer: a line break, a leading reserved word, runners anywhere in the command
		"ls\ncd ~/.ssh && cat id_rsa", "ls\r\ncat x", "if true; then cd ..; fi", "! cd x", "time cd x", "while true; do cd x; done",
		"for f in a; do cat $f; done", "case x in x) cat y;; esac", "ls && cd sub", "ls; popd", "echo x | setsid cat y", "stdbuf -o0 cat x",
		"ionice cat x", "chrt 1 cat x", "taskset 1 cat x", "flock f cat x", "unbuffer cat x", "chroot / cat x", "su -c ls", "pkexec ls",
		"parallel cat", "busybox cat x", "echo x && exec ls", "ls | command cat", "ls ; builtin cd x", "ls ; source x", "time make", "then ls", "do ls", ". x",
	}
	for _, c := range wait {
		if plainCommand(c) {
			t.Errorf("%q must wait", c)
		}
	}
	replay := []string{"go test ./...", "make test", "make", "make -j4", "git status", "git log --oneline", "git diff HEAD", "ls src", "ls -la",
		"cat src/a.go", "echo hi>out.txt", `git log "--oneline"`, "pnpm test", "npm run build", "tar -xf a.tar", "tar -czf out.tgz src", "ls -l | wc -l",
		"cargo build --release", "terraform plan", "FOO=1 go test ./...", "ls .", "git add .", "grep -r x ."}
	for _, c := range replay {
		if !plainCommand(c) {
			t.Errorf("%q should replay", c)
		}
	}
	if plainCommand("echo 100%") == (runtime.GOOS == "windows") {
		t.Error("% must be a plain character everywhere except Windows, where it starts a variable")
	}
}
