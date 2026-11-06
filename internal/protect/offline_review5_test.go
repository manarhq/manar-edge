package protect

import (
	"path/filepath"
	"testing"
)

// W1: the shell removes quotes anywhere in a word; the check does too.
func TestShellQuotesInsideAWordAreRemovedBeforeChecking(t *testing.T) {
	for _, c := range []struct{ cmd, file string }{
		{`c"d" sub && cat x.txt`, "sub/x.txt"},
		{`e'nv' -C sub cat x.txt`, "sub/x.txt"},
		{`git -"C"sub show HEAD`, ""},
		{`cat "x".txt`, "x.txt"},
		{`cat x".txt"`, "x.txt"},
	} {
		t.Run(c.cmd, func(t *testing.T) {
			if c.file == "" {
				if plainCommand(c.cmd) {
					t.Errorf("%q passes plainCommand", c.cmd)
				}
				return
			}
			proj := cmdRig(t, c.cmd)
			linkTo(t, filepath.Join(userHome(), ".aws", "credentials"), filepath.Join(proj, c.file))
			if v, ok := offlineVerdict("claude-code", "bash", c.cmd); ok && v.Allow {
				t.Errorf("%q with %s -> ~/.aws/credentials allowed offline: %+v", c.cmd, c.file, v)
			}
		})
	}
	if !commandTouchesQuoted(t) {
		t.Error("the quote-split word x\".txt\" was not resolved")
	}
}

func commandTouchesQuoted(t *testing.T) bool {
	proj := cmdRig(t, "cat x")
	linkTo(t, filepath.Join(userHome(), ".aws", "credentials"), filepath.Join(proj, "x.txt"))
	return commandTouchesSecretViaLink(`cat x".txt"`, userHome(), proj) && commandTouchesSecretViaLink(`cat "x".txt`, userHome(), proj)
}

// U1: a no-break space is not a separator to bash, so it must not split a word here either: the
// word names the file bash opens, or the command waits.
func TestUnicodeSpaceDoesNotSplitAWord(t *testing.T) {
	cmd := "cat notes x.txt"
	proj := cmdRig(t, cmd)
	linkTo(t, filepath.Join(userHome(), ".aws", "credentials"), filepath.Join(proj, "notes x.txt"))
	if v, ok := offlineVerdict("claude-code", "bash", cmd); ok && v.Allow {
		t.Errorf("%q (file 'notes<NBSP>x.txt' -> ~/.aws/credentials) allowed offline: %+v", cmd, v)
	}
	for _, c := range []string{"cat a b", "cat a b", "cat a　b", "cat a\u0085b"} {
		if plainCommand(c) {
			t.Errorf("%q replays", c)
		}
	}
}

// The reviewer's final wait and friction tables.
func TestPlainCommandFinalReviewTables(t *testing.T) {
	for _, c := range []string{
		"cd\tsub && cat x.txt", "cat x \\\n.txt", "cat x\r.txt", "cat${IFS}x.txt", "{ cd sub; cat x.txt; }",
		"(cd sub; cat x.txt)", "(cd sub) && cat x.txt", "command -p cat x.txt", "/usr/bin/env -C sub cat x.txt",
		"/usr/bin/xargs cat", "ls | /usr/bin/xargs cat", "git -C sub show", "git --git-dir=sub/.git show",
		"git --work-tree=sub status", "tar -xzCf sub a.tgz", "make -kf other.mk", "make --file=other.mk",
		"terraform -chdir=sub plan", "time cat x.txt", "if true; then cat x.txt; fi", ". ./x.sh", "source x.sh",
		"FOO=1 env -C sub cat x.txt", "nohup cat x.txt", "sudo cat x.txt", "pnpm -C sub test", "go -C sub test ./...",
		"CD sub & type x.txt",
	} {
		if plainCommand(c) {
			t.Errorf("%q is replayed offline", c)
		}
	}
	for _, c := range []string{
		"go test ./...", "npm test", "pnpm test", "git status", "git diff --stat", "ls -la", "make test", "make -j8 test",
		`git commit -m "fix"`, "git log --oneline -5", "cat README.md", "tar -xzf a.tgz", "docker compose up -d",
		"python -m pytest -q", "rg foo src/", "NODE_ENV=test npm test", "git checkout -b feat/x", "npm run build",
		"go vet ./... && go test ./...", "cargo build --release", "git -c color.ui=false status",
	} {
		if !plainCommand(c) {
			t.Errorf("%q waits offline (friction)", c)
		}
	}
}
