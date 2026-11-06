package protect

// Regression tests for the fourth review of PR #36 (V1 to V6).

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func linkTo(t *testing.T, target, link string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(target), 0o700)
	if _, err := os.Stat(target); err != nil {
		os.WriteFile(target, []byte("SECRET"), 0o600)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func hardTo(t *testing.T, target, link string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(target), 0o700)
	if _, err := os.Stat(target); err != nil {
		os.WriteFile(target, []byte("SECRET"), 0o600)
	}
	if err := os.Link(target, link); err != nil {
		t.Fatal(err)
	}
}

func allowedRoot(t *testing.T) string {
	offlineRig(t)
	resetCredentialIDs()
	proj := project(t)
	setOfflineReadsPolicy(true, []string{"secrets/**"})
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	return proj
}

// V1: refusals live only in the service's memory; a service restart (rec starts empty and the
// first flush overwrites the file) forgets them, and the folder rule then allows the refused read.
func TestOfflineRefusalSurvivesAServiceRestart(t *testing.T) {
	proj := allowedRoot(t)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "other.go"), proj, "DENY")
	save(t)
	resetRec()                                          // the service restarts
	setOfflineReadsPolicy(true, []string{"secrets/**"}) // first config poll after the restart
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	save(t)
	if v, ok := offlineVerdict("claude-code", "read", filepath.Join(proj, "other.go")); ok && v.Allow {
		t.Errorf("FINDING: refusal forgotten after a service restart; denied read allowed: %+v", v)
	}
}

// V2: an ALLOW for a symlink's name is recorded under its TARGET's key and erases the target's refusal.
func TestOfflineAllowOnALinkNameKeepsTheTargetsRefusal(t *testing.T) {
	proj := allowedRoot(t)
	target := filepath.Join(proj, "other.go")
	recordOfflineDecision("host.claude-code", me, "read", target, proj, "DENY")
	link := filepath.Join(proj, "harmless.go")
	os.Symlink(target, link)
	recordOfflineDecision("host.claude-code", me, "read", link, proj, "ALLOW") // the server judged the name
	save(t)
	if v, ok := offlineVerdict("claude-code", "read", target); ok && v.Allow {
		t.Errorf("FINDING: ALLOW on a link name erased the refusal of its target: %+v", v)
	}
}

// V3: a hard link inside the root to a refused file, to a deny-rule file, or to another project's
// .env (a credential by NAME, not in the home-level inode list) is allowed.
func TestOfflineHardLinksDoNotBypassRefusalsDenyRulesOrOtherProjectsSecrets(t *testing.T) {
	proj := allowedRoot(t)
	recordOfflineDecision("host.claude-code", me, "read", filepath.Join(proj, "other.go"), proj, "DENY")
	save(t)
	cases := map[string]string{
		"refused file":         filepath.Join(proj, "other.go"),
		"deny-rule file":       filepath.Join(proj, "secrets", "prod.yaml"),
		"other project's .env": filepath.Join(userHome(), "other-proj", ".env.production"),
		"other project's pem":  filepath.Join(userHome(), "other-proj", "deploy.pem"),
	}
	i := 0
	for name, target := range cases {
		i++
		link := filepath.Join(proj, "alias"+strconv.Itoa(i)+".txt")
		hardTo(t, target, link)
		resetCredentialIDs()
		if v, ok := offlineVerdict("claude-code", "read", link); ok && v.Allow {
			t.Errorf("FINDING: hard link to %s allowed offline: %+v", name, v)
		}
	}
}

// V4: the credential inode walk shares one 4000-entry budget; a big ~/.config/gcloud (walked
// before ~/.kube) hides ~/.kube/config.
func TestOfflineCredentialWalkBudgetCannotHideTheKubeConfig(t *testing.T) {
	proj := allowedRoot(t)
	save(t)
	logs := filepath.Join(userHome(), ".config", "gcloud", "logs", "2026.11.06")
	os.MkdirAll(logs, 0o700)
	for i := 0; i < 4100; i++ {
		os.WriteFile(filepath.Join(logs, strconv.Itoa(i)+".log"), nil, 0o600)
	}
	link := filepath.Join(proj, "cfg.yaml")
	hardTo(t, filepath.Join(userHome(), ".kube", "config"), link)
	resetCredentialIDs()
	if v, ok := offlineVerdict("claude-code", "read", link); ok && v.Allow {
		t.Errorf("FINDING: hard link to ~/.kube/config allowed once the inode walk budget is spent: %+v", v)
	}
}

func cmdRig(t *testing.T, cmd string) string {
	proj := allowedRoot(t)
	recordOfflineDecision("host.claude-code", me, "bash", cmd, proj, "ALLOW")
	save(t)
	wd, _ := os.Getwd()
	os.Chdir(proj)
	t.Cleanup(func() { os.Chdir(wd) })
	return proj
}

// V5: words the splitter cannot map to a file skip the link check.
func TestOfflineShellWordsTheSplitterCannotSeeAreNotReplayed(t *testing.T) {
	for name, c := range map[string]struct{ cmd, file string }{
		"quoted name with a space": {`cat "my notes.txt"`, "my notes.txt"},
		"backslash-escaped space":  {`cat my\ notes.txt`, "my notes.txt"},
		"ANSI-C quoting":           {`cat $'notes.txt'`, "notes.txt"},
		"variable":                 {`cat ${PWD}/notes.txt`, "notes.txt"},
		"glob":                     {`cat note?.txt`, "notes.txt"},
		"cd first":                 {`cd sub && cat x.txt`, "sub/x.txt"},
	} {
		t.Run(name, func(t *testing.T) {
			proj := cmdRig(t, c.cmd)
			linkTo(t, filepath.Join(userHome(), ".aws", "credentials"), filepath.Join(proj, c.file))
			if v, ok := offlineVerdict("claude-code", "bash", c.cmd); ok && v.Allow {
				t.Errorf("FINDING: %q with %s -> ~/.aws/credentials allowed offline: %+v", c.cmd, c.file, v)
			}
		})
	}
}

// The credential list: a huge log folder in one watched folder cannot hide another folder's
// credentials, a folder whose budget runs out makes the list incomplete (hard links then wait), and
// the list is rebuilt when older than a few minutes.
func TestCredentialIDsHaveABudgetPerFolderAndExpire(t *testing.T) {
	offlineRig(t)
	home := userHome()
	logs := filepath.Join(home, ".config", "gcloud", "logs")
	os.MkdirAll(logs, 0o700)
	for i := 0; i < credentialFolderBudget+100; i++ {
		os.WriteFile(filepath.Join(logs, strconv.Itoa(i)+".log"), nil, 0o600)
	}
	kube := filepath.Join(home, ".kube", "config")
	os.MkdirAll(filepath.Dir(kube), 0o700)
	os.WriteFile(kube, []byte("x"), 0o600)
	fi, _ := os.Stat(kube)
	id, _ := fileID(fi)
	ids, complete := credentialIDs(home)
	if !ids[id] || !complete {
		t.Errorf("kube config missing (complete %v)", complete)
	}
	// a watched folder over its budget: cannot tell
	ssh := filepath.Join(home, ".ssh")
	os.MkdirAll(ssh, 0o700)
	for i := 0; i < credentialFolderBudget+100; i++ {
		os.WriteFile(filepath.Join(ssh, "f"+strconv.Itoa(i)), nil, 0o600)
	}
	resetCredentialIDs()
	if _, complete := credentialIDs(home); complete {
		t.Error("a spent budget was reported as a complete list")
	}
	// rebuilt when old
	resetCredentialIDs()
	credentialIDs(home)
	late := filepath.Join(home, ".netrc")
	os.WriteFile(late, []byte("x"), 0o600)
	fi, _ = os.Stat(late)
	lid, _ := fileID(fi)
	credCache.mu.Lock()
	credCache.at = time.Now().Add(-credentialTTL - time.Second)
	credCache.mu.Unlock()
	if ids, _ := credentialIDs(home); !ids[lid] {
		t.Error("the list was not rebuilt after its time")
	}
}
