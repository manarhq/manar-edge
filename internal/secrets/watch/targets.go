// Package watch is the secrets watcher: it notices which process opens a secret file (cloud keys,
// ssh keys, browser cookie and login databases, .env files), attributes it to an AI tool by the
// process tree, reports it to Manar, and on Linux can deny the open for the AI tool's own
// processes (docs: spec 4.5 item 3).
package watch

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Path classes as they appear in events.
const (
	ClassAWS     = "aws"
	ClassSSH     = "ssh"
	ClassAzure   = "azure"
	ClassGCloud  = "gcloud"
	ClassKube    = "kube"
	ClassDocker  = "docker"
	ClassBrowser = "browser"
	ClassEnv     = "env"
	ClassNPM     = "npm"
	ClassPyPI    = "pypi"
	ClassGitHub  = "github"
)

// Target is one watched path. Dir targets cover the files directly inside the directory that
// IsSecretFile accepts (and, for Recursive, the directories below it).
type Target struct {
	Path      string
	Class     string
	Dir       bool
	Recursive bool
}

// Targets lists what to watch for one home directory. Paths that do not exist are still
// returned (a file created later is caught by the daily rescan); expansion of globs needs the
// disk, so only existing browser profile directories are listed.
func Targets(home string) []Target {
	j := func(p ...string) string { return filepath.Join(append([]string{home}, p...)...) }
	t := []Target{
		{Path: j(".aws"), Class: ClassAWS, Dir: true},
		{Path: j(".ssh"), Class: ClassSSH, Dir: true},
		{Path: j(".azure"), Class: ClassAzure, Dir: true},
		{Path: j(".config", "gcloud"), Class: ClassGCloud, Dir: true, Recursive: true},
		{Path: j(".kube"), Class: ClassKube, Dir: true},
		{Path: j(".docker"), Class: ClassDocker, Dir: true},
		// Single files: an inode mark. A tool that replaces the file by rename loses the mark
		// until the next rescan (hourly).
		{Path: j(".npmrc"), Class: ClassNPM},
		{Path: j(".pypirc"), Class: ClassPyPI},
		{Path: j(".git-credentials"), Class: ClassGitHub},
		{Path: j(".config", "gh", "hosts.yml"), Class: ClassGitHub},
	}
	return append(t, browserTargets(home)...)
}

// browserTargets returns the profile directories of Chrome, Edge, Brave and Firefox that exist.
func browserTargets(home string) []Target {
	var roots []string
	if runtime.GOOS == "windows" {
		l := filepath.Join(home, "AppData", "Local")
		r := filepath.Join(home, "AppData", "Roaming")
		roots = []string{
			filepath.Join(l, "Google", "Chrome", "User Data"),
			filepath.Join(l, "Microsoft", "Edge", "User Data"),
			filepath.Join(l, "BraveSoftware", "Brave-Browser", "User Data"),
			filepath.Join(r, "Mozilla", "Firefox", "Profiles"),
		}
	} else {
		c := filepath.Join(home, ".config")
		roots = []string{
			filepath.Join(c, "google-chrome"), filepath.Join(c, "chromium"),
			filepath.Join(c, "microsoft-edge"), filepath.Join(c, "BraveSoftware", "Brave-Browser"),
			filepath.Join(home, ".mozilla", "firefox"), filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
		}
	}
	var out []Target
	for _, root := range roots {
		ents, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			prof := filepath.Join(root, e.Name())
			out = append(out, Target{Path: prof, Class: ClassBrowser, Dir: true})
			// Chromium keeps cookies in <profile>/Network.
			if n := filepath.Join(prof, "Network"); isDir(n) {
				out = append(out, Target{Path: n, Class: ClassBrowser, Dir: true})
			}
		}
	}
	return out
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// ClassOf returns the class of a path if it is a secret file, else "". It decides on the path
// alone (the home directory may differ), so it is what the permission handler calls.
func ClassOf(p string) string {
	n := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	base := n[strings.LastIndex(n, "/")+1:]
	has := func(seg string) bool { return strings.Contains(n, seg) }
	switch {
	case has("/.aws/") && (base == "credentials" || base == "config"):
		return ClassAWS
	case has("/.ssh/") && isSSHPrivate(n, base):
		return ClassSSH
	case has("/.azure/") && base != "":
		return ClassAzure
	case has("/.config/gcloud/") && base != "":
		return ClassGCloud
	case has("/.kube/") && base == "config":
		return ClassKube
	case has("/.docker/") && base == "config.json":
		return ClassDocker
	case base == ".npmrc" && !has("/node_modules/"):
		return ClassNPM
	case base == ".pypirc":
		return ClassPyPI
	case base == ".git-credentials", has("/.config/gh/") && base == "hosts.yml":
		return ClassGitHub
	case isBrowserSecret(n, base):
		return ClassBrowser
	case isEnvFile(base):
		return ClassEnv
	}
	return ""
}

func isSSHPrivate(n, base string) bool {
	if strings.HasSuffix(base, ".pub") {
		return false
	}
	switch base {
	case "known_hosts", "known_hosts.old", "config", "authorized_keys", "environment", "rc":
		return false
	}
	// Anything else directly in ~/.ssh: id_*, *.pem, custom names. A sub-folder file counts too.
	return !strings.HasSuffix(base, ".lock") && !strings.HasPrefix(base, ".")
}

func isBrowserSecret(n, base string) bool {
	if !(strings.Contains(n, "/google-chrome/") || strings.Contains(n, "/chromium/") ||
		strings.Contains(n, "/microsoft-edge/") || strings.Contains(n, "/edge/user data/") ||
		strings.Contains(n, "/chrome/user data/") || strings.Contains(n, "/brave-browser/") ||
		strings.Contains(n, "/.mozilla/firefox/") || strings.Contains(n, "/mozilla/firefox/profiles/")) {
		return false
	}
	switch base {
	case "cookies", "cookies-journal", "login data", "login data for account", "web data",
		"cookies.sqlite", "logins.json", "key4.db", "key3.db":
		return true
	}
	return false
}

// isEnvFile accepts .env and .env.* except the committed templates.
func isEnvFile(base string) bool {
	if base != ".env" && !strings.HasPrefix(base, ".env.") {
		return false
	}
	for _, t := range []string{".example", ".sample", ".template", ".dist", ".defaults"} {
		if strings.HasSuffix(base, t) {
			return false
		}
	}
	return true
}

var projectFolders = []string{"code", "src", "projects", "project", "dev", "work", "repos", "repo",
	"workspace", "git", "github", "Documents", "Desktop", "go", "source"}

var skipDirs = map[string]bool{"node_modules": true, ".git": true, ".cache": true, "vendor": true,
	"target": true, "dist": true, "build": true, ".venv": true, "venv": true, "__pycache__": true,
	".npm": true, ".cargo": true, ".rustup": true, "AppData": true, "Library": true, "snap": true}

// DiscoverEnv returns the .env* files under the user's usual project folders, at most maxDepth
// levels deep and maxFiles in total (a runaway tree must not stall the watcher).
func DiscoverEnv(home string, maxDepth, maxFiles int) []string {
	var out []string
	for _, f := range projectFolders {
		root := filepath.Join(home, f)
		if !isDir(root) {
			continue
		}
		rootDepth := strings.Count(filepath.ToSlash(root), "/")
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if len(out) >= maxFiles {
				return fs.SkipAll
			}
			if d.IsDir() {
				if p != root && (skipDirs[d.Name()] || strings.Count(filepath.ToSlash(p), "/")-rootDepth > maxDepth) {
					return fs.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() && isEnvFile(strings.ToLower(d.Name())) {
				out = append(out, p)
			}
			return nil
		})
	}
	return out
}
