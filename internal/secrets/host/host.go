// Package host holds what the secrets watcher and the vault share: the state directory, the
// users' home directories and the masking of paths that leave the device.
package host

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var (
	mu       sync.RWMutex
	stateDir string
)

// SetStateDir is called once by the command with the --state-dir value.
func SetStateDir(d string) { mu.Lock(); stateDir = d; mu.Unlock() }

// StateDir is the edge state directory ("" until set).
func StateDir() string { mu.RLock(); defer mu.RUnlock(); return stateDir }

// Homes returns the home directories of the people who use this computer (not system accounts).
func Homes() []string {
	if runtime.GOOS == "windows" {
		root := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
		skip := map[string]bool{"public": true, "default": true, "default user": true, "all users": true}
		var out []string
		ents, _ := os.ReadDir(root)
		for _, e := range ents {
			if e.IsDir() && !skip[strings.ToLower(e.Name())] {
				out = append(out, filepath.Join(root, e.Name()))
			}
		}
		return out
	}
	return passwdHomes("/etc/passwd")
}

// passwdHomes lists homes of accounts with uid 1000..59999 that exist on disk.
func passwdHomes(passwd string) []string {
	f, err := os.Open(passwd)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 6 {
			continue
		}
		uid, err := strconv.Atoi(p[2])
		if err != nil || uid < 1000 || uid >= 60000 {
			continue
		}
		if st, err := os.Stat(p[5]); err == nil && st.IsDir() {
			out = append(out, p[5])
		}
	}
	return out
}

// MaskPath replaces a leading home directory with "~" so the user name does not leave the
// device. A path under none of the homes is returned with any /home/<name> or C:\Users\<name>
// prefix masked the same way.
func MaskPath(homes []string, p string) string {
	norm := func(s string) string { return strings.ReplaceAll(s, `\`, "/") }
	np := norm(p)
	for _, h := range homes {
		nh := strings.TrimRight(norm(h), "/")
		if nh != "" && hasPrefixFold(np, nh+"/") {
			return "~" + np[len(nh):]
		}
		if np == nh {
			return "~"
		}
	}
	for _, root := range []string{"/home/", "/Users/", "C:/Users/", "c:/users/", "/root"} {
		if hasPrefixFold(np, root) {
			if root == "/root" {
				if np == "/root" || strings.HasPrefix(np, "/root/") {
					return "~" + np[len("/root"):]
				}
				continue
			}
			rest := np[len(root):]
			if i := strings.Index(rest, "/"); i >= 0 {
				return "~" + rest[i:]
			}
			return "~"
		}
	}
	return np
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
