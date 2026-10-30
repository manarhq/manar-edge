// Package discovery finds the AI tools on a device (installs and running processes) and reports
// them to Manar every 10 minutes and whenever the list changes.
package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Probe is the machine, so tests can supply a fake one.
type Probe struct {
	Exists   func(path string) bool
	Glob     func(pattern string) []string
	ReadFile func(path string) ([]byte, error)
	// Procs returns lower-case process names.
	Procs func() []string
}

// OSProbe looks at the real machine.
func OSProbe() Probe {
	return Probe{
		Exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
		Glob: func(p string) []string {
			m, _ := filepath.Glob(p)
			return m
		},
		ReadFile: func(p string) ([]byte, error) { return os.ReadFile(p) },
		Procs:    processNames,
	}
}

// Found is one tool seen on the device.
type Found struct {
	Spec
	// Users are the accounts that use it (their settings are what protection edits).
	Users   []User
	Path    string
	Version string
	Other   bool // not in the catalogue: reported as other:<slug>
}

// ReportID is the id sent to Manar.
func (f Found) ReportID() string {
	if f.Other {
		return "other:" + f.Key
	}
	return f.ID
}

func expand(tmpl string, u User, goos string) string {
	config, local := filepath.Join(u.Home, ".config"), filepath.Join(u.Home, ".local", "share")
	if goos == "windows" {
		config, local = filepath.Join(u.Home, "AppData", "Roaming"), filepath.Join(u.Home, "AppData", "Local")
	}
	r := strings.NewReplacer("{home}", u.Home, "{config}", config, "{local}", local)
	return filepath.FromSlash(r.Replace(tmpl))
}

func (p Probe) first(tmpl string, u User, goos string) string {
	path := expand(tmpl, u, goos)
	if strings.ContainsAny(path, "*?[") {
		if m := p.Glob(path); len(m) > 0 {
			sort.Strings(m)
			return m[len(m)-1]
		}
		return ""
	}
	if p.Exists(path) {
		return path
	}
	return ""
}

// Scan finds every catalogue tool that is installed (per user or system-wide) or running, and any
// running "other" tool. goos is runtime.GOOS unless a test says otherwise.
func Scan(users []User, goos string, p Probe) []Found {
	procs := map[string]bool{}
	for _, n := range p.Procs() {
		procs[n] = true
	}
	var out []Found
	for _, s := range Catalogue {
		f := Found{Spec: s}
		for _, u := range users {
			for _, t := range s.User {
				if path := p.first(t, u, goos); path != "" {
					f.Users = append(f.Users, u)
					if f.Path == "" {
						f.Path = path
					}
					break
				}
			}
		}
		for _, t := range s.System {
			if path := p.first(t, User{}, goos); path != "" {
				if f.Path == "" {
					f.Path = path
				}
				break
			}
		}
		if f.Path == "" {
			for _, n := range s.Procs {
				if procs[n] {
					f.Path = n
				}
			}
		}
		if f.Path == "" {
			continue
		}
		f.Version = version(p, s, users, goos, f.Path)
		out = append(out, f)
	}
	var others []string
	for proc := range Others {
		if procs[proc] || procs[proc+".exe"] {
			others = append(others, proc)
		}
	}
	sort.Strings(others)
	for _, proc := range others {
		out = append(out, Found{Spec: Spec{Key: proc, Name: Others[proc]}, Path: proc, Other: true})
	}
	return out
}

func version(p Probe, s Spec, users []User, goos, path string) string {
	// The Copilot extension folder carries its version: github.copilot-1.2.3
	if s.Key == "vscode-copilot" {
		base := filepath.Base(path)
		if i := strings.LastIndex(base, "-"); i >= 0 && i+1 < len(base) {
			return base[i+1:]
		}
	}
	cands := []User{{}}
	cands = append(cands, users...)
	for _, t := range s.VersionFiles {
		for _, u := range cands {
			b, err := p.ReadFile(expand(t, u, goos))
			if err != nil {
				continue
			}
			var j struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(b, &j) == nil && len(j.Version) > 0 && len(j.Version) <= 64 {
				return j.Version
			}
		}
	}
	return ""
}
