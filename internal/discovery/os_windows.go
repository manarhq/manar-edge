package discovery

import (
	"bytes"
	"context"
	"encoding/csv"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Users returns the profile folders under the system drive's Users folder.
func Users() []User {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	root := drive + `\Users`
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	skip := map[string]bool{"public": true, "default": true, "default user": true, "all users": true, "defaultapppool": true}
	var out []User
	for _, e := range ents {
		if !e.IsDir() || skip[strings.ToLower(e.Name())] {
			continue
		}
		out = append(out, User{Name: e.Name(), Home: filepath.Join(root, e.Name()), UID: -1, GID: -1})
	}
	return out
}

func processNames() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command (fixed System32 path)
	b, err := exec.CommandContext(ctx, filepath.Join(sys, "System32", "tasklist.exe"), "/fo", "csv", "/nh").Output()
	if err != nil {
		return nil
	}
	recs, _ := csv.NewReader(bytes.NewReader(b)).ReadAll()
	var out []string
	for _, r := range recs {
		if len(r) > 0 {
			out = append(out, strings.ToLower(r[0]))
		}
	}
	return out
}
