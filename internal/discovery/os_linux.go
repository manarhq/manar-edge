package discovery

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Users returns the accounts whose home folders hold tool settings: root and every regular
// account (uid 1000 and up) with a real shell and an existing home.
func Users() []User {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	var out []User
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, e1 := strconv.Atoi(f[2])
		gid, e2 := strconv.Atoi(f[3])
		if e1 != nil || e2 != nil || (uid != 0 && uid < 1000) || uid == 65534 {
			continue
		}
		if strings.HasSuffix(f[6], "nologin") || strings.HasSuffix(f[6], "/false") {
			continue
		}
		if st, err := os.Stat(f[5]); err != nil || !st.IsDir() {
			continue
		}
		out = append(out, User{Name: f[0], Home: f[5], UID: uid, GID: gid})
	}
	return out
}

func processNames() []string {
	dirs, _ := filepath.Glob("/proc/[0-9]*/comm")
	var out []string
	for _, d := range dirs {
		if b, err := os.ReadFile(d); err == nil {
			out = append(out, strings.ToLower(strings.TrimSpace(string(b))))
		}
	}
	return out
}
