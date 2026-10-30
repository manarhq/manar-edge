//go:build linux

package vault

import (
	"os"
	"strconv"
	"strings"
)

// parentExe returns the executable of pid's parent ("" when unknown).
func parentExe(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(f) < 2 {
		return ""
	}
	exe, err := os.Readlink("/proc/" + f[1] + "/exe")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(exe, " (deleted)")
}
