package warden

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func ops(exe string, files map[string]fileInfo) procOps {
	return procOps{
		exeOf: func(int) (string, error) { return exe, nil },
		stat: func(p string) (fileInfo, error) {
			if f, ok := files[p]; ok {
				return f, nil
			}
			return fileInfo{}, errors.New("no such file")
		},
	}
}

func TestOnlyTheInstalledRootOwnedBinaryMayBeTheHelper(t *testing.T) {
	const want = "/usr/local/bin/manar-edge"
	safe := map[string]fileInfo{
		want:             {OwnerUID: 0, Mode: 0o755},
		"/usr/local/bin": {OwnerUID: 0, Mode: 0o755},
	}
	if err := verifyHelperExe(ops(want, safe), 42, want); err != nil {
		t.Fatalf("the installed binary was refused: %v", err)
	}
	// Some other program of the same user opens the socket.
	if err := verifyHelperExe(ops("/home/u/.npm/evil", safe), 42, want); err == nil {
		t.Fatal("another binary was accepted")
	}
	// A deleted-and-replaced binary reads as "... (deleted)".
	if err := verifyHelperExe(ops(want+" (deleted)", safe), 42, want); err == nil {
		t.Fatal("a deleted binary was accepted")
	}
	// The installed path is user-writable: not trustworthy.
	writable := map[string]fileInfo{want: {OwnerUID: 1000, Mode: 0o755}, "/usr/local/bin": {OwnerUID: 0, Mode: 0o755}}
	if err := verifyHelperExe(ops(want, writable), 42, want); err == nil {
		t.Fatal("a user-owned binary was accepted")
	}
	groupW := map[string]fileInfo{want: {OwnerUID: 0, Mode: 0o755}, "/usr/local/bin": {OwnerUID: 0, Mode: 0o775}}
	if err := verifyHelperExe(ops(want, groupW), 42, want); err == nil {
		t.Fatal("a group-writable directory was accepted")
	}
	// An unreadable /proc entry fails closed.
	failing := procOps{exeOf: func(int) (string, error) { return "", errors.New("gone") }, stat: ops(want, safe).stat}
	if err := verifyHelperExe(failing, 42, want); err == nil {
		t.Fatal("an unreadable peer was accepted")
	}
}

func TestInProtectedDir(t *testing.T) {
	sep := string(filepath.Separator)
	root := sep + "Program Files"
	cases := []struct {
		exe  string
		want bool
	}{
		{root + sep + "manar-edge" + sep + "manar-edge.exe", true},
		{strings.ToUpper(root) + sep + "manar-edge" + sep + "x.exe", true},
		{root + " Evil" + sep + "x.exe", false},
		{sep + "Users" + sep + "bob" + sep + "Downloads" + sep + "manar-edge.exe", false},
		{root + sep + ".." + sep + "tmp" + sep + "x", false},
		{"", false},
	}
	for _, c := range cases {
		if got := InProtectedDir(c.exe, root); got != c.want {
			t.Errorf("%q: got %v want %v", c.exe, got, c.want)
		}
	}
	if InProtectedDir(root+sep+"a", "") {
		t.Error("empty root must refuse")
	}
}

func TestWindowsACLPolicy(t *testing.T) {
	const users, everyone, admins, system = "S-1-5-32-545", "S-1-1-0", "S-1-5-32-544", "S-1-5-18"
	if !OwnerTrusted(admins) || !OwnerTrusted(system) || OwnerTrusted("S-1-5-21-1-2-3-1001") || OwnerTrusted("S-1-3-0") {
		t.Error("owner policy wrong")
	}
	read := uint32(0x1200a9) // read and execute
	if AllowACEWritable(users, read) {
		t.Error("read and execute for Users is fine")
	}
	for _, mask := range []uint32{0x2, 0x4, 0x40, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000, 0x1f01ff} {
		if !AllowACEWritable(users, mask) || !AllowACEWritable(everyone, mask) {
			t.Errorf("mask %#x for an ordinary group must count as writable", mask)
		}
		if AllowACEWritable(admins, mask) || AllowACEWritable(system, mask) {
			t.Errorf("mask %#x for admins or SYSTEM is allowed", mask)
		}
	}
}
