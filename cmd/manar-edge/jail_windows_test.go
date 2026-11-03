package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func setOwner(t *testing.T, p, sid string) {
	t.Helper()
	s, err := windows.StringToSid(sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, s, nil, nil, nil); err != nil {
		t.Skipf("cannot set the owner here (not elevated?): %v", err)
	}
}

func TestStateFolderOwner(t *testing.T) {
	d := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	setOwner(t, d, u.User.Sid.String())
	if err := checkStateFolder(d, sidSystem, sidAdmins); err == nil {
		t.Fatal("a folder owned by a user was accepted")
	}
	setOwner(t, d, sidAdmins)
	if err := checkStateFolder(d, sidSystem, sidAdmins); err != nil {
		t.Fatalf("a folder owned by Administrators was refused: %v", err)
	}
	j := filepath.Join(t.TempDir(), "j")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", j, d).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v: %s", err, out)
	}
	if err := checkStateFolder(j, sidSystem, sidAdmins); err == nil {
		t.Fatal("a junction was accepted")
	}
}
