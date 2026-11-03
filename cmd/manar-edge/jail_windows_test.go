package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func ownerOf(t *testing.T, p string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	o, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return o.String()
}

func TestNewStateFolderIsBornProtected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state")
	if err := makeStateFolder(p); errors.Is(err, windows.ERROR_INVALID_OWNER) {
		t.Skip("not elevated: cannot make Administrators the owner")
	} else if err != nil {
		t.Fatal(err)
	}
	if o := ownerOf(t, p); o != sidAdmins {
		t.Fatalf("owner %s", o)
	}
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if c, _, _ := sd.Control(); c&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the DACL is not protected")
	}
	if s := sd.String(); strings.Contains(s, ";;;BU)") || strings.Contains(s, ";;;AU)") || strings.Contains(s, ";;;CO)") {
		t.Fatalf("users have access: %s", s)
	}
	if err := makeStateFolder(p); err != nil { // adopting our own folder again
		t.Fatalf("adopting a protected folder: %v", err)
	}
}

func TestAdoptRefusesForeignOrLinkedContent(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := u.User.Sid.String()
	mk := func(t *testing.T) string {
		p := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		setOwner(t, p, sidAdmins)
		return p
	}

	// A file owned by a user inside the folder.
	p := mk(t)
	f := filepath.Join(p, "manifest.json")
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	setOwner(t, f, me)
	if me != sidAdmins {
		if err := makeStateFolder(p); err == nil {
			t.Fatal("a user-owned file inside was accepted")
		}
	}

	// A junction inside the folder.
	p = mk(t)
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(p, "protect"), t.TempDir()).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v: %s", err, out)
	}
	if err := makeStateFolder(p); err == nil {
		t.Fatal("a junction inside was accepted")
	}

	// An Administrators-owned file with its own access list is reset to inherit only.
	p = mk(t)
	f = filepath.Join(p, "keep.json")
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	setOwner(t, f, sidAdmins)
	everyone, _ := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	dacl, _, _ := everyone.DACL()
	if err := windows.SetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := makeStateFolder(p); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if s := sd.String(); strings.Contains(s, ";;;WD)") {
		t.Fatalf("the file kept its own access list: %s", s)
	}
}
