//go:build windows

package warden

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkProtected refuses the helper path unless the file and every directory from it up to root
// (Program Files) is owned by SYSTEM, Administrators or TrustedInstaller and no ordinary user,
// group or Everyone is allowed to write, delete or take ownership of it. An error reading a
// security descriptor is a refusal.
func checkProtected(exe, root string) error {
	p := filepath.Clean(exe)
	r := strings.ToLower(filepath.Clean(root))
	for {
		if err := checkOne(p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if strings.ToLower(p) == r {
			return nil
		}
		parent := filepath.Dir(p)
		if parent == p {
			return fmt.Errorf("%s is not under %s", exe, root)
		}
		p = parent
	}
}

func checkOne(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !OwnerTrusted(owner.String()) {
		return fmt.Errorf("owner is not SYSTEM, Administrators or TrustedInstaller")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil {
		return fmt.Errorf("no DACL (everyone has full access)")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if AllowACEWritable(sid, uint32(ace.Mask)) {
			return fmt.Errorf("%s may change it", sid)
		}
	}
	return nil
}
