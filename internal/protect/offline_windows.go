package protect

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/manarhq/manar-edge/internal/warden"
)

// offlineDir is a folder inside the state base, which only SYSTEM and Administrators can change.
func offlineDir(state string) string { return filepath.Join(filepath.Clean(state), "policy") }

// policyDACL is the state base's protected DACL (SYSTEM and Administrators full control, as
// stateDACL in the command package) plus read for Users, so the hook (running as the user) can read
// the snapshot. Nobody but SYSTEM and Administrators can write, delete or take ownership of it.
const policyDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;BU)"

var errUnprotected = errors.New("the saved policy is not protected")

func isReparse(path string) (bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		return false, err
	}
	return a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

// readTrusted reads the snapshot only when the file and the folders above it, up to the state
// folder, are owned by SYSTEM or Administrators with no write access for anyone else (the check the
// WARDEN helper uses), neither the file nor its folder is a reparse point, and the file is opened
// with FILE_FLAG_OPEN_REPARSE_POINT and checked on the handle. Otherwise the hook fails closed.
var readTrusted = func(state string) ([]byte, error) {
	f := offlineFile(state)
	for _, p := range []string{offlineDir(state), f} {
		if r, err := isReparse(p); err != nil || r {
			return nil, errUnprotected
		}
	}
	// Only the file and its folder are checked: a standard user cannot read the security descriptor
	// of ProgramData\manar-edge above them, and need not (nobody but SYSTEM and Administrators can
	// replace the folder, which lives in a SYSTEM/Administrators-only parent).
	if err := warden.CheckProtected(f, offlineDir(state)); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(f)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, errUnprotected
	}
	fd := os.NewFile(uintptr(h), f)
	defer fd.Close()
	return io.ReadAll(io.LimitReader(fd, 1<<20))
}

// writeOffline stores the snapshot. The folder is created with the protected DACL; one that already
// exists must not be a reparse point and must be owned by SYSTEM or Administrators, else it is
// refused. Not verified on a real Windows machine: until it passes, hooks fail closed.
func writeOffline(state string, b []byte) error {
	d := offlineDir(state)
	if _, err := os.Lstat(d); err == nil {
		if r, err := isReparse(d); err != nil || r {
			return errUnprotected
		}
		if err := warden.CheckProtected(d, filepath.Clean(state)); err != nil {
			return err
		}
	} else {
		sd, err := windows.SecurityDescriptorFromString("O:BA" + policyDACL)
		if err != nil {
			return err
		}
		name, err := windows.UTF16PtrFromString(d)
		if err != nil {
			return err
		}
		sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		if err := windows.CreateDirectory(name, sa); err != nil {
			return err
		}
	}
	tmp := offlineFile(state) + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, offlineFile(state))
}

// localCaller names the account the hook runs as, in the form the service records ("sid:<SID>").
var localCaller = func() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "unknown"
	}
	return "sid:" + u.User.Sid.String()
}
