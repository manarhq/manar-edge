package warden

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// CheckUID is the policy behind the Linux socket check: root and the listed users only.
func CheckUID(uid uint32, allowed []uint32) error {
	if uid == 0 {
		return nil
	}
	for _, a := range allowed {
		if a == uid {
			return nil
		}
	}
	return fmt.Errorf("user %d is not allowed to use WARDEN on this device", uid)
}

// fileInfo is what the exe check needs to know about a path (a fake in tests).
type fileInfo struct {
	OwnerUID uint32
	Mode     fs.FileMode
}

type procOps struct {
	// exeOf returns the executable path of a running process (Linux: readlink /proc/<pid>/exe).
	exeOf func(pid int) (string, error)
	stat  func(path string) (fileInfo, error)
}

// verifyHelperExe checks that the connecting process is the installed manar-edge binary: its
// executable is exactly want, and that file and its directory are owned by root and not writable
// by anyone else. A same-user process that merely opens the socket (the AI tool, a postinstall
// script) runs some other binary and is refused. It cannot stop code that runs inside the real
// binary's process (see docs/warden.md, residual risk).
func verifyHelperExe(ops procOps, pid int, want string) error {
	got, err := ops.exeOf(pid)
	if err != nil {
		return fmt.Errorf("cannot read the peer's executable: %w", err)
	}
	if got != want {
		return errors.New("the peer is not the installed manar-edge")
	}
	for _, p := range []string{want, filepath.Dir(want)} {
		fi, err := ops.stat(p)
		if err != nil {
			return err
		}
		if fi.OwnerUID != 0 || fi.Mode.Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not root-owned and protected", p)
		}
	}
	return nil
}
