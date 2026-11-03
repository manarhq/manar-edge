//go:build windows

package vault

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// WhoOfHome identifies the owner (SID) of a home folder (which must not be a reparse point).
func WhoOfHome(home string) (Who, error) {
	st, err := os.Lstat(home)
	if err != nil {
		return Who{}, err
	}
	if !st.IsDir() || st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return Who{}, errors.New("the home folder is not a plain folder")
	}
	sd, err := windows.GetNamedSecurityInfo(home, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return Who{}, err
	}
	sid, _, err := sd.Owner()
	if err != nil || sid == nil {
		return Who{}, errors.New("no owner on the home folder")
	}
	return Who{UID: -1, GID: -1, SID: sid.String(), Home: home}, nil
}

func (w Who) do(fn func() error) error { return fn() }
