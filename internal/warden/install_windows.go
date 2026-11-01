//go:build windows

package warden

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// Install makes the helper start when this user logs on (HKCU Run) and records the user's SID,
// the only one the service's pipe will accept besides SYSTEM. It must run in the session of the
// person the device belongs to (the elevated PowerShell of the one-liner). Windows prompting
// is on by default; `manar-edge warden windows-ui off` opts a device out.
func Install(base, exe string) error {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(Dir(base), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(userSIDFile(base), []byte(u.User.Sid.String()), 0o644); err != nil {
		return err
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("ManarWarden", fmt.Sprintf(`"%s" --state-dir "%s" warden`, exe, base))
}

// Remove undoes Install for the user who runs the uninstall.
func Remove(base string) error {
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue("ManarWarden")
		k.Close()
	}
	return os.RemoveAll(Dir(base))
}
