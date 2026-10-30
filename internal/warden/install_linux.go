//go:build linux

package warden

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const autostartFile = "/etc/xdg/autostart/manar-warden.desktop"

// Install makes the helper start at every desktop login (XDG autostart) and records which user
// the one-liner was run for (SUDO_UID), the only non-root user the socket check will accept.
// Run as root by `manar-edge install`.
func Install(base, exe string) error {
	uid, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err != nil || uid == 0 {
		return errNoUser
	}
	if err := os.MkdirAll(Dir(base), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(Dir(base), "allowed-uids"), []byte(strconv.FormatUint(uid, 10)+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(autostartFile), 0o755); err != nil {
		return err
	}
	entry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=WARDEN (Manar app on this device)
Exec=%s --state-dir %s warden
Terminal=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
`, exe, base)
	return os.WriteFile(autostartFile, []byte(entry), 0o644)
}

// Remove undoes Install.
func Remove(base string) error {
	if err := os.Remove(autostartFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.RemoveAll(Dir(base))
}
