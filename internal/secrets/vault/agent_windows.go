//go:build windows

package vault

import "os/exec"

func platformAgent() Agent { return ExecAgent{} }

// ensureAgent starts the OpenSSH Authentication Agent service and sets it to start at boot.
func ensureAgent() {
	_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent").Run()
}
