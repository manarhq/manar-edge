package main

import (
	"os/exec"
	"strings"
)

// serviceState asks systemd (no root needed): active, inactive, failed, or unknown.
func serviceState() string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "unknown"
	}
	out, _ := exec.Command("systemctl", "is-active", deviceUnit).Output()
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	return "unknown"
}

const (
	fixStartService   = "sudo systemctl enable --now manar-edge"
	fixRestartService = "sudo systemctl restart manar-edge"
	fixServiceLog     = "journalctl -u manar-edge -n 50"
	fixAsAdmin        = "run it with sudo to see more"
	fixUninstall      = "sudo manar-edge uninstall"
)
