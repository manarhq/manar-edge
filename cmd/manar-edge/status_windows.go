package main

import (
	"os/exec"
	"strings"
)

// serviceState asks the service manager (no elevation needed): active, inactive, or unknown.
func serviceState() string {
	out, err := exec.Command("sc.exe", "query", deviceServiceName).Output()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	switch s := string(out); {
	case strings.Contains(s, "RUNNING"):
		return "active"
	case strings.Contains(s, "STOPPED"):
		return "inactive"
	case strings.Contains(s, "1060"): // not installed
		return "inactive"
	}
	return "unknown"
}

const (
	fixStartService   = "In an Administrator PowerShell: Start-Service ManarEdge"
	fixRestartService = "In an Administrator PowerShell: Restart-Service ManarEdge"
	fixServiceLog     = "Event Viewer, Windows Logs, Application"
	fixAsAdmin        = "run it in an Administrator PowerShell to see more"
	fixUninstall      = "In an Administrator PowerShell: manar-edge uninstall"
)
