package protect

import "golang.org/x/sys/windows"

// isPrivileged is true for an elevated process (the device service runs as SYSTEM).
func isPrivileged() bool { return windows.GetCurrentProcessToken().IsElevated() }
