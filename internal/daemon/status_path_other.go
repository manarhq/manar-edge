//go:build !linux

package daemon

import (
	"os"
	"path/filepath"
)

func defaultStatusPath() string {
	if d := os.Getenv("ProgramData"); d != "" {
		return filepath.Join(d, "manar-edge", "status.json")
	}
	return ""
}

// StatusPathFor is where `manar-edge status` reads (the same path).
func StatusPathFor() string { return defaultStatusPath() }
