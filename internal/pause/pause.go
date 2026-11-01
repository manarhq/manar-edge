// Package pause is the device side of "Pause all AI". The device service copies the workspace's
// `paused` flag (GET /host/v1/config) into a small file; every protect and hook path on the device
// reads it and denies with reason "paused". The API denies too (its kill-switch check), so a device
// that has not polled yet is still stopped as soon as it asks.
package pause

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Reason is what a paused path tells the agent.
const Reason = "paused"

type state struct {
	Paused bool `json:"paused"`
}

func path(base string) string { return filepath.Join(base, "pause.json") }

// Paused reports whether AI is paused on this device. A missing file means not paused; a file that
// exists but cannot be read or parsed means paused (fail closed: someone tampered with it).
func Paused(base string) bool {
	b, err := os.ReadFile(path(base))
	if os.IsNotExist(err) {
		return false
	}
	var s state
	return err != nil || json.Unmarshal(b, &s) != nil || s.Paused
}

// Set records the flag. It is written atomically and readable by every user (the hook runs as the
// agent user), writable by the service only.
func Set(base string, paused bool) error {
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(state{Paused: paused})
	tmp := path(base) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path(base))
}
