package warden

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Dir is where WARDEN keeps its small files under the state directory.
func Dir(base string) string { return filepath.Join(base, "warden") }

// Settings are device-local switches, set by an administrator with `manar-edge warden ...`.
type Settings struct {
	// WindowsUI turns the Windows tray helper and toast on. Default off: the toast could not be
	// proven on a real desktop before launch (spec slip rule), so Windows shows nothing and
	// approvals are answered in the console until an administrator turns this on.
	WindowsUI bool `json:"windows_ui"`
}

func LoadSettings(base string) Settings {
	var s Settings
	if b, err := os.ReadFile(filepath.Join(Dir(base), "settings.json")); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func SaveSettings(base string, s Settings) error {
	if err := os.MkdirAll(Dir(base), 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(s)
	return os.WriteFile(filepath.Join(Dir(base), "settings.json"), b, 0o644)
}

// LoadAllowedUIDs reads the Linux users who may use WARDEN (one uid per line).
func LoadAllowedUIDs(base string) []uint32 {
	b, err := os.ReadFile(filepath.Join(Dir(base), "allowed-uids"))
	if err != nil {
		return nil
	}
	var out []uint32
	for _, l := range strings.Fields(string(b)) {
		if n, err := strconv.ParseUint(l, 10, 32); err == nil {
			out = append(out, uint32(n))
		}
	}
	return out
}

var errNoUser = errors.New("warden: could not tell which user installed Manar")
