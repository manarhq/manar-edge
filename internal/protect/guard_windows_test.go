package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestGuardShortNamesAndStreams(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".claude")
	if err := os.Mkdir(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "settings.local.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	short := func(p string) string {
		long, _ := windows.UTF16PtrFromString(p)
		buf := make([]uint16, 1024)
		n, err := windows.GetShortPathName(long, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			t.Skipf("no short names here: %v", err)
		}
		return windows.UTF16ToString(buf[:n])
	}
	s := short(cfg)
	if strings.EqualFold(filepath.Base(s), ".claude") {
		t.Skip("8.3 names are off on this volume")
	}
	for _, p := range []string{
		filepath.Join(s, "settings.json"),                // the folder by its short name, a new file
		short(filepath.Join(cfg, "settings.local.json")), // the file by its short name
		filepath.Join(cfg, "settings.json::$DATA"),       // the main stream
		filepath.Join(s, "settings.json. "),              // trailing dot and space
	} {
		if !guardedTarget(p, dir) {
			t.Errorf("guardedTarget(%q) = false", p)
		}
	}
}
