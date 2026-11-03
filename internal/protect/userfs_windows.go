package protect

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/manarhq/manar-edge/internal/safefs"
)

// ServeUserFS exists only on Linux, where the service runs as root.
func ServeUserFS(io.Reader, io.Writer) int { return 2 }

// newUserFS: the Windows service runs as SYSTEM and has no user to become, so every access goes
// through handles opened one folder at a time with no link followed (internal/safefs explains
// why a path check followed by a path operation is not enough).
func newUserFS(o Owner) FS { return winFS{Home: o.Home} }

type winFS struct{ Home string }

func linkErr(path string, err error) error {
	if errors.Is(err, safefs.ErrLink) {
		return fmt.Errorf("%s: %w", path, errLink)
	}
	return err
}

// Read reports mode 0644: Windows files have no Unix mode, and Write does not use one.
func (w winFS) Read(path string) ([]byte, bool, os.FileMode, error) {
	b, exists, err := safefs.Read(w.Home, path, 32<<20)
	if err != nil {
		return nil, false, 0, linkErr(path, err)
	}
	return b, exists, 0o644, nil
}

func (w winFS) Write(path string, data []byte, _ os.FileMode) error {
	return linkErr(path, safefs.Write(w.Home, path, data))
}

func (w winFS) Remove(path string) error { return linkErr(path, safefs.Remove(w.Home, path)) }
