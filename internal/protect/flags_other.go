//go:build !linux && !windows

package protect

import "os"

// Windows has its own open; elsewhere checkPath refuses links before the open.
const oNoFollow = 0

func openRead(path string) (*os.File, error) { return os.OpenFile(path, os.O_RDONLY, 0) }
