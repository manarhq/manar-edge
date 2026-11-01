//go:build !linux

package watch

import "os"

// No blocking off Linux: nothing is ever pinned, so nothing is granted.
func identify(*os.File) (fileID, bool) { return fileID{}, false }
