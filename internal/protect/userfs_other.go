//go:build !linux && !windows

package protect

import "io"

// ServeUserFS exists only on Linux, where the service runs as root.
func ServeUserFS(io.Reader, io.Writer) int { return 2 }

func newUserFS(o Owner) FS { return directFS{Home: o.Home} }
