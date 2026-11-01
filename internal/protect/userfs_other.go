//go:build !linux

package protect

import "io"

// ServeUserFS exists only on Linux, where the service runs as root.
func ServeUserFS(io.Reader, io.Writer) int { return 2 }

// newUserFS: on Windows the service has no user to become, so it acts directly and relies on the
// reparse-point refusal in directFS.
func newUserFS(o Owner) FS { return directFS{Home: o.Home} }
