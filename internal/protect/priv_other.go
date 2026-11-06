//go:build !linux && !windows

package protect

import "os"

func isPrivileged() bool { return os.Geteuid() == 0 }
