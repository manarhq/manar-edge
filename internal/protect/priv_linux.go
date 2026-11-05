package protect

import "os"

// isPrivileged is true for root, which is what the systemd unit runs as.
func isPrivileged() bool { return os.Geteuid() == 0 }
