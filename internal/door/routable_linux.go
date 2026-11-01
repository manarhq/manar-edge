package door

import (
	"os"
	"strconv"
	"strings"

	"gitlab.vax.sh/manar/manar-edge/internal/ports"
)

// Routable says whether tools may be pointed at DOOR. On Linux that holds only while binding the
// DOOR port needs root, i.e. the machine's unprivileged port start is above it. If someone
// lowered it, any user could take the port while the service is down and read API keys.
func Routable() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	if err != nil {
		return false
	}
	start, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && start > ports.DoorPort
}
