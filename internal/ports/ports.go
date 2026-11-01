// Package ports is the one place that names the loopback ports Manar uses on a device, so two
// features can never pick the same one.
package ports

import "strconv"

const (
	// DoorPort is DOOR, the device-level LLM gateway of a personal device. It is below 1024 on
	// purpose: on Linux only root may bind such a port (unless the machine lowers
	// net.ipv4.ip_unprivileged_port_start), so a user program cannot take it while the service
	// restarts and receive the API key a tool sends. Tools are only routed here when that holds.
	DoorPort = 848
	// JailGatewayPort is the per-agent gateway of a jailed agent (Linux netns, Windows service).
	JailGatewayPort = 8480
	// JailWindowsProxyPort is JAIL's per-tool proxy for Claude Code on Windows (named in the
	// tool's settings.json, so it is fixed).
	JailWindowsProxyPort = 8491

	DoorListen        = "127.0.0.1:" + "848"
	DoorURL           = "http://" + DoorListen
	JailGatewayListen = "127.0.0.1:" + "8480"
	JailGatewayURL    = "http://" + JailGatewayListen
)

// Check at init time that the string forms match the numbers.
func init() {
	if DoorListen != "127.0.0.1:"+strconv.Itoa(DoorPort) || JailGatewayListen != "127.0.0.1:"+strconv.Itoa(JailGatewayPort) {
		panic("ports: string and number forms differ")
	}
}
