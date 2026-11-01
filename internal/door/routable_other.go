//go:build !linux

package door

// Routable is false off Linux: there is no way to keep a user program from taking a loopback port
// while the service is down (Windows HTTP.sys reservations do not stop raw sockets), so Manar does
// not point any tool at DOOR there. DOOR still runs for tools the user sets up by hand.
func Routable() bool { return false }
