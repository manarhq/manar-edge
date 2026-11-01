package discovery

// User is a person's account on the device. Tool settings live in their home folder, and the
// device service runs as root or SYSTEM, so it visits each one.
type User struct {
	Name string
	Home string
	// UID and GID are -1 where the OS has no such notion (Windows).
	UID, GID int
}
