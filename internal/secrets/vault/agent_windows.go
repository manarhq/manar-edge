//go:build windows

package vault

// The Windows ssh vault stays off. ssh-add run by the service (SYSTEM) would load the key into
// SYSTEM's agent store, not the signed-in user's, and the key file would then be deleted. It
// needs a process started with the user's session token; until that exists the vault refuses ssh.
func platformAgent() Agent { return nil }

func ensureAgent() {}
