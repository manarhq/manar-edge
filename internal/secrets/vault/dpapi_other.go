//go:build !windows

package vault

// On Linux the protection is the 0700 directory owned by the service; nothing more is added.
func protect(b []byte) ([]byte, error)   { return b, nil }
func unprotect(b []byte) ([]byte, error) { return b, nil }
