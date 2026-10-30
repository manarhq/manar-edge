//go:build windows

package vault

import "os"

// Windows keeps the ACL of the directory the new file lands in; the replaced file's ACL is the
// user's profile default.
func owner(os.FileInfo) (int, int)       { return -1, -1 }
func chownFile(*os.File, FileInfo) error { return nil }
