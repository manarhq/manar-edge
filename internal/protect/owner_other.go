//go:build !linux

package protect

import "io/fs"

func chown(string, Owner) error { return nil }

func fileOwner(_ fs.FileInfo, fallback Owner) (int, int) { return fallback.UID, fallback.GID }
