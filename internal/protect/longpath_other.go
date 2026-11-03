//go:build !windows

package protect

func longPath(p string) (string, error) { return p, nil }
