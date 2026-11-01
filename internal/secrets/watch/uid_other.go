//go:build !linux

package watch

func defaultFileUID(string) (int, bool) { return 0, false }
