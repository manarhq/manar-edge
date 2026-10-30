//go:build !linux && !windows

package vault

func parentExe(int) string { return "" }
