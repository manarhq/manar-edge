//go:build !linux && !windows

package vault

func (w Who) do(fn func() error) error { return fn() }
