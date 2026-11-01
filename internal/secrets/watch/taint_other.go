//go:build !linux

package watch

func procsWithTaint(base ProcSource) ProcSource { return base }
