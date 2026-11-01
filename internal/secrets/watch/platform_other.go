//go:build !linux && !windows

package watch

import "context"

func cleanupPlatform(context.Context) error { return nil }

// runPlatform: no watcher on this OS; the device says so.
func runPlatform(ctx context.Context, out chan<- Event, _ Mode, _ *Gate) bool {
	notice(out, TypeUnavailable)
	<-ctx.Done()
	return false
}
