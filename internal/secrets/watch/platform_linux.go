//go:build linux

package watch

import (
	"context"
	"errors"
	"log"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/secrets/host"
)

func cleanupPlatform(context.Context) error { return nil } // the marks go with the process

// runPlatform marks the secret files and answers events until ctx ends. It reports true when
// the watchdog fired. Rescans (new .env files, new browser profiles) run daily.
func runPlatform(ctx context.Context, out chan<- Event, block bool) (stalled bool) {
	src, err := newFanSource(block)
	if err != nil {
		log.Printf("manar-edge: secrets watcher unavailable: %v", err)
		notice(out, TypeUnavailable)
		<-ctx.Done()
		return false
	}
	mark := func() int {
		var targets []Target
		var env []string
		for _, h := range host.Homes() {
			targets = append(targets, Targets(h)...)
			env = append(env, DiscoverEnv(h, 5, 500)...)
		}
		return markAll(src, targets, env)
	}
	if mark() == 0 {
		log.Printf("manar-edge: secrets watcher: nothing to watch yet")
	}
	procs := newProcSource()
	eng := &Engine{Src: src, Procs: procs, Block: func() bool { return block }, Self: selfFunc(procs),
		Out: out, Homes: host.Homes}
	notice(out, TypeAvailable)
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mark()
			}
		}
	}()
	err = eng.Run(ctx)
	if errors.Is(err, ErrStalled) {
		notice(out, TypeUnavailable)
		return true
	}
	if err != nil && ctx.Err() == nil {
		log.Printf("manar-edge: secrets watcher stopped: %v", err)
		notice(out, TypeUnavailable)
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
	}
	return false
}
