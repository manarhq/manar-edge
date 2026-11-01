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
// the watchdog fired. Rescans (new .env files, new browser profiles, replaced token files) run
// hourly.
//
// Two fanotify groups: files the mode may deny (and .env files, for attribution) sit in a
// permission group; everything else (browser stores, kube and docker config in the default mode)
// sits in a notify-only group
// that can never hold an open up. So a busy browser profile is never in the permission path
// unless the person chose "block all".
func runPlatform(ctx context.Context, out chan<- Event, mode Mode, gate *Gate, degraded bool) (stalled bool) {
	var perm, notif *fanSource
	var err error
	if mode != ModeAlert {
		if perm, err = newFanSource(true); err != nil {
			log.Printf("manar-edge: secrets blocking unavailable, watching only: %v", err)
			perm, mode = nil, ModeAlert
		}
	}
	if mode != ModeAll {
		if notif, err = newFanSource(false); err != nil && perm == nil {
			log.Printf("manar-edge: secrets watcher unavailable: %v", err)
			notice(out, TypeUnavailable)
			<-ctx.Done()
			return false
		}
	}
	var envFound []string
	mark := func(rediscover bool) int {
		var targets []Target
		for _, h := range host.Homes() {
			targets = append(targets, Targets(h)...)
			if rediscover { // the walk is the costly part: hourly
				envFound = append(envFound, DiscoverEnv(h, 5, 500)...)
			}
		}
		env := envFound
		n := 0
		if perm != nil {
			n += markAll(perm, targets, env, mode.Held, mode.Blocks(ClassEnv))
		}
		if notif != nil {
			n += markAll(notif, targets, env, func(c string) bool { return !mode.Held(c) }, false)
		}
		return n
	}
	if mark(true) == 0 {
		log.Printf("manar-edge: secrets watcher: nothing to watch yet")
	}
	procs := newProcSource()
	startTaint(ctx, procs) // follows descendants of AI tools past setsid and re-parenting
	engine := func(src Source) *Engine {
		e := &Engine{Src: src, Procs: procsWithTaint(procs), Mode: func() Mode { return mode }, Gate: gate,
			Self: selfFunc(procs), Out: out, Homes: host.Homes}
		if fs, ok := src.(*fanSource); ok {
			e.InodeClass = fs.ClassOfInode
		}
		return e
	}
	if degraded { // blocking was asked for but a stall switched it off: say so, do not claim all is well
		notice(out, TypeUnavailable)
	} else {
		notice(out, TypeAvailable)
	}
	go func() {
		// Key and token files are re-marked every 30 s, which only matters for a directory that
		// did not exist yet (first `gh auth login`, first ~/.aws). A file that is replaced inside
		// a marked directory is covered at once. New .env files wait for the hourly walk.
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		n := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n++
				if n%120 == 0 {
					envFound = nil
				}
				mark(n%120 == 0)
			}
		}
	}()
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	res := make(chan error, 2)
	n := 0
	for _, s := range []*fanSource{perm, notif} {
		if s != nil {
			n++
			go func(s *fanSource) { res <- engine(s).Run(rctx) }(s)
		}
	}
	for i := 0; i < n; i++ {
		err = <-res
		cancel() // when one group ends the other ends too: the watcher restarts as a whole
		switch {
		case errors.Is(err, ErrStalled):
			stalled = true
		case err != nil && ctx.Err() == nil:
			log.Printf("manar-edge: secrets watcher stopped: %v", err)
			select {
			case <-ctx.Done():
			case <-time.After(30 * time.Second):
			}
		}
	}
	if stalled {
		notice(out, TypeUnavailable)
	} else if ctx.Err() == nil {
		notice(out, TypeUnavailable)
	}
	return stalled
}
