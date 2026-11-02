package jail

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/manarhq/manar-edge/internal/daemon"
	"github.com/manarhq/manar-edge/internal/hostclient"
)

func init() { daemon.Register(&module{}) }

// platform is the OS layer. Apply makes the filter cover exactly the given tools; Teardown puts
// the machine back.
type platform interface {
	Apply(ports map[string]int) error
	Teardown() error
}

// module keeps the filter in step with the API's `jail` config: which tools, which rules.
type module struct {
	pf platform // set by tests
}

func (*module) Name() string { return "jail" }

// Cleanup is `manar-edge uninstall`: remove every trace of the filter.
func (*module) Cleanup(context.Context) error { return joinErrs(PlatformCleanup()) }

// PlatformCleanup removes the filter's rules and cgroups; safe when there are none.
func PlatformCleanup() []error { return platformCleanupErrs() }

func (m *module) Start(ctx context.Context, c *hostclient.Client) error {
	pf := m.pf
	if pf == nil {
		var err error
		if pf, err = newPlatform(); err != nil {
			// Not supported here (no cgroup v2, no nft, a platform not built yet): nothing is
			// filtered and nothing was changed. Say so once and idle.
			log.Printf("jail: off on this device: %v", err)
			<-ctx.Done()
			return nil
		}
	}
	r := &runner{pf: pf, policy: NewPolicy(), asker: &APIAsker{API: c}, running: map[string]*toolProxy{}}
	defer r.stop()
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		cfg, err := c.Config(ctx)
		switch {
		case err != nil:
			// Keep what is running: a network blip must neither open nor close anything.
			if ctx.Err() == nil {
				log.Printf("jail: config: %v", err)
			}
		default:
			r.reconcile(cfg)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

type toolProxy struct {
	port int
	lns  []net.Listener
}

func (t *toolProxy) close() {
	for _, l := range t.lns {
		l.Close()
	}
}

type runner struct {
	pf      platform
	policy  *Policy
	asker   Asker
	mu      sync.Mutex
	running map[string]*toolProxy
	last    string
	lastErr string
	applied bool // the OS rules are installed
	// resolve replaces the system resolver (tests).
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
}

// reconcile starts proxies for newly wanted tools, applies the OS rules, then stops proxies of
// tools no longer wanted (in that order, so no rule ever points at a closed port).
func (r *runner) reconcile(cfg *hostclient.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	want := map[string]bool{}
	j := cfg.Jail
	// A device the owner has not approved yet cannot be asked about: it stays unfiltered rather
	// than locked out of the sites its tools need.
	if cfg.Status == "APPROVED" && j.Enabled && (runtime.GOOS != "windows" || j.Windows) {
		for _, t := range j.Tools {
			if known(t) && (runtime.GOOS != "windows" || slices.Contains(WindowsTools(), t)) {
				want[t] = true
			}
		}
	}
	rules := make([]Rule, 0, len(j.Rules))
	for _, x := range j.Rules {
		ru := Rule{Tool: x.ToolID, Site: x.Site, Mode: x.Mode}
		if x.ExpiresAt != nil {
			ru.Expires = *x.ExpiresAt
		}
		rules = append(rules, ru)
	}
	r.policy.SetRules(rules)

	for t := range want {
		if _, ok := r.running[t]; ok {
			continue
		}
		tp, err := r.startProxy(t)
		if err != nil {
			log.Printf("jail: starting the proxy for %s: %v", t, err)
			delete(want, t)
			continue
		}
		r.running[t] = tp
	}
	ports := map[string]int{}
	for t, tp := range r.running {
		if want[t] {
			ports[t] = tp.port
		}
	}
	if len(ports) == 0 && !r.applied {
		return // nothing wanted and nothing installed
	}
	if err := r.pf.Apply(ports); err != nil {
		// Could not install the rules: do not leave proxies running for nothing, and make sure no
		// half-installed rules stay.
		if msg := err.Error(); msg != r.lastErr {
			r.lastErr = msg // once per distinct problem, not every 20 seconds
			log.Printf("jail: applying the filter: %v", err)
		}
		_ = r.pf.Teardown()
		for t, tp := range r.running {
			tp.close()
			delete(r.running, t)
		}
		return
	}
	r.applied = len(ports) > 0
	for t, tp := range r.running {
		if !want[t] {
			tp.close()
			delete(r.running, t)
		}
	}
	if s := fmt.Sprint(ports); s != r.last {
		r.last = s
		log.Printf("jail: filtering %d tool(s)", len(ports))
	}
}

func known(tool string) bool {
	for _, t := range Tools() {
		if t == tool {
			return true
		}
	}
	return false
}

// stop turns the filter off when the service stops, so a stopped Manar leaves networking alone.
func (r *runner) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.pf.Teardown(); err != nil {
		log.Printf("jail: teardown: %v", err)
	}
	for t, tp := range r.running {
		tp.close()
		delete(r.running, t)
	}
}

func joinErrs(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%v", errs)
}
