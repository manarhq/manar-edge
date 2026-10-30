package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"runtime"
	"sort"
	"sync"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/daemon"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

// State is what protection did for one tool across the accounts that use it.
type State struct {
	Protected bool
	Mode      string // hook, mcp, gateway, none
	Changes   []string
}

// Reconciler applies or removes protection for what was found, following the owner's choices in
// cfg, and returns the resulting state by report id. internal/protect installs it.
type Reconciler func(ctx context.Context, found []Found, cfg *hostclient.Config) map[string]State

var (
	mu         sync.Mutex
	reconciler Reconciler
)

// SetReconciler is called by internal/protect when it loads.
func SetReconciler(r Reconciler) {
	mu.Lock()
	reconciler = r
	mu.Unlock()
}

func currentReconciler() Reconciler {
	mu.Lock()
	defer mu.Unlock()
	return reconciler
}

func init() { daemon.Register(&Module{}) }

type api interface {
	Config(ctx context.Context) (*hostclient.Config, error)
	Inventory(ctx context.Context, tools []hostclient.Tool) error
}

// Module scans the device, lets protection catch up, and reports. A scan runs every Poll (so a
// new install is protected within a minute and an owner's switch is honoured quickly); the list
// goes to Manar when it changed and at least every Report.
type Module struct {
	Poll, Report time.Duration
	Probe        *Probe
	Users        func() []User
	GOOS         string
}

func (*Module) Name() string { return "discovery" }

func (m *Module) Start(ctx context.Context, c *hostclient.Client) error {
	return m.run(ctx, c)
}

func (m *Module) run(ctx context.Context, c api) error {
	poll, every := m.Poll, m.Report
	if poll == 0 {
		poll = time.Minute
	}
	if every == 0 {
		every = 10 * time.Minute
	}
	probe, users, goos := OSProbe(), Users, runtime.GOOS
	if m.Probe != nil {
		probe = *m.Probe
	}
	if m.Users != nil {
		users = m.Users
	}
	if m.GOOS != "" {
		goos = m.GOOS
	}
	var last []byte
	var lastAt time.Time
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		found := Scan(users(), goos, probe)
		var states map[string]State
		cfg, cerr := c.Config(ctx)
		if cerr != nil && ctx.Err() == nil {
			log.Printf("manar-edge: discovery: config: %v", cerr)
		}
		if r := currentReconciler(); r != nil && cfg != nil {
			states = r(ctx, found, cfg)
		}
		tools := Report(found, states)
		b, _ := json.Marshal(tools)
		if ctx.Err() == nil && (!bytes.Equal(b, last) || time.Since(lastAt) >= every) {
			if err := c.Inventory(ctx, tools); err != nil {
				log.Printf("manar-edge: discovery: inventory: %v", err)
			} else {
				last, lastAt = b, time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Report builds the inventory body. A tool with no state is reported as not protected.
func Report(found []Found, states map[string]State) []hostclient.Tool {
	out := make([]hostclient.Tool, 0, len(found))
	for _, f := range found {
		st := states[f.ReportID()]
		mode := st.Mode
		if !st.Protected || mode == "" {
			mode = "none"
		}
		out = append(out, hostclient.Tool{
			ID: f.ReportID(), Name: f.Name, Version: f.Version, Path: f.Path,
			Protected: st.Protected && mode != "none", ProtectMode: mode, Changes: st.Changes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
