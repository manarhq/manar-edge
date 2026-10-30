package protect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/daemon"
	"gitlab.vax.sh/manar/manar-edge/internal/discovery"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

// GatewayURL is the local LLM gateway base URL; set by the command package.
var GatewayURL = "http://127.0.0.1:8480"

// ClaudeSettingsPath is the managed Claude Code settings file; set by the command package.
// Claude Code is protected by `install-claude-code`; this only reads whether that is in place.
var ClaudeSettingsPath string

var (
	cfgMu    sync.Mutex
	stateDir string
	store    *Store
	logged   = map[string]bool{}
)

// Configure sets the device state directory. Call it before the service starts and before uninstall.
func Configure(dir string) {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	stateDir, store = dir, NewStore(dir)
}

func theStore() *Store {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return store
}

func init() {
	discovery.SetReconciler(reconcile)
	daemon.Register(&relayModule{})
}

func logOnce(msg string) {
	cfgMu.Lock()
	seen := logged[msg]
	logged[msg] = true
	cfgMu.Unlock()
	if !seen {
		log.Print("manar-edge: protect: " + msg)
	}
}

func gatewayUp() bool {
	c := &http.Client{Timeout: time.Second}
	res, err := c.Get(GatewayURL + "/healthz")
	if err != nil {
		return false
	}
	res.Body.Close()
	return res.StatusCode == 200
}

// reconcile protects what was found for every account that uses it, undoes it for tools the
// owner switched off, and returns the resulting state. Nothing is changed until the owner has
// approved the device: a pending device would deny every call its hooks make.
func reconcile(_ context.Context, found []discovery.Found, cfg *hostclient.Config) map[string]discovery.State {
	st := theStore()
	states := map[string]discovery.State{}
	if st == nil {
		return states
	}
	if cfg.Status == discovery.StatusRevoked || cfg.Status == "REJECTED" || cfg.Status == "REVOKED" {
		for _, err := range st.RestoreAll() {
			logOnce("restore after revocation: " + err.Error())
		}
		logOnce("this device was revoked or rejected: Manar's hooks and wrappers are removed")
		return states
	}
	off := map[string]bool{}
	for _, id := range cfg.Tools.Unprotect {
		off[id] = true
	}
	approved := cfg.Status == "APPROVED"
	ctx := Ctx{Exe: exePath(), GatewayURL: GatewayURL}
	if approved {
		ctx.GatewayUp = gatewayUp()
	}
	for _, f := range found {
		if f.Other {
			continue
		}
		if f.Key == "claude-code" {
			states[f.ID] = claudeCodeState()
			continue
		}
		known := false
		for _, k := range Keys {
			known = known || k == f.Key
		}
		if !known {
			continue
		}
		states[f.ID] = reconcileTool(st, f, ctx, approved, off[f.ID])
	}
	return states
}

func reconcileTool(st *Store, f discovery.Found, ctx Ctx, approved, off bool) discovery.State {
	res := discovery.State{Protected: len(f.Users) > 0, Mode: "hook"}
	if len(f.Users) == 0 {
		res.Mode = "none"
	}
	rank := map[string]int{"hook": 3, "gateway": 2, "mcp": 1}
	for _, u := range f.Users {
		if off || !approved {
			if st.Has(f.Key, u.Name) && off {
				if err := st.Restore(f.Key, u.Name); err != nil {
					logOnce("restore " + f.Name + " for " + u.Name + ": " + err.Error())
				} else {
					logOnce("protection for " + f.Name + " turned off for " + u.Name + "; the original settings are back")
				}
			}
			res.Protected, res.Mode = false, "none"
			continue
		}
		items := Plan(f.Key, u, ctx)
		edits := make([]FileEdit, len(items))
		for i, it := range items {
			edits[i] = it.FileEdit
		}
		out, err := st.Apply(f.Key, u.Name, Owner{UID: u.UID, GID: u.GID, Home: u.Home}, edits)
		if err != nil {
			logOnce("apply " + f.Name + " for " + u.Name + ": " + err.Error())
			res.Protected, res.Mode = false, "none"
			continue
		}
		for _, o := range out {
			if o.Warning != "" {
				logOnce("WARNING " + f.Name + " " + o.Path + ": " + o.Warning)
				res.Changes = append(res.Changes, "Not changed: "+o.Path+" ("+o.Warning+")")
			} else if o.Changed {
				logOnce("changed " + o.Path + " for " + f.Name + " (user " + u.Name + "); backup kept")
			}
		}
		res.Changes = append(res.Changes, st.Describe(f.Key, u.Name)...)
		prot, mode := Mode(items, out)
		if !prot {
			res.Protected, res.Mode = false, "none"
		} else if res.Protected && rank[mode] < rank[res.Mode] {
			res.Mode = mode
		}
	}
	if !res.Protected {
		res.Mode = "none"
	}
	return res
}

func claudeCodeState() discovery.State {
	if ClaudeSettingsPath == "" {
		return discovery.State{Mode: "none"}
	}
	b, err := os.ReadFile(ClaudeSettingsPath)
	if err != nil || !strings.Contains(string(b), "claude-code") || !strings.Contains(string(b), `"hook"`) {
		return discovery.State{Mode: "none"}
	}
	return discovery.State{Protected: true, Mode: "hook", Changes: []string{ClaudeSettingsPath + " (managed settings written by install-claude-code)"}}
}

func exePath() string {
	p, err := os.Executable()
	if err != nil {
		return "manar-edge"
	}
	return p
}

// relayModule is the local endpoint hooks and MCP wrappers call, and the uninstall cleanup.
type relayModule struct{}

func (*relayModule) Name() string { return "protect" }

// Cleanup restores every tool's settings (uninstall).
func (*relayModule) Cleanup(context.Context) error {
	st := theStore()
	if st == nil {
		return errors.New("protect is not configured")
	}
	return errors.Join(st.RestoreAll()...)
}

type callerKey struct{}

func newRelayServer(b backend) *http.Server {
	return &http.Server{
		Handler:           relayHandler(b),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, callerKey{}, callerOf(conn))
		},
	}
}

type backend interface {
	Authorize(ctx context.Context, toolID, actionID, resource, caller string) (*hostclient.AuthorizeResult, error)
	ApprovalStatus(ctx context.Context, id string) (string, error)
}

func (m *relayModule) Start(ctx context.Context, c *hostclient.Client) error {
	l, err := listenRelay()
	if err != nil {
		return err
	}
	srv := newRelayServer(c)
	go func() { <-ctx.Done(); srv.Close() }()
	if err := srv.Serve(l); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// relayHandler serves /v1/authorize and /v1/approvals/<id>. It only passes the three fields on;
// the tenant and device come from the device's certificate on the way to Manar.
func relayHandler(b backend) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ToolID, ActionID, Resource string }
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
		var raw map[string]string
		if dec.Decode(&raw) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		in.ToolID, in.ActionID, in.Resource = raw["toolId"], raw["actionId"], raw["resource"]
		if !validTool(in.ToolID) || in.ActionID == "" || in.Resource == "" {
			http.Error(w, "bad request", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		caller, _ := r.Context().Value(callerKey{}).(string)
		res, err := b.Authorize(ctx, in.ToolID, in.ActionID, in.Resource, caller)
		if err != nil {
			http.Error(w, "upstream", 502)
			return
		}
		json.NewEncoder(w).Encode(res)
	})
	mux.HandleFunc("GET /v1/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		s, err := b.ApprovalStatus(ctx, r.PathValue("id"))
		if err != nil {
			http.Error(w, "upstream", 502)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": s})
	})
	return mux
}

func validTool(id string) bool {
	for _, k := range Keys {
		if id == "host."+k {
			return true
		}
	}
	return false
}

// RestoreEverything puts back every file Manar changed (the CLI and uninstall).
func RestoreEverything() []error {
	st := theStore()
	if st == nil {
		return []error{errors.New("protect is not configured")}
	}
	return st.RestoreAll()
}

// RestoreTool restores one tool (by key, e.g. cursor) for every account.
func RestoreTool(key string) error {
	st := theStore()
	if st == nil {
		return errors.New("protect is not configured")
	}
	var errs []error
	for _, k := range st.Tools() {
		if tool, user, ok := strings.Cut(k, "|"); ok && tool == key {
			errs = append(errs, st.Restore(tool, user))
		}
	}
	return errors.Join(errs...)
}

// Changes lists what Manar changed for a found tool, per account (empty before protection).
func Changes(f discovery.Found) []string {
	st := theStore()
	if st == nil {
		return nil
	}
	var out []string
	for _, u := range f.Users {
		out = append(out, st.Describe(f.Key, u.Name)...)
	}
	return out
}
