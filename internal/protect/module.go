package protect

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/manarhq/manar-edge/internal/telemetry"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/manarhq/manar-edge/internal/daemon"
	"github.com/manarhq/manar-edge/internal/discovery"
	"github.com/manarhq/manar-edge/internal/door"
	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/pause"
	"github.com/manarhq/manar-edge/internal/ports"
	"github.com/manarhq/manar-edge/internal/undo"
)

// GatewayURL is the local LLM gateway base URL; set by the command package.
var GatewayURL = ports.DoorURL

// ClaudeSettingsPath is the managed Claude Code settings file; set by the command package. When
// `install-claude-code` put Manar's hook there (agent mode), that is what protects Claude Code and
// the person's own settings are left alone; otherwise Claude Code is protected like every other
// tool, with a hook in ~/.claude/settings.json.
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

// isPaused is "Pause all AI" on this device (a var so tests can set it).
var isPaused = func() bool {
	cfgMu.Lock()
	d := stateDir
	cfgMu.Unlock()
	return d != "" && pause.Paused(d)
}

func theStore() *Store {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	return store
}

func init() {
	discovery.SetReconciler(reconcile)
	discovery.SetUserReader(readUserFile)
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

// gatewayUp is true only when the port cannot be squatted (door.Routable) and DOOR itself answers a
// fresh challenge on GatewayURL.
func gatewayUp() bool { return door.Routable() && door.Healthy(GatewayURL) }

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
			if s := claudeCodeState(); s.Protected {
				states[f.ID] = s
				continue
			}
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
		if isPaused() {
			// Not even asked: every protected tool is denied while AI is paused.
			json.NewEncoder(w).Encode(&hostclient.AuthorizeResult{Decision: "DENY", Reason: pause.Reason})
			return
		}
		caller, _ := r.Context().Value(callerKey{}).(string)
		// The tool's session id rides on the caller string ("uid:1000|s:<id>") so the backend
		// interface stays as it is; Manar splits it off and records it with the action.
		if sid := raw["session"]; sessionOK.MatchString(sid) {
			caller += "|s:" + sid
		}
		t0 := time.Now()
		res, err := b.Authorize(ctx, in.ToolID, in.ActionID, in.Resource, caller)
		if err != nil {
			http.Error(w, "upstream", 502)
			return
		}
		recordDecision(in.ToolID, in.ActionID, in.Resource, res.Decision, caller, time.Since(t0))
		json.NewEncoder(w).Encode(res)
	})
	// Undo AI file changes: the hook (running as the user) tells the service what it saved. The
	// service takes the user from the kernel, never from the body.
	mux.HandleFunc("POST /v1/changes", func(w http.ResponseWriter, r *http.Request) {
		var rec undo.Record
		if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&rec) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		caller, _ := r.Context().Value(callerKey{}).(string)
		if undo.Default.Report(caller, rec) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("GET /v1/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		s, err := b.ApprovalStatus(ctx, r.PathValue("id"))
		if err != nil {
			http.Error(w, "upstream", 502)
			return
		}
		if isPaused() {
			// An approval that lands during a pause does not let the call through.
			s = "PAUSED"
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

// readUserFile is how discovery reads a person's MCP settings: as that person, never following a
// link, and only below their home folder. A file that cannot be read safely is as good as absent.
func readUserFile(u discovery.User, path string) ([]byte, bool) {
	b, exists, _, err := newUserFS(Owner{UID: u.UID, GID: u.GID, Home: u.Home}).Read(path)
	if err != nil || !exists {
		return nil, false
	}
	return b, true
}

// recordDecision hands a WARDEN decision to telemetry (non-blocking; a no-op while it is off).
func recordDecision(toolID, actionID, resource, decision, caller string, took time.Duration) {
	d := map[string]string{"ALLOW": "allow", "APPROVAL_REQUIRED": "ask", "DENY": "block"}[decision]
	if d == "" {
		return
	}
	kind, text := "", resource
	switch actionID {
	case "shell":
		kind = "command"
	case "webfetch":
		kind, text = "domain", telemetry.SampleHost(resource)
		if text == "" {
			kind = ""
		}
	}
	telemetry.Record("warden", strings.TrimPrefix(toolID, "host."), d, kind, text, caller, took)
}

// Unprotect restores every tool's settings when the device is removed from its workspace.
func (m *relayModule) Unprotect(ctx context.Context) error { return m.Cleanup(ctx) }
