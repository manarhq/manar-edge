package vault

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/manarhq/manar-edge/internal/daemon"
	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/secrets/host"
)

// featureSSH means "the option to move an ssh key is offered on this device". Manar moves a key only
// when the person clicks Move to vault (console) or runs `manar-edge vault add`; nothing is automatic.
const featureSSH = "secrets.vault.ssh"

func init() { daemon.Register(&Module{}) }

// New builds the vault for this computer.
func New() *Vault {
	exe, _ := os.Executable()
	v := &Vault{Store: FileStore{Dir: filepath.Join(host.StateDir(), "vault")}, Exe: exe, Homes: host.Homes}
	v.Agent = platformAgent()
	v.Keys = platformKeys()
	return v
}

// RestoreAll is what `manar-edge uninstall` calls first. A failure means: do not remove Manar.
func RestoreAll() error { return New().RestoreAll() }

// Module is the vault as a daemon module: it carries out the console's store and restore
// instructions and answers the credential_process helper.
type Module struct{}

func (*Module) Name() string { return "secrets-vault" }

// Cleanup restores every vaulted secret (uninstall also calls RestoreAll before anything else).
func (*Module) Cleanup(context.Context) error { return RestoreAll() }

// Approver is replaced by the WARDEN prompt when it exists (Broker.A); until then the person
// answers in the console.
var NewApprover func(c *hostclient.Client) Approver = func(c *hostclient.Client) Approver { return consoleApprover{c} }

func (m *Module) Start(ctx context.Context, c *hostclient.Client) error {
	v := New()
	ensureAgent()
	b := &Broker{V: v, A: NewApprover(c), OnDenied: func(r Request) {
		sendEvent(ctx, c, "secret.vault.denied", filepath.Base(r.Program), r)
	}}
	srv := newAgentRunner(ctx, v, b)
	defer srv.Close()
	env := Env{Identify: Identify, RestoreAll: func() error {
		quiesced.Store(true) // no new secrets move in while they are being put back
		defer srv.Ensure()
		return v.RestoreAll()
	},
		AddSSH: func(owner, name string) error {
			if quiesced.Load() {
				return errors.New("Manar is being removed")
			}
			_, err := v.StoreSSHFor(owner, name)
			srv.Ensure()
			if err == nil {
				go reportStored(ctx, c, "ssh", name)
			}
			return err
		},
		RestoreSSH: func(owner, name string) error {
			defer srv.Ensure()
			err := v.RestoreSSHFor(owner, name)
			if err == nil {
				go reportRestored(ctx, c, "ssh", name)
			}
			return err
		}}
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, b, env) }()
	srv.Ensure() // keys vaulted before a restart are served again at once
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	last := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return err
		case <-t.C:
			syncGrants(ctx, c, v)
			runInstructions(ctx, c, v)
			srv.Ensure() // an agent that died is listening again within one interval
			if !quiesced.Load() && time.Since(last) > 5*time.Minute {
				last = time.Now()
				offerKeys(ctx, c, v)
			}
		}
	}
}

// syncGrants takes the server's standing grants from the config. Refused (423, the device is
// locked): no standing grant counts, and a revoked device (lost or stolen) wipes its vault. Any
// other failure keeps the last list, which lapses after Lease.
func syncGrants(ctx context.Context, c *hostclient.Client, v *Vault) {
	cfg, err := c.Config(ctx)
	if err == nil {
		var list []hostclient.VaultGrant
		if cfg.VaultGrants != nil {
			list = *cfg.VaultGrants
			if list == nil {
				list = []hostclient.VaultGrant{}
			}
		}
		SetServerGrants(list, time.Now())
		return
	}
	code := hostclient.LockedCode(c.StateDir())
	if code == "" {
		return
	}
	SetServerGrants(nil, time.Time{})
	if code == "device_revoked" {
		if n, err := v.Wipe(); err != nil {
			log.Printf("manar-edge: vault: wiping a revoked device: %v", err)
		} else if n > 0 {
			log.Printf("manar-edge: vault: this device was revoked by its workspace: %d vault entries deleted", n)
		}
	}
}

type instruction struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Action string `json:"action"`
}

// quiesced is set when uninstall starts: the module takes no more store instructions.
var quiesced atomic.Bool

func runInstructions(ctx context.Context, c *hostclient.Client, v *Vault) {
	if quiesced.Load() {
		return
	}
	var in struct {
		Vault []instruction `json:"vault"`
	}
	if err := c.Do(ctx, http.MethodGet, "/secrets/instructions", nil, &in); err != nil {
		return
	}
	var features []string
	if cfg, err := c.Config(ctx); err == nil {
		features = cfg.Features
	}
	for _, i := range in.Vault {
		state, detail := "FAILED", ""
		var err error
		switch {
		case i.Kind == "ssh" && !slices.Contains(features, featureSSH):
			err = errors.New("protecting ssh keys is turned off on this device")
		case i.Action == "store" && i.Kind == "aws":
			_, err = v.StoreAWS(i.Ref)
		case i.Action == "store" && i.Kind == "ssh":
			_, err = v.StoreSSH(i.Ref)
		case i.Action == "restore" && i.Kind == "aws":
			err = v.RestoreAWS(i.Ref)
		case i.Action == "restore" && i.Kind == "ssh":
			err = v.RestoreSSH(i.Ref)
		default:
			err = errors.New("unknown instruction")
		}
		switch {
		case err == nil && i.Action == "store", errors.Is(err, ErrExists):
			state = "STORED"
		case err == nil:
			state = "RESTORED"
		default:
			detail = err.Error()
			if len(detail) > 280 {
				detail = detail[:280]
			}
			log.Printf("manar-edge: vault %s %s %s: %v", i.Action, i.Kind, i.Ref, err)
		}
		// The detail never carries a secret: errors above name files and steps only.
		_ = c.Do(ctx, http.MethodPost, "/secrets/vault/report",
			map[string]string{"kind": i.Kind, "ref": i.Ref, "state": state, "detail": detail}, nil)
	}
}

// offerKeys tells the console which ssh keys could be moved. Names only; moving stays a click.
func offerKeys(ctx context.Context, c *hostclient.Client, v *Vault) {
	if cfg, err := c.Config(ctx); err != nil || !slices.Contains(cfg.Features, featureSSH) || v.Keys == nil {
		return
	}
	for _, n := range v.DetectSSH() {
		_ = c.Do(ctx, http.MethodPost, "/secrets/vault/report",
			map[string]string{"kind": "ssh", "ref": n, "state": "AVAILABLE"}, nil)
	}
}

func reportStored(ctx context.Context, c *hostclient.Client, kind, ref string) {
	_ = c.Do(ctx, http.MethodPost, "/secrets/vault/report", map[string]string{"kind": kind, "ref": ref, "state": "STORED"}, nil)
}

func reportRestored(ctx context.Context, c *hostclient.Client, kind, ref string) {
	_ = c.Do(ctx, http.MethodPost, "/secrets/vault/report", map[string]string{"kind": kind, "ref": ref, "state": "RESTORED"}, nil)
}

// eventClass is the watcher's path class for a vault request kind ("" leaves it out): an SSH key
// restore is about SSH keys, and a refused secret file's Ref already is its class.
func eventClass(r Request) string {
	switch r.Kind {
	case "aws", "ssh":
		return r.Kind
	case kindRestore:
		return "ssh"
	case "file":
		return r.Ref
	}
	return ""
}

func sendEvent(ctx context.Context, c *hostclient.Client, typ, process string, r Request) {
	ev := map[string]any{"type": typ, "blocked": true, "at": time.Now().UTC()}
	if process != "" && process != "." {
		ev["process"] = process
	}
	if cl := eventClass(r); cl != "" {
		ev["pathClass"] = cl
	}
	if r.Ref != "" && r.Kind != "file" {
		ev["maskedPath"] = r.Ref
	}
	if err := c.Do(ctx, http.MethodPost, "/events", map[string]any{"events": []any{ev}}, nil); err != nil {
		log.Printf("manar-edge: vault event: %v", err)
	}
}

// consoleApprover asks in the console: it opens a request and waits for the person.
type consoleApprover struct{ c *hostclient.Client }

func (a consoleApprover) Ask(ctx context.Context, r Request) (Decision, error) {
	d, _, err := a.AskGrant(ctx, r)
	return d, err
}

// AskGrant is Ask plus the console request's id: a standing grant is matched with the server's list
// by it.
func (a consoleApprover) AskGrant(ctx context.Context, r Request) (Decision, string, error) {
	var created struct{ ID string }
	// The console sees the full path (home masked) and the hash of the binary, not just a name.
	body := map[string]string{"kind": r.Kind, "ref": r.Ref, "program": filepath.Base(r.Program),
		"programPath": host.MaskPath(host.Homes(), r.Program), "programSha": r.SHA}
	if r.Program == "" {
		body["program"], body["programPath"], body["programSha"] = "unknown program", "unknown", strings.Repeat("0", 64)
	}
	// The console offers 8 hours and always; say when the device will count any yes as once (the
	// secret-file gate keeps its own grants).
	switch {
	case r.Kind == "file":
	case r.ViaAI:
		body["program"] += " (run by an AI tool; a yes counts once)"
	case OnceOnly(r):
		body["program"] += " (a yes counts once)"
	}
	if err := a.c.Do(ctx, http.MethodPost, "/secrets/access", body, &created); err != nil {
		return Deny, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		var st struct{ Status string }
		if err := a.c.Do(ctx, http.MethodGet, "/secrets/access/"+created.ID, nil, &st); err == nil && st.Status != "PENDING" {
			return Decision(st.Status), created.ID, nil
		}
		select {
		case <-ctx.Done():
			return Deny, "", ctx.Err()
		case <-t.C:
		}
	}
}

// Unprotect puts vaulted secrets back when the device is removed from its workspace.
func (m *Module) Unprotect(ctx context.Context) error { return m.Cleanup(ctx) }
