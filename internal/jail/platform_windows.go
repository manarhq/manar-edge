package jail

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/manarhq/manar-edge/internal/discovery"
	"github.com/manarhq/manar-edge/internal/protect"
)

// storeTool is the key JAIL's settings edits are backed up under in the protect store.
const storeTool = "jail-claude-code"

func newPlatform() (platform, error) {
	// Opening the engine proves we have the rights and that Base Filtering Engine runs.
	n, err := wfpFilterCount()
	if err != nil {
		return nil, fmt.Errorf("the Windows Filtering Platform is not available: %w", err)
	}
	_ = n
	if protect.SharedStore() == nil {
		return nil, errors.New("the backup store is not set up")
	}
	return &winPlatform{}, nil
}

func platformCleanupErrs() []error { return (&winPlatform{}).teardown() }

func (r *runner) startProxy(tool string) (*toolProxy, error) {
	port := winPort(tool)
	if port == 0 {
		return nil, fmt.Errorf("%s is not filtered on Windows", tool)
	}
	// A fixed loopback port, because the tool's own settings name it. If something else holds it
	// the proxy cannot start, and with no proxy nothing is blocked.
	// SO_EXCLUSIVEADDRUSE: no other program can bind the same port, not even with SO_REUSEADDR.
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	ln, err := lc.Listen(context.Background(), "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("port %d is taken by another program: %w", port, err)
	}
	p := &Proxy{Tool: tool, Policy: r.policy, Asker: r.asker, Resolve: r.resolve, Log: log.Printf}
	go p.ServeConnect(ln)
	return &toolProxy{port: port, lns: []net.Listener{ln}}, nil
}

// winPlatform installs, per account that has a native Claude Code: the proxy variables in that
// account's settings.json (backed up), then the WFP filters for its claude.exe files. Order
// matters: the block is added only after the tool is pointed at a proxy that has just proved it is
// ours, and taken away before the settings are restored.
type winPlatform struct {
	mu   sync.Mutex
	last string // what is installed, to do nothing when nothing changed

	// users and running are the real accounts and processes unless a test supplies its own.
	users     func() []discovery.User
	running   func() []string
	resolvers func() []netip.Addr
}

func (w *winPlatform) accounts() []discovery.User {
	if w.users != nil {
		return w.users()
	}
	return discovery.Users()
}

func (w *winPlatform) dns() []netip.Addr {
	if w.resolvers != nil {
		return w.resolvers()
	}
	return windowsResolvers()
}

func (w *winPlatform) claudeProcs() []string {
	if w.running != nil {
		return w.running()
	}
	return runningClaudeExes()
}

func (w *winPlatform) Apply(ports map[string]int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	port := ports[winTool]
	if len(ports) == 0 || port == 0 {
		w.last = ""
		return errors.Join(w.teardown()...)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := Challenge(addr); err != nil {
		// Never block a tool whose proxy cannot be trusted: take everything back out.
		_ = w.teardown()
		w.last = ""
		return fmt.Errorf("not installing the block: %w", err)
	}
	plans := planWindows(w.accounts(), w.claudeProcs(), globFiles)
	store := protect.SharedStore()
	env := proxyEnv(port)
	var exes []string
	handled := map[string]bool{}
	for _, pl := range plans {
		out, err := store.Apply(storeTool, pl.User.Name, protect.Owner{UID: -1, GID: -1, Home: pl.User.Home},
			[]protect.FileEdit{protect.JailEnvEdit(pl.Settings, env)})
		if err != nil || len(out) != 1 || out[0].Warning != "" {
			// A settings file we cannot edit safely (unreadable, not JSON, a link): this account is
			// left completely alone, because blocking its tool without the proxy setting would
			// cut it off.
			log.Printf("jail: %s: settings not changed, claude.exe not filtered (%v %+v)", pl.User.Name, err, out)
			continue
		}
		if !settingsHasProxy(pl.Settings, env["HTTPS_PROXY"]) {
			log.Printf("jail: %s: the proxy setting did not stick, claude.exe not filtered", pl.User.Name)
			continue
		}
		handled[pl.User.Name] = true
		exes = append(exes, pl.Exes...)
	}
	// Accounts we no longer handle (the tool was removed) get their settings back.
	for _, u := range w.accounts() {
		if !handled[u.Name] && store.Has(storeTool, u.Name) {
			if err := store.Restore(storeTool, u.Name); err != nil {
				log.Printf("jail: restoring %s: %v", u.Name, err)
			}
		}
	}
	slices.Sort(exes)
	resolvers := w.dns()
	key := fmt.Sprint(port, exes, resolvers)
	if n, err := wfpFilterCount(); err == nil && n > 0 && key == w.last {
		return nil
	}
	if len(exes) == 0 {
		w.last = ""
		return wfpRemove()
	}
	if err := wfpInstall(exes, resolvers); err != nil {
		_ = w.teardown()
		w.last = ""
		return err
	}
	w.last = key
	log.Printf("jail: Windows filter installed for %d claude.exe file(s)", len(exes))
	return nil
}

func settingsHasProxy(path, want string) bool {
	b, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(b), want)
}

func (w *winPlatform) Teardown() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.last = ""
	return errors.Join(w.teardown()...)
}

// teardown removes the filters first, then puts the settings back. It works from the state on the
// machine, so it also cleans up after a service that died.
func (w *winPlatform) teardown() []error {
	var errs []error
	if err := wfpRemove(); err != nil {
		errs = append(errs, err)
	}
	if store := protect.SharedStore(); store != nil {
		for _, u := range w.accounts() {
			if store.Has(storeTool, u.Name) {
				if err := store.Restore(storeTool, u.Name); err != nil {
					errs = append(errs, fmt.Errorf("restoring %s: %w", u.Name, err))
				}
			}
		}
	}
	return errs
}

func globFiles(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE, (int)~SO_REUSEADDR in winsock2.h.
const soExclusiveAddrUse = ^4
