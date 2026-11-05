package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/manarhq/manar-edge/internal/daemon"
	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/jail"
	"github.com/manarhq/manar-edge/internal/secrets/vault"
	"github.com/manarhq/manar-edge/internal/warden"
)

// The one-liner path for personal devices (manar-api GET /i/<code>): `install --code` enrols
// with the install key from the console, installs the device service and starts it. The device
// lands PENDING until the owner approves it in the console. There is no WireGuard here: the
// egress filter of a personal device runs on the device itself.

// Defaults for new installs; the release build overrides them with
// -ldflags "-X main.defaultAPIURL=... -X main.defaultHostURL=..." so a domain move is a build change.
var (
	defaultAPIURL  = "https://console-manar.fixio.ae"
	defaultHostURL = "https://agents-manar.fixio.ae:3443"
)

// installCodeEnv carries the install code from the one-liner.
const installCodeEnv = "MANAR_INSTALL_CODE"

// confirmMoveEnv=1 confirms moving the computer to another workspace (the one-liner runs without a
// terminal to ask in: `curl ... | sudo MANAR_CONFIRM_MOVE=1 sh`).
const confirmMoveEnv = "MANAR_CONFIRM_MOVE"

// askMove asks whether to move the computer to the new workspace; only "y" or "yes" says so.
func askMove(e *hostclient.OtherWorkspaceError, in io.Reader, out io.Writer) bool {
	fmt.Fprintf(out, "This computer moves from %q to %q: %q's rules will apply to the AI tools on it, "+
		"and %q will show it as moved. Continue? [y/N] ", e.From, e.To, e.To, e.From)
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// moveRefused is the answer when nobody can be asked (no terminal).
func moveRefused(e *hostclient.OtherWorkspaceError) error {
	return fmt.Errorf("%v. Nothing was changed. To move it, run the install again with --confirm-move "+
		"(for the one-line installer: `curl ... | sudo MANAR_CONFIRM_MOVE=1 sh`, or set $env:MANAR_CONFIRM_MOVE=1 "+
		"first in PowerShell), or uninstall Manar first", e)
}

func strconvQuote(s string) string { return fmt.Sprintf("%q", s) }

// openPrompt finds the person's terminal: standard input when it is one, otherwise (the one-liner
// pipes the script into sh) the controlling terminal on Linux. ok is false when there is none.
func openPrompt() (io.ReadWriteCloser, bool) {
	if isTerminal(os.Stdin) {
		return struct {
			io.Reader
			io.Writer
			io.Closer
		}{os.Stdin, os.Stderr, io.NopCloser(nil)}, true
	}
	if runtime.GOOS == "windows" {
		return nil, false
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil || !isTerminal(f) {
		if f != nil {
			f.Close()
		}
		return nil, false
	}
	return f, true
}

func cmdInstall(base string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	code := fs.String("code", "", "install code from the console (Add device)")
	tenant := fs.String("tenant", "", "tenant slug (with a short code; not needed for a mik_ key)")
	api := fs.String("api", defaultAPIURL, "Manar API base URL")
	hostURL := fs.String("host-url", defaultHostURL, "Manar device (mTLS) URL")
	confirmMove := fs.Bool("confirm-move", false, "move this computer from the workspace it is enrolled in (its rules stop applying, the new workspace's apply)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Getenv(confirmMoveEnv) == "1" {
		*confirmMove = true
	}
	// The one-liner passes the code in the environment: a command line is visible to every local
	// user while the install runs, the environment of an elevated process is not. Not passed on to
	// anything this process starts.
	if env := os.Getenv(installCodeEnv); env != "" {
		_ = os.Unsetenv(installCodeEnv)
		if *code == "" {
			*code = env
		}
	}
	if *code == "" || fs.NArg() != 0 {
		return errors.New("usage: manar-edge install --code <code> --tenant <slug> [--api URL] [--host-url URL] [--confirm-move] (or the code in " + installCodeEnv + ")")
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	if err := secureMkdir(base); err != nil {
		return err
	}
	if err := secureMkdir(hostclient.Dir(base)); err != nil {
		return err
	}
	mid, err := machineID()
	if err != nil {
		return fmt.Errorf("reading the machine id: %w", err)
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fmt.Fprintln(out, "Registering this computer with Manar...")
	in := hostclient.EnrolInput{
		StateDir: base, APIURL: *api, HostURL: *hostURL, InstallKey: strings.TrimSpace(*code), TenantSlug: *tenant,
		MachineID: mid, Hostname: hostname, OS: osLabel(), ConfirmMove: *confirmMove,
	}
	info, err := hostclient.Enrol(ctx, in)
	var other *hostclient.OtherWorkspaceError
	if errors.As(err, &other) {
		// Ask the person at the keyboard; a script (no terminal) is refused with what to do.
		tty, ok := openPrompt()
		if !ok {
			return moveRefused(other)
		}
		yes := askMove(other, tty, tty)
		tty.Close()
		if !yes {
			return errors.New("nothing was changed: this computer stays in workspace " + strconvQuote(other.From))
		}
		in.ConfirmMove = true
		info, err = hostclient.Enrol(ctx, in)
	}
	if err != nil {
		return err
	}
	// Stop a running service first: on Windows its exe is locked, and the copy below would fail
	// or leave the old binary running.
	if err := deviceServiceStop(); err != nil {
		return fmt.Errorf("stopping the running service: %w", err)
	}
	// A move: only now, with the old service stopped, tell the old workspace (told earlier, it
	// would answer the old service "removed" and that service would take protection out).
	if info.MovedFrom != "" {
		fmt.Fprintf(out, "This computer moved from workspace %q to %q, with a new device key.\n", info.MovedFrom, info.TenantSlug)
		if !info.TellOldWorkspace(context.Background(), base) {
			fmt.Fprintf(out, "Workspace %q could not be told; an admin there can remove this computer from its device list.\n", info.MovedFrom)
		}
	}
	exe, err := installedBinary()
	if err != nil {
		return err
	}
	if err := deviceServiceInstall(exe, base); err != nil {
		return fmt.Errorf("installing the service: %w", err)
	}
	if err := warden.Install(base, exe); err != nil {
		fmt.Fprintf(out, "warning: WARDEN prompts are not set up (approve in the console): %v\n", err)
	}
	fmt.Fprintf(out, "Installed the Manar device service and started it (host %s).\n", info.HostID)
	printCoverage(out)
	fmt.Fprintln(out, "Done, approve it in the console.")
	return nil
}

// uninstallSteps are the pieces of uninstall, as values so the order can be tested.
type uninstallSteps struct {
	// restoreSecrets puts every vaulted secret back (nil: nothing to do). It runs before anything
	// is stopped or removed: on Windows only the running service can decrypt the vault.
	restoreSecrets func() error
	removeService  func() error
	cleanup        func(ctx context.Context) []error
	agents         func() []string // every enrolled agent's name
	down           func(agent string) error
	warden         func() error // WARDEN helper autostart and its files
	claudeCode     func() error
	removeHost     func() error
	removeBinary   func() error
}

// runUninstall: service, module cleanups, every agent (jail, gateway units, namespaces, users),
// the Claude Code policy, the host files, and the binary LAST and only when every step before it
// worked: the units that are left run that binary. It returns what failed.
func runUninstall(ctx context.Context, st uninstallSteps, out io.Writer) []error {
	var errs []error
	note := func(what string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
			fmt.Fprintf(out, "warning: %s: %v\n", what, err)
		}
	}
	if st.restoreSecrets != nil {
		if err := st.restoreSecrets(); err != nil {
			fmt.Fprintf(out, "Manar was not removed: vaulted secrets could not all be put back (%v).\n"+
				"Fix that, or run `manar-edge secret restore --all` as an administrator to see what is left, then run uninstall again.\n", err)
			return []error{fmt.Errorf("restoring vaulted secrets: %w", err)}
		}
	}
	note("removing the service", st.removeService())
	for _, err := range st.cleanup(ctx) {
		note("restore step", err)
	}
	if st.warden != nil {
		note("removing WARDEN", st.warden())
	}
	for _, agent := range st.agents() {
		note("taking down agent "+agent, st.down(agent))
	}
	note("removing the Claude Code policy", st.claudeCode())
	note("removing the host files", st.removeHost())
	if len(errs) == 0 {
		note("removing the program", st.removeBinary())
	} else {
		fmt.Fprintln(out, "the program was left in place because some steps above failed: fix them and run uninstall again")
	}
	return errs
}

// cmdUninstall removes everything Manar put on this computer. On Windows a running exe cannot
// delete itself, so the uninstall one-liner removes the folder after this process exits.
func cmdUninstall(base string, out io.Writer) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	errs := runUninstall(ctx, uninstallSteps{
		restoreSecrets: restoreSecrets,
		removeService:  deviceServiceRemove,
		cleanup:        daemon.Cleanup,
		agents: func() []string {
			var names []string
			for _, dir := range listAgents(base) {
				if st, err := loadState(dir); err == nil {
					names = append(names, st.Name)
				}
			}
			return names
		},
		down:       func(agent string) error { return cmdDown(base, agent, true) },
		warden:     func() error { return warden.Remove(base) },
		claudeCode: uninstallClaudeCode,
		removeHost: func() error {
			// The vault folders are removed only when empty: os.Remove, never RemoveAll, so a
			// secret that is somehow still there is not deleted with them.
			_ = os.Remove(filepath.Join(base, "vault"))
			_ = os.Remove(filepath.Join(base, "secrets"))
			return os.RemoveAll(hostclient.Dir(base))
		},
		removeBinary: func() error {
			if runtime.GOOS == "windows" {
				return nil
			}
			exe, err := installedBinary()
			if err != nil {
				return err
			}
			return os.Remove(exe)
		},
	}, out)
	if len(errs) > 0 {
		return errors.New("some steps failed (see above): Manar is only partly removed")
	}
	fmt.Fprintln(out, "Manar is removed from this computer.")
	return nil
}

// restoreSecrets asks the running service to put every vaulted secret back (it is the one that can
// decrypt them on Windows), then checks locally that nothing is left.
func restoreSecrets() error {
	if _, err := vault.RestoreAllViaService(); err != nil {
		return err
	}
	return vault.RestoreAll()
}

// writePrivateMode writes through a temp file and rename.
func writePrivateMode(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func cmdService(base string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: manar-edge service run|install|remove")
	}
	switch args[0] {
	case "run":
		return runDeviceService(base)
	case "install":
		if err := requireAdmin(); err != nil {
			return err
		}
		exe, err := installedBinary()
		if err != nil {
			return err
		}
		return deviceServiceInstall(exe, base)
	case "remove":
		if err := requireAdmin(); err != nil {
			return err
		}
		err := deviceServiceRemove()
		// Removing the service must leave networking as it was, even if the service never ran.
		return errors.Join(err, jailRestore(os.Stdout))
	}
	return errors.New("usage: manar-edge service run|install|remove")
}

// serveDevice loads the host files and runs the registered modules until ctx is done.
func serveDevice(ctx context.Context, base string) error {
	c, err := hostclient.New(base)
	if err != nil {
		return err
	}
	warden.SetStateDir(base)
	// Steps for a device the workspace removed. The undo copies and the program itself stay.
	daemon.RegisterOnRemoved("claude-code-policy", func(context.Context) error { return uninstallClaudeCode() })
	daemon.RegisterOnRemoved("warden", func(context.Context) error { return warden.Remove(base) })
	return daemon.Run(ctx, c)
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// hashedMachineID turns the OS machine identifier into the id Manar sees: stable, and not the
// raw OS value (systemd asks that /etc/machine-id is not exposed as it is).
func hashedMachineID(raw string) string {
	sum := sha256.Sum256([]byte("manar-edge:" + strings.TrimSpace(raw)))
	return "m-" + hex.EncodeToString(sum[:16])
}

// unitText is the Linux systemd unit for the device service.
func unitText(exe, base string) string {
	return fmt.Sprintf(`[Unit]
Description=Manar device service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=%s --state-dir %s service run
# Behind a corporate proxy, put HTTPS_PROXY=http://host:port (and NO_PROXY) in <state dir>/proxy.env.
# A systemd service does not inherit a login shell's variables. Only http:// CONNECT proxies work.
EnvironmentFile=-%s/proxy.env
Restart=always
RestartSec=5
# Whenever the service stops or dies, give the protected tools their network back (the filter is
# put up again within seconds when the service restarts).
ExecStopPost=-%s --state-dir %s jail-restore

[Install]
WantedBy=multi-user.target
`, filepath.ToSlash(exe), base, base, filepath.ToSlash(exe), base)
}

// jailRestore removes the egress filter's rules and cgroups (nothing happens if there are none).
func jailRestore(out io.Writer) error {
	errs := jail.PlatformCleanup()
	for _, e := range errs {
		fmt.Fprintf(out, "warning: removing the egress filter: %v\n", e)
	}
	return errors.Join(errs...)
}
