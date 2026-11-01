package main

import (
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

	"gitlab.vax.sh/manar/manar-edge/internal/daemon"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

// The one-liner path for personal devices (manar-api GET /i/<code>): `install --code` enrols
// with the install key from the console, installs the device service and starts it. The device
// lands PENDING until the owner approves it in the console. There is no WireGuard here: the
// egress filter of a personal device runs on the device itself.

const (
	defaultAPIURL  = "https://console-manar.vax.sh"
	defaultHostURL = "https://agents-manar.vax.sh:3443"
)

func cmdInstall(base string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	code := fs.String("code", "", "install code from the console (Add device)")
	tenant := fs.String("tenant", "", "tenant slug (with a short code; not needed for a mik_ key)")
	api := fs.String("api", defaultAPIURL, "Manar API base URL")
	hostURL := fs.String("host-url", defaultHostURL, "Manar device (mTLS) URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *code == "" || fs.NArg() != 0 {
		return errors.New("usage: manar-edge install --code <code> --tenant <slug> [--api URL] [--host-url URL]")
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
	info, err := hostclient.Enrol(ctx, hostclient.EnrolInput{
		StateDir: base, APIURL: *api, HostURL: *hostURL, InstallKey: strings.TrimSpace(*code), TenantSlug: *tenant,
		MachineID: mid, Hostname: hostname, OS: osLabel(),
	})
	if err != nil {
		return err
	}
	// Stop a running service first: on Windows its exe is locked, and the copy below would fail
	// or leave the old binary running.
	if err := deviceServiceStop(); err != nil {
		return fmt.Errorf("stopping the running service: %w", err)
	}
	exe, err := installedBinary()
	if err != nil {
		return err
	}
	if err := deviceServiceInstall(exe, base); err != nil {
		return fmt.Errorf("installing the service: %w", err)
	}
	fmt.Fprintf(out, "Installed the Manar device service and started it (host %s).\n", info.HostID)
	fmt.Fprintln(out, "Done, approve it in the console.")
	return nil
}

// uninstallSteps are the pieces of uninstall, as values so the order can be tested.
type uninstallSteps struct {
	removeService func() error
	cleanup       func(ctx context.Context) []error
	agents        func() []string // every enrolled agent's name
	down          func(agent string) error
	claudeCode    func() error
	removeHost    func() error
	removeBinary  func() error
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
	note("removing the service", st.removeService())
	for _, err := range st.cleanup(ctx) {
		note("restore step", err)
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
		removeService: deviceServiceRemove,
		cleanup:       daemon.Cleanup,
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
		claudeCode: uninstallClaudeCode,
		removeHost: func() error { return os.RemoveAll(hostclient.Dir(base)) },
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
		return deviceServiceRemove()
	}
	return errors.New("usage: manar-edge service run|install|remove")
}

// serveDevice loads the host files and runs the registered modules until ctx is done.
func serveDevice(ctx context.Context, base string) error {
	c, err := hostclient.New(base)
	if err != nil {
		return err
	}
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
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, filepath.ToSlash(exe), base)
}
