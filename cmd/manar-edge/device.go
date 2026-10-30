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
	api := fs.String("api", defaultAPIURL, "Manar API base URL")
	hostURL := fs.String("host-url", defaultHostURL, "Manar device (mTLS) URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *code == "" || fs.NArg() != 0 {
		return errors.New("usage: manar-edge install --code <code> [--api URL] [--host-url URL]")
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
		StateDir: base, APIURL: *api, HostURL: *hostURL, InstallKey: strings.TrimSpace(*code),
		MachineID: mid, Hostname: hostname, OS: osLabel(),
	})
	if err != nil {
		return err
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

// cmdUninstall stops the service, lets every module restore what it changed, and removes the
// device's files. The binary itself is removed last, on Linux; on Windows a running exe cannot
// delete itself, so the uninstall one-liner removes the folder after this process exits.
func cmdUninstall(base string, out io.Writer) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	if err := deviceServiceRemove(); err != nil {
		fmt.Fprintf(out, "warning: removing the service: %v\n", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	failed := false
	for _, err := range daemon.Cleanup(ctx) {
		failed = true
		fmt.Fprintf(out, "warning: restore step failed: %v\n", err)
	}
	if err := os.RemoveAll(hostclient.Dir(base)); err != nil {
		return err
	}
	if exe, err := installedBinary(); err == nil && runtime.GOOS != "windows" {
		_ = os.Remove(exe)
	}
	if failed {
		return errors.New("Manar was removed, but some restore steps failed (see above): check those tools' settings by hand")
	}
	fmt.Fprintln(out, "Manar is removed from this computer.")
	return nil
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
