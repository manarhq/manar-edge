package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const deviceUnit = "manar-edge.service"

func machineID() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
			return hashedMachineID(string(b)), nil
		}
	}
	return "", errors.New("no /etc/machine-id on this system")
}

func osLabel() string {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				return strings.Trim(v, `"`) + " (linux)"
			}
		}
	}
	return "linux"
}

func deviceServiceInstall(exe, base string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd (systemctl) was not found: run `manar-edge service run` under your init system")
	}
	if err := os.WriteFile(filepath.Join(unitDir, deviceUnit), []byte(unitText(exe, base)), 0o644); err != nil {
		return err
	}
	if err := sh("", "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return sh("", "systemctl", "enable", "--now", deviceUnit)
}

func deviceServiceRemove() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	_ = sh("", "systemctl", "disable", "--now", deviceUnit)
	if err := os.Remove(filepath.Join(unitDir, deviceUnit)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return sh("", "systemctl", "daemon-reload")
}

func runDeviceService(base string) error {
	ctx, stop := signalContext()
	defer stop()
	return serveDevice(ctx, base)
}

// deviceServiceStop stops the service if it is running (nothing to do when it is not installed).
func deviceServiceStop() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(unitDir, deviceUnit)); err != nil {
		return nil
	}
	return sh("", "systemctl", "stop", deviceUnit)
}
