package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const deviceServiceName = "ManarEdge"

func machineID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	g, _, err := k.GetStringValue("MachineGuid")
	if err != nil || strings.TrimSpace(g) == "" {
		return "", errors.New("no MachineGuid in the registry")
	}
	return hashedMachineID(g), nil
}

func osLabel() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "windows"
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	// ProductName still says "Windows 10" on Windows 11; build 22000 and up is Windows 11.
	if n := strings.TrimSpace(build); len(n) == 5 && n >= "22000" {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	if name == "" {
		name = "Windows"
	}
	return name + " (windows)"
}

func deviceServiceInstall(exe, base string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	args := []string{"--state-dir", base, "service", "run"}
	cfg := mgr.Config{
		DisplayName: "Manar device service",
		Description: "Keeps this computer connected to Manar and applies your rules.",
		StartType:   mgr.StartAutomatic,
	}
	s, err := m.OpenService(deviceServiceName)
	if err != nil {
		s, err = m.CreateService(deviceServiceName, exe, cfg, args...)
		if err != nil {
			return err
		}
	} else {
		stopService(s)
		cur, err := s.Config()
		if err != nil {
			s.Close()
			return err
		}
		cur.DisplayName, cur.Description, cur.StartType = cfg.DisplayName, cfg.Description, cfg.StartType
		q := []string{syscall.EscapeArg(exe)}
		for _, a := range args {
			q = append(q, syscall.EscapeArg(a))
		}
		cur.BinaryPathName = strings.Join(q, " ")
		if err := s.UpdateConfig(cur); err != nil {
			s.Close()
			return err
		}
	}
	defer s.Close()
	// Restart on failure within seconds: 2 s, 2 s, 10 s, and reset the count after a day.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2_000_000_000},
		{Type: mgr.ServiceRestart, Delay: 2_000_000_000},
		{Type: mgr.ServiceRestart, Delay: 10_000_000_000},
	}, 86400)
	return s.Start()
}

func deviceServiceRemove() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(deviceServiceName)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	stopService(s)
	return s.Delete()
}

type deviceSvc struct{ base string }

func (d *deviceSvc) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveDevice(ctx, d.base) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				fmt.Fprintln(os.Stderr, "manar-edge:", err)
				return false, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}

func runDeviceService(base string) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isSvc {
		ctx, stop := signalContext()
		defer stop()
		return serveDevice(ctx, base)
	}
	return svc.Run(deviceServiceName, &deviceSvc{base: base})
}

// deviceServiceStop stops the service if it is installed; the exe cannot be replaced while it runs.
func deviceServiceStop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(deviceServiceName)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	stopService(s)
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		return errors.New("the service did not stop")
	}
	return nil
}
