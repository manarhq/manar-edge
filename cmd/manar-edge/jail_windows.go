package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/wgctrl"
)

const (
	defaultStateBase    = `C:\ProgramData\manar-edge`
	upUsageExtra        = ` [--program <exe>]...`
	managedSettingsPath = `C:\Program Files\ClaudeCode\managed-settings.json`
	// stateDACL: SYSTEM and Administrators full control, inherited by children, nothing else.
	stateDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

func tunnelName(st *State) string  { return "manar-" + st.Name }
func serviceName(st *State) string { return "manar-edge-gw-" + st.Name }

func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("this command must run as Administrator")
	}
	return nil
}

func secureMkdir(p string) error {
	if err := os.MkdirAll(p, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(stateDACL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func wireguardExe() (string, error) {
	p := filepath.Join(os.Getenv("ProgramFiles"), "WireGuard", "wireguard.exe")
	if _, err := os.Stat(p); err != nil {
		return "", errors.New("WireGuard for Windows is not installed (expected " + p + "); install it from https://www.wireguard.com/install/")
	}
	return p, nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// powershell runs a script passed as -EncodedCommand (UTF-16LE), so non-ASCII paths are not
// mangled by the console code page, and returns its standard output.
func powershell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", psEncode(script))
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// applyFirewall replaces the agent's rule group and reads it back: every program must have
// exactly its rules, with the path as given.
func applyFirewall(st *State) error {
	allowed := allowedTCP(st.Edge)
	for _, s := range firewallScripts(st.Name, st.Programs, allowed) {
		if _, err := powershell(s); err != nil {
			return err
		}
	}
	out, err := powershell(firewallReadback(st.Name))
	if err != nil {
		return err
	}
	return checkRulePrograms(out, st.Programs, rulesPerProgram(allowed))
}

func serviceExists(m *mgr.Mgr, name string) bool {
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

func waitServiceState(s *mgr.Service, want svc.State) error {
	for range 60 {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach state %d", want)
}

func stopService(s *mgr.Service) {
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		_ = waitServiceState(s, svc.Stopped)
	}
}

// installGatewayService creates or updates the local gateway service and (re)starts it.
func installGatewayService(st *State, exe, base string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	args := []string{"--state-dir", base, "gateway", st.Name}
	cfg := mgr.Config{
		DisplayName: "Manar Edge local gateway (" + st.Name + ")",
		Description: "Forwards the agent's LLM and MCP calls to Manar over mTLS.",
		StartType:   mgr.StartAutomatic,
	}
	s, err := m.OpenService(serviceName(st))
	if err != nil {
		s, err = m.CreateService(serviceName(st), exe, cfg, args...)
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
	return s.Start()
}

func restartGateway(st *State) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName(st))
	if err != nil {
		return err
	}
	defer s.Close()
	stopService(s)
	return s.Start()
}

// gatewayHealth checks the gateway the way the hook reaches it: over the pipe, served by the service.
func gatewayHealth(st *State) error {
	tr, base := hookTransport(st.Name)
	c := &http.Client{Timeout: 3 * time.Second, Transport: tr}
	res, err := c.Get(base + "/healthz")
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: HTTP %d", res.StatusCode)
	}
	return nil
}

func waitGateway(st *State) error {
	var err error
	for range 40 {
		if err = gatewayHealth(st); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("local gateway did not become healthy: %w", err)
}

func cmdUp(base string, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	task := fs.String("task", "", "task id the local gateway injects")
	var programs multiFlag
	fs.Var(&programs, "program", "absolute path of a program to confine (repeatable)")
	agent, err := parseAgentFlags(fs, args)
	if err != nil {
		return err
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	dir, st, err := resolveAgent(base, agent)
	if err != nil {
		return err
	}
	if _, err := applyTask(dir, st, *task); err != nil {
		return err
	}
	if len(programs) > 0 {
		var abs []string
		for _, p := range programs {
			if !filepath.IsAbs(p) {
				return fmt.Errorf("--program %q must be an absolute path", p)
			}
			// New-NetFirewallRule accepts a path that does not exist, which would confine nothing.
			if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
				return fmt.Errorf("--program %q is not an existing file", p)
			}
			abs = append(abs, filepath.Clean(p))
		}
		st.Programs = abs
		if err := saveState(dir, st); err != nil {
			return err
		}
	}
	targets, err := overlayTargets(st.Edge)
	if err != nil {
		return err
	}
	wg, err := wireguardExe()
	if err != nil {
		return err
	}
	exe, err := installedBinary()
	if err != nil {
		return err
	}
	if err := secureMkdir(dir); err != nil {
		return err
	}
	key, err := os.ReadFile(filepath.Join(dir, fileWGKey))
	if err != nil {
		return err
	}

	// Firewall first, so the programs are confined before the tunnel comes up.
	for _, p := range st.Programs { // also on a later up without --program
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("confined program %q no longer exists; pass the --program list again", p)
		}
	}
	if err := applyFirewall(st); err != nil {
		return err
	}
	conf := filepath.Join(dir, tunnelName(st)+".conf")
	if err := writePrivate(conf, []byte(wgConfig(strings.TrimSpace(string(key)), st.Edge, targets))); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	exists := serviceExists(m, `WireGuardTunnel$`+tunnelName(st))
	m.Disconnect()
	if exists {
		_ = run(wg, "/uninstalltunnelservice", tunnelName(st))
		time.Sleep(2 * time.Second)
	}
	if err := run(wg, "/installtunnelservice", conf); err != nil {
		return err
	}
	if err := installGatewayService(st, exe, base); err != nil {
		return err
	}
	if err := waitGateway(st); err != nil {
		return err
	}
	fmt.Printf("%s is up: tunnel %s, service %s, overlay %s, task %q\n", st.Name, tunnelName(st), serviceName(st), st.Edge.Address, st.Task)
	if len(st.Programs) == 0 {
		fmt.Println("warning: no --program given, so no program is confined by the firewall")
	}
	if st.Task == "" {
		fmt.Println("no task set: LLM and MCP calls get 412 until `manar-edge up " + st.Name + " --task <taskId>`")
	}
	return nil
}

// purge is accepted for symmetry with Linux; Windows agents have no Manar-managed home.
func cmdDown(base, agent string, _ bool) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	_, st, err := resolveAgent(base, agent)
	if err != nil {
		return err
	}
	var errs []error
	if m, err := mgr.Connect(); err == nil {
		if s, err := m.OpenService(serviceName(st)); err == nil {
			stopService(s)
			if err := s.Delete(); err != nil {
				errs = append(errs, err)
			}
			s.Close()
		}
		exists := serviceExists(m, `WireGuardTunnel$`+tunnelName(st))
		m.Disconnect()
		if exists {
			if wg, err := wireguardExe(); err == nil {
				if err := run(wg, "/uninstalltunnelservice", tunnelName(st)); err != nil {
					errs = append(errs, err)
				}
			}
		}
	} else {
		errs = append(errs, err)
	}
	if _, err := powershell(fmt.Sprintf("Get-NetFirewallRule -Group %s -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n", psQuote(fwGroup(st.Name)))); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	fmt.Printf("%s is down\n", st.Name)
	return nil
}

func cmdStatus(base string, args []string) error {
	dirs := listAgents(base)
	if len(args) == 1 {
		dir, _, err := resolveAgent(base, args[0])
		if err != nil {
			return err
		}
		dirs = []string{dir}
	}
	if len(dirs) == 0 {
		fmt.Println("no agents enrolled in", base)
		return nil
	}
	for _, dir := range dirs {
		st, err := loadState(dir)
		if err != nil {
			return err
		}
		fmt.Printf("%s (%s/%s) overlay %s task %q\n", st.Name, st.TenantSlug, st.AgentSlug, st.Edge.Address, st.Task)
		fmt.Println("  confined programs:", strings.Join(st.Programs, ", "))
		if c, err := wgctrl.New(); err == nil {
			if d, err := c.Device(tunnelName(st)); err == nil && len(d.Peers) > 0 && !d.Peers[0].LastHandshakeTime.IsZero() {
				fmt.Println("  handshake:", time.Since(d.Peers[0].LastHandshakeTime).Round(time.Second), "ago")
			} else {
				fmt.Println("  handshake: never or tunnel down")
			}
			c.Close()
		}
		if conn, err := net.DialTimeout("tcp", st.Edge.ManarAddress, 3*time.Second); err == nil {
			conn.Close()
			fmt.Println("  manar through the tunnel: reachable (peer active)")
		} else {
			fmt.Println("  manar through the tunnel: unreachable (peer cut or tunnel down)")
		}
		if err := gatewayHealth(st); err == nil {
			fmt.Println("  local gateway: healthy")
		} else {
			fmt.Println("  local gateway: down:", err)
		}
	}
	return nil
}

func cmdRun(base string, args []string) error {
	i := slices.Index(args, "--")
	if i < 0 || i == len(args)-1 {
		return errors.New("usage: manar-edge run <agent> [--task <taskId>] -- <command> [args...]")
	}
	before, command := args[:i], args[i+1:]
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	task := fs.String("task", "", "task id (restarts the local gateway when it changes)")
	agent, err := parseAgentFlags(fs, before)
	if err != nil {
		return err
	}
	dir, st, err := resolveAgent(base, agent)
	if err != nil {
		return err
	}
	changed, err := applyTask(dir, st, *task)
	if err != nil {
		return err
	}
	if changed {
		if err := restartGateway(st); err != nil {
			return err
		}
		if err := waitGateway(st); err != nil {
			return err
		}
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	if abs, err := filepath.Abs(path); err == nil && !slices.ContainsFunc(st.Programs, func(p string) bool { return strings.EqualFold(p, abs) }) {
		fmt.Fprintf(os.Stderr, "warning: %s is not a confined program; add it with `manar-edge up %s --program %s`\n", abs, st.Name, abs)
	}
	cmd := exec.Command(path, command[1:]...)
	cmd.Env = agentEnv(os.Environ(), st.Edge.ProxyAddress)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signal.Ignore(os.Interrupt) // the child gets Ctrl+C from the console itself
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	return err
}

func jailExec([]string) error { return errors.New("not supported on Windows") }

func hookTransport(name string) (http.RoundTripper, string) {
	return pipeRoundTripper{pipe: pipeName(name), service: "manar-edge-gw-" + name}, "http://manar-edge-gateway"
}

// osPolicyConflicts finds the HKLM Claude Code policy and cached server-managed settings of local
// users, either of which Claude Code would apply instead of our file.
func osPolicyConflicts() []string {
	var out []string
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\ClaudeCode`, registry.QUERY_VALUE); err == nil {
		if _, _, err := k.GetValue("Settings", nil); err == nil {
			out = append(out, `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`)
		}
		k.Close()
	}
	m, _ := filepath.Glob(filepath.Join(os.Getenv("SystemDrive")+`\`, "Users", "*", ".claude", "remote-settings.json"))
	return append(out, m...)
}

// installedBinary returns a path under Program Files (writable by administrators only), copying
// the binary there when it runs from elsewhere: SYSTEM runs it as a service and the hook path
// must not be changeable by the agent.
func installedBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		return "", errors.New("ProgramFiles is not set")
	}
	if rel, err := filepath.Rel(pf, exe); err == nil && !strings.HasPrefix(rel, "..") {
		return exe, nil
	}
	dst := filepath.Join(pf, "manar-edge", "manar-edge.exe")
	if err := copyFile(exe, dst, 0o755); err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "installed %s as %s\n", exe, dst)
	return dst, nil
}

func isTerminal(f *os.File) bool {
	var m uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &m) == nil
}

// readSecret reads one line from the console with echo off.
func readSecret(f *os.File) (string, error) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return "", err
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return "", err
	}
	defer windows.SetConsoleMode(h, mode)
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return line, nil
}

type gatewayService struct{ base, agent string }

func (g *gatewayService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveGateway(ctx, g.base, g.agent) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
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

func runGatewayService(base, agent string) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isSvc {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return serveGateway(ctx, base, agent)
	}
	_, st, err := resolveAgent(base, agent)
	if err != nil {
		return err
	}
	return svc.Run(serviceName(st), &gatewayService{base: base, agent: agent})
}
