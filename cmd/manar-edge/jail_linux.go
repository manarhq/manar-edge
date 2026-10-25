package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultStateBase    = "/var/lib/manar-edge"
	upUsageExtra        = ""
	managedSettingsPath = "/etc/claude-code/managed-settings.json"
	unitPath            = "/etc/systemd/system/manar-edge-gw@.service"
	jailLink            = "manar0"
)

func nsName(st *State) string   { return "manar-" + st.Name }
func userName(st *State) string { return "manar-" + st.Name }
func unitName(st *State) string { return "manar-edge-gw@" + st.Name + ".service" }

func requireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("this command must run as root")
	}
	return nil
}

func secureMkdir(p string) error {
	if err := os.MkdirAll(p, 0o700); err != nil {
		return err
	}
	if err := os.Chown(p, 0, 0); err != nil {
		return err
	}
	return os.Chmod(p, 0o700)
}

// sh runs a command; its output is returned in the error only (no secrets go on these command lines).
func sh(stdin string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func ensureUser(name string) (uid, gid int, err error) {
	if _, err := osuser.Lookup(name); err != nil {
		if err := sh("", "useradd", "--system", "--user-group", "--no-create-home",
			"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", name); err != nil {
			return 0, 0, err
		}
	}
	return lookupUser(name)
}

func lookupUser(name string) (uid, gid int, err error) {
	u, err := osuser.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err := errors.Join(err1, err2); err != nil {
		return 0, 0, err
	}
	if uid == 0 || gid == 0 {
		return 0, 0, fmt.Errorf("user %s maps to root", name)
	}
	return uid, gid, nil
}

func wgDeviceConfig(dir string, st *State) (wgtypes.Config, error) {
	raw, err := os.ReadFile(filepath.Join(dir, fileWGKey))
	if err != nil {
		return wgtypes.Config{}, err
	}
	priv, err := wgtypes.ParseKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return wgtypes.Config{}, errors.New("wg.key in the state dir is not a WireGuard key")
	}
	pub, err := wgtypes.ParseKey(st.Edge.GatewayPublicKey)
	if err != nil {
		return wgtypes.Config{}, err
	}
	ep, err := net.ResolveUDPAddr("udp", st.Edge.GatewayEndpoint)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("gateway endpoint %s: %w", st.Edge.GatewayEndpoint, err)
	}
	targets, err := overlayTargets(st.Edge)
	if err != nil {
		return wgtypes.Config{}, err
	}
	var allowed []net.IPNet
	for _, t := range targets {
		allowed = append(allowed, net.IPNet{IP: t.Addr().AsSlice(), Mask: net.CIDRMask(32, 32)})
	}
	keepalive := time.Duration(st.Edge.KeepaliveSeconds) * time.Second
	return wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey: pub, Endpoint: ep, AllowedIPs: allowed, ReplaceAllowedIPs: true,
			PersistentKeepaliveInterval: &keepalive,
		}},
	}, nil
}

func configureWG(dev string, cfg wgtypes.Config) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ConfigureDevice(dev, cfg)
}

// inNetns runs fn on an OS thread switched into the named netns. The thread stays locked and
// is discarded when the goroutine ends, so no other goroutine ever runs in that namespace.
// Sockets fn creates stay in the netns after it returns.
func inNetns(ns string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		f, err := os.Open("/run/netns/" + ns)
		if err != nil {
			errc <- err
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("setns %s: %w", ns, err)
			return
		}
		errc <- fn()
	}()
	return <-errc
}

func nsDial(ns, addr string, timeout time.Duration) (net.Conn, error) {
	var c net.Conn
	err := inNetns(ns, func() (err error) {
		c, err = net.DialTimeout("tcp", addr, timeout)
		return err
	})
	return c, err
}

// gatewayHealth checks the local gateway inside the netns.
func gatewayHealth(st *State) error {
	conn, err := nsDial(nsName(st), gatewayListen, 2*time.Second)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }, DisableKeepAlives: true,
	}}
	res, err := c.Get(gatewayURL + "/healthz")
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
	return fmt.Errorf("local gateway did not become healthy: %w (journalctl -u %s)", err, unitName(st))
}

func unitFile(exe, base string) string {
	return fmt.Sprintf(`[Unit]
Description=Manar Edge local gateway (%%i)
After=network.target

[Service]
Type=simple
ExecStart=%q --state-dir %q gateway %%i
NetworkNamespacePath=/run/netns/manar-%%i
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
`, exe, base)
}

func cmdUp(base string, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	task := fs.String("task", "", "task id the local gateway injects")
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
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if err := buildJail(dir, st); err != nil {
		return err
	}
	// 6. local gateway as a systemd unit in the netns.
	if err := os.WriteFile(unitPath, []byte(unitFile(exe, base)), 0o644); err != nil {
		return err
	}
	if err := sh("", "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := sh("", "systemctl", "restart", unitName(st)); err != nil {
		return err
	}
	if err := waitGateway(st); err != nil {
		return err
	}
	fmt.Printf("%s is up: netns %s, user %s, overlay %s, task %q\n", st.Name, nsName(st), userName(st), st.Edge.Address, st.Task)
	if st.Task == "" {
		fmt.Println("no task set: LLM and MCP calls get 412 until `manar-edge up " + st.Name + " --task <taskId>`")
	}
	return nil
}

// buildJail does steps 1 to 5 of the contract: user, root-namespace drop, netns, WireGuard link,
// addressing, resolv.conf and the netns nftables. It is idempotent.
func buildJail(dir string, st *State) error {
	targets, err := overlayTargets(st.Edge)
	if err != nil {
		return err
	}
	cfg, err := wgDeviceConfig(dir, st)
	if err != nil {
		return err
	}
	ns := nsName(st)

	// 1. system user, and at once the root-namespace drop for its sockets.
	uid, _, err := ensureUser(userName(st))
	if err != nil {
		return err
	}
	if sh("", "nft", "list", "table", "inet", "manar_edge") != nil {
		if err := sh(rootRuleset, "nft", "-f", "-"); err != nil {
			return err
		}
	}
	if err := sh("", "nft", rootElement("add", uid)...); err != nil {
		return err
	}

	// 2. netns, and a fresh WireGuard link created in the root namespace then moved in.
	if _, err := os.Stat("/run/netns/" + ns); err != nil {
		if err := sh("", "ip", "netns", "add", ns); err != nil {
			return err
		}
	}
	_ = sh("", "ip", "-n", ns, "link", "del", jailLink)
	sum := sha256.Sum256([]byte(st.Name))
	tmp := "mt-" + hex.EncodeToString(sum[:4])
	_ = sh("", "ip", "link", "del", tmp)
	if err := sh("", "ip", "link", "add", tmp, "type", "wireguard"); err != nil {
		return fmt.Errorf("%w (is the wireguard kernel module available?)", err)
	}
	if err := configureWG(tmp, cfg); err != nil {
		_ = sh("", "ip", "link", "del", tmp)
		return fmt.Errorf("configure WireGuard: %w", err)
	}
	if err := sh("", "ip", "link", "set", tmp, "netns", ns); err != nil {
		_ = sh("", "ip", "link", "del", tmp)
		return err
	}
	// 3. addressing inside the netns; no DNS.
	for _, a := range [][]string{
		{"-n", ns, "link", "set", tmp, "name", jailLink},
		{"-n", ns, "addr", "add", st.Edge.Address, "dev", jailLink},
		{"-n", ns, "link", "set", "lo", "up"},
		{"-n", ns, "link", "set", jailLink, "up"},
		{"-n", ns, "route", "replace", "default", "dev", jailLink},
	} {
		if err := sh("", "ip", a...); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/etc/netns/"+ns, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/netns/"+ns+"/resolv.conf", []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		return err
	}
	// 4. nftables inside the netns.
	if err := sh(jailRuleset(targets), "ip", "netns", "exec", ns, "nft", "-f", "-"); err != nil {
		return err
	}
	return nil
}

func cmdDown(base, agent string) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	_, st, err := resolveAgent(base, agent)
	if err != nil {
		return err
	}
	var errs []error
	user := userName(st)
	uid, _, uerr := lookupUser(user)
	if uerr == nil {
		// pkill exits 1 when nothing matched.
		if err := exec.Command("pkill", "-KILL", "-u", user).Run(); err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 1 {
				errs = append(errs, fmt.Errorf("pkill: %w", err))
			}
		}
	}
	_ = sh("", "systemctl", "stop", unitName(st))
	if _, err := os.Stat("/run/netns/" + nsName(st)); err == nil {
		if err := sh("", "ip", "netns", "del", nsName(st)); err != nil {
			errs = append(errs, err)
		}
	}
	if err := os.RemoveAll("/etc/netns/" + nsName(st)); err != nil {
		errs = append(errs, err)
	}
	if uerr == nil {
		_ = sh("", "nft", rootElement("delete", uid)...)
		if err := sh("", "userdel", user); err != nil {
			errs = append(errs, err)
		}
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
		printStatus(st)
	}
	return nil
}

func printStatus(st *State) {
	ns := nsName(st)
	fmt.Printf("%s (%s/%s) overlay %s task %q\n", st.Name, st.TenantSlug, st.AgentSlug, st.Edge.Address, st.Task)
	if _, err := os.Stat("/run/netns/" + ns); err != nil {
		fmt.Println("  jail: down")
		return
	}
	fmt.Println("  jail: netns", ns)
	var hs time.Time
	err := inNetns(ns, func() error {
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer c.Close()
		d, err := c.Device(jailLink)
		if err != nil {
			return err
		}
		if len(d.Peers) > 0 {
			hs = d.Peers[0].LastHandshakeTime
		}
		return nil
	})
	switch {
	case err != nil:
		fmt.Println("  handshake: unknown:", err)
	case hs.IsZero():
		fmt.Println("  handshake: never")
	default:
		fmt.Println("  handshake:", time.Since(hs).Round(time.Second), "ago")
	}
	if c, err := nsDial(ns, st.Edge.ManarAddress, 3*time.Second); err == nil {
		c.Close()
		fmt.Println("  manar through the tunnel: reachable (peer active)")
	} else {
		fmt.Println("  manar through the tunnel: unreachable (peer cut or gateway down)")
	}
	if err := gatewayHealth(st); err == nil {
		fmt.Println("  local gateway: healthy")
	} else {
		fmt.Println("  local gateway: down:", err)
	}
}

func runGatewayService(base, agent string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	return serveGateway(ctx, base, agent)
}

// splitCommand splits `run` arguments at "--".
func splitCommand(args []string) (before, command []string, err error) {
	for i, a := range args {
		if a == "--" {
			if i == len(args)-1 {
				break
			}
			return args[:i], args[i+1:], nil
		}
	}
	return nil, nil, errors.New("usage: manar-edge run <agent> [--task <taskId>] -- <command> [args...]")
}

func cmdRun(base string, args []string) error {
	before, command, err := splitCommand(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	task := fs.String("task", "", "task id (restarts the local gateway when it changes)")
	agent, err := parseAgentFlags(fs, before)
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
	ns := nsName(st)
	if _, err := os.Stat("/run/netns/" + ns); err != nil {
		return fmt.Errorf("the jail for %s is not up: manar-edge up %s", st.Name, st.Name)
	}
	changed, err := applyTask(dir, st, *task)
	if err != nil {
		return err
	}
	if changed {
		if err := sh("", "systemctl", "restart", unitName(st)); err != nil {
			return err
		}
		if err := waitGateway(st); err != nil {
			return err
		}
	}
	uid, gid, err := lookupUser(userName(st))
	if err != nil {
		return err
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	env := setEnv(agentEnv(os.Environ(), st.Edge.ProxyAddress),
		"HOME=/nonexistent", "USER="+userName(st), "LOGNAME="+userName(st))

	// The child starts from this thread, so it inherits the netns; Unshareflags gives it a private
	// mount namespace (Go remounts / private) for the resolv.conf bind mount.
	runtime.LockOSThread()
	f, err := os.Open("/run/netns/" + ns)
	if err != nil {
		return err
	}
	if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
		f.Close()
		return fmt.Errorf("setns: %w", err)
	}
	f.Close()
	cmd := exec.Command(exe, append([]string{"__jail-exec", ns, strconv.Itoa(uid), strconv.Itoa(gid), path}, command...)...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS}
	if err := cmd.Start(); err != nil {
		return err
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			os.Exit(128 + int(ws.Signal()))
		}
		os.Exit(ee.ExitCode())
	}
	return err
}

// jailExec runs in the child started by cmdRun, as root inside the netns and a private mount
// namespace: it points DNS at the netns resolv.conf, drops to the agent user for good and execs.
func jailExec(args []string) error {
	if len(args) < 5 {
		return errors.New("internal: bad __jail-exec arguments")
	}
	runtime.LockOSThread()
	ns, path, argv := args[0], args[3], args[4:]
	uid, err1 := strconv.Atoi(args[1])
	gid, err2 := strconv.Atoi(args[2])
	if err := errors.Join(err1, err2); err != nil || uid == 0 || gid == 0 {
		return errors.New("internal: bad uid or gid")
	}
	if err := unix.Mount("/etc/netns/"+ns+"/resolv.conf", "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind resolv.conf: %w", err)
	}
	if err := unix.Setgroups(nil); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := unix.Setresgid(gid, gid, gid); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := unix.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if unix.Setuid(0) == nil || os.Geteuid() != uid || os.Getegid() != gid {
		return errors.New("privilege drop did not hold")
	}
	if groups, err := unix.Getgroups(); err != nil || len(groups) > 0 {
		return errors.New("supplementary groups still present")
	}
	return unix.Exec(path, argv, os.Environ())
}
