package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
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
	unitDir             = "/etc/systemd/system"
	homeBase            = "/var/lib/manar-edge-home"
	jailLink            = "manar0"
)

func nsName(st *State) string   { return "manar-" + st.Name }
func userName(st *State) string { return "manar-" + st.Name }
func unitName(st *State) string { return "manar-edge-gw@" + st.Name + ".service" }
func jailUnit(st *State) string { return "manar-edge-jail@" + st.Name + ".service" }
func homeDir(st *State) string  { return filepath.Join(homeBase, st.Name) }

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

func ensureUser(name, home string) (uid, gid int, err error) {
	if _, err := osuser.Lookup(name); err != nil {
		if err := sh("", "useradd", "--system", "--user-group", "--no-create-home",
			"--home-dir", home, "--shell", "/usr/sbin/nologin", name); err != nil {
			return 0, 0, err
		}
	}
	return lookupUser(name)
}

// ensureHome gives the agent a writable home outside the root-only state dir. A home left by an
// earlier user with another uid is never re-owned as root (a tree walk would race the old owner's
// symlinks and hard links): that uid's processes are killed, the old home is moved aside to
// <home>.stale-<time>, root 0700, for an administrator, and a fresh home is created.
func ensureHome(home string, uid, gid int) error {
	if err := os.MkdirAll(homeBase, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(homeBase, 0o755); err != nil {
		return err
	}
	if fi, err := os.Lstat(home); err == nil {
		old := int(fi.Sys().(*syscall.Stat_t).Uid)
		if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 && (old == uid || old == 0) {
			if err := os.Lchown(home, uid, gid); err != nil {
				return err
			}
			return os.Chmod(home, 0o700)
		}
		if old != 0 && old != uid {
			if err := killUser(old); err != nil {
				return err
			}
		}
		stale := fmt.Sprintf("%s.stale-%d", home, time.Now().UnixNano())
		if err := os.Rename(home, stale); err != nil {
			return err
		}
		if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
			if err := os.Lchown(stale, 0, 0); err != nil {
				return err
			}
			if err := os.Chmod(stale, 0o700); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stderr, "moved the previous home (uid %d) to %s\n", old, stale)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	if err := os.Lchown(home, uid, gid); err != nil {
		return err
	}
	return os.Chmod(home, 0o700)
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
ReadWritePaths=/run/manar-edge/%%i
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
# CAP_CHOWN only: the hook socket is handed to the agent's group (root:<group> 0660).
CapabilityBoundingSet=CAP_CHOWN
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

// jailUnitFile is the per-agent boot unit: it rebuilds the jail (`up --boot`) after a reboot,
// before the gateway unit starts.
func jailUnitFile(exe, base, name string) string {
	return fmt.Sprintf(`[Unit]
Description=Manar Edge jail (%%i)
Wants=network-online.target manar-edge-gw@%%i.service
After=network-online.target
Before=manar-edge-gw@%%i.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%q --state-dir %q up --boot %s
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
`, exe, base, name)
}

// installUnits writes the gateway template and the agent's boot unit and, when systemd is
// present, enables the boot unit. It reports whether systemctl was found.
func installUnits(exe, base string, st *State) (bool, error) {
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(unitDir, "manar-edge-gw@.service"), []byte(unitFile(exe, base)), 0o644); err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(unitDir, jailUnit(st)), []byte(jailUnitFile(exe, base, st.Name)), 0o644); err != nil {
		return false, err
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, nil
	}
	if err := sh("", "systemctl", "daemon-reload"); err != nil {
		return true, err
	}
	return true, sh("", "systemctl", "enable", jailUnit(st))
}

func cmdUp(base string, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	task := fs.String("task", "", "task id the local gateway injects")
	boot := fs.Bool("boot", false, "internal: rebuild the jail only (used by the boot unit)")
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
	if *boot {
		// systemd starts the gateway unit after this one; restarting it here would deadlock.
		return buildJail(dir, st)
	}
	if _, err := applyTask(dir, st, *task); err != nil {
		return err
	}
	exe, err := installedBinary() // root runs it from the units: must not be user-writable
	if err != nil {
		return err
	}
	if err := buildJail(dir, st); err != nil {
		return err
	}
	// 6. local gateway as a systemd unit in the netns, and the boot unit that rebuilds the jail.
	systemd, err := installUnits(exe, base, st)
	if err != nil {
		return err
	}
	if !systemd {
		fmt.Printf("%s: jail built and unit files written, but systemctl was not found, so the gateway is not started\n", st.Name)
		return nil
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

// jailNsswitch resolves names from files only, so no lookup reaches a host resolver service.
const jailNsswitch = `passwd: files
group: files
shadow: files
hosts: files
networks: files
protocols: files
services: files
ethers: files
rpc: files
`

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
	uid, gid, err := ensureUser(userName(st), homeDir(st))
	if err != nil {
		return err
	}
	if err := ensureHome(homeDir(st), uid, gid); err != nil {
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
	if err := os.WriteFile("/etc/netns/"+ns+"/nsswitch.conf", []byte(jailNsswitch), 0o644); err != nil {
		return err
	}
	// Directory for the gateway's hook socket: root-owned 0755, so the agent can connect to the
	// socket but cannot create or replace anything here.
	for _, d := range []string{runBase, sockDir(st.Name)} {
		if err := os.Mkdir(d, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := os.Lchown(d, 0, 0); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o755); err != nil {
			return err
		}
		if err := rootOnlyWritable(d, true); err != nil {
			return err
		}
	}
	// 4. nftables inside the netns.
	if err := sh(jailRuleset(targets), "ip", "netns", "exec", ns, "nft", "-f", "-"); err != nil {
		return err
	}
	return nil
}

func cmdDown(base, agent string, purge bool) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	_, st, err := resolveAgent(base, agent)
	if err != nil {
		return err
	}
	var errs []error
	_, noSystemd := exec.LookPath("systemctl")
	if noSystemd == nil {
		_ = sh("", "systemctl", "disable", jailUnit(st))
	}
	if err := os.Remove(filepath.Join(unitDir, jailUnit(st))); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	user := userName(st)
	uid, _, uerr := lookupUser(user)
	if uerr == nil {
		// Nothing else is removed while an agent process is alive: its uid stays in the drop set.
		if err := killUser(uid); err != nil {
			return fmt.Errorf("%w; the jail is left in place, run down again", err)
		}
	}
	if noSystemd == nil {
		_ = sh("", "systemctl", "stop", unitName(st))
		_ = sh("", "systemctl", "daemon-reload")
	}
	if _, err := os.Stat("/run/netns/" + nsName(st)); err == nil {
		if err := sh("", "ip", "netns", "del", nsName(st)); err != nil {
			errs = append(errs, err)
		}
	}
	for _, d := range []string{"/etc/netns/" + nsName(st), sockDir(st.Name)} {
		if err := os.RemoveAll(d); err != nil {
			errs = append(errs, err)
		}
	}
	if uerr == nil {
		_ = sh("", "nft", rootElement("delete", uid)...)
		if err := sh("", "userdel", user); err != nil {
			errs = append(errs, err)
		}
	}
	if purge {
		stale, _ := filepath.Glob(homeDir(st) + ".stale-*")
		for _, d := range append(stale, homeDir(st)) {
			if err := os.RemoveAll(d); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	fmt.Printf("%s is down\n", st.Name)
	return nil
}

// killUser SIGKILLs every process of uid until none is left, so a forking agent cannot outlive
// down. It gives up after about 5 s.
func killUser(uid int) error {
	for range 100 {
		pids := userPIDs(uid)
		if len(pids) == 0 {
			return nil
		}
		for _, p := range pids {
			_ = unix.Kill(p, unix.SIGKILL)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("processes of uid %d are still running", uid)
}

// userPIDs lists live processes with uid as any of their user ids (zombies hold nothing).
func userPIDs(uid int) []int {
	entries, _ := os.ReadDir("/proc")
	want := strconv.Itoa(uid)
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/status")
		if err != nil {
			continue
		}
		var match, zombie bool
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) > 1 {
				switch f[0] {
				case "State:":
					zombie = f[1] == "Z"
				case "Uid:":
					match = slices.Contains(f[1:], want)
				}
			}
		}
		if match && !zombie {
			pids = append(pids, pid)
		}
	}
	return pids
}

// verifyJail refuses to start an agent unless both nftables layers are in place.
func verifyJail(st *State, uid int) error {
	fix := "; run: manar-edge up " + st.Name
	out, err := exec.Command("ip", "netns", "exec", nsName(st), "nft", "list", "chain", "inet", "manar_jail", "output").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "policy drop") {
		return errors.New("the jail's nftables rules are missing" + fix)
	}
	out, err = exec.Command("nft", "list", "chain", "inet", "manar_edge", "output").CombinedOutput()
	if err != nil || !regexp.MustCompile(`meta skuid @agent_uids .*drop`).Match(out) {
		return errors.New("the root namespace drop rule is missing" + fix)
	}
	out, err = exec.Command("nft", "list", "set", "inet", "manar_edge", "agent_uids").CombinedOutput()
	if err != nil || !regexp.MustCompile(`\b`+strconv.Itoa(uid)+`\b`).Match(out) {
		return errors.New("the agent user is not in the root namespace drop set" + fix)
	}
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
	if err := ensureHome(homeDir(st), uid, gid); err != nil {
		return err
	}
	if err := verifyJail(st, uid); err != nil {
		return err
	}
	if err := rootOnlyWritable(sockDir(st.Name), true); err != nil {
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
		"HOME="+homeDir(st), "USER="+userName(st), "LOGNAME="+userName(st))

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
	// A new session always; on a terminal, a fresh pty becomes the agent's controlling terminal,
	// so it never holds root's terminal.
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, Setsid: true}
	var master, slave *os.File
	restore := func() {}
	if isTerminal(os.Stdin) {
		m, s, err := openPTY()
		if err != nil {
			return fmt.Errorf("pty: %w", err)
		}
		if err := s.Chown(uid, -1); err != nil {
			return err
		}
		copyWinsize(os.Stdin, m)
		master, slave = m, s
		cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s
		cmd.SysProcAttr.Setctty, cmd.SysProcAttr.Ctty = true, 0
	} else {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if slave != nil {
		slave.Close() // only the agent holds it now, so the master sees EOF when the agent exits
	}
	outDone := make(chan struct{})
	if master != nil {
		if old, err := makeRaw(int(os.Stdin.Fd())); err == nil {
			restore = func() { _ = unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, old) }
		}
		go func() { _, _ = io.Copy(master, os.Stdin) }()
		go func() { _, _ = io.Copy(os.Stdout, master); close(outDone) }()
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		go func() {
			for range winch {
				copyWinsize(os.Stdin, master)
			}
		}()
	} else {
		close(outDone)
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	select { // let the last output through the pty
	case <-outDone:
	case <-time.After(time.Second):
	}
	restore()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			os.Exit(128 + int(ws.Signal()))
		}
		os.Exit(ee.ExitCode())
	}
	return err
}

func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

// jailMounts runs in the private mount namespace of `run`:
//   - files in /etc/netns/<ns> (resolv.conf, nsswitch.conf) cover their /etc counterparts, as
//     `ip netns exec` does;
//   - fresh tmpfs over /run, /var/run, /tmp and /var/tmp, so host unix sockets (systemd-resolved,
//     D-Bus, nscd, Docker, X11) are out of reach: a local resolver would otherwise carry DNS out;
//   - only the gateway's hook socket directory is bound back in.
func jailMounts(ns, name string) error {
	dirFd, err := unix.Open(sockDir(name), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("gateway socket directory: %w", err)
	}
	defer unix.Close(dirFd)
	type file struct {
		path string
		data []byte
	}
	var recreate []file // targets that live under a directory replaced below
	entries, err := os.ReadDir("/etc/netns/" + ns)
	if err != nil {
		return err
	}
	for _, e := range entries {
		src, dst := filepath.Join("/etc/netns", ns, e.Name()), filepath.Join("/etc", e.Name())
		target := dst
		if link, err := os.Readlink(dst); err == nil { // resolv.conf is often a link into /run
			if !filepath.IsAbs(link) {
				link = filepath.Join(filepath.Dir(dst), link)
			}
			target = filepath.Clean(link)
		}
		if under(target, "/run") || under(target, "/var/run") || under(target, "/tmp") || under(target, "/var/tmp") {
			data, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			recreate = append(recreate, file{target, data})
			continue
		}
		if _, err := os.Stat(target); err != nil {
			continue
		}
		if err := unix.Mount(src, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", dst, err)
		}
	}
	for _, m := range []struct{ dir, mode string }{{"/run", "0755"}, {"/var/run", "0755"}, {"/tmp", "1777"}, {"/var/tmp", "1777"}} {
		if fi, err := os.Lstat(m.dir); err != nil || !fi.IsDir() {
			continue // /var/run is usually a link to /run
		}
		if err := unix.Mount("tmpfs", m.dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode="+m.mode); err != nil {
			return fmt.Errorf("tmpfs %s: %w", m.dir, err)
		}
	}
	if err := os.MkdirAll(sockDir(name), 0o755); err != nil {
		return err
	}
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", dirFd), sockDir(name), "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind gateway socket directory: %w", err)
	}
	for _, f := range recreate {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(f.path, f.data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// jailExec runs in the child started by cmdRun, as root inside the netns and a private mount
// namespace: it sets up the jail's view of the filesystem, drops to the agent user for good and
// execs.
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
	if err := jailMounts(ns, strings.TrimPrefix(ns, "manar-")); err != nil {
		return err
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
