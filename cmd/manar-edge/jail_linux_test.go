//go:build jail

package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestJail builds a real jail (needs root, iproute2, nftables and the wireguard module), checks
// what the agent can and cannot do, and tears it down. Run with: sudo -E go test -tags jail ./...
func TestJail(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	base := t.TempDir()
	if err := secureMkdir(base); err != nil {
		t.Fatal(err)
	}
	st := &State{Name: edgeName("jt", "agent"), TenantSlug: "jt", AgentSlug: "agent", Edge: testEdge}
	gw, _ := wgtypes.GeneratePrivateKey()
	key, _ := wgtypes.GeneratePrivateKey()
	st.Edge.GatewayPublicKey = gw.PublicKey().String()
	st.Edge.GatewayEndpoint = "127.0.0.1:51820"
	dir := agentDir(base, st.Name)
	if err := secureMkdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(filepath.Join(dir, fileWGKey), []byte(key.String())); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(filepath.Join(dir, fileKey), []byte("not a real key")); err != nil {
		t.Fatal(err)
	}
	if err := saveState(dir, st); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmdDown(base, st.Name, true) })

	for i := range 2 { // idempotent
		if err := buildJail(dir, st); err != nil {
			t.Fatalf("buildJail #%d: %v", i+1, err)
		}
	}
	uid, gid, err := lookupUser(userName(st))
	if err != nil {
		t.Fatal(err)
	}
	checkHome := func(uid int) {
		t.Helper()
		fi, err := os.Stat(homeDir(st))
		if err != nil || fi.Mode().Perm() != 0o700 || int(fi.Sys().(*syscall.Stat_t).Uid) != uid {
			t.Fatalf("home: %v %v", fi, err)
		}
	}
	checkHome(uid)
	if err := rootOnlyWritable(sockDir(st.Name), true); err != nil {
		t.Fatal(err)
	}

	// Units: written twice (idempotent); without systemd, enablement is skipped.
	for range 2 {
		if _, err := installUnits("/usr/local/bin/manar-edge", base, st); err != nil {
			t.Fatalf("installUnits: %v", err)
		}
	}
	unit, err := os.ReadFile(filepath.Join(unitDir, jailUnit(st)))
	if err != nil || !strings.Contains(string(unit), "up --boot "+st.Name) || !strings.Contains(string(unit), "Before=manar-edge-gw@%i.service") {
		t.Fatalf("jail unit: %v %s", err, unit)
	}
	if gwUnit, err := os.ReadFile(filepath.Join(unitDir, "manar-edge-gw@.service")); err != nil || !strings.Contains(string(gwUnit), "ReadWritePaths=/run/manar-edge/%i") {
		t.Fatalf("gateway unit: %v", err)
	}

	out, err := exec.Command("ip", "netns", "exec", nsName(st), "nft", "list", "table", "inet", "manar_jail").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "policy drop") {
		t.Fatalf("netns ruleset: %v %s", err, out)
	}
	if err := verifyJail(st, uid); err != nil {
		t.Fatal(err)
	}

	// Inside the netns, anything but the overlay endpoints is refused.
	if c, err := nsDial(nsName(st), "1.1.1.1:443", 2*time.Second); err == nil {
		c.Close()
		t.Fatal("jail reached 1.1.1.1")
	}

	// In the root namespace, the agent user's sockets are dropped, loopback included.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	// nftables drops silently, so a blocked connect hangs; a working one returns at once.
	cmd := exec.Command("timeout", "5", "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/"+port)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if err := cmd.Run(); err == nil {
		t.Fatal("agent user connected in the root namespace")
	}

	// The real binary, where the agent user can run it.
	built := filepath.Join(t.TempDir(), "manar-edge")
	if out, err := exec.Command("go", "build", "-o", built, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	bin := "/usr/local/bin/manar-edge-jailtest"
	if err := copyFile(built, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(bin) })
	run := func(stdin string, args ...string) (string, error) {
		c := exec.Command(bin, append([]string{"--state-dir", base, "run", st.Name, "--"}, args...)...)
		c.Dir = "/"
		c.Stdin = strings.NewReader(stdin)
		b, err := c.CombinedOutput()
		return strings.TrimSpace(string(b)), err
	}
	expect := func(want string, args ...string) {
		t.Helper()
		if got, err := run("", args...); err != nil || got != want {
			t.Errorf("%v: got %q (%v), want %q", args, got, err, want)
		}
	}
	expect(strconv.Itoa(uid), "id", "-u")
	expect(strconv.Itoa(gid), "id", "-G")
	expect("NoNewPrivs:\t1", "grep", "NoNewPrivs", "/proc/self/status")
	expect("nameserver 127.0.0.1", "cat", "/etc/resolv.conf")
	expect("hosts: files", "grep", "^hosts:", "/etc/nsswitch.conf")
	expect(homeDir(st), "sh", "-c", "touch $HOME/.written && echo $HOME")
	expect("http://127.0.0.1:8480 http://100.88.0.1:3128", "sh", "-c", "echo $ANTHROPIC_BASE_URL $HTTPS_PROXY")
	// On a terminal the agent gets its own pty, owned by the agent user, as controlling terminal.
	if _, err := exec.LookPath("script"); err == nil {
		c := exec.Command("script", "-qec", bin+" --state-dir "+base+" run "+st.Name+" -- sh -c 'stat -c %U $(tty)'", "/dev/null")
		if b, err := c.CombinedOutput(); err != nil || !strings.Contains(string(b), userName(st)) {
			t.Errorf("pty: %q %v", b, err)
		}
	} else {
		t.Log("script(1) missing: pty path not exercised")
	}
	if got, err := run("", "cat", filepath.Join(dir, fileKey)); err == nil {
		t.Errorf("agent read the key: %q", got)
	}
	if _, err := run("", "timeout", "5", "bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/443"); err == nil {
		t.Error("run reached 1.1.1.1")
	}
	if _, err := run("", "false"); err == nil {
		t.Error("exit code not propagated")
	}
	// Host unix sockets under /run are out of reach; only the gateway socket directory is there.
	sentinel, err := net.Listen("unix", "/run/manar-jailtest.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer sentinel.Close()
	if _, err := run("", "test", "-e", "/run/manar-jailtest.sock"); err == nil {
		t.Error("host /run socket visible in the jail")
	}
	if _, err := run("", "touch", sockDir(st.Name)+"/x"); err == nil {
		t.Error("agent created a file in the gateway socket directory")
	}

	// The hook, run by the agent inside the jail, reaches a root-served gateway on the socket.
	pki := newTestPKI(t)
	var decision atomic.Value
	decision.Store(`{"decision":"ALLOW"}`)
	manar := newTestManar(t, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(decision.Load().(string)))
	}))
	hl, err := hookListener(st)
	if err != nil {
		t.Fatal(err)
	}
	defer hl.Close()
	g := &localGateway{host: testServerName, task: "t1", agent: st.Name,
		transport: newMTLSTransport(pki.clientCert, pki.roots, testServerName, strings.TrimPrefix(manar.URL, "https://"))}
	go http.Serve(hl, g.handler())
	hook := func() string {
		got, err := run(bashInput, bin, "hook", "claude-code", st.Name)
		if err != nil {
			t.Errorf("hook exit: %v %s", err, got)
		}
		return got
	}
	if got := hook(); !strings.Contains(got, `"permissionDecision":"allow"`) {
		t.Errorf("hook through the socket: %s", got)
	}
	decision.Store(`{"decision":"DENY","reason":"policy"}`)
	if got := hook(); !strings.Contains(got, `"permissionDecision":"deny"`) {
		t.Errorf("deny: %s", got)
	}
	hl.Close() // gateway gone: the hook denies
	if got := hook(); !strings.Contains(got, `"permissionDecision":"deny"`) {
		t.Errorf("gateway down: %s", got)
	}

	// run refuses to start when the root namespace drop is missing.
	if err := sh("", "nft", rootElement("delete", uid)...); err != nil {
		t.Fatal(err)
	}
	if got, err := run("", "true"); err == nil || !strings.Contains(got, "drop set") {
		t.Errorf("run without the uid in the drop set: %q %v", got, err)
	}
	if err := sh("", "nft", rootElement("add", uid)...); err != nil {
		t.Fatal(err)
	}

	// down kills a forking agent before it removes anything.
	forker := exec.Command(bin, "--state-dir", base, "run", st.Name, "--", "sh", "-c", "while :; do sleep 30 & sleep 0.02; done")
	if err := forker.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if len(userPIDs(uid)) == 0 {
		t.Fatal("forker not running")
	}
	if err := cmdDown(base, st.Name, false); err != nil {
		t.Fatalf("down: %v", err)
	}
	_ = forker.Wait()
	if pids := userPIDs(uid); len(pids) > 0 {
		t.Errorf("agent processes survived down: %v", pids)
	}
	if _, err := os.Stat("/run/netns/" + nsName(st)); err == nil {
		t.Error("netns left after down")
	}
	if _, _, err := lookupUser(userName(st)); err == nil {
		t.Error("user left after down")
	}
	if _, err := os.Stat(filepath.Join(unitDir, jailUnit(st))); err == nil {
		t.Error("jail unit left after down")
	}
	if _, err := os.Stat(sockDir(st.Name)); err == nil {
		t.Error("socket directory left after down")
	}
	out, _ = exec.Command("nft", "list", "set", "inet", "manar_edge", "agent_uids").CombinedOutput()
	if strings.Contains(string(out), strconv.Itoa(uid)) {
		t.Error("uid left in the root set after down")
	}
	if _, err := os.Stat(filepath.Join(homeDir(st), ".written")); err != nil {
		t.Error("down without --purge removed the home")
	}

	// Up again with the home owned by a stale uid: its files are handed over, a root file is not.
	for _, p := range []string{homeDir(st), filepath.Join(homeDir(st), ".written")} {
		if err := os.Lchown(p, 4242, 4242); err != nil {
			t.Fatal(err)
		}
	}
	rootFile := filepath.Join(homeDir(st), "rootfile")
	if err := os.WriteFile(rootFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := buildJail(dir, st); err != nil {
		t.Fatal(err)
	}
	uid2, _, _ := lookupUser(userName(st))
	checkHome(uid2)
	if fi, err := os.Stat(filepath.Join(homeDir(st), ".written")); err != nil || int(fi.Sys().(*syscall.Stat_t).Uid) != uid2 {
		t.Errorf("home file not handed over: %v", err)
	}
	if fi, err := os.Stat(rootFile); err != nil || fi.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Errorf("root-owned file in the home was chowned: %v", err)
	}
	if err := cmdDown(base, st.Name, true); err != nil {
		t.Fatalf("down --purge: %v", err)
	}
	if _, err := os.Stat(homeDir(st)); err == nil {
		t.Error("down --purge left the home")
	}
}
