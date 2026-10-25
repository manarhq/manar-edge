//go:build jail

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	t.Cleanup(func() { _ = cmdDown(base, st.Name) })

	for i := range 2 { // idempotent
		if err := buildJail(dir, st); err != nil {
			t.Fatalf("buildJail #%d: %v", i+1, err)
		}
	}
	uid, gid, err := lookupUser(userName(st))
	if err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("ip", "netns", "exec", nsName(st), "nft", "list", "table", "inet", "manar_jail").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "policy drop") {
		t.Fatalf("netns ruleset: %v %s", err, out)
	}
	out, err = exec.Command("nft", "list", "set", "inet", "manar_edge", "agent_uids").CombinedOutput()
	if err != nil || !strings.Contains(string(out), strconv.Itoa(uid)) {
		t.Fatalf("root set: %v %s", err, out)
	}

	// Inside the netns, anything but the overlay endpoints is refused at once by nftables.
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

	// `run` through the real binary.
	bin := filepath.Join(t.TempDir(), "manar-edge")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	run := func(args ...string) (string, error) {
		c := exec.Command(bin, append([]string{"--state-dir", base, "run", st.Name, "--"}, args...)...)
		c.Dir = "/"
		b, err := c.CombinedOutput()
		return strings.TrimSpace(string(b)), err
	}
	if got, err := run("id", "-u"); err != nil || got != strconv.Itoa(uid) {
		t.Errorf("uid: %q %v", got, err)
	}
	if got, err := run("id", "-G"); err != nil || got != strconv.Itoa(gid) {
		t.Errorf("groups: %q %v", got, err)
	}
	if got, err := run("grep", "NoNewPrivs", "/proc/self/status"); err != nil || !strings.HasSuffix(got, "1") {
		t.Errorf("no_new_privs: %q %v", got, err)
	}
	if got, err := run("cat", "/etc/resolv.conf"); err != nil || got != "nameserver 127.0.0.1" {
		t.Errorf("resolv.conf: %q %v", got, err)
	}
	if got, err := run("cat", filepath.Join(dir, fileKey)); err == nil {
		t.Errorf("agent read the key: %q", got)
	}
	if got, err := run("sh", "-c", "echo $ANTHROPIC_BASE_URL $HTTPS_PROXY"); err != nil || got != "http://127.0.0.1:8480 http://100.88.0.1:3128" {
		t.Errorf("env: %q %v", got, err)
	}
	if _, err := run("timeout", "5", "bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/443"); err == nil {
		t.Error("run reached 1.1.1.1")
	}
	if _, err := run("false"); err == nil {
		t.Error("exit code not propagated")
	}

	if err := cmdDown(base, st.Name); err != nil && !strings.Contains(err.Error(), "systemctl") {
		t.Fatalf("down: %v", err)
	}
	if _, err := os.Stat("/run/netns/" + nsName(st)); err == nil {
		t.Error("netns left after down")
	}
	if _, _, err := lookupUser(userName(st)); err == nil {
		t.Error("user left after down")
	}
	out, _ = exec.Command("nft", "list", "set", "inet", "manar_edge", "agent_uids").CombinedOutput()
	if strings.Contains(string(out), strconv.Itoa(uid)) {
		t.Error("uid left in the root set after down")
	}
}
