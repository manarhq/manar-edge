//go:build jail && linux

package jail

// Needs root, cgroup v2 on the real hierarchy and the nft program. Run it in a throwaway
// privileged container (its own network namespace, so the host's rules are untouched):
//
//	scripts/test-jail-linux.sh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	switch os.Getenv("JAIL_HELPER") {
	case "sleep":
		time.Sleep(2 * time.Minute)
		return
	case "get":
		if d, err := time.ParseDuration(os.Getenv("JAIL_DELAY")); err == nil {
			time.Sleep(d) // let the filter find this process first
		}
		c, err := net.DialTimeout("tcp", os.Getenv("JAIL_ADDR"), 3*time.Second)
		if err != nil {
			fmt.Print("ERR: ", err)
			os.Exit(1)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", os.Getenv("JAIL_HOST"))
		b, _ := io.ReadAll(c)
		fmt.Print(string(b))
		return
	}
	os.Exit(m.Run())
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func localIP(t *testing.T) string {
	as, _ := net.InterfaceAddrs()
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			return n.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return ""
}

func cgroupOf(pid int) string {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	return strings.TrimSpace(string(b))
}

func helper(t *testing.T, bin string, uid int, env []string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)}}
	return cmd
}

func get(t *testing.T, bin string, uid int, addr, host string) string {
	return getAfter(t, bin, uid, addr, host, "0s")
}

func getAfter(t *testing.T, bin string, uid int, addr, host, delay string) string {
	out, _ := helper(t, bin, uid, []string{"JAIL_HELPER=get", "JAIL_ADDR=" + addr, "JAIL_HOST=" + host, "JAIL_DELAY=" + delay}).CombinedOutput()
	// the body, or the status line when there is none
	if _, body, ok := strings.Cut(string(out), "\r\n\r\n"); ok && body != "" {
		return body
	}
	return string(out)
}

func TestLinuxFilterEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if err := Supported(); err != nil {
		t.Skip(err)
	}
	ip := localIP(t)
	logs := &syncBuf{}
	log.SetOutput(logs)
	defer log.SetOutput(os.Stderr)

	ln, err := net.Listen("tcp", ip+":9000")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "hello %s", r.Host) }))

	dir, _ := os.MkdirTemp("", "jailtest")
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0o755)
	self, _ := os.ReadFile(os.Args[0])
	for _, n := range []string{"claude", "node", "other"} {
		if err := os.WriteFile(filepath.Join(dir, n), self, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bin := func(n string) string { return filepath.Join(dir, n) }
	sleepEnv := []string{"JAIL_HELPER=sleep"}
	start := func(uid int, name string, args ...string) *exec.Cmd {
		c := helper(t, bin(name), uid, sleepEnv, args...)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Process.Kill(); c.Wait() })
		return c
	}
	// Candidates, started before the filter goes up.
	userClaude := start(1000, "claude")
	userNodeClaude := start(1000, "node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js")
	userNodeOther := start(1000, "node", "/home/u/project/server.js")
	userOther := start(1000, "other")
	rootClaude := start(0, "claude")
	origCg := cgroupOf(userClaude.Process.Pid)

	pol := NewPolicy()
	pol.SetRules([]Rule{{Tool: claude, Site: "allowed.test", Mode: "ALLOW"}})
	ask := &fakeAsker{res: Result{Reason: "denied"}}
	e := newEnforcer()
	r := &runner{pf: e, policy: pol, asker: ask, running: map[string]*toolProxy{},
		resolve: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr(ip)}, nil }}
	tp, err := r.startProxy(claude)
	if err != nil {
		t.Fatal(err)
	}
	defer tp.close()
	if err := e.Apply(map[string]int{claude: tp.port}); err != nil {
		t.Fatal(err)
	}
	defer e.Teardown()

	wait := func(pid int, want bool) {
		for range 40 {
			if strings.Contains(cgroupOf(pid), cgParent+"/") == want {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("pid %d cgroup %q, in jail wanted %v", pid, cgroupOf(pid), want)
	}
	wait(userClaude.Process.Pid, true)
	wait(userNodeClaude.Process.Pid, true)
	for name, c := range map[string]*exec.Cmd{"node server.js": userNodeOther, "other": userOther, "root's claude": rootClaude} {
		if strings.Contains(cgroupOf(c.Process.Pid), cgParent) {
			t.Errorf("%s must not be filtered", name)
		}
	}

	// A firewall reload that flushes the ruleset must not leave the tools unfiltered: the next
	// Apply (every config poll) puts the table back.
	if out, err := exec.Command("nft", "delete", "table", "inet", nftTable).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := e.Apply(map[string]int{claude: tp.port}); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("nft", "list", "table", "inet", nftTable).Run(); err != nil {
		t.Fatal("table not restored after a flush")
	}

	addr := ip + ":9000"
	// The tool: an allowed site goes through the proxy, the destination really is that name's address.
	if out := getAfter(t, bin("claude"), 1000, addr, "allowed.test:9000", "1s"); out != "hello allowed.test:9000" {
		t.Fatalf("allowed: %q", out)
	}
	// A new site is asked about and refused here.
	if out := getAfter(t, bin("claude"), 1000, addr, "denied.test:9000", "1s"); !strings.Contains(out, "403") {
		t.Fatalf("denied: %q", out)
	}
	if ask.calls.Load() != 1 {
		t.Fatalf("asked %d", ask.calls.Load())
	}
	// A child of the tool is filtered too (it inherits the cgroup): run the "get" helper through a
	// process the tool started.
	// The user's own program and root's are not touched: no proxy involved, any Host works.
	proxied := strings.Count(logs.String(), "jail:")
	if out := get(t, bin("other"), 1000, addr, "denied.test:9000"); out != "hello denied.test:9000" {
		t.Fatalf("user program was filtered: %q", out)
	}
	if out := get(t, bin("other"), 0, addr, "denied.test:9000"); out != "hello denied.test:9000" {
		t.Fatalf("root program was filtered: %q", out)
	}
	if n := strings.Count(logs.String(), "jail:"); n != proxied {
		t.Fatalf("the proxy saw the user's traffic:\n%s", logs.String())
	}
	// Nothing but the proxy is reachable for the tool: a direct connect to another port is refused fast.
	other, _ := net.Listen("tcp", ip+":9001")
	defer other.Close()
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("direct"))
			c.Close()
		}
	}()
	if out := getAfter(t, bin("claude"), 1000, ip+":9001", "x", "1s"); strings.Contains(out, "direct") {
		t.Fatalf("a non-HTTP connect must go through the proxy and be asked about: %q", out)
	}

	// A crash leaves the rules; the next start (or `jail-restore`) removes them without any memory.
	e.mu.Lock()
	e.cancel()
	<-e.done
	e.mu.Unlock()
	if errs := Teardown(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if out, err := exec.Command("nft", "list", "table", "inet", nftTable).CombinedOutput(); err == nil {
		t.Fatalf("table still there: %s", out)
	}
	if _, err := os.Stat(filepath.Join(cgRoot, cgParent)); !os.IsNotExist(err) {
		t.Fatalf("cgroup still there: %v", err)
	}
	for _, c := range []*exec.Cmd{userClaude, userNodeClaude} {
		if cg := cgroupOf(c.Process.Pid); strings.Contains(cg, cgParent) {
			t.Fatalf("process left in the jail cgroup: %s", cg)
		}
	}
	_ = origCg
	before := strings.Count(logs.String(), "jail:")
	if out := get(t, bin("claude"), 1000, addr, "denied.test:9000"); out != "hello denied.test:9000" {
		t.Fatalf("networking not restored: %q", out)
	}
	if strings.Count(logs.String(), "jail:") != before {
		t.Fatal("traffic still went through the proxy after teardown")
	}
	// Teardown with nothing installed is fine.
	if errs := Teardown(); len(errs) > 0 {
		t.Fatal(errs)
	}
}

// TestWatchExec needs the host's network and pid namespaces (the proc connector only talks to the
// initial ones): scripts/test-jail-linux.sh runs it with --network host --pid host. It only listens.
func TestWatchExec(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("JAIL_HOSTNS") == "" {
		t.Skip("needs root and JAIL_HOSTNS=1")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan int, 64)
	errc := make(chan error, 1)
	go func() { errc <- watchExec(ctx, func(pid int) { got <- pid }) }()
	time.Sleep(500 * time.Millisecond)
	cmd := exec.Command("/bin/sleep", "0.1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case pid := <-got:
			if pid == cmd.Process.Pid {
				return
			}
		case err := <-errc:
			t.Fatalf("watcher ended: %v", err)
		case <-deadline:
			t.Fatal("no exec event for the child")
		}
	}
}

// If the cgroup match ever hit everything, the user's network would break. Apply must notice with
// its self-test and take its own rules out again.
func TestSelfTestRemovesRulesThatHitEveryone(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if err := Supported(); err != nil {
		t.Skip(err)
	}
	localIP(t)
	rulesetFor = func(ports map[string]int) string {
		return "table inet " + nftTable + "\ndelete table inet " + nftTable + "\ntable inet " + nftTable + " {\n" +
			"\tchain x {\n\t\ttype nat hook output priority -100; policy accept;\n\t\tmeta l4proto tcp redirect to :1\n\t}\n}\n"
	}
	defer func() { rulesetFor = Ruleset }()
	e := newEnforcer()
	err := e.Apply(map[string]int{claude: 1})
	defer e.Teardown()
	if err == nil || !strings.Contains(err.Error(), "self-test") {
		t.Fatalf("a ruleset that hits everyone was kept: %v", err)
	}
	if err := exec.Command("nft", "list", "table", "inet", nftTable).Run(); err == nil {
		t.Fatal("the bad table is still installed")
	}
}
