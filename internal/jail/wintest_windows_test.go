//go:build jailwin

package jail

// Runs on a real Windows machine, as an administrator or SYSTEM. It installs the real Windows
// Filtering Platform filters for a copy of this test binary named claude.exe in a throwaway
// profile, and removes them again. It does not touch any real account.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/discovery"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
	"gitlab.vax.sh/manar/manar-edge/internal/protect"
)

func TestMain(m *testing.M) {
	switch os.Getenv("JAILWIN_HELPER") {
	case "dial":
		c, err := net.DialTimeout("tcp", os.Getenv("JAILWIN_ADDR"), 3*time.Second)
		if err != nil {
			fmt.Print("BLOCKED ", err)
			os.Exit(1)
		}
		c.Close()
		fmt.Print("CONNECTED")
		return
	case "connect": // an HTTP CONNECT through the proxy, then one line through the tunnel
		c, err := net.DialTimeout("tcp", os.Getenv("JAILWIN_PROXY"), 3*time.Second)
		if err != nil {
			fmt.Print("PROXY-DOWN ", err)
			os.Exit(1)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(8 * time.Second))
		t := os.Getenv("JAILWIN_TARGET")
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", t, t)
		br := bufio.NewReader(c)
		res, err := http.ReadResponse(br, nil)
		if err != nil {
			fmt.Print("ERR ", err)
			os.Exit(1)
		}
		if res.StatusCode != 200 {
			fmt.Print("REFUSED ", res.StatusCode, " ", res.Header.Get("X-Manar-Reason"))
			os.Exit(1)
		}
		io.WriteString(c, "ping\n")
		line, _ := br.ReadString('\n')
		fmt.Print("TUNNEL ", strings.TrimSpace(line))
		return
	}
	os.Exit(m.Run())
}

func run(t *testing.T, exe string, env ...string) string {
	t.Helper()
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run()
	return out.String()
}

func nonLoopback(t *testing.T) string {
	as, _ := net.InterfaceAddrs()
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	t.Skip("no non-loopback address")
	return ""
}

func wfpDump(t *testing.T) string {
	f := filepath.Join(t.TempDir(), "f.xml")
	if out, err := exec.Command("netsh", "wfp", "show", "filters", "file="+f).CombinedOutput(); err != nil {
		t.Fatalf("netsh: %v %s", err, out)
	}
	b, _ := os.ReadFile(f)
	return string(b)
}

func TestWindowsFilterEndToEnd(t *testing.T) {
	ip := nonLoopback(t)
	root, _ := os.MkdirTemp(`C:\`, "jailwin")
	defer os.RemoveAll(root)
	protect.Configure(filepath.Join(root, "state"))
	self, _ := os.ReadFile(os.Args[0])
	home := filepath.Join(root, "home", "sam")
	claudeExe := filepath.Join(home, ".local", "bin", "claude.exe")
	otherExe := filepath.Join(root, "other.exe")
	for _, p := range []string{claudeExe, otherExe, filepath.Join(home, ".claude", "x")} {
		os.MkdirAll(filepath.Dir(p), 0o755)
	}
	os.WriteFile(claudeExe, self, 0o755)
	os.WriteFile(otherExe, self, 0o755)
	settings := filepath.Join(home, ".claude", "settings.json")
	orig := `{"model":"opus","env":{"FOO":"bar"}}`
	os.WriteFile(settings, []byte(orig), 0o644)

	// A site on this machine's own (non-loopback) address that echoes a line.
	site, err := net.Listen("tcp4", ip+":9000")
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	go func() {
		for {
			c, err := site.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); b, _ := bufio.NewReader(c).ReadString('\n'); io.WriteString(c, b) }()
		}
	}()
	direct := func(exe string) string { return run(t, exe, "JAILWIN_HELPER=dial", "JAILWIN_ADDR="+ip+":9000") }
	viaProxy := func(target string) string {
		return run(t, claudeExe, "JAILWIN_HELPER=connect", "JAILWIN_PROXY=127.0.0.1:8491", "JAILWIN_TARGET="+target)
	}

	if got := direct(claudeExe); got != "CONNECTED" {
		t.Fatalf("before the filter claude.exe must connect: %q", got)
	}

	pol := NewPolicy()
	pol.SetRules([]Rule{{Tool: claude, Site: "allowed.test", Mode: "ALLOW"}})
	ask := &fakeAsker{res: Result{Reason: "denied"}}
	pf := &winPlatform{
		users:   func() []discovery.User { return []discovery.User{{Name: "sam", Home: home, UID: -1, GID: -1}} },
		running: func() []string { return nil },
	}
	r := &runner{pf: pf, policy: pol, asker: ask, running: map[string]*toolProxy{},
		resolve: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr(ip)}, nil }}
	cfg := &hostclient.Config{Status: "APPROVED", Jail: hostclient.JailConfig{Enabled: true, Windows: true, Tools: []string{claude, "host.codex-cli"}}}
	r.reconcile(cfg)
	defer r.stop()
	if len(r.running) != 1 || r.running[claude] == nil {
		t.Fatalf("proxy not running: %v", r.running)
	}

	// 1. the settings file got the proxy, other settings kept
	b, _ := os.ReadFile(settings)
	for _, want := range []string{`"HTTPS_PROXY": "http://127.0.0.1:8491"`, `"NO_PROXY": "localhost,127.0.0.1"`, `"FOO": "bar"`, `"model": "opus"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("settings lack %s:\n%s", want, b)
		}
	}
	// 2. the filters exist under the Manar sublayer
	n, err := wfpFilterCount()
	if err != nil || n != 6 {
		t.Fatalf("filters: %d %v", n, err)
	}
	if d := wfpDump(t); !strings.Contains(d, "Manar JAIL") {
		t.Fatal("netsh wfp does not show the Manar filters")
	}
	// 3. the tool's exe cannot connect directly, not to this machine's address and not to the internet
	if got := direct(claudeExe); !strings.HasPrefix(got, "BLOCKED") {
		t.Fatalf("direct connect from claude.exe was not blocked: %q", got)
	}
	if got := run(t, claudeExe, "JAILWIN_HELPER=dial", "JAILWIN_ADDR=1.1.1.1:443"); !strings.HasPrefix(got, "BLOCKED") {
		t.Fatalf("internet connect from claude.exe was not blocked: %q", got)
	}
	// 4. the same exe reaches an allowed host through the proxy (loopback is permitted)
	if got := viaProxy("allowed.test:9000"); got != "TUNNEL ping" {
		t.Fatalf("allowed host via proxy: %q", got)
	}
	// 5. a new host asks, and is refused here
	if got := viaProxy("new.test:9000"); !strings.HasPrefix(got, "REFUSED 403") || ask.calls.Load() != 1 {
		t.Fatalf("new host: %q (asked %d)", got, ask.calls.Load())
	}
	// 6. DNS is permitted for the tool (TCP 53 to the domain controller)
	if got := run(t, claudeExe, "JAILWIN_HELPER=dial", "JAILWIN_ADDR=10.80.0.4:53"); got != "CONNECTED" {
		t.Logf("DNS port (informational, depends on the machine): %q", got)
	}
	// 7. other programs are not affected
	if got := direct(otherExe); got != "CONNECTED" {
		t.Fatalf("another program was blocked: %q", got)
	}

	// 8. a config poll with nothing changed does nothing; a flush of our filters is repaired
	r.reconcile(cfg)
	if n, _ := wfpFilterCount(); n != 6 {
		t.Fatalf("filters after a repeat: %d", n)
	}
	if err := wfpRemove(); err != nil {
		t.Fatal(err)
	}
	r.reconcile(cfg)
	if n, _ := wfpFilterCount(); n != 6 {
		t.Fatalf("filters not restored after removal: %d", n)
	}

	// 9. the tool is turned off: block gone first, settings back
	r.reconcile(&hostclient.Config{Status: "APPROVED", Jail: hostclient.JailConfig{Enabled: true, Windows: true}})
	if n, _ := wfpFilterCount(); n != 0 {
		t.Fatalf("filters left: %d", n)
	}
	if b, _ := os.ReadFile(settings); string(b) != orig {
		t.Fatalf("settings not restored byte for byte:\n%s", b)
	}
	if d := wfpDump(t); strings.Contains(d, "Manar JAIL") {
		t.Fatal("netsh wfp still shows Manar filters")
	}
	if got := direct(claudeExe); got != "CONNECTED" {
		t.Fatalf("networking not restored: %q", got)
	}

	// 10. a crash leaves the filters; a fresh process (jail-restore, uninstall) removes them from
	// the state on the machine
	r.reconcile(cfg)
	if n, _ := wfpFilterCount(); n != 6 {
		t.Fatalf("reinstall: %d", n)
	}
	r.mu.Lock()
	for _, tp := range r.running {
		tp.close() // the service "dies": the proxy is gone, the filters stay
	}
	r.running = map[string]*toolProxy{}
	r.mu.Unlock()
	if got := direct(claudeExe); !strings.HasPrefix(got, "BLOCKED") {
		t.Fatalf("a dead service must leave the tool blocked (fail closed): %q", got)
	}
	pfFresh := &winPlatform{users: pf.users, running: pf.running}
	if errs := pfFresh.teardown(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if n, _ := wfpFilterCount(); n != 0 {
		t.Fatalf("restore left %d filters", n)
	}
	if b, _ := os.ReadFile(settings); string(b) != orig {
		t.Fatalf("settings not restored by a fresh process:\n%s", b)
	}
	if got := direct(claudeExe); got != "CONNECTED" {
		t.Fatalf("networking not restored after the crash: %q", got)
	}

	// 11. an impostor on the proxy port: nothing is blocked and nothing is edited
	squat, err := net.Listen("tcp4", "127.0.0.1:8491")
	if err != nil {
		t.Fatal(err)
	}
	defer squat.Close()
	go func() {
		for {
			c, err := squat.Accept()
			if err != nil {
				return
			}
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Manar-Jail-Proof: 00\r\n\r\n")
			c.Close()
		}
	}()
	if err := pfFresh.Apply(map[string]int{claude: 8491}); err == nil {
		t.Fatal("the block was installed behind an impostor")
	}
	if n, _ := wfpFilterCount(); n != 0 {
		t.Fatalf("filters installed behind an impostor: %d", n)
	}
	if b, _ := os.ReadFile(settings); string(b) != orig {
		t.Fatalf("settings changed behind an impostor:\n%s", b)
	}
	if got := direct(claudeExe); got != "CONNECTED" {
		t.Fatalf("tool blocked behind an impostor: %q", got)
	}
}
