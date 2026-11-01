package jail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// cgRoot is where the unified cgroup hierarchy is mounted (a variable for the container test).
var cgRoot = "/sys/fs/cgroup"

// rulesetFor builds the nftables text (a variable so a test can feed a wrong one).
var rulesetFor = Ruleset

// resolvConf is where the tools' DNS servers are read from (a variable for tests).
var resolvConf = "/etc/resolv.conf"

// scanEvery is how often new processes of the tools are looked for.
var scanEvery = 250 * time.Millisecond

// enforcer is the Linux OS layer: a cgroup per tool, an nftables table that matches those cgroups,
// and a scanner that moves the tools' processes in.
type enforcer struct {
	mu        sync.Mutex
	ports     map[string]int
	resolvers []netip.Addr
	rules     string // the ruleset text last installed, to put it back
	cancel    context.CancelFunc
	done      chan struct{}
	scan      *scanner
	wanted    atomic.Value // []string, read by the scanner
}

func newEnforcer() *enforcer { return &enforcer{} }

// Supported says whether this machine can run the filter, and why not.
func Supported() error {
	if os.Geteuid() != 0 {
		return errors.New("needs root")
	}
	if _, err := os.Stat(filepath.Join(cgRoot, "cgroup.controllers")); err != nil {
		return errors.New("cgroup v2 is not mounted")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("the nft program is not installed")
	}
	return nil
}

// Apply makes the filter cover exactly the tools in ports (tool id -> local proxy port). It can
// be called again with a different set. The nftables rules are installed before any process is
// moved in, and a tool dropped from ports is released (its processes moved back) before its rules
// go.
func (e *enforcer) Apply(ports map[string]int) error {
	if err := Supported(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// Nothing changed and our table is still there (a firewall reload that flushes the ruleset
	// would otherwise leave the tools unfiltered without anyone noticing): nothing to do.
	resolvers := readResolvers(resolvConf)
	if e.scan != nil && maps.Equal(e.ports, ports) && slices.Equal(e.resolvers, resolvers) && tableExists() {
		return nil
	}
	for t := range e.ports {
		if _, keep := ports[t]; !keep && e.scan != nil {
			e.scan.release(t)
			sweepCgroup(t)
		}
	}
	if len(ports) == 0 {
		return e.teardownLocked()
	}
	for t := range ports {
		if err := os.MkdirAll(filepath.Join(cgRoot, cgParent, cgName(t)), 0o755); err != nil {
			return fmt.Errorf("cgroup for %s: %w", t, err)
		}
	}
	rules := rulesetFor(ports, resolvers)
	if err := nft(rules); err != nil {
		return err
	}
	// The rules must touch only the tools. If this kernel or nft reads the cgroup match differently
	// than we expect and it hits everything, the user's whole network would break: check that this
	// process (never in a tool cgroup) still connects straight, and take the rules out if not.
	if err := selfTest(); err != nil {
		_ = Teardown()
		return fmt.Errorf("the rules were removed again: %w", err)
	}
	e.ports, e.resolvers, e.rules = ports, resolvers, rules
	wanted := make([]string, 0, len(ports))
	for t := range ports {
		wanted = append(wanted, t)
	}
	e.wanted.Store(wanted)
	if e.scan == nil {
		e.scan = newScanner()
		ctx, cancel := context.WithCancel(context.Background())
		e.cancel, e.done = cancel, make(chan struct{})
		done := e.done
		go func() {
			defer close(done)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := watchNFT(ctx, e.reapply); err != nil && ctx.Err() == nil {
					log.Printf("jail: no nftables events (%v): a flushed table is put back at the next poll", err)
				}
			}()
			e.scan.run(ctx, func() []string { return e.tools() })
			wg.Wait()
		}()
	}
	return nil
}

// tableExists says whether our nftables table is installed.
func tableExists() bool {
	return exec.Command("nft", "list", "table", "inet", nftTable).Run() == nil
}

// sweepCgroup moves whatever is still in a released tool's cgroup (children of its processes)
// to the cgroup root and removes the directory.
func sweepCgroup(tool string) {
	dir := filepath.Join(cgRoot, cgParent, cgName(tool))
	for _, pid := range readPids(filepath.Join(dir, "cgroup.procs")) {
		_ = os.WriteFile(filepath.Join(cgRoot, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
	}
	_ = os.Remove(dir)
}

// tools is read by the scanner without taking e.mu, which Apply and Teardown hold while they wait
// for the scanner to stop.
func (e *enforcer) tools() []string {
	if v, ok := e.wanted.Load().([]string); ok {
		return v
	}
	return nil
}

// Teardown puts the machine back as it was: the scanner stops, every process is moved back to the
// cgroup it came from, the nftables table and the cgroups are removed. It works from the state on
// the machine, not from memory, so `uninstall` in a fresh process finishes what a crashed service
// left. Safe to call when nothing is installed.
func (e *enforcer) Teardown() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.teardownLocked()
}

func (e *enforcer) teardownLocked() error {
	if e.cancel != nil {
		e.cancel()
		<-e.done
		e.cancel, e.done = nil, nil
	}
	var errs []error
	if e.scan != nil {
		e.scan.releaseAll()
		e.scan = nil
	}
	e.ports, e.rules, e.resolvers = nil, "", nil
	e.wanted.Store([]string(nil))
	errs = append(errs, Teardown()...)
	return errors.Join(errs...)
}

// Teardown is the stateless part: remove the table, empty and remove the cgroups. Processes still
// in a tool cgroup (a crashed service never moved them back) go to the cgroup root.
func Teardown() []error {
	var errs []error
	errs = append(errs, restoreRecorded()...)
	if _, err := exec.LookPath("nft"); err == nil {
		out, err := exec.Command("nft", "list", "table", "inet", nftTable).CombinedOutput()
		if err == nil || !bytes.Contains(out, []byte("No such file")) {
			if err := nft(fmt.Sprintf("table inet %[1]s\ndelete table inet %[1]s\n", nftTable)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	parent := filepath.Join(cgRoot, cgParent)
	kids, _ := os.ReadDir(parent)
	for _, k := range kids {
		if !k.IsDir() {
			continue
		}
		dir := filepath.Join(parent, k.Name())
		for _, pid := range readPids(filepath.Join(dir, "cgroup.procs")) {
			if err := os.WriteFile(filepath.Join(cgRoot, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil && !errors.Is(err, syscall.ESRCH) {
				errs = append(errs, fmt.Errorf("moving %d out of %s: %w", pid, k.Name(), err))
			}
		}
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(parent); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	return errs
}

func readPids(path string) []int {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// nft feeds a ruleset to `nft -f -` (checked first: a bad ruleset never half-applies).
func nft(rules string) error {
	for _, args := range [][]string{{"-c", "-f", "-"}, {"-f", "-"}} {
		cmd := exec.Command("nft", args...)
		cmd.Stdin = strings.NewReader(rules)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// scanner moves the processes of the tools into their cgroups.
type scanner struct {
	mu    sync.Mutex
	moved map[int]moved // pid -> where it came from
	self  int
	netns string // this service's network namespace
	tools func() []string
}

type moved struct {
	Tool  string `json:"tool"`
	From  string `json:"from"`  // cgroup path relative to the root, "" for the root
	Start uint64 `json:"start"` // the process's start time: a reused pid is not the same process
}

// movedFile records what was moved where, so a fresh process (uninstall, jail-restore after a
// crash) can put each process back in the cgroup it came from. /run is cleared at boot, when the
// cgroups are gone too.
var movedFile = "/run/manar-edge/jail-moved.json"

func newScanner() *scanner {
	ns, _ := os.Readlink("/proc/self/ns/net")
	return &scanner{moved: map[int]moved{}, self: os.Getpid(), netns: ns}
}

// procStart is the start time (clock ticks since boot) of pid, field 22 of /proc/<pid>/stat.
func procStart(pid int) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0, errors.New("bad stat")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return 0, errors.New("short stat")
	}
	return strconv.ParseUint(f[19], 10, 64)
}

// persistLocked writes the moved map; the caller holds s.mu.
func (s *scanner) persistLocked() {
	m := make(map[string]moved, len(s.moved))
	for pid, v := range s.moved {
		m[strconv.Itoa(pid)] = v
	}
	b, _ := json.Marshal(m)
	if err := os.MkdirAll(filepath.Dir(movedFile), 0o755); err == nil {
		_ = os.WriteFile(movedFile, b, 0o600)
	}
}

// restoreRecorded puts every recorded process back where it came from, but only a process whose
// start time still matches (a pid reused by something else is left alone).
func restoreRecorded() []error {
	b, err := os.ReadFile(movedFile)
	if err != nil {
		return nil
	}
	var m map[string]moved
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	for k, v := range m {
		if pid, err := strconv.Atoi(k); err == nil {
			if st, err := procStart(pid); err == nil && st == v.Start {
				restore(pid, v.From)
			}
		}
	}
	_ = os.Remove(movedFile)
	return nil
}

func (s *scanner) run(ctx context.Context, tools func() []string) {
	s.tools = tools
	// Exec events catch a tool within a millisecond of its start; the periodic scan below is the
	// safety net (a lost event, a kernel without the connector, tools already running).
	go func() {
		if err := watchExec(ctx, s.consider); err != nil && ctx.Err() == nil {
			log.Printf("jail: no exec events (%v): new tool processes are found within %s", err, scanEvery)
		}
	}()
	t := time.NewTicker(scanEvery)
	defer t.Stop()
	for {
		s.once()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// once looks at every process.
func (s *scanner) once() {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	live := map[int]bool{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		live[pid] = true
		s.consider(pid)
	}
	s.mu.Lock()
	pruned := false
	for pid := range s.moved {
		if !live[pid] {
			delete(s.moved, pid)
			pruned = true
		}
	}
	if pruned {
		s.persistLocked()
	}
	s.mu.Unlock()
}

// consider moves pid into its tool's cgroup if it is one of the tools. It never touches root's
// processes, its own, or anything it cannot name as one of the tools.
func (s *scanner) consider(pid int) {
	if pid == s.self || pid <= 1 {
		return
	}
	s.mu.Lock()
	_, done := s.moved[pid]
	s.mu.Unlock()
	if done {
		return
	}
	name := strconv.Itoa(pid)
	st, err := os.Stat("/proc/" + name)
	if err != nil {
		return
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid == 0 {
		return // the service and root's own programs are never filtered
	}
	// A process in another network namespace (a container) is not on this machine's network:
	// the rules would not see its traffic, and it is not ours to move.
	if ns, err := os.Readlink("/proc/" + name + "/ns/net"); err != nil || ns != s.netns {
		return
	}
	comm, err := os.ReadFile("/proc/" + name + "/comm")
	if err != nil {
		return
	}
	tool := matchProc(strings.TrimSpace(string(comm)), func() []string { return cmdline(pid) }, s.tools())
	if tool == "" {
		return
	}
	from := currentCgroup(pid)
	if strings.HasPrefix(from, "/"+cgParent+"/") {
		return
	}
	// The same process may be considered from the event and the scan at once: whoever writes
	// first wins, the other write is a no-op into the same cgroup.
	if err := os.WriteFile(filepath.Join(cgRoot, cgParent, cgName(tool), "cgroup.procs"), []byte(name), 0o644); err != nil {
		if !errors.Is(err, syscall.ESRCH) {
			log.Printf("jail: moving %d (%s): %v", pid, tool, err)
		}
		return
	}
	start, _ := procStart(pid)
	s.mu.Lock()
	if _, ok := s.moved[pid]; !ok {
		s.moved[pid] = moved{tool, from, start}
		s.persistLocked()
	}
	s.mu.Unlock()
}

func cmdline(pid int) []string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return nil
	}
	if len(b) > 4096 {
		b = b[:4096]
	}
	return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
}

// currentCgroup is the unified-hierarchy path of pid ("/user.slice/..."), "" if unknown.
func currentCgroup(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return p
		}
	}
	return ""
}

// release moves one tool's processes back to where they came from.
func (s *scanner) release(tool string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for pid, m := range s.moved {
		if m.Tool == tool {
			if st, err := procStart(pid); err == nil && st == m.Start {
				restore(pid, m.From)
			}
			delete(s.moved, pid)
		}
	}
	s.persistLocked()
}

func (s *scanner) releaseAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for pid, m := range s.moved {
		if st, err := procStart(pid); err == nil && st == m.Start {
			restore(pid, m.From)
		}
	}
	s.moved = map[int]moved{}
	s.persistLocked()
}

// restore puts pid back in its old cgroup, or the root if that is gone.
func restore(pid int, from string) {
	data := []byte(strconv.Itoa(pid))
	if from != "" && from != "/" {
		if os.WriteFile(filepath.Join(cgRoot, from, "cgroup.procs"), data, 0o644) == nil {
			return
		}
	}
	_ = os.WriteFile(filepath.Join(cgRoot, "cgroup.procs"), data, 0o644)
}

// selfTest connects from this process to a listener on one of this machine's own non-loopback
// addresses. Loopback is never redirected, so it would prove nothing; a non-loopback destination is
// redirected or rejected if (and only if) the cgroup match wrongly covers this process. Machines
// with no such address pass: there is nothing to break either.
func selfTest() error {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.To4() == nil || n.IP.IsLinkLocalUnicast() {
			continue
		}
		ln, err := net.Listen("tcp4", net.JoinHostPort(n.IP.String(), "0"))
		if err != nil {
			continue
		}
		defer ln.Close()
		acc := make(chan struct{}, 1)
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Close()
				acc <- struct{}{}
			}
		}()
		c, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return fmt.Errorf("self-test: a program outside the tools could not connect: %w", err)
		}
		c.Close()
		select {
		case <-acc:
			return nil
		case <-time.After(2 * time.Second):
			return errors.New("self-test: a program outside the tools was redirected")
		}
	}
	return nil
}
