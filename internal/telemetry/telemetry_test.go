package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

type fakeAPI struct {
	mu    sync.Mutex
	cfg   *hostclient.Config
	cerr  error
	posts []batch
	path  string
	perr  error
}

func (f *fakeAPI) Config(context.Context) (*hostclient.Config, error) { return f.cfg, f.cerr }
func (f *fakeAPI) Do(_ context.Context, _, path string, in, _ any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.perr != nil {
		return f.perr
	}
	f.path = path
	f.posts = append(f.posts, in.(batch))
	return nil
}

func setup(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	Configure(base, "1.2.3")
	enabled.Store(false)
	mem.take()
	return filepath.Join(base, dirName)
}

func flag(on bool) *hostclient.Config {
	return &hostclient.Config{DataCollection: &hostclient.DataCollection{ImproveManar: on}}
}

func TestSendsOnlyWhenFlagTrue(t *testing.T) {
	setup(t)
	for name, cfg := range map[string]*hostclient.Config{"missing": {}, "false": flag(false)} {
		a := &fakeAPI{cfg: cfg}
		syncFlag(context.Background(), a)
		if enabled.Load() {
			t.Fatalf("%s: enabled", name)
		}
		Record("jail", "t", "block", "domain", "evil.example", "", time.Millisecond)
		if len(queue) != 0 {
			t.Fatalf("%s: recorded while off", name)
		}
	}
	// A failed sync keeps the last value, and the initial value is false.
	syncFlag(context.Background(), &fakeAPI{cerr: errors.New("down")})
	if enabled.Load() {
		t.Fatal("enabled after a failed first sync")
	}
}

func TestBatchContentAndPath(t *testing.T) {
	d := setup(t)
	a := &fakeAPI{cfg: flag(true)}
	syncFlag(context.Background(), a)
	if !enabled.Load() {
		t.Fatal("not enabled")
	}
	for i := 0; i < 30; i++ {
		mem.add(rec("warden", "cursor", "ask", "command", "rm -rf /home/zed/x PASSWORD=hunter2hunter2", time.Duration(i+1)*time.Millisecond))
	}
	mem.add(rec("jail", "claude-code", "allow", "", "", 2*time.Millisecond))
	writeCrash(errors.New("boom secret=abc"), []byte("goroutine 1 [running]:\nmain.f(0xc000012345, {0x1, 0x2})\n\t/home/zed/src/a.go:10 +0x1f\n"))
	if err := send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if a.path != "/telemetry" || len(a.posts) != 1 {
		t.Fatalf("path %q posts %d", a.path, len(a.posts))
	}
	b := a.posts[0]
	raw, _ := json.Marshal(b)
	for _, bad := range []string{"hunter2", "zed", "0xc000012345", "boom", "abc"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("batch contains %q: %s", bad, raw)
		}
	}
	if b.Schema != 1 || b.Version != "1.2.3" || b.OS == "" || b.Arch == "" {
		t.Fatalf("header: %+v", b)
	}
	if len(b.Samples) != 20 {
		t.Fatalf("samples %d, want 20", len(b.Samples))
	}
	types := map[string]int{}
	for _, e := range b.Events {
		types[e.Type]++
	}
	if types["first_run"] != 1 || types["crash"] != 1 || types["health"] != 1 || types["timing"] != 2 {
		t.Fatalf("events: %v", types)
	}
	for _, e := range b.Events {
		if e.Type == "timing" && e.Data["component"] == "warden" {
			if e.Data["p50Ms"].(float64) != 15 || e.Data["p95Ms"].(float64) != 29 {
				t.Errorf("percentiles: %v", e.Data)
			}
		}
	}
	// Sent: crash file gone, first_run is not repeated, counters restart.
	if m, _ := filepath.Glob(filepath.Join(d, "crash-*.json")); len(m) != 0 {
		t.Fatal("crash file kept")
	}
	b2, _ := build(mem.take(), time.Now())
	for _, e := range b2.Events {
		if e.Type == "first_run" || e.Type == "crash" || e.Type == "timing" {
			t.Fatalf("repeated %s", e.Type)
		}
	}
}

func TestFailedSendKeepsCrash(t *testing.T) {
	d := setup(t)
	a := &fakeAPI{cfg: flag(true), perr: errors.New("503")}
	syncFlag(context.Background(), a)
	writeCrash("x", []byte("goroutine 1"))
	if send(context.Background(), a) == nil {
		t.Fatal("expected error")
	}
	if m, _ := filepath.Glob(filepath.Join(d, "crash-*.json")); len(m) != 1 {
		t.Fatal("crash report lost after a failed send")
	}
}

func TestTurningOffClearsSpool(t *testing.T) {
	d := setup(t)
	a := &fakeAPI{cfg: flag(true)}
	syncFlag(context.Background(), a)
	mem.add(rec("jail", "t", "block", "domain", "a.example", time.Millisecond))
	mem.save()
	writeCrash("x", []byte("s"))
	a.cfg = flag(false)
	syncFlag(context.Background(), a)
	if _, err := os.Stat(filepath.Join(d, "spool.json")); err == nil {
		t.Fatal("spool kept")
	}
	if m, _ := filepath.Glob(filepath.Join(d, "crash-*.json")); len(m) != 0 {
		t.Fatal("crash kept")
	}
	if len(mem.st.Samples) != 0 || len(mem.st.Counts) != 0 {
		t.Fatal("memory kept")
	}
	writeCrash("x", []byte("s")) // off: nothing is written
	if m, _ := filepath.Glob(filepath.Join(d, "crash-*.json")); len(m) != 0 {
		t.Fatal("crash written while off")
	}
}

func TestSpoolRoundTripAndBound(t *testing.T) {
	d := setup(t)
	enabled.Store(true)
	for i := 0; i < 5000; i++ {
		mem.add(rec("jail", "t", "allow", "", "", time.Millisecond))
	}
	mem.save()
	fi, err := os.Stat(filepath.Join(d, "spool.json"))
	if err != nil || fi.Size() > maxSpool {
		t.Fatalf("spool: %v %v", fi, err)
	}
	if len(mem.st.Dur["jail"]) != maxDurations {
		t.Fatalf("durations %d", len(mem.st.Dur["jail"]))
	}
	mem.take()
	mem.load()
	if mem.st.Counts["jail"]["allow"] != 5000 {
		t.Fatal("not restored")
	}
}

func TestRecordNeverBlocks(t *testing.T) {
	setup(t)
	enabled.Store(true)
	defer enabled.Store(false)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10*cap(queue); i++ { // nobody drains the queue
			Record("jail", "t", "allow", "", "", "", 0)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked")
	}
	for len(queue) > 0 {
		<-queue
	}
}

func TestStripArgs(t *testing.T) {
	got := stripArgs("goroutine 1 [running]:\nmain.(*T).Do(0xc0001, {0x1, 0x2})\n\t/x/a.go:3 +0x1\npanic({0x1, 0x2})")
	if strings.Contains(got, "0xc0001") || strings.Contains(got, "{0x1") || !strings.Contains(got, "main.(*T).Do(...)") {
		t.Fatal(got)
	}
}

func TestRunSendsAtStartThenStops(t *testing.T) {
	setup(t)
	a := &fakeAPI{cfg: flag(true)}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { run(ctx, a, time.Hour); close(stopped) }()
	defer func() { cancel(); <-stopped }() // run saves on exit; wait before the temp dir goes
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		n := len(a.posts)
		a.mu.Unlock()
		if n == 1 {
			cancel()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("no batch sent at start")
}

var apiKey = regexpKey()

func regexpKey() *regexp.Regexp { return regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`) }

func u16(s string) int { return len(utf16.Encode([]rune(s))) }

// TestBatchSatisfiesApiContract mirrors DeviceTelemetryBody in manar-api
// (src/data-collection/data-collection.dto.ts).
func TestBatchSatisfiesApiContract(t *testing.T) {
	setup(t)
	enabled.Store(true)
	huge := strings.Repeat("goroutine 1 [running]:\nmain.f(0x1)\n\t/home/zed/src/a.go:10 +0x1f\n", 400)
	writeCrash(errors.New("x"), []byte(huge))
	for i := 0; i < 80; i++ {
		mem.add(rec("warden", strings.Repeat("t", 100), "ask", "command", "ls "+strings.Repeat("a b ", 300), time.Millisecond))
		mem.add(rec("warden", "cursor", "block", "domain", "x.example", 2*time.Millisecond))
		mem.add(rec("warden", "cursor", "allow", "", "", 3*time.Millisecond))
		mem.add(rec("jail", "claude-code", "ask", "domain", "y.example", time.Millisecond))
		mem.add(rec("jail", "claude-code", "block", "domain", "z.example", time.Millisecond))
	}
	b, _ := build(mem.peek(), time.Now())
	body, _ := json.Marshal(b)
	if len(body) > 256*1024 || len(b.Events) > 200 || len(b.Samples) > 50 {
		t.Fatalf("limits: body %d events %d samples %d", len(body), len(b.Events), len(b.Samples))
	}
	if len(b.Version) > 64 || len(b.OS) > 64 || len(b.Arch) > 32 || b.Schema != 1 {
		t.Fatalf("header %+v", b)
	}
	date := func(s string) {
		if _, err := time.Parse(time.RFC3339, s); err != nil || len(s) > 40 {
			t.Errorf("bad date %q", s)
		}
	}
	seen := map[string]bool{}
	for _, e := range b.Events {
		seen[e.Type] = true
		date(e.At)
		if len(e.Data) > 30 {
			t.Errorf("%s: %d keys", e.Type, len(e.Data))
		}
		for k, v := range e.Data {
			if !apiKey.MatchString(k) {
				t.Errorf("%s: bad key %q", e.Type, k)
			}
			switch x := v.(type) {
			case string:
				if u16(x) > 4000 {
					t.Errorf("%s.%s: string of %d", e.Type, k, u16(x))
				}
			case bool, int, int64, uint64, uint32:
			case float64:
				if math.IsNaN(x) || math.IsInf(x, 0) {
					t.Errorf("%s.%s not finite", e.Type, k)
				}
			default:
				t.Errorf("%s.%s: non-primitive %T", e.Type, k, v)
			}
		}
	}
	for _, ty := range []string{"first_run", "crash", "health", "timing"} {
		if !seen[ty] {
			t.Errorf("no %s event", ty)
		}
	}
	for _, s := range b.Samples {
		date(s.At)
		if (s.Kind != "command" && s.Kind != "domain") || (s.Decision != "ask" && s.Decision != "block") || len(s.Tool) > 64 || u16(s.Text) > 4000 {
			t.Errorf("bad sample %+v", s)
		}
	}
	// The health event carries the counts as flat keys.
	for _, e := range b.Events {
		if e.Type == "health" && e.Data["decisions.warden.allow"] != 80 {
			t.Errorf("flat count missing: %v", e.Data)
		}
	}
}

func TestFailedSendKeepsSamples(t *testing.T) {
	setup(t)
	a := &fakeAPI{cfg: flag(true), perr: errors.New("503")}
	syncFlag(context.Background(), a)
	mem.add(rec("jail", "t", "block", "domain", "a.example", time.Millisecond))
	if send(context.Background(), a) == nil {
		t.Fatal("expected error")
	}
	if len(mem.st.Samples) != 1 || mem.st.Counts["jail"]["block"] != 1 || len(mem.st.Dur["jail"]) != 1 {
		t.Fatalf("lost after a failed send: %+v", mem.st)
	}
	// A record that arrives during a successful send is kept.
	a.perr = nil
	mem.add(rec("jail", "t", "block", "domain", "b.example", time.Millisecond))
	if err := send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if len(mem.st.Samples) != 0 || len(mem.st.Counts) != 0 || len(mem.st.Dur) != 0 {
		t.Fatalf("not cleared after 2xx: %+v", mem.st)
	}
}

func TestRejectedBatchIsDropped(t *testing.T) {
	d := setup(t)
	a := &fakeAPI{cfg: flag(true), perr: &hostclient.StatusError{Code: 400, Message: "bad"}}
	syncFlag(context.Background(), a)
	writeCrash("x", []byte("s"))
	mem.add(rec("jail", "t", "block", "domain", "a.example", time.Millisecond))
	if send(context.Background(), a) == nil {
		t.Fatal("expected the error to be returned")
	}
	if m, _ := filepath.Glob(filepath.Join(d, "crash-*.json")); len(m) != 0 {
		t.Fatal("crash file kept after a 400")
	}
	if len(mem.st.Samples) != 0 || len(mem.st.Counts) != 0 {
		t.Fatal("spool kept after a 400")
	}
	if _, err := os.Stat(filepath.Join(d, "first_run")); err == nil {
		t.Fatal("first_run marked after a 400")
	}
}

// rec is a record made under the current consent epoch.
func rec(component, tool, decision, kind, text string, took time.Duration) record {
	return record{component, tool, decision, kind, text, "", took, epoch.Load()}
}

func TestMinimise(t *testing.T) {
	for in, want := range map[string]string{
		"git push --force":                          "git push --force",
		"git push --force origin main":              "git push --force",
		"mysql -u root -pHunter2 db":                "mysql -u -p",
		"/usr/bin/curl -H 'X: y' --data=secret url": "curl -H --data",
		"AWS_KEY=zzz rm -rf /home/a/b":              "rm -r",
		"git -C /x push --force origin main":        "git -C push --force",
		"C:\\Tools\\Kubectl.exe delete pod x":       "kubectl delete",
		"cd /srv && npm install left-pad | tee out": "<cmd> ; npm install ; <cmd>",
		"python3 script.py --token abc":             "python3 --token",
		"python3.11 script.py --token abc":          "<cmd>",
		"./mytool --secret-flag=abc":                "<cmd>",
		`echo "a; secretvalue"`:                     "<cmd> ; <cmd>",
		`bash -c 'x; y'`:                            "bash -c ; <cmd>",
		`echo "a && sk_live_abc" | cat`:             "<cmd> ; <cmd> ; cat",
		`ls "x; --token=abc"`:                       "ls ; <cmd>",
		"":                                          "",
	} {
		if got := Minimise(in); got != want {
			t.Errorf("Minimise(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSampleHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://Docs.Example.com/a?q=1": "docs.example.com",
		"http://example.org":             "example.org",
		"http://localhost:3000/x":        "",
		"https://10.1.2.3/x":             "",
		"https://[2001:db8::1]/":         "",
		"ftp://example.com/":             "",
		"how do I fix my password":       "",
		"example.com":                    "",
		"":                               "",
	} {
		if got := SampleHost(in); got != want {
			t.Errorf("SampleHost(%q) = %q, want %q", in, got, want)
		}
	}
	if sampleText(record{kind: "domain", text: "10.0.0.1"}) != "" || sampleText(record{kind: "domain", text: "intranet"}) != "" {
		t.Error("ip or dotless host sampled")
	}
}

func TestSampleScrubsCallerUser(t *testing.T) {
	u, err := user.Current()
	if err != nil || len(u.Username) < 3 {
		t.Skip("no usable user")
	}
	caller := "uid:" + u.Uid
	if runtime.GOOS == "windows" {
		caller = "sid:" + u.Uid
	}
	for _, c := range []string{caller, caller + "|s:abc123"} { // the relay may append a session id
		got := scrubUser("owner "+u.Username+" home "+u.HomeDir+"/x", c)
		if strings.Contains(got, u.Username) || (len(u.HomeDir) > 1 && strings.Contains(got, u.HomeDir)) {
			t.Errorf("caller %q: name or home survived: %q", c, got)
		}
	}
}

// Records queued or in flight when consent is withdrawn are neither stored, saved nor sent.
func TestConsentWithdrawnDropsQueued(t *testing.T) {
	d := setup(t)
	a := &fakeAPI{cfg: flag(true)}
	syncFlag(context.Background(), a)
	for i := 0; i < 50; i++ {
		Record("jail", "t", "block", "domain", "a.example.com", "", time.Millisecond)
	}
	inflight := rec("jail", "t", "block", "domain", "b.example.com", time.Millisecond) // already taken from the queue
	a.cfg = flag(false)
	syncFlag(context.Background(), a)
	if len(queue) != 0 {
		t.Fatal("queue not drained")
	}
	mem.add(inflight)
	for i := 0; i < 3; i++ { // a worker that was slow: epoch is old, flag is off
		mem.add(record{component: "jail", decision: "block", epoch: 0, took: time.Millisecond})
	}
	mem.save()
	if _, err := os.Stat(filepath.Join(d, "spool.json")); err == nil {
		t.Fatal("spool saved after off")
	}
	if len(mem.st.Counts) != 0 || len(mem.st.Samples) != 0 || len(mem.st.Dur) != 0 {
		t.Fatalf("stored after off: %+v", mem.st)
	}
	// Back on: a record from before the toggle (old epoch) is still refused.
	old := rec("jail", "t", "block", "domain", "c.example.com", time.Millisecond)
	a.cfg = flag(true)
	syncFlag(context.Background(), a)
	mem.add(old)
	if len(mem.st.Counts) != 0 {
		t.Fatal("old-epoch record accepted")
	}
	mem.add(rec("jail", "t", "block", "domain", "d.example.com", time.Millisecond))
	if mem.st.Counts["jail"]["block"] != 1 {
		t.Fatal("current record refused")
	}
}
