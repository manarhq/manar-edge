// Package telemetry is the device's "product improvement data" (design spec 2026-11-02). It
// collects, locally and cheaply, health and timing numbers, crash reports and at most 20 redacted
// samples a day, and sends one batch at start and then daily. It sends nothing unless the last
// synced dataCollection.improveManar is true; unknown or missing means false.
//
// Never collected: secret values, file contents, prompt text, environment, full URLs.
package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/manarhq/manar-edge/internal/daemon"
	"github.com/manarhq/manar-edge/internal/hostclient"
)

// telemetryPath is relative to the host API base: POST /host/v1/telemetry (manar-api#24).
const telemetryPath = "/telemetry"

const (
	dirName      = "telemetry"
	maxSamples   = 20      // per day
	maxDurations = 2000    // per component; the oldest are dropped
	maxCrashes   = 5       // report files kept
	maxSpool     = 1 << 20 // the spool file never exceeds 1 MB
	maxStack     = 3900    // the api caps strings in event data at 4000
	syncEvery    = 10 * time.Minute
	sendEvery    = 24 * time.Hour
	retryAfter   = time.Hour
)

var (
	startedAt = time.Now()
	dir       atomic.Pointer[string]
	version   atomic.Pointer[string]
	enabled   atomic.Bool // last synced dataCollection.improveManar
	// epoch changes every time the flag changes; a record made under an older epoch is dropped,
	// so nothing recorded before "off" can be stored or sent after it.
	epoch atomic.Uint64
	queue = make(chan record, 256)
)

func init() {
	daemon.Register(&module{})
	daemon.OnPanic = writeCrash
}

// Configure tells the package where the state directory is and which version is running.
func Configure(stateDir, ver string) {
	d := filepath.Join(stateDir, dirName)
	dir.Store(&d)
	version.Store(&ver)
}

func spoolDir() string {
	if p := dir.Load(); p != nil {
		return *p
	}
	return ""
}

type record struct {
	component, tool, decision, kind, text, owner string
	took                                         time.Duration
	epoch                                        uint64
}

// Record notes one WARDEN or JAIL decision. It never blocks: when telemetry is off it returns at
// once, and when the queue is full the record is dropped. decision is allow, ask or block; kind
// (command or domain) and text only matter for ask and block, which are sampled after
// minimisation and redaction. owner is the caller ("uid:1000", "sid:S-1-5-..."), so that user's
// name and home directory can be scrubbed too; "" when unknown.
func Record(component, tool, decision, kind, text, owner string, took time.Duration) {
	if !enabled.Load() {
		return
	}
	select {
	case queue <- record{component, tool, decision, kind, text, owner, took, epoch.Load()}:
	default:
	}
}

// Sample is one redacted command or domain.
type Sample struct {
	Kind     string `json:"kind"`
	Tool     string `json:"tool"`
	Decision string `json:"decision"`
	Text     string `json:"text"`
	At       string `json:"at"`
}

// state is the day's numbers; it is also the spool file.
type state struct {
	Since   time.Time                 `json:"since"`
	Counts  map[string]map[string]int `json:"counts"`
	Dur     map[string][]float64      `json:"durMs"`
	Samples []Sample                  `json:"samples"`
}

type store struct {
	mu sync.Mutex
	st state
}

var mem = &store{st: newState()}

func newState() state {
	return state{Since: time.Now().UTC(), Counts: map[string]map[string]int{}, Dur: map[string][]float64{}}
}

func (s *store) add(r record) {
	var smp *Sample
	if (r.decision == "ask" || r.decision == "block") && (r.kind == "command" || r.kind == "domain") {
		s.mu.Lock()
		full := len(s.st.Samples) >= maxSamples
		s.mu.Unlock()
		if !full { // minimise and redact outside the lock; it is the costly part
			if text := sampleText(r); text != "" {
				smp = &Sample{r.kind, cut(r.tool, 64), r.decision, text, time.Now().UTC().Format(time.RFC3339)}
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Consent is checked under the lock that clearAll and save also take.
	if !enabled.Load() || r.epoch != epoch.Load() {
		return
	}
	c := s.st.Counts[r.component]
	if c == nil {
		c = map[string]int{}
		s.st.Counts[r.component] = c
	}
	c[r.decision]++
	d := append(s.st.Dur[r.component], float64(r.took.Microseconds())/1000)
	if len(d) > maxDurations {
		d = d[len(d)-maxDurations:]
	}
	s.st.Dur[r.component] = d
	if smp != nil && len(s.st.Samples) < maxSamples {
		s.st.Samples = append(s.st.Samples, *smp)
	}
}

// sampleText is what may leave the device: a command shrinks to program and flag names, a domain
// must be a real host name; then redaction and the caller's name and home are scrubbed as well.
func sampleText(r record) string {
	t := r.text
	if r.kind == "command" {
		t = Minimise(t)
	} else if !eligibleHost(t) {
		return ""
	}
	return cut(scrubUser(Redact(t), r.owner), maxSample)
}

func (s *store) take() state {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.st
	s.st = newState()
	return out
}

// peek copies the day's numbers without clearing them; remove drops what a batch carried once the
// api has answered, so a failed send loses nothing.
func (s *store) peek() state {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := state{Since: s.st.Since, Counts: map[string]map[string]int{}, Dur: map[string][]float64{},
		Samples: append([]Sample(nil), s.st.Samples...)}
	for c, m := range s.st.Counts {
		out.Counts[c] = map[string]int{}
		for k, v := range m {
			out.Counts[c][k] = v
		}
	}
	for c, d := range s.st.Dur {
		out.Dur[c] = append([]float64(nil), d...)
	}
	return out
}

func (s *store) remove(sent state) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c, m := range sent.Counts {
		for k, v := range m {
			if s.st.Counts[c][k] -= v; s.st.Counts[c][k] <= 0 {
				delete(s.st.Counts[c], k)
			}
		}
		if len(s.st.Counts[c]) == 0 {
			delete(s.st.Counts, c)
		}
	}
	for c, d := range sent.Dur {
		cur := s.st.Dur[c]
		if n := min(len(d), len(cur)); n > 0 {
			s.st.Dur[c] = cur[n:]
		}
		if len(s.st.Dur[c]) == 0 {
			delete(s.st.Dur, c)
		}
	}
	s.st.Samples = s.st.Samples[min(len(sent.Samples), len(s.st.Samples)):]
	s.st.Since = time.Now().UTC()
}

// ---- spool file ----

func (s *store) save() {
	d := spoolDir()
	if d == "" {
		return
	}
	// The lock is held through the write so a clearAll cannot be followed by a stale file.
	s.mu.Lock()
	defer s.mu.Unlock()
	if !enabled.Load() {
		return
	}
	b, _ := json.Marshal(s.st)
	if len(b) > maxSpool {
		return
	}
	if os.MkdirAll(d, 0o700) == nil {
		_ = os.WriteFile(filepath.Join(d, "spool.json"), b, 0o600)
	}
}

func (s *store) load() {
	b, err := os.ReadFile(filepath.Join(spoolDir(), "spool.json"))
	if err != nil || len(b) > maxSpool {
		return
	}
	var st state
	if json.Unmarshal(b, &st) != nil || st.Counts == nil || st.Dur == nil {
		return
	}
	if len(st.Samples) > maxSamples {
		st.Samples = st.Samples[:maxSamples]
	}
	s.mu.Lock()
	s.st = st
	s.mu.Unlock()
}

// clearAll removes everything collected (the flag is off). first_run stays: it is a once-only mark.
func clearAll() {
	for { // records queued before "off" are discarded, not stored later
		select {
		case <-queue:
			continue
		default:
		}
		break
	}
	mem.take()
	d := spoolDir()
	if d == "" {
		return
	}
	_ = os.Remove(filepath.Join(d, "spool.json"))
	m, _ := filepath.Glob(filepath.Join(d, "crash-*.json"))
	for _, f := range m {
		_ = os.Remove(f)
	}
}

// ---- crash reports ----

type crash struct {
	Type  string `json:"panicType"`
	Stack string `json:"stack"`
	At    string `json:"at"`
}

// CrashGuard is deferred first thing in main: it writes a crash report and panics again so the
// process still dies as before.
func CrashGuard() {
	if r := recover(); r != nil {
		writeCrash(r, debug.Stack())
		panic(r)
	}
}

// writeCrash stores the panic value's type and a stack without arguments, and nothing else (no
// message, no environment). It only writes while collection is on.
func writeCrash(v any, stack []byte) {
	d := spoolDir()
	if d == "" || !enabled.Load() {
		return
	}
	if m, _ := filepath.Glob(filepath.Join(d, "crash-*.json")); len(m) >= maxCrashes {
		return
	}
	b, err := json.Marshal(crash{cut(fmt.Sprintf("%T", v), 200), cutUTF16(scrubPaths(stripArgs(string(stack))), maxStack), time.Now().UTC().Format(time.RFC3339)})
	if err != nil || os.MkdirAll(d, 0o700) != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(d, fmt.Sprintf("crash-%d.json", time.Now().UnixNano())), b, 0o600)
}

// stripArgs cuts the "(0xc000...)" argument list off every function line of a Go stack.
func stripArgs(stack string) string {
	lines := strings.Split(stack, "\n")
	for i, l := range lines {
		if l != "" && l[0] != '\t' && l[0] != ' ' && strings.HasSuffix(l, ")") {
			if j := strings.LastIndex(l, "("); j > 0 {
				lines[i] = l[:j] + "(...)"
			}
		}
	}
	return strings.Join(lines, "\n")
}

// cutUTF16 cuts s to at most n UTF-16 units (how the api counts string length).
func cutUTF16(s string, n int) string {
	u := 0
	for i, r := range s {
		w := 1
		if r > 0xFFFF {
			w = 2
		}
		if u+w > n {
			return s[:i]
		}
		u += w
	}
	return s
}

// ---- batch ----

type event struct {
	Type string         `json:"type"`
	At   string         `json:"at"`
	Data map[string]any `json:"data"`
}

type batch struct {
	Schema  int      `json:"schema"`
	Version string   `json:"version"`
	OS      string   `json:"os"`
	Arch    string   `json:"arch"`
	Events  []event  `json:"events"`
	Samples []Sample `json:"samples"`
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p*float64(len(sorted))+0.999999) - 1
	return sorted[max(0, min(i, len(sorted)-1))]
}

func cpuSeconds() float64 {
	s := []metrics.Sample{{Name: "/cpu/classes/user:cpu-seconds"}, {Name: "/cpu/classes/gc/total:cpu-seconds"}}
	metrics.Read(s)
	var t float64
	for _, x := range s {
		if x.Value.Kind() == metrics.KindFloat64 {
			t += x.Value.Float64()
		}
	}
	return t
}

// build assembles the batch from the taken state and the crash files; sentFiles lists what to
// delete after a successful send.
func build(st state, now time.Time) (b batch, sentFiles []string) {
	ver := "dev"
	if p := version.Load(); p != nil {
		ver = *p
	}
	at := now.UTC().Format(time.RFC3339)
	b = batch{Schema: 1, Version: ver, OS: runtime.GOOS, Arch: runtime.GOARCH, Samples: st.Samples}
	if b.Samples == nil {
		b.Samples = []Sample{}
	}
	d := spoolDir()
	if _, err := os.Stat(filepath.Join(d, "first_run")); err != nil {
		b.Events = append(b.Events, event{"first_run", at, map[string]any{}})
		sentFiles = append(sentFiles, "+first_run")
	}
	m, _ := filepath.Glob(filepath.Join(d, "crash-*.json"))
	for _, f := range m {
		raw, err := os.ReadFile(f)
		var c crash
		if err != nil || json.Unmarshal(raw, &c) != nil {
			sentFiles = append(sentFiles, f) // unreadable: drop it
			continue
		}
		b.Events = append(b.Events, event{"crash", c.At, map[string]any{"panicType": c.Type, "stack": c.Stack}})
		sentFiles = append(sentFiles, f)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	up := now.Sub(startedAt).Seconds()
	cpu := cpuSeconds()
	health := map[string]any{
		"version": ver, "os": runtime.GOOS, "arch": runtime.GOARCH, "uptimeSeconds": int(up),
		"cpuSeconds": cpu, "cpuPercent": cpu / max(up, 1) * 100,
		"heapBytes": ms.HeapAlloc, "sysBytes": ms.Sys,
	}
	// The api takes primitive values only: counts are flat keys like "decisions.warden.allow".
	for c, m := range st.Counts {
		for dec, n := range m {
			health["decisions."+c+"."+dec] = n
		}
	}
	b.Events = append(b.Events, event{"health", at, health})
	comps := make([]string, 0, len(st.Dur))
	for c := range st.Dur {
		comps = append(comps, c)
	}
	sort.Strings(comps)
	for _, c := range comps {
		d := append([]float64(nil), st.Dur[c]...)
		sort.Float64s(d)
		b.Events = append(b.Events, event{"timing", at, map[string]any{
			"component": c, "count": len(d), "p50Ms": percentile(d, 0.5), "p95Ms": percentile(d, 0.95),
		}})
	}
	if len(b.Events) > 200 {
		b.Events = b.Events[:200]
	}
	return b, sentFiles
}

// ---- module ----

type api interface {
	Config(ctx context.Context) (*hostclient.Config, error)
	Do(ctx context.Context, method, path string, in, out any) error
}

type module struct{}

func (*module) Name() string { return "telemetry" }

func (*module) Start(ctx context.Context, c *hostclient.Client) error {
	if spoolDir() == "" {
		<-ctx.Done()
		return nil
	}
	run(ctx, c, syncEvery)
	return nil
}

func run(ctx context.Context, c api, every time.Duration) {
	mem.load()
	defer func() {
		if enabled.Load() {
			mem.save()
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-queue:
				mem.add(r)
			}
		}
	}()
	var next time.Time
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		syncFlag(ctx, c)
		if enabled.Load() {
			if !time.Now().Before(next) {
				if err := send(ctx, c); err != nil {
					next = time.Now().Add(retryAfter)
				} else {
					next = time.Now().Add(sendEvery)
				}
			}
			mem.save()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// syncFlag reads the last synced flag. A failed sync keeps the previous value; a missing
// dataCollection block means false, and turning off clears the spool.
func syncFlag(ctx context.Context, c api) {
	cfg, err := c.Config(ctx)
	if err != nil {
		return
	}
	on := cfg.DataCollection != nil && cfg.DataCollection.ImproveManar
	if enabled.Swap(on) != on {
		epoch.Add(1)
	}
	if !on {
		clearAll()
	}
}

func send(ctx context.Context, c api) error {
	st := mem.peek()
	b, files := build(st, time.Now())
	err := c.Do(ctx, http.MethodPost, telemetryPath, b, nil)
	var se *hostclient.StatusError
	rejected := errors.As(err, &se) && se.Code == http.StatusBadRequest
	if err != nil && !rejected {
		return err // samples and crash files stay until a 2xx
	}
	// A 400 means the api will never accept this batch: drop it so one bad file cannot block the
	// device. A 2xx also marks first_run; a 400 does not.
	mem.remove(st)
	for _, f := range files {
		if f == "+first_run" {
			if rejected {
				continue
			}
			_ = os.MkdirAll(spoolDir(), 0o700)
			_ = os.WriteFile(filepath.Join(spoolDir(), "first_run"), nil, 0o600)
		} else {
			_ = os.Remove(f)
		}
	}
	return err
}

// SampleHost returns the host of a web address that may be sampled: an http(s) URL whose host
// name has a dot and is not an IP address. Search queries and free text give "".
func SampleHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	if h := strings.ToLower(u.Hostname()); eligibleHost(h) {
		return h
	}
	return ""
}

func eligibleHost(h string) bool {
	if !strings.Contains(h, ".") || strings.ContainsAny(h, " /@?#:\t\n") {
		return false
	}
	_, err := netip.ParseAddr(h)
	return err != nil
}
