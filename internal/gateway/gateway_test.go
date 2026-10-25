package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var discard = slog.New(slog.DiscardHandler)

func TestHostAllowed(t *testing.T) {
	rules := []string{"graph.microsoft.com", "*.Example.org"}
	for host, want := range map[string]bool{
		"graph.microsoft.com":     true,
		"GRAPH.Microsoft.COM":     true,
		"graph.microsoft.com.":    true,
		"login.microsoft.com":     false,
		"x.graph.microsoft.com":   false, // exact rule, no subdomains
		"api.example.org":         true,
		"a.b.example.org":         true,
		"example.org":             false, // wildcard needs one label or more
		"badexample.org":          false,
		"example.org.evil.com":    false,
		"":                        false,
		"api.example.org.evil.io": false,
	} {
		if _, got := HostAllowed(rules, host); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
	if _, ok := HostAllowed([]string{"*."}, "anything"); ok {
		t.Error(`rule "*." must match nothing`)
	}
}

func TestBlocked(t *testing.T) {
	overlay := netip.MustParsePrefix("100.88.0.0/16")
	for s, want := range map[string]bool{
		"10.1.2.3": true, "172.16.0.1": true, "192.168.1.1": true, "127.0.0.1": true,
		"169.254.169.254": true, "100.64.0.1": true, "100.88.0.17": true, "0.0.0.0": true,
		"255.255.255.255": true, "224.0.0.1": true, "::": true, "::1": true, "fe80::1": true,
		"fc00::1": true, "::ffff:10.0.0.1": true, "::ffff:127.0.0.1": true, "64:ff9b::a00:1": true,
		"8.8.8.8": false, "20.190.160.1": false, "2606:4700::1111": false, "::ffff:8.8.8.8": false,
	} {
		if got := Blocked(netip.MustParseAddr(s), overlay); got != want {
			t.Errorf("Blocked(%s) = %v, want %v", s, got, want)
		}
	}
	if !Blocked(netip.MustParseAddr("203.0.113.9"), netip.MustParsePrefix("203.0.113.0/24")) {
		t.Error("an overlay outside CGNAT must still be blocked")
	}
}

type fakeNet struct {
	mu    sync.Mutex
	calls [][]WGPeer
	err   error
}

func (f *fakeNet) SetPeers(p []WGPeer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, p)
	return f.err
}

func (f *fakeNet) last() []WGPeer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

type closeRec struct{ closed atomic.Bool }

func (c *closeRec) Close() error { c.closed.Store(true); return nil }

func newKey(t *testing.T) string {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func tokenFile(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSyncApply(t *testing.T) {
	ka, kb := newKey(t), newKey(t)
	a := Peer{ID: "a", PublicKey: ka, Address: "100.88.0.17/32", State: "active", AllowHosts: []string{"x.com"}}
	b := Peer{ID: "b", PublicKey: kb, Address: "100.88.0.18/32", State: "cut"}
	bad := Peer{ID: "bad", PublicKey: "nope", Address: "100.88.0.19/32", State: "active"}
	outside := Peer{ID: "out", PublicKey: newKey(t), Address: "10.0.0.5/32", State: "active"}

	var mu sync.Mutex
	var afters []string
	responses := []any{
		PeerSet{Version: 10, Full: true, Peers: []Peer{a, b, bad, outside}},
		PeerSet{Version: 11, Peers: []Peer{{ID: "b", PublicKey: kb, Address: b.Address, State: "active"}}},
		PeerSet{Version: 12, Peers: []Peer{{ID: "a", PublicKey: ka, Address: a.Address, State: "cut"}}},
		500,
		PeerSet{Version: 20, Full: true, Peers: nil},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" || r.URL.Path != "/internal/v1/edge/peers" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		afters = append(afters, r.URL.Query().Get("after"))
		resp := responses[0]
		responses = responses[1:]
		mu.Unlock()
		if code, ok := resp.(int); ok {
			w.WriteHeader(code)
			return
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	fn := &fakeNet{}
	m := &Metrics{}
	reg := NewRegistry(netip.MustParsePrefix("100.88.0.0/16"), discard)
	s := &Syncer{APIURL: srv.URL, TokenFile: tokenFile(t), Client: srv.Client(), Registry: reg, Net: fn, Metrics: m, Log: discard}
	ctx := context.Background()
	src := func(p Peer) netip.Addr { return netip.MustParsePrefix(p.Address).Addr() }

	// Full: only the valid active peer is configured; ready.
	if s.Ready() {
		t.Fatal("ready before the first sync")
	}
	if err := s.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fn.last(); len(got) != 1 || got[0].PublicKey.String() != ka || got[0].Addr != src(a) {
		t.Fatalf("after full: %+v", got)
	}
	if !s.Ready() {
		t.Fatal("not ready after the full sync")
	}
	connA := &closeRec{}
	if _, _, ok := reg.Acquire(src(a), connA); !ok {
		t.Fatal("active peer a refused")
	}
	if _, _, ok := reg.Acquire(src(b), &closeRec{}); ok {
		t.Fatal("cut peer b accepted")
	}

	// Delta: b becomes active, a untouched.
	if err := s.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fn.last()) != 2 || connA.closed.Load() {
		t.Fatalf("after delta: %d peers, a closed %v", len(fn.last()), connA.closed.Load())
	}

	// Delta: a cut; its connection is closed and it is refused.
	if err := s.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if !connA.closed.Load() {
		t.Fatal("cut did not close a's connection")
	}
	if _, _, ok := reg.Acquire(src(a), &closeRec{}); ok {
		t.Fatal("cut peer a accepted")
	}
	if m.CutsApplied.Load() != 1 || m.PeersActive.Load() != 1 {
		t.Fatalf("metrics: cuts %d active %d", m.CutsApplied.Load(), m.PeersActive.Load())
	}

	// Error: last state kept, nothing configured.
	calls := len(fn.calls)
	if err := s.Poll(ctx); err == nil {
		t.Fatal("500 must be an error")
	}
	if len(fn.calls) != calls || reg.Active() != 1 {
		t.Fatal("an error changed the state")
	}

	// Full replacement without b: b removed.
	connB := &closeRec{}
	reg.Acquire(src(b), connB)
	if err := s.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fn.last()) != 0 || !connB.closed.Load() {
		t.Fatal("full set did not remove the missing peer")
	}
	if want := "0,10,11,12,12"; strings.Join(afters, ",") != want {
		t.Fatalf("after= sequence %v, want %s", afters, want)
	}
}

func TestSyncNetErrorRetriesSameVersion(t *testing.T) {
	var after atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after.Store(r.URL.Query().Get("after"))
		json.NewEncoder(w).Encode(PeerSet{Version: 5, Full: true})
	}))
	defer srv.Close()
	fn := &fakeNet{err: errors.New("netlink down")}
	s := &Syncer{APIURL: srv.URL, TokenFile: tokenFile(t), Client: srv.Client(), Net: fn, Metrics: &Metrics{}, Log: discard,
		Registry: NewRegistry(netip.MustParsePrefix("100.88.0.0/16"), discard)}
	if err := s.Poll(context.Background()); err == nil || s.Ready() {
		t.Fatal("a wg0 error must fail the poll and keep the gateway unready")
	}
	fn.err = nil
	s.Poll(context.Background())
	if after.Load() != "0" || !s.Ready() {
		t.Fatalf("retry used after=%v ready=%v", after.Load(), s.Ready())
	}
}

func TestEventsDropOldest(t *testing.T) {
	m := &Metrics{}
	e := &Events{Max: 3, Metrics: m}
	for i := range 5 {
		e.Add(Event{Port: i})
	}
	if m.EventsDropped.Load() != 2 || len(e.q) != 3 || e.q[0].Port != 2 || e.q[2].Port != 4 {
		t.Fatalf("dropped %d queue %+v", m.EventsDropped.Load(), e.q)
	}
}

func TestEventsBatching(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	fail := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" || fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var body struct{ Events []Event }
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		sizes = append(sizes, len(body.Events))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	m := &Metrics{}
	e := &Events{APIURL: srv.URL, TokenFile: tokenFile(t), Client: srv.Client(), Metrics: m, Log: discard, Max: 2000}
	for i := range 1200 {
		e.Add(Event{PeerID: "p", Port: i})
	}
	fail.Store(true)
	if err := e.Flush(context.Background()); err == nil || len(e.q) != 1200 {
		t.Fatalf("failed flush must keep the events: err %v, queued %d", err, len(e.q))
	}
	fail.Store(false)
	if err := e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sizes) != "[500 500 200]" || len(e.q) != 0 || m.EventsDropped.Load() != 0 {
		t.Fatalf("batches %v, left %d", sizes, len(e.q))
	}
}

func TestMetricsText(t *testing.T) {
	m := &Metrics{}
	m.PeersActive.Store(3)
	m.Decision("denied", "sni_mismatch")
	m.Decision("denied", "sni_mismatch")
	m.Synced(time.Now().Add(-2 * time.Second))
	rec := httptest.NewRecorder()
	m.Handler(func() bool { return false }).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		"manar_edge_gateway_peers_active 3\n",
		`manar_edge_gateway_proxy_decisions_total{decision="denied",reason="sni_mismatch"} 2`,
		"manar_edge_gateway_sync_lag_seconds 2",
		"manar_edge_gateway_events_dropped_total 0\n",
		"manar_edge_gateway_cuts_applied_total 0\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q:\n%s", want, out)
		}
	}
	rec = httptest.NewRecorder()
	m.Handler(func() bool { return false }).ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz before sync: %d", rec.Code)
	}
}
