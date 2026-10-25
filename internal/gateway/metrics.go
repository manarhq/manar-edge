package gateway

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics are the gateway's Prometheus series, written in the text exposition format by hand to
// keep the binary free of a client library for five series.
type Metrics struct {
	PeersActive   atomic.Int64
	CutsApplied   atomic.Int64
	EventsDropped atomic.Int64
	RelayRefused  atomic.Int64
	PeersRejected atomic.Int64
	lastSync      atomic.Int64 // unix nanoseconds of the last applied sync response

	mu        sync.Mutex
	decisions map[[2]string]int64
}

// Synced records a successfully applied sync response.
func (m *Metrics) Synced(t time.Time) { m.lastSync.Store(t.UnixNano()) }

// Decision counts one proxy decision.
func (m *Metrics) Decision(decision, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.decisions == nil {
		m.decisions = map[[2]string]int64{}
	}
	m.decisions[[2]string{decision, reason}]++
}

func (m *Metrics) write(w io.Writer, now time.Time) {
	lag := "+Inf"
	if t := m.lastSync.Load(); t != 0 {
		lag = fmt.Sprintf("%g", now.Sub(time.Unix(0, t)).Seconds())
	}
	series := []struct{ name, typ, help, value string }{
		{"manar_edge_gateway_peers_active", "gauge", "WireGuard peers configured as active.", fmt.Sprint(m.PeersActive.Load())},
		{"manar_edge_gateway_cuts_applied_total", "counter", "Peers removed from the active set (cut or missing).", fmt.Sprint(m.CutsApplied.Load())},
		{"manar_edge_gateway_sync_lag_seconds", "gauge", "Seconds since the last applied peer sync.", lag},
		{"manar_edge_gateway_events_dropped_total", "counter", "Egress events dropped because the queue was full.", fmt.Sprint(m.EventsDropped.Load())},
		{"manar_edge_gateway_peers_rejected", "gauge", "Active peers not configured (invalid, or address or key shared).", fmt.Sprint(m.PeersRejected.Load())},
		{"manar_edge_gateway_relay_refused_total", "counter", "Relay connections refused (not an active peer, or over the connection cap).", fmt.Sprint(m.RelayRefused.Load())},
	}
	for _, s := range series {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %s\n", s.name, s.help, s.name, s.typ, s.name, s.value)
	}
	const d = "manar_edge_gateway_proxy_decisions_total"
	fmt.Fprintf(w, "# HELP %s Egress proxy decisions by result.\n# TYPE %s counter\n", d, d)
	m.mu.Lock()
	keys := make([][2]string, 0, len(m.decisions))
	for k := range m.decisions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	for _, k := range keys {
		fmt.Fprintf(w, "%s{decision=%q,reason=%q} %d\n", d, k[0], k[1], m.decisions[k])
	}
	m.mu.Unlock()
}

// Handler serves /healthz, /readyz and /metrics.
func (m *Metrics) Handler(ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "waiting for the first full peer sync", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		m.write(w, time.Now())
	})
	return mux
}
