package door

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"

	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

type ukey struct{ tool, provider, model string }
type gkey struct{ tool, kind, action string }

type uval struct{ Requests, In, Out int64 }
type gval struct {
	Count  int64
	Sample string
}

// batch is what POST /host/v1/ai-usage carries. The id makes a resend after a lost reply count once.
type batch struct {
	BatchID string      `json:"batchId"`
	Usage   []usageItem `json:"usage"`
	Guard   []guardItem `json:"guard"`
}

type usageItem struct {
	ToolID       string `json:"toolId"`
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	Requests     int64  `json:"requests"`
	InputTokens  int64  `json:"inputTokens"`
	OutputTokens int64  `json:"outputTokens"`
}

type guardItem struct {
	ToolID string `json:"toolId"`
	Kind   string `json:"kind"`
	Action string `json:"action"`
	Count  int64  `json:"count"`
	Sample string `json:"sample"`
}

// cleanModel keeps what the API accepts for a model name: letters, digits and . _ : / -, at most 100.
func cleanModel(m string) string {
	b := []byte(m)
	if len(b) > 100 {
		b = b[:100]
	}
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._:/-", c) >= 0) {
			b[i] = '_'
		}
	}
	if len(b) == 0 {
		return "unknown"
	}
	return string(b)
}

// recorder sums usage in memory and hands it to the API in batches.
// ponytail: a crash loses up to one flush interval of counts; persist to disk if that matters.
type recorder struct {
	mu      sync.Mutex
	usages  map[ukey]*uval
	guards  map[gkey]*gval
	pending *batch // sent but not acknowledged: resent unchanged
	skipped int64
}

func newRecorder() *recorder {
	return &recorder{usages: map[ukey]*uval{}, guards: map[gkey]*gval{}}
}

func (r *recorder) unscanned() { r.mu.Lock(); r.skipped++; r.mu.Unlock() }

func (r *recorder) usage(tool, provider string, u usage) {
	model := u.Model
	if model == "" {
		model = "unknown"
	}
	model = cleanModel(model)
	r.mu.Lock()
	defer r.mu.Unlock()
	k := ukey{tool, provider, model}
	v := r.usages[k]
	if v == nil {
		v = &uval{}
		r.usages[k] = v
	}
	v.Requests++
	v.In += u.In
	v.Out += u.Out
}

func (r *recorder) guard(tool, kind, action, sample string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := gkey{tool, kind, action}
	v := r.guards[k]
	if v == nil {
		v = &gval{Sample: sample}
		r.guards[k] = v
	}
	v.Count++
}

// takeBatch moves what has been counted into a pending batch, unless one is still unacknowledged.
func (r *recorder) takeBatch() *batch {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil {
		return r.pending
	}
	if len(r.usages) == 0 && len(r.guards) == 0 {
		return nil
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	b := &batch{BatchID: hex.EncodeToString(id), Usage: []usageItem{}, Guard: []guardItem{}}
	for k, v := range r.usages {
		b.Usage = append(b.Usage, usageItem{k.tool, k.provider, k.model, v.Requests, v.In, v.Out})
	}
	for k, v := range r.guards {
		b.Guard = append(b.Guard, guardItem{k.tool, k.kind, k.action, v.Count, v.Sample})
	}
	r.usages, r.guards = map[ukey]*uval{}, map[gkey]*gval{}
	r.pending = b
	return b
}

func (r *recorder) acked(b *batch) {
	r.mu.Lock()
	if r.pending == b {
		r.pending = nil
	}
	r.mu.Unlock()
}

type sender interface {
	Do(ctx context.Context, method, path string, in, out any) error
}

// flush sends the pending batch (a new one if none) to the API. On failure it stays pending.
func (r *recorder) flush(ctx context.Context, s sender) error {
	b := r.takeBatch()
	if b == nil {
		return nil
	}
	err := s.Do(ctx, http.MethodPost, "/ai-usage", b, nil)
	var se *hostclient.StatusError
	if errors.As(err, &se) && se.Code >= 400 && se.Code < 500 && se.Code != 429 {
		// The API refused this report for good (not approved, out of bounds): resending cannot help.
		r.acked(b)
		return err
	}
	if err != nil {
		return err
	}
	r.acked(b)
	return nil
}
