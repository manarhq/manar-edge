// Package door is DOOR, the local LLM gateway of a personal device (127.0.0.1:8480). Tools whose
// base URL Manar points here (Codex CLI today) send their model calls through it. DOOR forwards each
// call to the provider with the user's own credentials, and on the way it (1) masks or blocks
// secrets in the prompt, (2) reads token usage from the response for the spend tracker and (3)
// refuses calls of a tool the owner's monthly cap paused. Prompt and response text is never stored
// or logged.
package door

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

// Listen is where DOOR listens. Protect routes tool base URLs here.
const Listen = "127.0.0.1:8480"

const (
	maxRequestBody = 32 << 20
	proofHeader    = "X-Manar-Door-Proof"
	challengeHdr   = "X-Manar-Door-Challenge"
)

// proofKey is a random per-process secret. Only this process can answer a health challenge, so a
// local program that grabbed port 8480 while the service was restarting cannot pass as DOOR.
var proofKey = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}()

func proof(nonce string) string {
	m := hmac.New(sha256.New, proofKey)
	m.Write([]byte(nonce))
	return hex.EncodeToString(m.Sum(nil))
}

// Healthy asks the gateway at base whether it is this process's DOOR (not just anything that
// answers /healthz on the port).
func Healthy(base string) bool {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return false
	}
	nonce := hex.EncodeToString(b)
	req, err := http.NewRequest(http.MethodGet, base+"/healthz", nil)
	if err != nil {
		return false
	}
	req.Header.Set(challengeHdr, nonce)
	res, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode == 200 && hmac.Equal([]byte(res.Header.Get(proofHeader)), []byte(proof(nonce)))
}

type Settings = hostclient.DoorSettings

type upstream struct {
	provider string
	url      *url.URL
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }

type Door struct {
	anthropic, openai, gemini upstream
	transport                 http.RoundTripper
	settings                  atomic.Pointer[Settings]
	rec                       *recorder
	rp                        *httputil.ReverseProxy
}

func New() *Door {
	d := &Door{
		anthropic: upstream{"anthropic", mustURL("https://api.anthropic.com")},
		openai:    upstream{"openai", mustURL("https://api.openai.com")},
		gemini:    upstream{"gemini", mustURL("https://generativelanguage.googleapis.com")},
		transport: &http.Transport{
			Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Minute, IdleConnTimeout: 90 * time.Second,
		},
		rec: newRecorder(),
	}
	d.settings.Store(&Settings{Secrets: "mask"})
	d.rp = &httputil.ReverseProxy{
		Rewrite:        d.rewrite,
		Transport:      d.transport,
		FlushInterval:  -1, // SSE goes through as it arrives
		ModifyResponse: d.watchResponse,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("manar-edge: door: provider unreachable: %v", err)
			writeErr(w, http.StatusBadGateway, "manar_provider_unreachable", "Manar could not reach the model provider.")
		},
	}
	return d
}

type ctxKey struct{}
type callInfo struct {
	tool string
	up   upstream
}

func (d *Door) route(path string) (upstream, bool) {
	switch {
	case path == "/v1/messages" || strings.HasPrefix(path, "/v1/messages/") || path == "/v1/complete":
		return d.anthropic, true
	case strings.HasPrefix(path, "/v1beta/") || strings.HasPrefix(path, "/v1alpha/") || strings.HasPrefix(path, "/v1/models/") && strings.Contains(path, ":"):
		return d.gemini, true
	case strings.HasPrefix(path, "/v1/"):
		return d.openai, true
	}
	return upstream{}, false
}

// toolOf names the tool from its User-Agent. It is a label for the spend page, not an identity:
// any local program can claim any name.
func toolOf(ua string) string {
	l := strings.ToLower(ua)
	for _, t := range []struct{ sub, id string }{
		{"codex", "host.codex-cli"}, {"gemini", "host.gemini-cli"}, {"copilot", "host.copilot-cli"},
		{"claude", "host.claude-code"}, {"cursor", "host.cursor"}, {"windsurf", "host.windsurf"},
	} {
		if strings.Contains(l, t.sub) {
			return t.id
		}
	}
	return "other:unknown"
}

func (d *Door) rewrite(pr *httputil.ProxyRequest) {
	ci := pr.In.Context().Value(ctxKey{}).(callInfo)
	pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = ci.up.url.Scheme, ci.up.url.Host, ci.up.url.Host
	for k := range pr.Out.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-manar-") {
			pr.Out.Header.Del(k)
		}
	}
	// Let the transport negotiate gzip itself, so responses reach the usage reader decoded.
	pr.Out.Header.Del("Accept-Encoding")
}

func (d *Door) watchResponse(res *http.Response) error {
	ci, _ := res.Request.Context().Value(ctxKey{}).(callInfo)
	if res.StatusCode/100 != 2 {
		return nil
	}
	sse := strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream")
	res.Body = newUsageTee(res.Body, sse, func(u usage) { d.rec.usage(ci.tool, ci.up.provider, u) })
	return nil
}

func (d *Door) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		if n := r.Header.Get(challengeHdr); n != "" && len(n) <= 64 {
			w.Header().Set(proofHeader, proof(n))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","service":"door"}`)
		return
	}
	up, ok := d.route(r.URL.Path)
	if !ok {
		writeErr(w, http.StatusNotFound, "manar_unknown_route", "DOOR serves model API calls only.")
		return
	}
	tool := toolOf(r.UserAgent())
	set := d.settings.Load()
	for _, p := range set.Paused {
		if p == tool {
			writeErr(w, http.StatusTooManyRequests, "manar_paused", "Manar paused this tool: the monthly AI spend cap is reached. Ask your workspace admin.")
			return
		}
	}
	if r.Body != nil && r.Body != http.NoBody {
		body, err := d.guardBody(w, r, tool, set.Secrets == "block")
		if err != nil {
			return // guardBody has answered
		}
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
		r.Header.Set("Content-Length", itoa(len(body)))
	}
	d.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, callInfo{tool, up})))
}

// guardBody reads the request body (bounded), scans it for secrets and returns the body to send.
// In block mode a secret refuses the call; otherwise it is masked. A body it cannot read as text
// (an encoding other than gzip) is passed on unscanned in mask mode and refused in block mode.
func (d *Door) guardBody(w http.ResponseWriter, r *http.Request, tool string, block bool) ([]byte, error) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "request_too_large", "The request is too large for DOOR to check.")
		return nil, err
	}
	switch enc := strings.ToLower(r.Header.Get("Content-Encoding")); enc {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err == nil {
			b, err = io.ReadAll(io.LimitReader(zr, maxRequestBody))
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_body", "The request body could not be read.")
			return nil, err
		}
		r.Header.Del("Content-Encoding")
	default:
		if block {
			writeErr(w, http.StatusBadRequest, "manar_unscannable", "Manar is set to block secrets and cannot check this request encoding.")
			return nil, errors.New("unscannable")
		}
		d.rec.unscanned()
		return b, nil
	}
	found, out := Scan(b)
	if len(found) == 0 {
		return b, nil
	}
	for _, f := range found {
		d.rec.guard(tool, f.Kind, map[bool]string{true: "blocked", false: "masked"}[block], f.Sample)
	}
	if block {
		writeErr(w, http.StatusBadRequest, "manar_secret_blocked", "Manar blocked this request: it contains "+found[0].Kind+" (a secret). Remove it and try again.")
		return nil, errors.New("blocked")
	}
	return out, nil
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": code, "message": msg}})
}
