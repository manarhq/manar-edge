package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	gatewayListen = "127.0.0.1:8480"
	gatewayURL    = "http://" + gatewayListen
	maxBody       = 10 << 20
)

// idPattern bounds task and approval ids so they can go into an upstream path without escaping:
// no '/', no '.', so no "..".
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,200}$`)

// forwardHeaders is the allowlist of request headers sent to Manar. Everything else, every
// X-Manar-* header and all credentials included, is dropped.
var forwardHeaders = []string{
	"Accept", "Accept-Encoding", "Content-Type", "User-Agent", "Last-Event-Id",
	"Anthropic-Version", "Anthropic-Beta", "Openai-Beta", "Mcp-Session-Id", "Mcp-Protocol-Version",
}

// mtlsTransport talks to Manar at manarAddress with the enrollment identity. The enrollment CA
// chain is the only trust anchor, the server name is manarServerName, and proxy env is ignored.
func mtlsTransport(dir string, st *State) (*http.Transport, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, fileCert), filepath.Join(dir, fileKey))
	if err != nil {
		return nil, errors.New("cannot load the agent certificate and key from the state dir")
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, fileCA))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("no certificate in the enrollment CA chain")
	}
	return newMTLSTransport(cert, pool, st.Edge.ManarServerName, st.Edge.ManarAddress), nil
}

func newMTLSTransport(cert tls.Certificate, roots *x509.CertPool, serverName, addr string) *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
			ServerName:   serverName,
			MinVersion:   tls.VersionTLS12,
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 16,
	}
}

type localGateway struct {
	host      string // manarServerName, used for the upstream URL and Host header
	transport http.RoundTripper
	task      string
	agent     string
}

func (g *localGateway) handler() http.Handler {
	fixed := func(p string) func(*http.Request) (string, bool) {
		return func(*http.Request) (string, bool) { return p, true }
	}
	mcp := g.proxy(func(*http.Request) (string, bool) { return "/agent/v1/tasks/" + g.task + "/mcp", true }, true, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "agent": g.agent, "taskId": g.task})
	})
	mux.Handle("POST /v1/chat/completions", g.proxy(fixed("/agent/v1/llm/chat/completions"), true, nil))
	mux.Handle("POST /v1/messages", g.proxy(fixed("/agent/v1/llm/anthropic/v1/messages"), true, nil))
	mux.Handle("GET /v1/models", g.proxy(fixed("/agent/v1/llm/models"), false, modelsFallback))
	mux.Handle("POST /mcp", mcp)
	mux.Handle("GET /mcp", mcp)
	mux.Handle("DELETE /mcp", mcp)
	// Used by `manar-edge hook claude-code`, which runs as the agent user and cannot read the key.
	mux.Handle("POST /agent/v1/authorize", g.pinTask(g.proxy(fixed("/agent/v1/authorize"), true, nil)))
	mux.Handle("GET /agent/v1/approvals/{id}", g.proxy(func(r *http.Request) (string, bool) {
		id := r.PathValue("id")
		return "/agent/v1/approvals/" + id, idPattern.MatchString(id)
	}, false, nil))
	return mux
}

func (g *localGateway) proxy(target func(*http.Request) (string, bool), needTask bool, modify func(*http.Response) error) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			path, _ := target(pr.In)
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = g.host
			pr.Out.URL.Path, pr.Out.URL.RawPath = path, ""
			pr.Out.Host = g.host
			h := http.Header{}
			for _, k := range forwardHeaders {
				if v := pr.In.Header.Values(k); len(v) > 0 {
					h[k] = v
				}
			}
			if g.task != "" {
				h.Set("X-Manar-Task-Id", g.task)
			}
			pr.Out.Header = h
		},
		Transport:      g.transport,
		FlushInterval:  -1, // SSE and chunked responses go through as they arrive
		ModifyResponse: modify,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				writeJSONError(w, http.StatusRequestEntityTooLarge, "request_too_large")
				return
			}
			log.Printf("manar unreachable: %v", err)
			writeJSONError(w, http.StatusBadGateway, "manar_unreachable")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if needTask && g.task == "" {
			writeJSONError(w, http.StatusPreconditionFailed, "manar_task_required")
			return
		}
		if _, ok := target(r); !ok {
			writeJSONError(w, http.StatusBadRequest, "invalid_id")
			return
		}
		if r.ContentLength > maxBody {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		rp.ServeHTTP(w, r)
	})
}

// pinTask lets an authorize request through only when its taskId is the gateway's task, so the
// agent cannot ask Manar about another task with this identity. The body is not rewritten.
func (g *localGateway) pinTask(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.task == "" {
			writeJSONError(w, http.StatusPreconditionFailed, "manar_task_required")
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
		if err != nil || len(b) > 64<<10 {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		var body struct {
			TaskID string `json:"taskId"`
		}
		if json.Unmarshal(b, &body) != nil || body.TaskID != g.task {
			writeJSONError(w, http.StatusForbidden, "task_mismatch")
			return
		}
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
		next.ServeHTTP(w, r)
	})
}

// modelsFallback answers a fixed, empty list while manar-api has no models endpoint yet.
func modelsFallback(res *http.Response) error {
	if res.StatusCode != http.StatusNotFound {
		return nil
	}
	_ = res.Body.Close()
	body := `{"object":"list","data":[]}`
	res.StatusCode, res.Status = http.StatusOK, "200 OK"
	res.Header = http.Header{"Content-Type": {"application/json"}, "Content-Length": {strconv.Itoa(len(body))}}
	res.ContentLength = int64(len(body))
	res.Body = io.NopCloser(strings.NewReader(body))
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": code, "statusCode": status})
}

// serveGateway runs the local gateway for one agent until ctx ends.
func serveGateway(ctx context.Context, base, arg string) error {
	dir, st, err := resolveAgent(base, arg)
	if err != nil {
		return err
	}
	tr, err := mtlsTransport(dir, st)
	if err != nil {
		return err
	}
	task := os.Getenv("MANAR_TASK_ID")
	if task == "" {
		task = st.Task
	}
	if task != "" && !idPattern.MatchString(task) {
		return errors.New("task id has characters this gateway does not accept")
	}
	g := &localGateway{host: st.Edge.ManarServerName, transport: tr, task: task, agent: st.Name}
	ln, err := net.Listen("tcp", gatewayListen)
	if err != nil {
		return err
	}
	listeners := []net.Listener{ln}
	hl, err := hookListener(st) // Linux: the unix socket the hook uses; nil on Windows
	if err != nil {
		ln.Close()
		return err
	}
	if hl != nil {
		listeners = append(listeners, hl)
	}
	srv := &http.Server{Handler: g.handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("local gateway for %s on %s (task %q)", st.Name, gatewayListen, task)
	errc := make(chan error, len(listeners))
	for _, l := range listeners {
		go func() { errc <- srv.Serve(l) }()
	}
	for range listeners {
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
			_ = srv.Close()
			return err
		}
	}
	return nil
}
