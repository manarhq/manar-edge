package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testServerName = "agents.manar.test"

type testPKI struct {
	roots      *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, mod func(*x509.Certificate)) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature,
		}
		mod(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	p := &testPKI{roots: x509.NewCertPool()}
	p.roots.AddCert(ca)
	p.serverCert = issue(2, func(c *x509.Certificate) {
		c.DNSNames = []string{testServerName}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	p.clientCert = issue(3, func(c *x509.Certificate) {
		c.Subject.CommonName = "agent://acme/soc-1"
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})
	return p
}

// newTestManar starts an mTLS server that requires a client certificate from the test CA.
func newTestManar(t *testing.T, p *testPKI, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{p.serverCert},
		ClientCAs:    p.roots, ClientAuth: tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newTestGateway(t *testing.T, p *testPKI, manar *httptest.Server, task string) *httptest.Server {
	t.Helper()
	addr := strings.TrimPrefix(manar.URL, "https://")
	g := &localGateway{host: testServerName, task: task, agent: "acme-soc-1",
		transport: newMTLSTransport(p.clientCert, p.roots, testServerName, addr)}
	gw := httptest.NewServer(g.handler())
	t.Cleanup(gw.Close)
	return gw
}

type seen struct {
	method, path, task, auth, apiKey, host, body string
	clientCN                                     string
}

func recordingManar(t *testing.T, p *testPKI, out chan<- seen) *httptest.Server {
	return newTestManar(t, p, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		out <- seen{r.Method, r.URL.Path, r.Header.Get("X-Manar-Task-Id"), r.Header.Get("Authorization"),
			r.Header.Get("X-Api-Key"), r.Host, string(b), r.TLS.PeerCertificates[0].Subject.CommonName}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
}

func TestGatewayRoutesAndHeaders(t *testing.T) {
	p := newTestPKI(t)
	got := make(chan seen, 1)
	gw := newTestGateway(t, p, recordingManar(t, p, got), "task-123")

	cases := []struct{ method, local, upstream string }{
		{"POST", "/v1/chat/completions", "/agent/v1/llm/chat/completions"},
		{"POST", "/v1/messages", "/agent/v1/llm/anthropic/v1/messages"},
		{"GET", "/v1/models", "/agent/v1/llm/models"},
		{"POST", "/mcp", "/agent/v1/tasks/task-123/mcp"},
		{"GET", "/mcp", "/agent/v1/tasks/task-123/mcp"},
		{"DELETE", "/mcp", "/agent/v1/tasks/task-123/mcp"},
		{"POST", "/agent/v1/authorize", "/agent/v1/authorize"},
		{"GET", "/agent/v1/approvals/ap-1", "/agent/v1/approvals/ap-1"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, gw.URL+c.local, strings.NewReader(`{"model":"x"}`))
		req.Header.Set("Authorization", "Bearer sk-should-not-leave")
		req.Header.Set("X-Api-Key", "sk-ant-should-not-leave")
		req.Header.Set("X-Manar-Task-Id", "spoofed")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("%s %s: status %d", c.method, c.local, res.StatusCode)
		}
		s := <-got
		if s.method != c.method || s.path != c.upstream {
			t.Errorf("%s %s went to %s %s, want %s", c.method, c.local, s.method, s.path, c.upstream)
		}
		if s.task != "task-123" {
			t.Errorf("%s: task header %q", c.local, s.task)
		}
		if s.auth != "" || s.apiKey != "" {
			t.Errorf("%s: auth headers forwarded: %q %q", c.local, s.auth, s.apiKey)
		}
		if s.host != testServerName || s.clientCN != "agent://acme/soc-1" {
			t.Errorf("%s: host %q client %q", c.local, s.host, s.clientCN)
		}
		if c.method == "POST" && s.body != `{"model":"x"}` {
			t.Errorf("%s: body rewritten: %q", c.local, s.body)
		}
	}
}

func TestGatewayTaskRequired(t *testing.T) {
	p := newTestPKI(t)
	got := make(chan seen, 1)
	gw := newTestGateway(t, p, recordingManar(t, p, got), "")
	for _, path := range []string{"/v1/chat/completions", "/v1/messages", "/mcp"} {
		res, err := http.Post(gw.URL+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusPreconditionFailed || !strings.Contains(string(b), "manar_task_required") {
			t.Errorf("%s: %d %s", path, res.StatusCode, b)
		}
	}
	select {
	case s := <-got:
		t.Fatalf("request reached Manar without a task: %+v", s)
	default:
	}
	res, err := http.Get(gw.URL + "/healthz")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("healthz: %v", err)
	}
}

func TestGatewayStreamsSSE(t *testing.T) {
	p := newTestPKI(t)
	release := make(chan struct{})
	manar := newTestManar(t, p, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release // the second event waits until the client has seen the first
		_, _ = io.WriteString(w, "data: second\n\n")
	}))
	gw := newTestGateway(t, p, manar, "t1")
	res, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	select {
	case l := <-lines:
		if l != "data: first" {
			t.Fatalf("first line %q", l)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("first SSE event was buffered")
	}
	close(release)
	var rest []string
	for l := range lines {
		rest = append(rest, l)
	}
	if !strings.Contains(strings.Join(rest, "\n"), "data: second") {
		t.Fatalf("second event missing: %q", rest)
	}
}

func TestGatewayBodyCap(t *testing.T) {
	p := newTestPKI(t)
	got := make(chan seen, 1)
	gw := newTestGateway(t, p, recordingManar(t, p, got), "t1")
	big := strings.Repeat("a", maxBody+1)
	res, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", res.StatusCode)
	}
	// Chunked (no Content-Length) bodies are capped too.
	pr, pw := io.Pipe()
	go func() { _, _ = io.Copy(pw, strings.NewReader(big)); pw.Close() }()
	req, _ := http.NewRequest("POST", gw.URL+"/v1/chat/completions", pr)
	res, err = http.DefaultClient.Do(req)
	if err == nil {
		res.Body.Close()
		if res.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked status %d", res.StatusCode)
		}
	}
}

func TestGatewayRejectsUntrustedServer(t *testing.T) {
	p := newTestPKI(t)
	other := newTestPKI(t) // Manar presents a certificate from a CA we did not enroll with
	got := make(chan seen, 1)
	manar := recordingManar(t, other, got)
	addr := strings.TrimPrefix(manar.URL, "https://")
	g := &localGateway{host: testServerName, task: "t1",
		transport: newMTLSTransport(p.clientCert, p.roots, testServerName, addr)}
	gw := httptest.NewServer(g.handler())
	defer gw.Close()
	res, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", res.StatusCode)
	}
}

func TestGatewayModelsFallback(t *testing.T) {
	p := newTestPKI(t)
	manar := newTestManar(t, p, http.NotFoundHandler())
	gw := newTestGateway(t, p, manar, "")
	res, err := http.Get(gw.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), `"object":"list"`) {
		t.Fatalf("%d %s", res.StatusCode, b)
	}
}

func TestGatewayRejectsBadApprovalID(t *testing.T) {
	p := newTestPKI(t)
	got := make(chan seen, 1)
	gw := newTestGateway(t, p, recordingManar(t, p, got), "t1")
	res, err := http.Get(gw.URL + "/agent/v1/approvals/a%2F..%2Fb")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", res.StatusCode)
	}
}
