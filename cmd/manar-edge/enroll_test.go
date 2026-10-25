package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseToken(t *testing.T) {
	if tn, a, ok := parseToken("acme:soc-1:s3cr3t"); !ok || tn != "acme" || a != "soc-1" {
		t.Errorf("valid token: %v %v %v", tn, a, ok)
	}
	for _, bad := range []string{"", "acme:soc-1", "acme:soc-1:", ":a:b", "a:b:c:d"} {
		if _, _, ok := parseToken(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCSRSAN(t *testing.T) {
	keyPEM, csrPEM, err := makeCSR("agent://acme/soc-1")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != "agent://acme/soc-1" {
		t.Errorf("URIs %v", csr.URIs)
	}
	if len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses) != 0 {
		t.Error("CSR has extra SANs")
	}
	kb, _ := pem.Decode(keyPEM)
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ek, ok := k.(*ecdsa.PrivateKey); !ok || ek.Curve != elliptic.P256() {
		t.Error("key is not ECDSA P-256")
	}
}

func TestPostEnroll(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agents/enroll" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{"certificate": "C", "caChain": "CA", "edge": testEdge})
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	res, err := postEnroll(context.Background(), srv.Client(), u, "acme:soc-1:s", "CSR", "WGPUB")
	if err != nil {
		t.Fatal(err)
	}
	if got["token"] != "acme:soc-1:s" || got["csr"] != "CSR" || got["edge"].(map[string]any)["wgPublicKey"] != "WGPUB" {
		t.Errorf("request %v", got)
	}
	if res.Edge.ManarServerName != "agents.manar.test" {
		t.Errorf("edge %+v", res.Edge)
	}
	if err := validateEdge(res.Edge); err != nil {
		t.Error(err)
	}
}

func TestPostEnrollErrors(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"no edge": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"certificate":"C","caChain":"CA"}`))
		},
		"refused": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"message":"edge_not_enabled"}`))
		},
	} {
		srv := httptest.NewServer(h)
		u, _ := url.Parse(srv.URL)
		_, err := postEnroll(context.Background(), srv.Client(), u, "acme:soc-1:supersecret", "CSR", "K")
		srv.Close()
		if err == nil {
			t.Errorf("%s: no error", name)
		} else if strings.Contains(err.Error(), "supersecret") {
			t.Errorf("%s: token in error", name)
		}
	}
}

func TestCheckAPIURL(t *testing.T) {
	for _, ok := range []string{"https://manar.test", "https://manar.test/", "http://127.0.0.1:3000", "http://localhost:3000"} {
		if _, err := checkAPIURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://manar.test", "manar.test", "ftp://x"} {
		if _, err := checkAPIURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestValidateEdgeRejects(t *testing.T) {
	e := testEdge
	e.ManarAddress = "manar.example:443" // must be an overlay IP, never a name to resolve
	if validateEdge(&e) == nil {
		t.Error("hostname manarAddress accepted")
	}
	e = testEdge
	e.GatewayPublicKey = "nope"
	if validateEdge(&e) == nil {
		t.Error("bad key accepted")
	}
}

func TestEnrollToken(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	var warn strings.Builder
	if tok, err := enrollToken("", env(" a:b:c "), strings.NewReader("x:y:z\n"), &warn); err != nil || tok != "a:b:c" {
		t.Errorf("env: %q %v", tok, err)
	}
	if tok, err := enrollToken("", env(""), strings.NewReader("x:y:z\n"), &warn); err != nil || tok != "x:y:z" {
		t.Errorf("stdin: %q %v", tok, err)
	}
	if tok, err := enrollToken("-", env(""), strings.NewReader("x:y:z"), &warn); err != nil || tok != "x:y:z" {
		t.Errorf("stdin with -: %q %v", tok, err)
	}
	if warn.Len() != 0 {
		t.Errorf("warned without --token: %q", warn.String())
	}
	if tok, _ := enrollToken("f:g:h", env(""), strings.NewReader(""), &warn); tok != "f:g:h" || !strings.Contains(warn.String(), "process list") {
		t.Errorf("flag: %q, warning %q", tok, warn.String())
	}
	if _, err := enrollToken("", env(""), strings.NewReader(""), &warn); err == nil {
		t.Error("empty stdin accepted")
	}
}

func TestEnrollRedirectRefused(t *testing.T) {
	var hit atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/agents/enroll", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	if _, err := postEnroll(context.Background(), enrollClient(u), u, "a:b:secret", "CSR", "K"); err == nil {
		t.Fatal("cross-origin redirect followed")
	}
	if hit.Load() {
		t.Fatal("the token reached another origin")
	}
}
