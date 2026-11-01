package hostclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodKey = "mik_me_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ" // 43 chars after "mik_me_"

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, k, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca *testCA) sign(t *testing.T, pub any, tpl *x509.Certificate) string {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestEnrolStoresHostFilesAndClientCallsConfig(t *testing.T) {
	ca := newCA(t)
	var gotCSR *x509.CertificateRequest
	var gotBody map[string]string
	mux := http.NewServeMux()
	mux.HandleFunc("/hosts/register", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		blk, _ := pem.Decode([]byte(gotBody["csr"]))
		gotCSR, _ = x509.ParseCertificateRequest(blk.Bytes)
		certPEM := ca.sign(t, gotCSR.PublicKey, &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "host"}, URIs: gotCSR.URIs,
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"hostId": "h1", "status": "PENDING", "certificatePem": certPEM, "caChainPem": ca.pem,
		})
	})
	mux.HandleFunc("/host/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no cert", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(Config{HostID: "h1", Status: "PENDING", StartMode: "ask", Features: []string{}})
	})
	srv := httptest.NewUnstartedServer(mux)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvCert := ca.sign(t, &srvKey.PublicKey, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: nil,
		NotBefore:   time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	srvKeyDER, _ := x509.MarshalPKCS8PrivateKey(srvKey)
	pair, err := tls.X509KeyPair([]byte(srvCert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	srv.StartTLS()
	defer srv.Close()
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	httpc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	dir := t.TempDir()
	info, err := Enrol(context.Background(), EnrolInput{
		StateDir: dir, APIURL: url, HostURL: url, InstallKey: goodKey,
		MachineID: "m-1", Hostname: "laptop", OS: "linux", HTTP: httpc,
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.HostID != "h1" || info.TenantSlug != "me" {
		t.Fatalf("info = %+v", info)
	}
	if len(gotCSR.URIs) != 1 || gotCSR.URIs[0].String() != "host://me/m-1" {
		t.Fatalf("CSR SAN = %v", gotCSR.URIs)
	}
	if gotBody["installKey"] != goodKey || gotBody["keyType"] != "SOFTWARE" {
		t.Fatalf("body = %v", gotBody)
	}
	if st, err := os.Stat(filepath.Join(Dir(dir), fileKey)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	c, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := c.Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StartMode != "ask" || cfg.Status != "PENDING" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestEnrolRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"expired code": {401, `{"message":"Invalid install key"}`, "expired or already used"},
		"plan limit":   {403, `{"code":"plan_limit_reached"}`, "device limit"},
		"server error": {500, `{"message":"boom"}`, "HTTP 500: boom"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := Enrol(context.Background(), EnrolInput{
				StateDir: t.TempDir(), APIURL: srv.URL, InstallKey: goodKey, MachineID: "m", Hostname: "h", OS: "linux",
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestEnrolWithShortCodeNeedsTheTenant(t *testing.T) {
	in := EnrolInput{StateDir: t.TempDir(), APIURL: "https://example.com", InstallKey: "ABCDEFGH23", MachineID: "m"}
	if _, err := Enrol(context.Background(), in); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("err = %v", err)
	}
	// With the tenant it gets as far as the network (which fails here), not the validation.
	in.TenantSlug = "me"
	in.APIURL = "http://127.0.0.1:1"
	if _, err := Enrol(context.Background(), in); err == nil || strings.Contains(err.Error(), "not valid") {
		t.Fatalf("err = %v", err)
	}
}

func TestAFailedEnrolKeepsTheKeyAndTheNextRunReusesIt(t *testing.T) {
	dir := t.TempDir()
	var csrs []*x509.CertificateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		blk, _ := pem.Decode([]byte(body["csr"]))
		c, _ := x509.ParseCertificateRequest(blk.Bytes)
		csrs = append(csrs, c)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	in := EnrolInput{StateDir: dir, APIURL: srv.URL, InstallKey: goodKey, MachineID: "m", Hostname: "h", OS: "linux"}
	for range 2 {
		if _, err := Enrol(context.Background(), in); err == nil {
			t.Fatal("want an error")
		}
	}
	if len(csrs) != 2 {
		t.Fatalf("requests = %d", len(csrs))
	}
	a, _ := x509.MarshalPKIXPublicKey(csrs[0].PublicKey)
	b, _ := x509.MarshalPKIXPublicKey(csrs[1].PublicKey)
	if string(a) != string(b) {
		t.Fatal("the second run made a new key")
	}
	if st, err := os.Stat(filepath.Join(Dir(dir), fileKey)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
}

func TestTenantSlugRuleMatchesTheAPI(t *testing.T) {
	good := "mik_me-1_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	if _, ok := tenantSlugOf(good); !ok {
		t.Fatal("a normal slug is refused")
	}
	if _, ok := tenantSlugOf("mik_me-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"); ok {
		t.Fatal("a slug ending in a dash is accepted")
	}
}

func TestEnrolRejectsBadInput(t *testing.T) {
	for name, in := range map[string]EnrolInput{
		"plain http":     {APIURL: "http://example.com", InstallKey: goodKey, MachineID: "m"},
		"bad key":        {APIURL: "https://example.com", InstallKey: "nope", MachineID: "m"},
		"bad machine id": {APIURL: "https://example.com", InstallKey: goodKey, MachineID: "a/b"},
	} {
		in.StateDir = t.TempDir()
		if _, err := Enrol(context.Background(), in); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestNewFailsWhenNotEnrolled(t *testing.T) {
	if _, err := New(t.TempDir()); err == nil {
		t.Fatal("want an error")
	}
}
