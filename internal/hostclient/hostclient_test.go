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
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	if err := MarkRemoved(dir); err != nil { // a removed device that enrols again is live again
		t.Fatal(err)
	}
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
	if IsMarkedRemoved(dir) {
		t.Fatal("enrolling did not clear the removed state")
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

func removedClient(t *testing.T, status int, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Client{Info: &Info{}, http: srv.Client(), base: srv.URL, stateDir: t.TempDir(), removed: make(chan struct{})}
}

func TestOnly410WithTheDeviceRemovedCodeCountsAsRemoval(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"removed", 410, `{"statusCode":410,"code":"device_removed","message":"This device was removed from the workspace"}`, true},
		{"410 without code", 410, `{"statusCode":410,"message":"gone"}`, false},
		{"410 other code", 410, `{"code":"something_else"}`, false},
		{"410 not json", 410, `gone`, false},
		{"401", 401, `{"code":"device_removed"}`, false},
		{"403", 403, `{"code":"device_removed"}`, false},
		{"500", 500, `{"code":"device_removed"}`, false},
		{"423 locked", 423, `{"code":"device_revoked"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := removedClient(t, tc.status, tc.body)
			_, err := c.Config(context.Background())
			if err == nil || IsRemoved(err) != tc.want {
				t.Fatalf("err = %v, IsRemoved = %v, want %v", err, IsRemoved(err), tc.want)
			}
			select {
			case <-c.Removed():
				if !tc.want {
					t.Fatal("Removed channel closed")
				}
			default:
				if tc.want {
					t.Fatal("Removed channel not closed")
				}
			}
		})
	}
}

func TestNetworkErrorIsNotRemoval(t *testing.T) {
	c := removedClient(t, 200, `{}`)
	c.base = "http://127.0.0.1:1"
	if _, err := c.Config(context.Background()); err == nil || IsRemoved(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestRemovedMarkSurvivesAndEnrolClearsIt(t *testing.T) {
	dir := t.TempDir()
	if IsMarkedRemoved(dir) {
		t.Fatal("marked before anything")
	}
	if err := MarkRemoved(dir); err != nil || !IsMarkedRemoved(dir) {
		t.Fatalf("mark: %v", err)
	}
	if err := ClearRemoved(dir); err != nil || IsMarkedRemoved(dir) {
		t.Fatalf("clear: %v", err)
	}
	if err := ClearRemoved(dir); err != nil {
		t.Fatalf("clearing twice: %v", err)
	}
}

// 423 is Manar refusing a genuine device (revoked, suspended, workspace deleted): the device
// remembers it, keeps protecting, stops sending anything but its config poll, and is unlocked by
// the first good config. 401 and 403 (a proxy, a misconfiguration) neither lock nor unprotect.
func TestLockedReplyIsRememberedStopsSyncingAndAGoodConfigUnlocks(t *testing.T) {
	var mu sync.Mutex
	status, body, hits := 423, `{"statusCode":423,"code":"device_revoked"}`, map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	c := &Client{Info: &Info{}, http: srv.Client(), base: srv.URL, stateDir: dir, removed: make(chan struct{})}

	if _, err := c.Config(context.Background()); err == nil || IsRemoved(err) {
		t.Fatalf("err = %v", err)
	}
	if got := LockedCode(dir); got != "device_revoked" {
		t.Fatalf("LockedCode = %q", got)
	}
	// Nothing else leaves the device while it is locked.
	err := c.Inventory(context.Background(), nil, nil)
	var se *StatusError
	if !errors.As(err, &se) || !se.Locked() {
		t.Fatalf("inventory while locked: %v", err)
	}
	mu.Lock()
	if hits["/host/v1/inventory"] != 0 {
		t.Fatal("inventory was sent while locked")
	}
	mu.Unlock()
	select {
	case <-c.Removed():
		t.Fatal("a locked device must not count as removed")
	default:
	}
	// A new client (a restart) is still locked.
	if LockedCode(dir) == "" {
		t.Fatal("lock not on disk")
	}
	// The workspace lets it back in: the first good config unlocks it.
	mu.Lock()
	status, body = 200, `{"hostId":"h","status":"APPROVED"}`
	mu.Unlock()
	if _, err := c.Config(context.Background()); err != nil {
		t.Fatal(err)
	}
	if LockedCode(dir) != "" {
		t.Fatal("still locked after a good config")
	}

	// 401 and 403 neither lock nor unprotect.
	for _, code := range []int{401, 403} {
		mu.Lock()
		status, body = code, `{"code":"device_revoked"}`
		mu.Unlock()
		_, _ = c.Config(context.Background())
		if LockedCode(dir) != "" || IsMarkedRemoved(dir) {
			t.Fatalf("%d changed the device state", code)
		}
	}
}

// moveServer is a Manar that signs any CSR and records POST /host/v1/moved with the caller's SAN.
func moveServer(t *testing.T) (url string, httpc *http.Client, moved *[]string, keys *[]string) {
	t.Helper()
	ca := newCA(t)
	var mu sync.Mutex
	moved, keys = &[]string{}, &[]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/hosts/register", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		blk, _ := pem.Decode([]byte(body["csr"]))
		csr, _ := x509.ParseCertificateRequest(blk.Bytes)
		der, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
		mu.Lock()
		*keys = append(*keys, string(der))
		mu.Unlock()
		certPEM := ca.sign(t, csr.PublicKey, &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "host"}, URIs: csr.URIs,
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"hostId": "h-" + csr.URIs[0].Host, "status": "APPROVED", "certificatePem": certPEM, "caChainPem": ca.pem,
		})
	})
	mux.HandleFunc("POST /host/v1/moved", func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no cert", 401)
			return
		}
		mu.Lock()
		*moved = append(*moved, r.TLS.PeerCertificates[0].URIs[0].String())
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewUnstartedServer(mux)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvCert := ca.sign(t, &srvKey.PublicKey, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	srvKeyDER, _ := x509.MarshalPKCS8PrivateKey(srvKey)
	pair, err := tls.X509KeyPair([]byte(srvCert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.Replace(srv.URL, "127.0.0.1", "localhost", 1),
		&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}, moved, keys
}

// One laptop, two workspaces (founder decision, 4 Nov 2026): installing for another workspace
// never silently replaces the first. Without a confirmation nothing is sent; with one the device
// gets a NEW key for the new workspace and tells the old one it moved, signed with its old
// certificate, so the old workspace shows it as moved instead of approved and silent.
func TestEnrolForAnotherWorkspaceNeedsConfirmationAndUsesANewKey(t *testing.T) {
	url, httpc, moved, keys := moveServer(t)
	dir := t.TempDir()
	in := EnrolInput{StateDir: dir, APIURL: url, HostURL: url, InstallKey: "ABCDEFGHJK", TenantSlug: "acme",
		MachineID: "m-1", Hostname: "laptop", OS: "linux", HTTP: httpc}
	if _, err := Enrol(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	oldKey, _ := os.ReadFile(filepath.Join(Dir(dir), fileKey))

	in.TenantSlug = "globex"
	_, err := Enrol(context.Background(), in)
	var other *OtherWorkspaceError
	if !errors.As(err, &other) || other.From != "acme" || other.To != "globex" {
		t.Fatalf("err = %v", err)
	}
	if len(*keys) != 1 {
		t.Fatal("a registration was sent without the person's confirmation")
	}
	if b, _ := os.ReadFile(filepath.Join(Dir(dir), fileInfo)); !strings.Contains(string(b), `"acme"`) {
		t.Fatal("host.json changed without confirmation")
	}

	in.ConfirmMove = true
	info, err := Enrol(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if info.TenantSlug != "globex" || info.MovedFrom != "acme" {
		t.Fatalf("info = %+v", info)
	}
	// The old workspace is told only when the caller says so (after it stopped the service).
	if len(*moved) != 0 {
		t.Fatal("the old workspace was told before the service was stopped")
	}
	if !info.TellOldWorkspace(context.Background(), dir) {
		t.Fatal("old workspace not told")
	}
	newKey, _ := os.ReadFile(filepath.Join(Dir(dir), fileKey))
	if string(newKey) == string(oldKey) || len(*keys) != 2 || (*keys)[0] == (*keys)[1] {
		t.Fatal("the device key was reused across workspaces")
	}
	if len(*moved) != 1 || (*moved)[0] != "host://acme/m-1" {
		t.Fatalf("old workspace told: %v", *moved)
	}
	// The new files work together.
	if _, err := New(dir); err != nil {
		t.Fatal(err)
	}
}

// proxyScenario runs one proxyFromEnv check in a child process: Go reads the proxy variables once
// per process, so each scenario needs its own.
func proxyScenario(t *testing.T, env []string, check func(t *testing.T)) {
	t.Helper()
	if os.Getenv("MANAR_TEST_PROXY_CHILD") == "1" {
		check(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(append(os.Environ(), "MANAR_TEST_PROXY_CHILD=1", "NO_PROXY=", "no_proxy="), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

func proxyFor(t *testing.T) (*url.URL, error) {
	req, _ := http.NewRequest(http.MethodGet, "https://manar.example/host/v1/config", nil)
	return proxyFromEnv(req)
}

// A device behind a corporate proxy must still reach Manar (edge-case spec section 7, item 9).
func TestProxyFromEnvUsesAnHTTPProxy(t *testing.T) {
	proxyScenario(t, []string{"HTTPS_PROXY=http://proxy.corp.example:3128"}, func(t *testing.T) {
		u, err := proxyFor(t)
		if err != nil || u == nil || u.Host != "proxy.corp.example:3128" {
			t.Fatalf("proxy = %v, %v", u, err)
		}
	})
}

// Only plain CONNECT proxies are supported: anything else fails the request, never unprotects.
func TestProxyFromEnvRefusesOtherSchemes(t *testing.T) {
	for _, v := range []string{"https://proxy.corp.example:3128", "socks5://proxy.corp.example:1080"} {
		t.Run(v, func(t *testing.T) {
			proxyScenario(t, []string{"HTTPS_PROXY=" + v}, func(t *testing.T) {
				u, err := proxyFor(t)
				if u != nil || err == nil || !strings.Contains(err.Error(), "only http:// CONNECT proxies are supported") {
					t.Fatalf("proxy = %v, %v", u, err)
				}
			})
		})
	}
}

// The environment JAIL gives a protected tool must never route the device service's own traffic.
func TestProxyFromEnvIgnoresTheJailFilter(t *testing.T) {
	proxyScenario(t, []string{"HTTPS_PROXY=http://127.0.0.1:8491", "NO_PROXY=localhost,127.0.0.1"}, func(t *testing.T) {
		if u, err := proxyFor(t); u != nil || err != nil {
			t.Fatalf("proxy = %v, %v", u, err)
		}
	})
}

// The Linux gateway port counts as JAIL's too.
func TestProxyFromEnvIgnoresTheJailGatewayPort(t *testing.T) {
	proxyScenario(t, []string{"HTTPS_PROXY=http://localhost:8480", "NO_PROXY=localhost,127.0.0.1"}, func(t *testing.T) {
		if u, err := proxyFor(t); u != nil || err != nil {
			t.Fatalf("proxy = %v, %v", u, err)
		}
	})
}

// A user's own local proxy (cntlm, px) keeps working, even with the very same NO_PROXY, because it
// is not on one of JAIL's ports.
func TestProxyFromEnvKeepsALocalCorporateProxy(t *testing.T) {
	proxyScenario(t, []string{"HTTPS_PROXY=http://127.0.0.1:3128", "NO_PROXY=localhost,127.0.0.1"}, func(t *testing.T) {
		if u, err := proxyFor(t); err != nil || u == nil || u.Host != "127.0.0.1:3128" {
			t.Fatalf("proxy = %v, %v", u, err)
		}
	})
}

// proxyRig is a real mTLS Manar behind a stand-in "corporate proxy".
type proxyRig struct {
	ca       *testCA
	pool     *x509.CertPool
	cert     tls.Certificate // the device's certificate
	manar    *httptest.Server
	peerSeen chan int // client certificates Manar saw per request
}

func newProxyRig(t *testing.T) *proxyRig {
	t.Helper()
	ca := newCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	issue := func(sn int64, tpl *x509.Certificate) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl.SerialNumber = big.NewInt(sn)
		tpl.NotBefore, tpl.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		pair, err := tls.X509KeyPair([]byte(ca.sign(t, &k.PublicKey, tpl)), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		if err != nil {
			t.Fatal(err)
		}
		return pair
	}
	r := &proxyRig{ca: ca, pool: pool, peerSeen: make(chan int, 16)}
	r.cert = issue(10, &x509.Certificate{Subject: pkix.Name{CommonName: "host"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	r.manar = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.peerSeen <- len(req.TLS.PeerCertificates)
		_ = json.NewEncoder(w).Encode(Config{HostID: "h1", Status: "APPROVED", Features: []string{}})
	}))
	r.manar.TLS = &tls.Config{
		Certificates: []tls.Certificate{issue(11, &x509.Certificate{Subject: pkix.Name{CommonName: "manar.test"}, DNSNames: []string{"manar.test"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}
	r.manar.StartTLS()
	t.Cleanup(r.manar.Close)
	return r
}

func (r *proxyRig) client(proxyURL string, dir string) *Client {
	pu, _ := url.Parse(proxyURL)
	return &Client{Info: &Info{}, base: "https://manar.test", stateDir: dir, removed: make(chan struct{}),
		http: mtlsHTTP(r.cert, r.pool, func(*http.Request) (*url.URL, error) { return pu, nil })}
}

// connectProxy serves CONNECT with handle; handle gets the raw client connection.
func connectProxy(t *testing.T, handle func(c net.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		handle(c)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestThroughAConnectProxyThePinnedCAAndTheDeviceCertificateStillApply(t *testing.T) {
	r := newProxyRig(t)
	p := connectProxy(t, func(c net.Conn) { // a plain tunnel to Manar
		up, err := net.Dial("tcp", r.manar.Listener.Addr().String())
		if err != nil {
			_ = c.Close()
			return
		}
		go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
		_, _ = io.Copy(c, up)
		_ = c.Close()
	})
	cfg, err := r.client(p.URL, t.TempDir()).Config(context.Background())
	if err != nil || cfg.Status != "APPROVED" {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
	select {
	case n := <-r.peerSeen:
		if n != 1 {
			t.Fatalf("Manar saw %d client certificates through the tunnel, want 1", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Manar never saw the request through the tunnel")
	}
}

func TestAProxyThatOpensTheTLSSessionFailsAndNeverGetsTheClientCertificate(t *testing.T) {
	r := newProxyRig(t)
	other := newCA(t) // not the pinned CA
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pair, err := tls.X509KeyPair([]byte(other.sign(t, &k.PublicKey, &x509.Certificate{
		SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: "manar.test"}, DNSNames: []string{"manar.test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	gotCert := make(chan int, 1)
	p := connectProxy(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequestClientCert})
		_ = tc.Handshake() // fails: the device rejects the certificate and aborts
		gotCert <- len(tc.ConnectionState().PeerCertificates)
		_ = tc.Close()
	})
	if _, err := r.client(p.URL, t.TempDir()).Config(context.Background()); err == nil {
		t.Fatal("the device trusted a proxy that opened the TLS session")
	}
	select {
	case n := <-gotCert:
		if n != 0 {
			t.Fatalf("the proxy received %d client certificates", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the intercepting proxy never finished its handshake")
	}
	select {
	case <-r.peerSeen:
		t.Fatal("Manar was reached through the interception")
	default:
	}
}

// A proxy's own refusal of CONNECT is a transport failure: it says nothing about the device, so it
// never marks it removed or locked (only Manar's 410 and 423, over the pinned channel, do).
func TestAProxyRefusingConnectNeverRemovesOrLocksTheDevice(t *testing.T) {
	r := newProxyRig(t)
	for _, code := range []int{http.StatusGone, http.StatusLocked, http.StatusForbidden, http.StatusProxyAuthRequired} {
		p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"statusCode":` + strconv.Itoa(code) + `,"code":"device_removed"}`))
		}))
		dir := t.TempDir()
		c := r.client(p.URL, dir)
		_, err := c.Config(context.Background())
		p.Close()
		if err == nil || IsRemoved(err) {
			t.Fatalf("CONNECT %d: err = %v", code, err)
		}
		var se *StatusError
		if errors.As(err, &se) && se.Locked() {
			t.Fatalf("CONNECT %d read as a lock", code)
		}
		if LockedCode(dir) != "" || IsMarkedRemoved(dir) {
			t.Fatalf("CONNECT %d changed the device state", code)
		}
		select {
		case <-c.removed:
			t.Fatalf("CONNECT %d signalled removal", code)
		default:
		}
	}
}
