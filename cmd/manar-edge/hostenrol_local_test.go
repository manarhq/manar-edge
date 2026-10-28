package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// localPlatform uses a certificate and key from files in place of the Windows store.
type localPlatform struct {
	fakePlatform
	certPEM string
}

func (l localPlatform) computerCert(string) ([]string, crypto.Signer, error) {
	return []string{l.certPEM}, l.certKey, nil
}

func loadPair(t *testing.T, dir, name string) localPlatform {
	t.Helper()
	crt, err := os.ReadFile(filepath.Join(dir, name+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	kb, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(kb)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	hk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return localPlatform{fakePlatform{k.(crypto.Signer), hk}, string(crt)}
}

// TestLocalManarAPI registers against a running manar-api. It is skipped unless
// MANAR_EDGE_LOCAL_API, MANAR_EDGE_LOCAL_TENANT and MANAR_EDGE_LOCAL_DIR (good.crt/key, bad.crt/key)
// are set; the manar-api side is a test tenant whose trusted CA signed both certificates and whose
// template allow-list holds only the "good" certificate's template.
func TestLocalManarAPI(t *testing.T) {
	api, tenant, dir := os.Getenv("MANAR_EDGE_LOCAL_API"), os.Getenv("MANAR_EDGE_LOCAL_TENANT"), os.Getenv("MANAR_EDGE_LOCAL_DIR")
	if api == "" || tenant == "" || dir == "" {
		t.Skip("no local manar-api configured")
	}
	u, _ := url.Parse(api)
	ctx := context.Background()

	good := loadPair(t, dir, "good")
	req, err := buildAdcsRequest(good, tenant, "client01-local", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	res, err := postAdcs(ctx, enrollClient(u), u, req)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("good certificate: host %s status %s", res.HostID, res.Status)
	if !strings.Contains(res.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Fatal("no host certificate returned")
	}
	// The same machine again with the same host key is a merge, not a rekey.
	req, _ = buildAdcsRequest(good, tenant, "client01-local", "", time.Now())
	if again, err := postAdcs(ctx, enrollClient(u), u, req); err != nil || again.HostID != res.HostID {
		t.Fatalf("re-registration: %v", err)
	}

	bad := loadPair(t, dir, "bad")
	req, _ = buildAdcsRequest(bad, tenant, "client02-local", "", time.Now())
	_, err = postAdcs(ctx, enrollClient(u), u, req)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a certificate from another template must be refused with 401, got %v", err)
	}
	t.Logf("other template: %v", err)
}
