package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type fakePlatform struct{ certKey, hostK crypto.Signer }

func (fakePlatform) machineID() (string, error) { return "pc-01.lab", nil }
func (fakePlatform) osName() string             { return "Windows 10.0.20348" }
func (f fakePlatform) computerCert(string) ([]string, crypto.Signer, error) {
	return []string{"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"}, f.certKey, nil
}
func (f fakePlatform) hostKey() (crypto.Signer, error) { return f.hostK, nil }

// verifyProofSig is the server's check (computer-proof.util.ts): SHA-256 with RSA PKCS#1 v1.5 or ECDSA DER.
func verifyProofSig(pub crypto.PublicKey, msg []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	d := sha256.Sum256(msg)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], sig) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, d[:], sig)
	}
	return false
}

// The fixture is produced by manar-api's own helpers (see "generator" in the file).
func TestProofMatchesManarAPIFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/manar-api-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Input struct {
			TenantSlug, MachineID, CsrKeyFingerprint, OS, KeyType, Timestamp string
		}
		Message string
		RSA, EC struct{ CertPem, Signature string }
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	in := fx.Input
	msg := proofMessage(in.TenantSlug, in.MachineID, in.CsrKeyFingerprint, in.OS, in.KeyType, in.Timestamp)
	if string(msg) != fx.Message {
		t.Fatalf("message differs from manar-api:\n%q\n%q", msg, fx.Message)
	}
	for name, c := range map[string]struct{ CertPem, Signature string }{"rsa": fx.RSA, "ec": fx.EC} {
		blk, _ := pem.Decode([]byte(c.CertPem))
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !verifyProofSig(cert.PublicKey, msg, c.Signature) {
			t.Errorf("%s: a signature made by manar-api does not verify in Go", name)
		}
	}
}

func TestBuildRequest(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	hk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, ck := range map[string]crypto.Signer{"ec": ec, "rsa": rk} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 10, 28, 12, 34, 56, 789e6, time.UTC)
			r, err := buildAdcsRequest(fakePlatform{ck, hk}, "acme", "pc-01.lab", "", now)
			if err != nil {
				t.Fatal(err)
			}
			if r.Timestamp != "2026-10-28T12:34:56.789Z" || r.KeyType != "SOFTWARE" {
				t.Fatalf("timestamp %q keyType %q", r.Timestamp, r.KeyType)
			}
			// CSR: self-signed, one URI SAN, nothing else.
			blk, _ := pem.Decode([]byte(r.CSR))
			csr, err := x509.ParseCertificateRequest(blk.Bytes)
			if err != nil || csr.CheckSignature() != nil {
				t.Fatalf("csr: %v", err)
			}
			if len(csr.URIs) != 1 || csr.URIs[0].String() != "host://acme/pc-01.lab" || len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses) != 0 {
				t.Fatalf("SANs: %v", csr.URIs)
			}
			// Proof names the CSR key.
			fp, _ := spkiFingerprint(csr.PublicKey)
			msg := proofMessage("acme", "pc-01.lab", fp, r.OS, r.KeyType, r.Timestamp)
			if !verifyProofSig(ck.Public(), msg, r.Signature) {
				t.Fatal("proof does not verify")
			}
			if verifyProofSig(ck.Public(), proofMessage("evil", "pc-01.lab", fp, r.OS, r.KeyType, r.Timestamp), r.Signature) {
				t.Fatal("proof verifies for another tenant")
			}
			// Body carries exactly the fields the server's strict schema accepts.
			b, _ := json.Marshal(r)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			for _, k := range []string{"tenantSlug", "certificates", "csr", "machineId", "os", "keyType", "timestamp", "signature"} {
				delete(m, k)
			}
			if len(m) != 0 {
				t.Fatalf("unexpected fields %v", m)
			}
		})
	}
}

func TestPostAdcs(t *testing.T) {
	var gotPath string
	status := http.StatusCreated
	body := `{"hostId":"h1","status":"PENDING","certificatePem":"C","caChainPem":"CA"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	req := &adcsRequest{TenantSlug: "acme"}
	res, err := postAdcs(context.Background(), srv.Client(), u, req)
	if err != nil || res.Status != "PENDING" || res.HostID != "h1" || gotPath != "/hosts/register/adcs" {
		t.Fatalf("%+v %v %q", res, err, gotPath)
	}
	status, body = http.StatusUnauthorized, `{"message":"Computer certificate not accepted"}`
	if _, err = postAdcs(context.Background(), srv.Client(), u, req); err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("401: %v", err)
	}
	status = http.StatusConflict
	if _, err = postAdcs(context.Background(), srv.Client(), u, req); err == nil || !strings.Contains(err.Error(), "admin must approve") {
		t.Fatalf("409: %v", err)
	}
}
