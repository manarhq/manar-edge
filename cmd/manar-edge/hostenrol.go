package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/lazyre"
)

// Key-less enrolment of a domain-joined Windows machine (manar-api docs/hosts.md, "Key-less
// enrolment with an AD CS computer certificate"): no install key. The machine proves it holds the
// computer certificate's private key by signing a message that names the tenant, the machine, the
// new host key and the time; manar-api checks the certificate chain, the template allow-list, the
// CRL and the computer's OU in AD, then issues the host certificate.

const (
	proofTag      = "manar-adcs-register-v2"
	hostKeyType   = "SOFTWARE" // ponytail: no TPM key or attestation yet, so never claim TPM
	hostStateDir  = "host"
	fileHostCert  = "host.cert.pem"
	fileHostCA    = "host-ca.pem"
	fileHostState = "host.json"
)

var machineIDPattern = lazyre.New(`^[A-Za-z0-9._-]{1,128}$`)

// hostPlatform is the part that needs the OS: the certificate store and the keys.
type hostPlatform interface {
	// machineID is a stable identifier of this machine (Windows: the MachineGuid registry value).
	machineID() (string, error)
	osName() string
	// computerCert returns the computer certificate and its intermediates as PEM (leaf first) and
	// a signer that signs with the certificate's private key through the OS.
	computerCert(issuer string) (chainPEM []string, key crypto.Signer, err error)
	// hostKey returns the machine's host key, creating it on first use; the same key is returned
	// on later runs, so re-enrolling is not a rekey.
	hostKey() (crypto.Signer, error)
}

// proofMessage is what the computer certificate's key signs; it must match manar-api's
// computer-proof.util.ts byte for byte.
func proofMessage(tenant, machineID, keyFingerprint, osName, keyType, timestamp string) []byte {
	return []byte(strings.Join([]string{proofTag, tenant, machineID, keyFingerprint, osName, keyType, timestamp}, "\n"))
}

// spkiFingerprint is the SHA-256 of the key's SubjectPublicKeyInfo, as hex.
func spkiFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// signProof signs with SHA-256: RSA gives PKCS#1 v1.5, ECDSA gives a DER signature, as the server verifies.
func signProof(key crypto.Signer, msg []byte) (string, error) {
	digest := sha256.Sum256(msg)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("signing the proof with the computer certificate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// hostCSR builds a CSR whose only SAN is the URI host://<tenant>/<machineId>.
func hostCSR(key crypto.Signer, tenant, machineID string) (string, error) {
	id := "host://" + tenant + "/" + machineID
	u, err := url.Parse(id)
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: machineID},
		URIs:    []*url.URL{u},
	}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

type adcsRequest struct {
	TenantSlug   string   `json:"tenantSlug"`
	Certificates []string `json:"certificates"`
	CSR          string   `json:"csr"`
	MachineID    string   `json:"machineId"`
	OS           string   `json:"os"`
	KeyType      string   `json:"keyType"`
	Timestamp    string   `json:"timestamp"`
	Signature    string   `json:"signature"`
}

type hostResponse struct {
	HostID         string `json:"hostId"`
	Status         string `json:"status"`
	CertificatePEM string `json:"certificatePem"`
	CAChainPEM     string `json:"caChainPem"`
}

// buildAdcsRequest assembles and signs the registration body.
func buildAdcsRequest(p hostPlatform, tenant, machineID, issuer string, now time.Time) (*adcsRequest, error) {
	chain, certKey, err := p.computerCert(issuer)
	if err != nil {
		return nil, err
	}
	hk, err := p.hostKey()
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	csr, err := hostCSR(hk, tenant, machineID)
	if err != nil {
		return nil, err
	}
	fp, err := spkiFingerprint(hk.Public())
	if err != nil {
		return nil, err
	}
	r := &adcsRequest{
		TenantSlug: tenant, Certificates: chain, CSR: csr, MachineID: machineID,
		OS: p.osName(), KeyType: hostKeyType,
		Timestamp: now.UTC().Format("2006-01-02T15:04:05.000Z"), // same shape as JS toISOString()
	}
	r.Signature, err = signProof(certKey, proofMessage(tenant, machineID, fp, r.OS, r.KeyType, r.Timestamp))
	return r, err
}

func postAdcs(ctx context.Context, c *http.Client, api *url.URL, r *adcsRequest) (*hostResponse, error) {
	body, _ := json.Marshal(r)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.String()+"/hosts/register/adcs", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	switch {
	case res.StatusCode == http.StatusConflict:
		return nil, fmt.Errorf("this machine is already registered with another key or group; an admin must approve the change (HTTP 409: %s)", serverMessage(b))
	case res.StatusCode/100 != 2:
		return nil, fmt.Errorf("registration refused: HTTP %d: %s", res.StatusCode, serverMessage(b))
	}
	var out hostResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("registration response is not JSON: %w", err)
	}
	if out.HostID == "" || out.Status == "" || out.CertificatePEM == "" {
		return nil, errors.New("registration response has no host id, status or certificate")
	}
	return &out, nil
}

func cmdHostEnrol(base string, args []string, p hostPlatform, out io.Writer) error {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	server := fs.String("server", "", "Manar API base URL (https)")
	tenant := fs.String("tenant", "", "tenant slug")
	machine := fs.String("machine-id", "", "machine id (default: the Windows MachineGuid)")
	issuer := fs.String("issuer", "", "only use a computer certificate whose issuer contains this text")
	plainHTTP := fs.Bool("allow-http", false, "lab only: allow an http:// server (the request carries a signed proof and public certificates, no secret)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *tenant == "" || fs.NArg() != 0 {
		return errors.New("usage: manar-edge enrol --server <url> --tenant <slug> [--machine-id ID] [--issuer TEXT]")
	}
	if !slugPattern.MatchString(*tenant) {
		return errors.New("--tenant is not a tenant slug")
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	// A computer enrolled in another workspace is not moved by IT behind the person's back (founder
	// decision, 4 Nov 2026). ponytail: the confirmed move for key-less enrolment is Phase B (EC-7);
	// until then it is refused.
	if err := refuseOtherWorkspace(base, *tenant); err != nil {
		return err
	}
	api, err := checkAPIURL(*server)
	if err != nil && *plainHTTP {
		if u, perr := url.Parse(strings.TrimRight(*server, "/")); perr == nil && u.Scheme == "http" && u.Host != "" {
			api, err = u, nil
			fmt.Fprintln(os.Stderr, "warning: --allow-http: the registration is sent in clear text")
		}
	}
	if err != nil {
		return err
	}
	id := *machine
	if id == "" {
		if id, err = p.machineID(); err != nil {
			return err
		}
	}
	if !machineIDPattern.MatchString(id) {
		return errors.New("machine id must be 1 to 128 characters of A-Z a-z 0-9 . _ -")
	}

	req, err := buildAdcsRequest(p, *tenant, id, *issuer, time.Now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := postAdcs(ctx, enrollClient(api), api, req)
	if err != nil {
		return err
	}

	dir := filepath.Join(base, hostStateDir)
	if err := secureMkdir(base); err != nil {
		return err
	}
	if err := secureMkdir(dir); err != nil {
		return err
	}
	state, _ := json.MarshalIndent(map[string]string{
		"tenantSlug": *tenant, "machineId": id, "hostId": resp.HostID, "status": resp.Status,
		"keyType": hostKeyType, "enrolledAt": time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err := hostclient.ClearRemoved(base); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{fileHostCert, []byte(resp.CertificatePEM)},
		{fileHostCA, []byte(resp.CAChainPEM)},
		{fileHostState, append(state, '\n')},
	} {
		if err := writePrivate(filepath.Join(dir, f.name), f.data); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "host %s (%s): %s\nkey type: %s (a software key held by this machine; not hardware-backed, not attested)\nsaved: %s\n",
		resp.HostID, id, resp.Status, hostKeyType, dir)
	if resp.Status != "APPROVED" {
		fmt.Fprintln(out, "waiting for an admin: approve it in the console under Fleet, Hosts")
	}
	return nil
}

// refuseOtherWorkspace fails when this computer is enrolled (and not removed) in another workspace.
func refuseOtherWorkspace(base, tenant string) error {
	b, err := os.ReadFile(filepath.Join(base, hostStateDir, fileHostState))
	if err != nil || hostclient.IsMarkedRemoved(base) {
		return nil
	}
	var cur struct {
		TenantSlug string `json:"tenantSlug"`
	}
	if json.Unmarshal(b, &cur) == nil && cur.TenantSlug != "" && cur.TenantSlug != tenant {
		return fmt.Errorf("this computer is enrolled in workspace %q, not %q: nothing was changed. "+
			"Ask the person to move it with `manar-edge install --confirm-move`, or uninstall Manar first", cur.TenantSlug, tenant)
	}
	return nil
}
