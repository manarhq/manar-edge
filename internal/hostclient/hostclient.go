// Package hostclient is the device's channel to Manar: enrolment with an install key
// (POST /hosts/register) and mTLS calls to /host/v1/* with the host certificate it was issued.
//
// Files live in <stateDir>/host/ (0600): host.key.pem, host.cert.pem, host-ca.pem, host.json.
// host.json holds no secret.
package hostclient

import (
	"bytes"
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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	dirName  = "host"
	fileKey  = "host.key.pem"
	fileCert = "host.cert.pem"
	fileCA   = "host-ca.pem"
	fileInfo = "host.json"

	maxBody = 1 << 20
)

var machineIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Info is host.json.
type Info struct {
	TenantSlug string `json:"tenantSlug"`
	MachineID  string `json:"machineId"`
	HostID     string `json:"hostId"`
	Status     string `json:"status"`
	KeyType    string `json:"keyType"`
	EnrolledAt string `json:"enrolledAt"`
	// APIURL is the public base URL used to enrol; HostURL is the mTLS listener for /host/v1/*.
	APIURL  string `json:"apiUrl,omitempty"`
	HostURL string `json:"hostUrl,omitempty"`
}

// EnrolInput is what Enrol needs. WriteDir must already exist with the right permissions.
type EnrolInput struct {
	StateDir   string
	APIURL     string // https base URL of the Manar API (loopback http allowed)
	HostURL    string // https base URL of the mTLS listener
	InstallKey string
	MachineID  string
	Hostname   string
	OS         string
	HTTP       *http.Client // optional; tests inject a client that trusts their server
}

// Dir is where a state dir keeps the host files.
func Dir(stateDir string) string { return filepath.Join(stateDir, dirName) }

// Enrol creates a P-256 host key, registers with the install key and stores the certificate.
// The install key is single-use: on any later failure the caller gets a new code from the console.
func Enrol(ctx context.Context, in EnrolInput) (*Info, error) {
	api, err := checkURL(in.APIURL, "API URL")
	if err != nil {
		return nil, err
	}
	hostURL := in.HostURL
	if hostURL == "" {
		hostURL = in.APIURL
	}
	if _, err := checkURL(hostURL, "host URL"); err != nil {
		return nil, err
	}
	if !machineIDPattern.MatchString(in.MachineID) {
		return nil, errors.New("machine id must be 1 to 128 characters of A-Z a-z 0-9 . _ -")
	}
	slug, ok := tenantSlugOf(in.InstallKey)
	if !ok {
		return nil, errors.New("the install code is not valid")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := csrPEM(key, slug, in.MachineID)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{
		"installKey": in.InstallKey, "csr": csr, "machineId": in.MachineID,
		"hostname": in.Hostname, "os": in.OS, "keyType": "SOFTWARE",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.String()+"/hosts/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c := in.HTTP
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, maxBody))
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return nil, errors.New("this install code is expired or already used: get a new one in the console")
	case res.StatusCode == http.StatusForbidden && bytes.Contains(b, []byte("plan_limit_reached")):
		return nil, errors.New("your plan's device limit is reached: remove a device or upgrade in the console")
	case res.StatusCode/100 != 2:
		return nil, fmt.Errorf("registration refused: HTTP %d: %s", res.StatusCode, message(b))
	}
	var out struct {
		HostID         string `json:"hostId"`
		Status         string `json:"status"`
		CertificatePEM string `json:"certificatePem"`
		CAChainPEM     string `json:"caChainPem"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("registration response is not JSON: %w", err)
	}
	if out.HostID == "" || out.CertificatePEM == "" || out.CAChainPEM == "" {
		return nil, errors.New("registration response has no host id or certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	info := &Info{
		TenantSlug: slug, MachineID: in.MachineID, HostID: out.HostID, Status: out.Status, KeyType: "SOFTWARE",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), APIURL: strings.TrimRight(in.APIURL, "/"),
		HostURL: strings.TrimRight(hostURL, "/"),
	}
	infoJSON, _ := json.MarshalIndent(info, "", "  ")
	dir := Dir(in.StateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{fileKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		{fileCert, []byte(out.CertificatePEM)},
		{fileCA, []byte(out.CAChainPEM)},
		{fileInfo, append(infoJSON, '\n')},
	} {
		if err := writePrivate(filepath.Join(dir, f.name), f.data); err != nil {
			return nil, err
		}
	}
	return info, nil
}

// Client calls /host/v1/* over mTLS.
type Client struct {
	Info *Info
	http *http.Client
	base string
}

// New loads the host files from stateDir and builds the mTLS client. It fails when the device
// is not enrolled (or was enrolled another way, with a key held by the OS).
func New(stateDir string) (*Client, error) {
	dir := Dir(stateDir)
	var info Info
	b, err := os.ReadFile(filepath.Join(dir, fileInfo))
	if err != nil {
		return nil, fmt.Errorf("this device is not enrolled: %w", err)
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, fmt.Errorf("%s: %w", fileInfo, err)
	}
	if info.HostURL == "" {
		return nil, errors.New("host.json has no hostUrl: enrol with `manar-edge install --code`")
	}
	base, err := checkURL(info.HostURL, "host URL")
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, fileCert), filepath.Join(dir, fileKey))
	if err != nil {
		return nil, fmt.Errorf("host certificate: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, fileCA))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("host-ca.pem has no certificate")
	}
	return &Client{Info: &info, base: base.String(), http: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS13,
		}},
	}}, nil
}

// Do sends in as JSON (nil for none) and decodes the JSON reply into out (nil to ignore it).
// path is under /host/v1, e.g. "/config".
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/host/v1"+path, rd)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if res.StatusCode/100 != 2 {
		return &StatusError{Code: res.StatusCode, Message: message(b)}
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, out)
}

// StatusError is a non-2xx reply.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Code, e.Message) }

// Config is GET /host/v1/config: the effective preset and the feature flags for this device.
type Config struct {
	HostID    string   `json:"hostId"`
	Status    string   `json:"status"` // PENDING until the owner approves it
	StartMode string   `json:"startMode"`
	Features  []string `json:"features"`
}

// Config fetches the device's effective configuration.
func (c *Client) Config(ctx context.Context) (*Config, error) {
	var cfg Config
	if err := c.Do(ctx, http.MethodGet, "/config", nil, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var keyPattern = regexp.MustCompile(`^mik_([a-z0-9][a-z0-9-]*)_[A-Za-z0-9_-]{43}$`)

func tenantSlugOf(installKey string) (string, bool) {
	m := keyPattern.FindStringSubmatch(installKey)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func csrPEM(key *ecdsa.PrivateKey, tenant, machineID string) (string, error) {
	u, err := url.Parse("host://" + tenant + "/" + machineID)
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: machineID}, URIs: []*url.URL{u},
	}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// checkURL accepts https, or http only for a loopback host (tests and local labs).
func checkURL(raw, what string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%s must be an absolute URL", what)
	}
	h := u.Hostname()
	if u.Scheme == "https" || (u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1")) {
		return u, nil
	}
	return nil, fmt.Errorf("%s must use https", what)
}

func writePrivate(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func message(b []byte) string {
	var m struct {
		Message any `json:"message"`
	}
	if json.Unmarshal(b, &m) == nil {
		if s, ok := m.Message.(string); ok && s != "" {
			return s
		}
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, s)
}
