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
	"strings"
	"sync"
	"time"

	"github.com/manarhq/manar-edge/internal/lazyre"
)

const (
	dirName  = "host"
	fileKey  = "host.key.pem"
	fileCert = "host.cert.pem"
	fileCA   = "host-ca.pem"
	fileInfo = "host.json"
	// fileRemoved exists while the workspace has removed this device (see MarkRemoved).
	fileRemoved = "removed"
	// fileLocked exists while Manar refuses this device with 423 (see LockedCode).
	fileLocked = "locked"

	maxBody = 1 << 20
)

var machineIDPattern = lazyre.New(`^[A-Za-z0-9._-]{1,128}$`)

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

	// MovedFrom is the workspace this enrolment moved the device away from (not stored).
	MovedFrom string `json:"-"`
	old       *Client
}

// TellOldWorkspace tells the workspace the device moved away from (POST /host/v1/moved, signed with
// the old certificate, held in memory since before the move). Call it only after the running
// service is stopped: told first, the old workspace answers that service 410 device_removed, and
// it would take protection out. It then clears any removed or locked mark that service left. It
// reports whether the old workspace was told.
func (i *Info) TellOldWorkspace(ctx context.Context, stateDir string) bool {
	if i.MovedFrom == "" || i.old == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ok := i.old.Do(ctx, http.MethodPost, "/moved", nil, nil) == nil
	_ = ClearRemoved(stateDir)
	_ = clearLocked(stateDir)
	return ok
}

// OtherWorkspaceError: the device is enrolled in another workspace. Enrolling here moves it, so
// the person must confirm first (EnrolInput.ConfirmMove); nothing was sent.
type OtherWorkspaceError struct{ From, To string }

func (e *OtherWorkspaceError) Error() string {
	return fmt.Sprintf("this computer is enrolled in workspace %q; installing for workspace %q moves it there and that workspace's rules will apply to the AI tools on it", e.From, e.To)
}

// EnrolInput is what Enrol needs. WriteDir must already exist with the right permissions.
type EnrolInput struct {
	StateDir string
	APIURL   string // https base URL of the Manar API (loopback http allowed)
	HostURL  string // https base URL of the mTLS listener
	// InstallKey is a `mik_<tenant>_...` key, or the short code from the console's Add device
	// (then TenantSlug names the tenant: the code does not).
	InstallKey string
	TenantSlug string
	MachineID  string
	Hostname   string
	OS         string
	HTTP       *http.Client // optional; tests inject a client that trusts their server
	// ConfirmMove: the person confirmed moving the device from the workspace it is enrolled in.
	ConfirmMove bool
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
		if !shortCode.MatchString(in.InstallKey) || !slugPattern.MatchString(in.TenantSlug) {
			return nil, errors.New("the install code is not valid")
		}
		slug = in.TenantSlug
	}
	// Enrolled in another workspace: only with the person's confirmation, a NEW key (one key per
	// workspace, never reused), and the old workspace told, with the old certificate (loaded now,
	// before anything on disk changes).
	var moveFrom string
	var old *Client
	if prev, err := enrolled(in.StateDir); err == nil && prev.TenantSlug != "" && prev.TenantSlug != slug {
		moveFrom = prev.TenantSlug
		if !IsMarkedRemoved(in.StateDir) {
			if !in.ConfirmMove {
				return nil, &OtherWorkspaceError{From: moveFrom, To: slug}
			}
			old, _ = New(in.StateDir) // best effort: a broken old enrolment cannot be told
		}
	}
	// Otherwise the key is written BEFORE the request and reused by every later run: a re-install
	// after a failed or interrupted one presents the same key, so the server sees the same machine,
	// not a new device.
	var key *ecdsa.PrivateKey
	if moveFrom != "" {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = loadOrCreateKey(Dir(in.StateDir))
	}
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
	if moveFrom != "" {
		info.MovedFrom, info.old = moveFrom, old
		// The old client must not touch this state dir: its lock or removed marks are not ours.
		if old != nil {
			old.stateDir = ""
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := writePrivate(filepath.Join(dir, fileKey), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
			return nil, err
		}
	}
	// A fresh registration is a new start: protection may resume.
	if err := ClearRemoved(in.StateDir); err != nil {
		return nil, err
	}
	if err := clearLocked(in.StateDir); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
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

// enrolled reads host.json.
func enrolled(stateDir string) (*Info, error) {
	b, err := os.ReadFile(filepath.Join(Dir(stateDir), fileInfo))
	if err != nil {
		return nil, err
	}
	var info Info
	return &info, json.Unmarshal(b, &info)
}

// Client calls /host/v1/* over mTLS.
type Client struct {
	Info *Info
	http *http.Client
	base string
	// stateDir is where the device keeps its files (pause flag, WARDEN settings).
	stateDir string

	removedOnce sync.Once
	removed     chan struct{}
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
	return &Client{Info: &info, base: base.String(), stateDir: stateDir, removed: make(chan struct{}), http: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS13,
		}},
	}}, nil
}

// NewForTest builds a client for an already running server, with no host files. Tests only.
func NewForTest(stateDir, baseURL string, hc *http.Client) *Client {
	return &Client{Info: &Info{}, http: hc, base: baseURL, stateDir: stateDir, removed: make(chan struct{})}
}

// StateDir is the state directory this client was loaded from.
func (c *Client) StateDir() string { return c.stateDir }

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
	// A locked device only polls its config (to learn when it is let back in); nothing else leaves.
	if path != "/config" && c.stateDir != "" {
		if code := LockedCode(c.stateDir); code != "" {
			return &StatusError{Code: http.StatusLocked, APICode: code, Message: "this device is locked by its workspace"}
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if res.StatusCode/100 != 2 {
		se := &StatusError{Code: res.StatusCode, Message: message(b), APICode: apiCode(b)}
		if se.Removed() && c.removed != nil {
			c.removedOnce.Do(func() { close(c.removed) })
		}
		if se.Locked() && c.stateDir != "" {
			if err := markLocked(c.stateDir, se.APICode); err != nil {
				return errors.Join(se, err)
			}
		}
		return se
	}
	if path == "/config" && c.stateDir != "" {
		if err := clearLocked(c.stateDir); err != nil {
			return err
		}
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
	APICode string // the "code" field of the JSON error body, if any
}

// Removed is true only for HTTP 410 with code "device_removed": the workspace removed this
// device. No other status (401, 403, 5xx, a 410 without the code) counts.
func (e *StatusError) Removed() bool {
	return e.Code == http.StatusGone && e.APICode == "device_removed"
}

// Locked is HTTP 423: Manar will not serve this genuine device (revoked, suspended, workspace
// deleted). The device keeps its hooks and denies AI actions; it never unprotects on it.
func (e *StatusError) Locked() bool { return e.Code == http.StatusLocked }

// LockedCode is the reason Manar gave when it locked this device ("" while it is not locked).
// device_revoked also wipes the secret vault (a lost or stolen laptop).
func LockedCode(stateDir string) string {
	b, err := os.ReadFile(filepath.Join(Dir(stateDir), fileLocked))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	var l struct {
		Code string `json:"code"`
	}
	if err != nil || json.Unmarshal(b, &l) != nil || l.Code == "" {
		return "locked" // unreadable or tampered with: still locked (fail closed)
	}
	return l.Code
}

var lockedCodePattern = lazyre.New(`^[a-z_]{1,64}$`)

func markLocked(stateDir, code string) error {
	if !lockedCodePattern.MatchString(code) {
		code = "locked"
	}
	if LockedCode(stateDir) == code {
		return nil
	}
	if err := os.MkdirAll(Dir(stateDir), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]string{"code": code, "at": time.Now().UTC().Format(time.RFC3339)})
	return writePrivate(filepath.Join(Dir(stateDir), fileLocked), append(b, '\n'))
}

func clearLocked(stateDir string) error {
	err := os.Remove(filepath.Join(Dir(stateDir), fileLocked))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// IsRemoved reports whether err is the "device removed from the workspace" reply.
func IsRemoved(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Removed()
}

// Removed is closed the first time a call on this client gets the "device removed" reply.
func (c *Client) Removed() <-chan struct{} { return c.removed }

// MarkRemoved records on disk that the workspace removed this device, so a restart or reboot
// does not resume protection. Enrol (and ClearRemoved) undo it.
func MarkRemoved(stateDir string) error {
	dir := Dir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, fileRemoved), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"))
}

// IsMarkedRemoved reports whether MarkRemoved was called and not cleared since.
func IsMarkedRemoved(stateDir string) bool {
	_, err := os.Stat(filepath.Join(Dir(stateDir), fileRemoved))
	return err == nil
}

// ClearRemoved forgets a removal; a fresh enrolment calls it.
func ClearRemoved(stateDir string) error {
	err := os.Remove(filepath.Join(Dir(stateDir), fileRemoved))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func apiCode(b []byte) string {
	var m struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(b, &m)
	return m.Code
}

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Code, e.Message) }

// Config is GET /host/v1/config: the effective preset and the feature flags for this device.
type Config struct {
	HostID    string   `json:"hostId"`
	Status    string   `json:"status"` // PENDING until the owner approves it
	StartMode string   `json:"startMode"`
	Features  []string `json:"features"`
	// Tools carries the owner's per-tool choices (coverage track): Unprotect lists tool ids
	// whose protection the owner turned off; the device restores their backups.
	Tools ToolInstructions `json:"tools"`
	// Paused is the workspace's "Pause all AI": deny every protected tool with reason "paused".
	Paused bool `json:"paused"`
	// Door is the owner's DOOR (local LLM gateway) setup: secrets guard mode and tools paused by
	// the monthly spend cap. Nil from an API that does not send it.
	Door *DoorSettings `json:"door,omitempty"`
	// Jail is the egress filter for protected AI tools (jail track).
	Jail JailConfig `json:"jail"`
	// DataCollection is the effective product-improvement-data choice of the device's owner.
	// Nil (an API that does not send it) means off.
	DataCollection *DataCollection `json:"dataCollection,omitempty"`
	// VaultGrants lists the standing secret-vault grants ("8 hours", "Always") the device may keep;
	// it drops any other. Nil from an API that does not send it: then no standing grant counts.
	VaultGrants *[]VaultGrant `json:"vaultGrants,omitempty"`
	// OfflineReadsAllowed is the workspace policy that reads of ordinary files keep working while
	// the device service restarts (decision 35). Nil from an API that does not send it: no.
	OfflineReadsAllowed *bool `json:"offlineReadsAllowed,omitempty"`
	// OfflineReadDeny are path patterns (globs, or folders ending in a slash) never read offline.
	OfflineReadDeny []string `json:"offlineReadDeny,omitempty"`
	// PolicyVersion identifies the workspace policy in force. A different value than before drops
	// every allow the device kept for offline use. Empty from an API that does not send it.
	PolicyVersion string `json:"policyVersion,omitempty"`
}

// VaultGrant is one standing grant: the console request that gave it and when it ends (nil: no end).
type VaultGrant struct {
	ID    string     `json:"id"`
	Until *time.Time `json:"until"`
}

// DataCollection is the "dataCollection" part of GET /host/v1/config.
type DataCollection struct {
	ImproveManar bool `json:"improveManar"`
	AITraining   bool `json:"aiTraining"`
}

// DoorSettings is the "door" part of GET /host/v1/config.
type DoorSettings struct {
	Secrets string   `json:"secrets"` // "mask" (default) or "block"
	Paused  []string `json:"paused"`  // providers (anthropic, openai, gemini) a monthly cap paused
	// Unavailable is set by the API when it could not work the settings out: keep the last ones.
	Unavailable bool `json:"unavailable,omitempty"`
}

// JailConfig is the "jail" part of GET /host/v1/config.
type JailConfig struct {
	Enabled bool `json:"enabled"`
	// Windows is the separate switch for Windows (off until proven on a real desktop).
	Windows bool `json:"windows"`
	// Tools are the tool ids to filter on this device.
	Tools []string `json:"tools"`
	// Rules are the remembered per-site decisions.
	Rules []JailRule `json:"rules"`
}

// JailRule is one remembered decision: a site an owner allowed or blocked for one tool.
type JailRule struct {
	ToolID    string     `json:"toolId"`
	Site      string     `json:"site"`
	Mode      string     `json:"mode"` // ALLOW or DENY
	ExpiresAt *time.Time `json:"expiresAt"`
}

// ToolInstructions is the "tools" part of GET /host/v1/config.
type ToolInstructions struct {
	Unprotect []string `json:"unprotect"`
}

// Tool is one AI tool in the inventory (POST /host/v1/inventory).
type Tool struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Path        string   `json:"path,omitempty"`
	Protected   bool     `json:"protected"`
	ProtectMode string   `json:"protectMode"` // hook, mcp, gateway or none
	Changes     []string `json:"changes,omitempty"`
}

// MCPServer is one MCP server a tool is configured to use. It is an allow-list: the command's
// base name, the package and pinned version, the transport, and a remote server's scheme, host and
// port. Arguments are never sent (only how many), and neither are environment values (names only),
// URL credentials, paths or query strings. OutsideHome is a yes/no worked out on the device from
// the arguments.
type MCPServer struct {
	Tool        string   `json:"tool"` // host.cursor
	Name        string   `json:"name"`
	Transport   string   `json:"transport"` // stdio, http or sse
	Command     string   `json:"command,omitempty"`
	ArgCount    int      `json:"argCount,omitempty"`
	URL         string   `json:"url,omitempty"`
	Package     string   `json:"package,omitempty"`
	Version     string   `json:"version,omitempty"`
	EnvKeys     []string `json:"envKeys,omitempty"`
	OutsideHome bool     `json:"outsideHome,omitempty"`
}

// Inventory reports the AI tools and their MCP servers found on this device. It is the whole list:
// a tool or server left out is treated as gone. An older Manar ignores mcpServers.
func (c *Client) Inventory(ctx context.Context, tools []Tool, mcp []MCPServer) error {
	if tools == nil {
		tools = []Tool{}
	}
	if mcp == nil {
		mcp = []MCPServer{}
	}
	return c.Do(ctx, http.MethodPost, "/inventory", map[string]any{"tools": tools, "mcpServers": mcp}, nil)
}

// Authorize asks for a decision on an action of another AI tool (POST /host/v1/authorize).
type AuthorizeResult struct {
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	ApprovalID string `json:"approvalId"`
	// Cacheable is false for an ALLOW served because of learning mode or a long grant: the device
	// must not keep it for offline use, or it would outlive the window or the revocation. Nil from an
	// API that does not send it (then only a plain policy allow may be kept).
	Cacheable *bool `json:"cacheable,omitempty"`
}

// Authorize asks for a decision. resolvedPath, when not empty, is the target of a file action with
// its links resolved; the API refuses learning and folder scopes when it differs from resource.
func (c *Client) Authorize(ctx context.Context, toolID, actionID, resource, caller, resolvedPath string) (*AuthorizeResult, error) {
	var out AuthorizeResult
	body := map[string]string{"toolId": toolID, "actionId": actionID, "resource": resource, "caller": caller}
	if resolvedPath != "" {
		body["resolvedPath"] = resolvedPath
	}
	err := c.Do(ctx, http.MethodPost, "/authorize", body, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ApprovalStatus reads the state of an approval opened by Authorize (APPROVED, PENDING, ...).
// The approvals track serves GET /host/v1/approvals/:id; until it does this returns an error and
// the hook denies.
func (c *Client) ApprovalStatus(ctx context.Context, id string) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	if err := c.Do(ctx, http.MethodGet, "/approvals/"+url.PathEscape(id), nil, &out); err != nil {
		return "", err
	}
	return out.Status, nil
}

// Config fetches the device's effective configuration.
func (c *Client) Config(ctx context.Context) (*Config, error) {
	var cfg Config
	if err := c.Do(ctx, http.MethodGet, "/config", nil, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var (
	shortCode   = lazyre.New(`^[A-HJKMNP-Z2-9]{10}$`)
	slugPattern = lazyre.New(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

var keyPattern = lazyre.New(`^mik_([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)_[A-Za-z0-9_-]{43}$`)

func tenantSlugOf(installKey string) (string, bool) {
	m := keyPattern.FindStringSubmatch(installKey)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// loadOrCreateKey returns the host key in dir/host.key.pem, creating (and writing, 0600) it first.
func loadOrCreateKey(dir string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(dir, fileKey)
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil {
			if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
				if ec, ok := k.(*ecdsa.PrivateKey); ok {
					return ec, nil
				}
			}
		}
		// An unreadable key file is replaced, not trusted.
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := writePrivate(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
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
