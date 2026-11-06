package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/manarhq/manar-edge/internal/lazyre"
)

// slugPattern is what we accept for tenant and agent slugs. Anything else is refused at
// enrollment, so derived names are always safe in paths, unit names and nft rules.
var slugPattern = lazyre.New(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// maxNameLen is the Linux interface and netns name limit the contract sizes names for.
const maxNameLen = 15

// edgeName derives the on-disk name: a prefix of `<tenant>-<agent>` plus 8 hex characters (32 bits)
// of a hash of the full pair, at most 15 characters. The hash is always there, so pairs that
// render the same prefix (`a-b`+`c` and `a`+`b-c`) still get different names; enrollment also
// refuses a state dir that belongs to another pair.
func edgeName(tenant, agent string) string {
	base := tenant + "-" + agent
	if len(base) > maxNameLen-9 {
		base = base[:maxNameLen-9]
	}
	sum := sha256.Sum256([]byte(tenant + "/" + agent))
	return strings.TrimRight(base, "-") + "-" + hex.EncodeToString(sum[:4])
}

// Edge is the `edge` object of the enrollment response (docs/design.md section 1).
type Edge struct {
	PeerID           string `json:"peerId"`
	Address          string `json:"address"`
	GatewayPublicKey string `json:"gatewayPublicKey"`
	GatewayEndpoint  string `json:"gatewayEndpoint"`
	ManarAddress     string `json:"manarAddress"`
	ManarServerName  string `json:"manarServerName"`
	ProxyAddress     string `json:"proxyAddress"`
	KeepaliveSeconds int    `json:"keepaliveSeconds"`
}

// State is state.json. It holds no secrets: keys live in their own 0600 files.
type State struct {
	Name        string   `json:"name"`
	TenantSlug  string   `json:"tenantSlug"`
	AgentSlug   string   `json:"agentSlug"`
	WGPublicKey string   `json:"wgPublicKey"`
	Edge        Edge     `json:"edge"`
	EnrolledAt  string   `json:"enrolledAt"`
	NotAfter    string   `json:"notAfter,omitempty"`
	Task        string   `json:"task,omitempty"`
	Programs    []string `json:"programs,omitempty"` // Windows: paths covered by firewall rules
}

const (
	fileState = "state.json"
	fileKey   = "agent.key.pem"
	fileCert  = "agent.cert.pem"
	fileCA    = "ca.pem"
	fileWGKey = "wg.key"
)

func agentDir(base, name string) string { return filepath.Join(base, name) }

func loadState(dir string) (*State, error) {
	b, err := os.ReadFile(filepath.Join(dir, fileState))
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", fileState, err)
	}
	return &s, nil
}

func saveState(dir string, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, fileState), append(b, '\n'))
}

// writePrivate writes a file readable by its owner only, through a temp file and rename so a
// reader never sees a partial key.
func writePrivate(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil { // WriteFile keeps the mode of an existing file
		return err
	}
	return os.Rename(tmp, path)
}

// resolveAgent turns the CLI <agent> argument into a state dir. It accepts the derived name, the
// agent slug when only one tenant uses it, or `<tenant>/<agent>`.
func resolveAgent(base, arg string) (string, *State, error) {
	if t, a, ok := strings.Cut(arg, "/"); ok {
		arg = edgeName(t, a)
	}
	if slugPattern.MatchString(arg) {
		if s, err := loadState(agentDir(base, arg)); err == nil {
			return agentDir(base, arg), s, nil
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return "", nil, fmt.Errorf("no enrolled agents in %s: %w", base, err)
	}
	var found []string
	var st *State
	for _, e := range entries {
		s, err := loadState(agentDir(base, e.Name()))
		if err == nil && s.AgentSlug == arg {
			found = append(found, e.Name())
			st = s
		}
	}
	switch len(found) {
	case 0:
		return "", nil, fmt.Errorf("agent %q is not enrolled on this host (state dir %s)", arg, base)
	case 1:
		return agentDir(base, found[0]), st, nil
	}
	return "", nil, errors.New("agent slug " + arg + " is enrolled for several tenants; use <tenant>/<agent>")
}

// applyTask records a new task for the local gateway; it reports whether the gateway must restart.
func applyTask(dir string, st *State, task string) (bool, error) {
	if task == "" || task == st.Task {
		return false, nil
	}
	if !idPattern.MatchString(task) {
		return false, errors.New("task id has characters this host does not accept")
	}
	st.Task = task
	return true, saveState(dir, st)
}

// listAgents returns every enrolled agent's state dir.
func listAgents(base string) []string {
	entries, _ := os.ReadDir(base)
	var dirs []string
	for _, e := range entries {
		if _, err := loadState(agentDir(base, e.Name())); err == nil {
			dirs = append(dirs, agentDir(base, e.Name()))
		}
	}
	return dirs
}

// copyFile copies src to dst through a temp file and rename.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
