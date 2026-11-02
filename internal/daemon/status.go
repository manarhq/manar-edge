package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// The device service publishes a small status file that any local user may read, so
// `manar-edge status` works without root. It holds no secret: the host id, the tenant slug, the
// approval state, feature names, the last sync time and one line per component.

// Component is one part of the device service (door, jail, warden, secrets, or a module).
type Component struct {
	State  string `json:"state"` // ok, off, problem
	Detail string `json:"detail,omitempty"`
	// Fix is one line a person can act on when State is problem.
	Fix string `json:"fix,omitempty"`
}

// ToolStatus is one AI tool found on the device.
type ToolStatus struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
	Mode      string `json:"mode"`
}

// Snapshot is the status file.
type Snapshot struct {
	UpdatedAt  time.Time `json:"updatedAt"`
	HostID     string    `json:"hostId,omitempty"`
	TenantSlug string    `json:"tenantSlug,omitempty"`
	Status     string    `json:"status,omitempty"` // PENDING, APPROVED, ...
	// Removed is set once the workspace removed this device: protection is off until it enrols again.
	Removed     bool                 `json:"removed,omitempty"`
	StartMode   string               `json:"startMode,omitempty"`
	Features    []string             `json:"features,omitempty"`
	LastSyncAt  *time.Time           `json:"lastSyncAt,omitempty"`
	LastError   string               `json:"lastError,omitempty"`
	Components  map[string]Component `json:"components,omitempty"`
	Tools       []ToolStatus         `json:"tools,omitempty"`
	ToolsSeenAt *time.Time           `json:"toolsSeenAt,omitempty"`
}

var (
	stMu   sync.Mutex
	cur    = Snapshot{Components: map[string]Component{}}
	notify = make(chan struct{}, 1)

	// StatusPath is where the file is written ("" disables it). Set before Run.
	StatusPath = defaultStatusPath()
)

// SetComponent records the state of one component. Feature packages call it when their state
// changes; the file is rewritten soon after.
func SetComponent(name string, c Component) {
	stMu.Lock()
	cur.Components[name] = c
	stMu.Unlock()
	poke()
}

// SetTools records the AI tools found and how each is protected.
func SetTools(tools []ToolStatus) {
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	now := time.Now().UTC()
	stMu.Lock()
	cur.Tools, cur.ToolsSeenAt = tools, &now
	stMu.Unlock()
	poke()
}

func recordSync(hostID, status, mode string, features []string, err error) {
	now := time.Now().UTC()
	stMu.Lock()
	if err == nil {
		cur.HostID, cur.Status, cur.StartMode, cur.Features = hostID, status, mode, features
		cur.LastSyncAt, cur.LastError = &now, ""
	} else {
		msg := err.Error()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		cur.LastError = msg
	}
	stMu.Unlock()
	poke()
}

// SetIdentity records who this device is, once, at start.
func SetIdentity(hostID, tenantSlug string) {
	stMu.Lock()
	cur.HostID, cur.TenantSlug = hostID, tenantSlug
	stMu.Unlock()
	poke()
}

// setRemoved records that the workspace removed this device. The device keeps no tool or part
// state of its own: everything is off.
func setRemoved() {
	stMu.Lock()
	cur.Removed, cur.Status, cur.Features, cur.LastError = true, "REMOVED", nil, ""
	cur.Tools, cur.ToolsSeenAt = nil, nil
	cur.Components = map[string]Component{}
	stMu.Unlock()
	poke()
}

func poke() {
	select {
	case notify <- struct{}{}:
	default:
	}
}

// writeStatus writes the current snapshot atomically, world-readable.
func writeStatus() error {
	if StatusPath == "" {
		return nil
	}
	stMu.Lock()
	cur.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(cur, "", "  ")
	stMu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(StatusPath), 0o755); err != nil {
		return err
	}
	tmp := StatusPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, StatusPath)
}

// ReadStatus reads a status file.
func ReadStatus(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// statusWriter keeps the file fresh: on every change (debounced) and at least every 30 s.
func statusWriter(done <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	_ = writeStatus()
	for {
		select {
		case <-done:
			return
		case <-notify:
			time.Sleep(500 * time.Millisecond)
		case <-t.C:
		}
		_ = writeStatus()
	}
}
