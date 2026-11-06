package protect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/manarhq/manar-edge/internal/secrets/host"
)

// An action allowed from the saved policy while the service was away is told to Manar once the
// service is back, so the admin's audit log shows it. The hook (a user process) keeps a small queue
// in the person's own cache folder and hands it to the service on its next successful call. The
// queue is only for the audit trail: it decides nothing, so a person who edits or deletes it gains
// no access, and loses only their own trail.

const (
	maxQueueBytes = 64 << 10
	maxQueueBatch = 50
)

type offlineAllow struct {
	Tool   string    `json:"toolId"`
	Action string    `json:"action"`
	Path   string    `json:"path,omitempty"` // only for file actions; a command is never sent
	At     time.Time `json:"at"`             // the hook's clock: clamped by the service
}

// offlineQueuePath is the queue file (a var so tests can set it).
var offlineQueuePath = func() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "manar-edge", "offline-allows.jsonl")
}

func queueOfflineAllow(key, action, resource string) {
	defer func() { _ = recover() }()
	p := offlineQueuePath()
	if p == "" {
		return
	}
	ev := offlineAllow{Tool: "host." + key, Action: action, At: time.Now().UTC()}
	if pathActions[action] {
		ev.Path = resource
	}
	b, _ := json.Marshal(ev)
	if fi, err := os.Stat(p); err == nil && fi.Size() > maxQueueBytes {
		return
	}
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// flushOfflineAllows hands the queue to the service (best effort, short).
func (r *Relay) flushOfflineAllows() {
	defer func() { _ = recover() }()
	p := offlineQueuePath()
	if p == "" {
		return
	}
	f, err := os.Open(p)
	if err != nil {
		return // nothing queued: the usual case, one failed open
	}
	var evs []offlineAllow
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(evs) < maxQueueBatch {
		var e offlineAllow
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			evs = append(evs, e)
		}
	}
	f.Close()
	if len(evs) == 0 {
		_ = os.Remove(p)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var ignore map[string]any
	if r.call(ctx, http.MethodPost, "/v1/offline-allows", map[string]any{"events": evs}, &ignore) == nil {
		_ = os.Remove(p)
	}
}

// reportOfflineAllows sends the events a hook queued. The service takes the person from the kernel
// (the caller), checks the tool, and masks the path; the hook only names what it allowed. The event
// carries the caller, says it was reported by the device, and its time is the hook's clock clamped
// to the last offlineMaxAge, so a hook cannot backdate or postdate the audit trail.
func reportOfflineAllows(evs []offlineAllow, caller string) {
	now := time.Now().UTC()
	for _, e := range evs {
		if !validTool(e.Tool) || e.Action == "" || len(e.Action) > 32 || len(e.Path) > 2048 {
			continue
		}
		path := ""
		if e.Path != "" {
			path = host.MaskPath(host.Homes(), e.Path)
		}
		at := e.At.UTC()
		if at.Before(now.Add(-offlineMaxAge)) {
			at = now.Add(-offlineMaxAge)
		}
		if at.After(now) {
			at = now
		}
		sendEvent(map[string]any{"type": "hook.offline_allowed", "toolId": e.Tool, "process": e.Action,
			"maskedPath": clipText(path, 1024), "blocked": false, "at": at,
			"caller": callerID(caller), "deviceReported": true})
	}
}

func decodeOfflineAllows(body []byte) []offlineAllow {
	var in struct {
		Events []offlineAllow `json:"events"`
	}
	if json.NewDecoder(bytes.NewReader(body)).Decode(&in) != nil || len(in.Events) > maxQueueBatch {
		return nil
	}
	return in.Events
}
