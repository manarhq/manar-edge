package protect

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/secrets/host"
)

// Tampering Manar can see and reports to the console (POST /host/v1/events). The console marks
// the device "tampered" and says which of these happened. Personal mode cannot stop a person, or a
// program they run, from switching the hooks off; it can block AI tools from doing it through the
// hook and say what it saw.
const (
	// TamperSettingsWrite: a hook refused an AI tool's edit or command on a hook or settings file.
	TamperSettingsWrite = "protect.tamper.settings_write"
	// TamperHookRemoved: Manar's hook was taken out of a settings file Manar protects (put back).
	TamperHookRemoved = "protect.tamper.hook_removed"
	// TamperHooksDisabled: a project's Claude Code settings set disableAllHooks.
	TamperHooksDisabled = "protect.tamper.hooks_disabled"
	// TamperSettingsFlag: Claude Code was started with --settings.
	TamperSettingsFlag = "protect.tamper.settings_flag"
	// TamperConfigDir: Claude Code runs with CLAUDE_CONFIG_DIR pointing away from ~/.claude.
	TamperConfigDir = "protect.tamper.config_dir"
)

// tamperEvery is how often the same thing is reported again while it lasts.
const tamperEvery = 6 * time.Hour

var tamper struct {
	mu   sync.Mutex
	c    *hostclient.Client
	seen map[string]time.Time
	// send is replaced by tests.
	send func(ev map[string]any)
}

func setTamperClient(c *hostclient.Client) {
	tamper.mu.Lock()
	tamper.c = c
	tamper.mu.Unlock()
}

// reportTamper sends one event, at most once per tamperEvery for the same kind, tool and place.
// Best effort: it never blocks the caller and never decides anything.
func reportTamper(kind, toolID, process, path string, blocked bool) {
	key := kind + "\x00" + toolID + "\x00" + process + "\x00" + path
	now := time.Now()
	tamper.mu.Lock()
	if tamper.seen == nil {
		tamper.seen = map[string]time.Time{}
	}
	if t, ok := tamper.seen[key]; ok && now.Sub(t) < tamperEvery {
		tamper.mu.Unlock()
		return
	}
	if len(tamper.seen) > 1000 {
		tamper.seen = map[string]time.Time{}
	}
	tamper.seen[key] = now
	tamper.mu.Unlock()

	ev := map[string]any{"type": kind, "toolId": toolID, "blocked": blocked, "at": now.UTC()}
	if process != "" {
		ev["process"] = clipText(process, 128)
	}
	if path != "" {
		ev["maskedPath"] = clipText(host.MaskPath(host.Homes(), path), 1024)
	}
	logOnce("tampering seen (" + kind + ") for " + toolID + ": reported to the console")
	sendEvent(ev)
}

// sendEvent posts one device event to Manar (best effort, never blocks the caller). Tests replace
// tamper.send.
func sendEvent(ev map[string]any) {
	tamper.mu.Lock()
	c, send := tamper.c, tamper.send
	tamper.mu.Unlock()
	if send != nil {
		send(ev)
		return
	}
	if c == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.Do(ctx, http.MethodPost, "/events", map[string]any{"events": []any{ev}}, nil); err != nil {
			log.Printf("manar-edge: protect: event report: %v", err)
		}
	}()
}

// clipText cuts s to at most n bytes on a rune boundary and drops control characters.
func clipText(s string, n int) string {
	out := make([]rune, 0, len(s))
	size := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		l := len(string(r))
		if size+l > n {
			break
		}
		out = append(out, r)
		size += l
	}
	return string(out)
}
