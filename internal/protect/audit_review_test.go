package protect

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// F10: hook.offline_allowed events carry the caller, say the device reported them, and their time
// is clamped to the last 8 hours whatever the hook wrote.
func TestOfflineAllowEventsCarryTheCallerAndAClampedTime(t *testing.T) {
	var got []map[string]any
	tamper.mu.Lock()
	save := tamper.send
	tamper.send = func(ev map[string]any) { got = append(got, ev) }
	tamper.mu.Unlock()
	defer func() { tamper.mu.Lock(); tamper.send = save; tamper.mu.Unlock() }()
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	body := []byte(`{"events":[{"toolId":"host.claude-code","action":"read","path":"/home/sam/proj/a.go","at":"2001-01-01T00:00:00Z"},` +
		`{"toolId":"host.claude-code","action":"read","path":"/home/sam/proj/b.go","at":"` + future + `"}]}`)
	reportOfflineAllows(decodeOfflineAllows(body), "uid:1000|s:abc")
	if len(got) != 2 {
		t.Fatalf("events: %v", got)
	}
	for _, ev := range got {
		if ev["caller"] != "uid:1000" {
			t.Errorf("caller: %v", ev["caller"])
		}
		if ev["deviceReported"] != true {
			t.Errorf("not marked device-reported: %v", ev)
		}
		at, _ := ev["at"].(time.Time)
		if at.Before(time.Now().Add(-offlineMaxAge-time.Minute)) || at.After(time.Now().Add(time.Minute)) {
			b, _ := json.Marshal(ev["at"])
			t.Errorf("time not clamped: %s", strings.TrimSpace(string(b)))
		}
	}
}
