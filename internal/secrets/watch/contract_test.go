package watch

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

// What the watcher sends is exactly what testdata/contract/host-contract.json says, and manar-api
// accepts that file: a notice without a tool or path class leaves both fields out.
func TestEventsMatchTheSharedContract(t *testing.T) {
	var fx struct {
		Events struct {
			Edge struct {
				Events []json.RawMessage `json:"events"`
			} `json:"edge"`
		} `json:"events"`
	}
	b, err := os.ReadFile("../../../testdata/contract/host-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339Nano, s); return v }
	sent := []Event{
		{Type: TypeTouched, ToolID: "host.claude-code", Process: "cat", PathClass: ClassAWS, MaskedPath: "~/.aws/credentials", Blocked: true, At: at("2026-11-02T21:01:51.329Z")},
		{Type: TypeTouched, ToolID: "host.vscode-copilot", Process: "docker", PathClass: ClassDocker, MaskedPath: "~/.docker/config.json", At: at("2026-11-02T21:01:52Z")},
		{Type: TypeAvailable, At: at("2026-11-02T21:01:53Z")},
		{Type: "secret.vault.denied", ToolID: "host.claude-code", Process: "aws", PathClass: ClassAWS, Blocked: true, At: at("2026-11-02T21:01:54Z")},
	}
	if len(sent) != len(fx.Events.Edge.Events) {
		t.Fatalf("fixture has %d events, test sends %d", len(fx.Events.Edge.Events), len(sent))
	}
	for i, ev := range sent {
		got, _ := json.Marshal(ev)
		var g, w any
		_ = json.Unmarshal(got, &g)
		_ = json.Unmarshal(fx.Events.Edge.Events[i], &w)
		if !reflect.DeepEqual(g, w) {
			t.Errorf("event %d\n got %s\nwant %s", i, got, fx.Events.Edge.Events[i])
		}
	}
}
