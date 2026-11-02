package protect

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A Claude Code hook input becomes the authorize body in testdata/contract/host-contract.json,
// which manar-api decides (known tool, known action) rather than denying as unknown.
func TestClaudeCodeHookMatchesTheSharedContract(t *testing.T) {
	var fx struct {
		Authorize struct {
			Cases []struct {
				Tool, Event string
				Input       json.RawMessage
				Body        map[string]string
			}
		}
	}
	b, err := os.ReadFile("../../testdata/contract/host-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Authorize.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range fx.Authorize.Cases {
		a, r, err := Classify(c.Tool, c.Event, c.Input)
		if err != nil || a != c.Body["actionId"] || r != c.Body["resource"] {
			t.Errorf("%s: got %q %q %v, want %q %q", c.Input, a, r, err, c.Body["actionId"], c.Body["resource"])
		}
		if id := "host." + c.Tool; id != c.Body["toolId"] || !validTool(id) {
			t.Errorf("the relay does not forward %s", c.Body["toolId"])
		}
		if _, sid, _ := strings.Cut(c.Body["caller"], "|s:"); sid != SessionID(c.Input) || !sessionOK.MatchString(sid) {
			t.Errorf("session %q not carried", SessionID(c.Input))
		}
	}
}
