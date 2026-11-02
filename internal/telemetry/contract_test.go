package telemetry

import (
	"encoding/json"
	"os"
	"testing"
)

// The commands manar-api stores for the Sessions view are redacted by its port of redactPortable.
// Both read the same answers from testdata/contract/host-contract.json.
func TestRedactionMatchesTheSharedContract(t *testing.T) {
	var fx struct {
		Redact struct {
			Cases []struct{ In, Out string }
		}
	}
	b, err := os.ReadFile("../../testdata/contract/host-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Redact.Cases) == 0 {
		t.Fatal("no redaction cases")
	}
	for _, c := range fx.Redact.Cases {
		if got := cut(redactPortable(c.In), maxSample); got != c.Out {
			t.Errorf("redact(%q)\n got %q\nwant %q", c.In, got, c.Out)
		}
	}
}
