package main

import (
	"regexp"
	"testing"

	"github.com/manarhq/manar-edge/internal/lazyre"
)

// Regular expressions are compiled on first use (lazyre), so a bad pattern would show up in the
// field instead of at start-up. This compiles every pattern the program's packages declare.
func TestEveryDeclaredRegexpCompiles(t *testing.T) {
	ps := lazyre.Patterns()
	if len(ps) < 50 {
		t.Fatalf("only %d patterns registered; are the packages linked in?", len(ps))
	}
	for _, p := range ps {
		if _, err := regexp.Compile(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
}
