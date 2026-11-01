package pause

import (
	"os"
	"testing"
)

func TestPausedRoundTripAndFailClosed(t *testing.T) {
	base := t.TempDir()
	if Paused(base) {
		t.Fatal("no file must mean not paused")
	}
	if err := Set(base, true); err != nil || !Paused(base) {
		t.Fatalf("set true: %v paused=%v", err, Paused(base))
	}
	if err := Set(base, false); err != nil || Paused(base) {
		t.Fatalf("set false: %v paused=%v", err, Paused(base))
	}
	if err := os.WriteFile(path(base), []byte("{garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Paused(base) {
		t.Fatal("an unreadable state file must mean paused")
	}
}
