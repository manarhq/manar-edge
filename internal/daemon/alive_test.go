package daemon

import (
	"os"
	"testing"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

func TestRestartAfterACrashIsReportedWithItsDowntime(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(hostclient.Dir(dir), 0o700)
	now := time.Now()
	markAlive(dir, now.Add(-9*time.Second))
	d, ok := takeRestart(dir, now)
	if !ok || d < 8*time.Second || d > 10*time.Second {
		t.Fatalf("%v %v", d, ok)
	}
	if _, ok := takeRestart(dir, now); ok {
		t.Fatal("the mark must be consumed")
	}
}

func TestCleanStopAndLongAbsenceAreNotRestarts(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(hostclient.Dir(dir), 0o700)
	now := time.Now()
	markAlive(dir, now)
	markStopped(dir)
	if _, ok := takeRestart(dir, now); ok {
		t.Fatal("a clean stop reported as a restart")
	}
	markAlive(dir, now.Add(-3*24*time.Hour))
	if _, ok := takeRestart(dir, now); ok {
		t.Fatal("a machine that was off for days reported as a restart")
	}
}
