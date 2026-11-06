package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

// maxDowntime bounds what is reported; an older mark is a machine that was off, not a restart.
const maxDowntime = 24 * time.Hour

func alivePath(state string) string { return filepath.Join(hostclient.Dir(state), "alive") }

// markAlive records that the service ran at now (every heartbeat, so the error is at most 15 s).
func markAlive(state string, now time.Time) {
	if state == "" {
		return
	}
	_ = os.WriteFile(alivePath(state), []byte(strconv.FormatInt(now.Unix(), 10)), 0o600)
}

// markStopped removes the mark: a clean stop is not a restart.
func markStopped(state string) {
	if state != "" {
		_ = os.Remove(alivePath(state))
	}
}

// takeRestart is true, with the time since the last mark, when the previous run left its mark
// behind (it did not stop cleanly). The mark is consumed.
func takeRestart(state string, now time.Time) (time.Duration, bool) {
	if state == "" {
		return 0, false
	}
	b, err := os.ReadFile(alivePath(state))
	if err != nil {
		return 0, false
	}
	_ = os.Remove(alivePath(state))
	sec, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	d := now.Sub(time.Unix(sec, 0))
	if d < 0 || d > maxDowntime {
		return 0, false
	}
	return d, true
}
