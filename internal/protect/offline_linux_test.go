package protect

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// serve answers every request on the relay socket with the given status and body.
func serve(t *testing.T, status int, body string) {
	t.Helper()
	l, err := net.Listen("unix", relaySock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
}

func relayRig(t *testing.T) string {
	t.Helper()
	offlineRig(t)
	dir := t.TempDir()
	saveDir, saveSock, saveOwner := relayDir, relaySock, relayOwner
	relayDir, relaySock, relayOwner = dir, filepath.Join(dir, "relay.sock"), uint32(os.Geteuid())
	t.Cleanup(func() { relayDir, relaySock, relayOwner = saveDir, saveSock, saveOwner })
	proj := project(t)
	setOfflineReadsPolicy(true, nil)
	recordOfflineDecision("host.cursor", me, "shell", "go build ./...", "", "ALLOW")
	recordOfflineDecision("host.cursor", me, "read", filepath.Join(proj, "a.go"), proj, "ALLOW")
	save(t)
	return proj
}

const closedHint = "restart it or contact their administrator"

func decide(action, res string) Verdict {
	return NewRelay().Decide(context.Background(), "cursor", action, res, 5e9)
}

// Only a service that cannot be reached at all uses the last policy.
func TestDecideUsesTheLastPolicyOnlyWhenTheServiceCannotBeReached(t *testing.T) {
	proj := relayRig(t)
	inside := filepath.Join(proj, "other.go")

	// socket missing
	if v := decide("read", inside); !v.Allow {
		t.Fatalf("missing socket: %+v", v)
	}
	if v := decide("shell", "git push"); v.Allow || !strings.Contains(v.Reason, "Try again in a moment") {
		t.Fatalf("approval-needing action must wait: %+v", v)
	}

	// connection refused: a socket file nobody listens on
	l, err := net.Listen("unix", relaySock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if v := decide("shell", "go build ./..."); !v.Allow {
		t.Fatalf("refused: %+v", v)
	}
	_ = os.Remove(relaySock)
}

func TestDecideFailsClosedWhenTheServiceAnsweredWithAnError(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"403":            {403, "forbidden"},
		"404":            {404, ""},
		"500":            {500, "boom"},
		"502":            {502, "upstream"},
		"garbage 200":    {200, "not json"},
		"empty 200":      {200, ""},
		"wrong shape":    {200, "[1,2]"},
		"decision error": {200, `{"decision":7}`},
	} {
		t.Run(name, func(t *testing.T) {
			proj := relayRig(t)
			serve(t, c.status, c.body)
			v := decide("read", filepath.Join(proj, "other.go")) // would pass offline
			if v.Allow || !strings.Contains(v.Reason, closedHint) {
				t.Fatalf("an answering service must fail closed: %+v", v)
			}
		})
	}
}

func TestDecideFailsClosedWithoutAValidSnapshot(t *testing.T) {
	proj := relayRig(t)
	_ = os.Remove(offlineFile(stateDirNow()))
	v := decide("read", filepath.Join(proj, "other.go"))
	if v.Allow || !strings.Contains(v.Reason, closedHint) || strings.Contains(v.Reason, "manar-edge ") {
		t.Fatalf("%+v", v)
	}
}

// Only a refused connection or a missing socket is "down"; a timeout or anything else fails closed.
func TestOnlyRefusedOrMissingSocketCountsAsServiceDown(t *testing.T) {
	var down *downError
	for name, err := range map[string]error{
		"refused": &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
		"missing": &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENOENT)},
	} {
		if !errors.As(classifyDial(err), &down) {
			t.Errorf("%s not treated as down", name)
		}
	}
	for name, err := range map[string]error{
		"deadline":   context.DeadlineExceeded,
		"io timeout": os.ErrDeadlineExceeded,
		"denied":     &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EACCES)},
		"reset":      &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)},
		"other":      errors.New("boom"),
	} {
		if errors.As(classifyDial(err), &down) {
			t.Errorf("%s treated as down", name)
		}
	}
}

// The real file checks, posing as the owner the service would be (the test user, since a test is
// not root): a link, a group-writable file or folder, or another owner is refused.
func TestReadTrustedRefusesLinksAndUnprotectedFiles(t *testing.T) {
	base := filepath.Join(t.TempDir(), "var")
	state := filepath.Join(base, "state")
	saveUID, saveRoot := trustedUID, trustedRoot
	trustedUID, trustedRoot = uint32(os.Geteuid()), base
	t.Cleanup(func() { trustedUID, trustedRoot = saveUID, saveRoot })
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	good := []byte(`{"version":1}`)
	if err := writeOffline(state, good); err != nil {
		t.Fatal(err)
	}
	if b, err := realReadTrusted(state); err != nil || string(b) != string(good) {
		t.Fatalf("a protected snapshot was refused: %v", err)
	}
	f, d := offlineFile(state), offlineDir(state)

	if err := os.Chmod(f, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := realReadTrusted(state); err == nil {
		t.Error("a group-writable file was trusted")
	}
	_ = os.Chmod(f, 0o644)

	if err := os.Chmod(d, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := realReadTrusted(state); err == nil {
		t.Error("a group-writable folder was trusted")
	}
	_ = os.Chmod(d, 0o755)

	trustedUID++ // not the service's owner
	if _, err := realReadTrusted(state); err == nil {
		t.Error("a file owned by someone else was trusted")
	}
	trustedUID--

	// the file replaced by a link to a good-looking file
	real := filepath.Join(base, "elsewhere.json")
	_ = os.Rename(f, real)
	if err := os.Symlink(real, f); err != nil {
		t.Fatal(err)
	}
	if _, err := realReadTrusted(state); err == nil {
		t.Error("a linked snapshot file was followed")
	}
	_ = os.Remove(f)
	_ = os.Rename(real, f)

	// the folder replaced by a link
	moved := d + ".real"
	_ = os.Rename(d, moved)
	if err := os.Symlink(moved, d); err != nil {
		t.Fatal(err)
	}
	if _, err := realReadTrusted(state); err == nil {
		t.Error("a linked snapshot folder was followed")
	}
	if err := writeOffline(state, good); err == nil {
		t.Error("the service wrote through a linked folder")
	}
}
