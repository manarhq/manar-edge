package protect

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

type fakeBackend struct {
	calls  int
	caller string
}

func (f *fakeBackend) Authorize(_ context.Context, tool, action, res, caller string) (*hostclient.AuthorizeResult, error) {
	f.calls++
	f.caller = caller
	return &hostclient.AuthorizeResult{Decision: "ALLOW"}, nil
}
func (f *fakeBackend) ApprovalStatus(context.Context, string) (string, error) { return "APPROVED", nil }

func TestRelayOnlyForwardsKnownToolsAndRecordsTheCaller(t *testing.T) {
	dir := t.TempDir()
	relayDir, relaySock, relayOwner = dir, filepath.Join(dir, "relay.sock"), uint32(os.Geteuid())
	l, err := listenRelay()
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{}
	srv := newRelayServer(b)
	go srv.Serve(l)
	defer srv.Close()

	r := NewRelay()
	if v := r.Decide(context.Background(), "cursor", "shell", "ls", 5e9); !v.Allow || b.calls != 1 {
		t.Fatalf("valid call not forwarded: %+v", v)
	}
	if b.caller != "uid:"+strconv.Itoa(os.Geteuid()) {
		t.Fatalf("caller %q: the kernel's answer must be recorded", b.caller)
	}
	// Tools Manar does not wrap, and empty fields, never reach Manar.
	for _, tool := range []string{"claude-code", "nope"} {
		if v := r.Decide(context.Background(), tool, "shell", "ls", 5e9); v.Allow {
			t.Errorf("allowed unknown tool %s", tool)
		}
	}
	if v := r.Decide(context.Background(), "cursor", "", "ls", 5e9); v.Allow {
		t.Error("allowed an empty action")
	}
	if b.calls != 1 {
		t.Fatal("forwarded a bad request")
	}
}

func TestRelayRefusesASocketThatIsNotTheServices(t *testing.T) {
	dir := t.TempDir()
	relayDir, relaySock = dir, filepath.Join(dir, "relay.sock")
	relayOwner = uint32(os.Geteuid()) + 1 // pretend the service is someone else
	l, err := listenRelay()
	if err != nil {
		t.Fatal(err)
	}
	srv := newRelayServer(&fakeBackend{})
	go srv.Serve(l)
	defer srv.Close()
	if v := NewRelay().Decide(context.Background(), "cursor", "shell", "ls", 5e9); v.Allow || !strings.Contains(v.Reason, "manar-edge protect restore") {
		t.Fatalf("trusted a squatted socket, or gave no way out: %+v", v)
	}
}

func TestDecideFailsClosedWithAWayOutWhenTheServiceIsGone(t *testing.T) {
	relayDir, relaySock, relayOwner = t.TempDir(), filepath.Join(t.TempDir(), "none.sock"), uint32(os.Geteuid())
	v := NewRelay().Decide(context.Background(), "cursor", "shell", "ls", 5e9)
	if v.Allow || !strings.Contains(v.Reason, "manar-edge protect restore") {
		t.Fatalf("%+v", v)
	}
}
