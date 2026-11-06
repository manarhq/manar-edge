package protect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readFileForBench(p string) ([]byte, error) { return os.ReadFile(p) }

// BenchmarkHookRoundTrip is one authorize through the local relay socket to an in-process service
// (the socket, HTTP and the service's own handling; the call to Manar is a fake).
func BenchmarkHookRoundTrip(b *testing.B) {
	dir := b.TempDir()
	relayDir, relaySock, relayOwner = dir, filepath.Join(dir, "relay.sock"), uint32(os.Geteuid())
	l, err := listenRelay()
	if err != nil {
		b.Fatal(err)
	}
	srv := newRelayServer(&fakeBackend{})
	go srv.Serve(l)
	defer srv.Close()
	old := protectedUID
	defer func() { protectedUID = old }()
	protectedUID = func(string) bool { return true }
	r := NewRelay()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if v := r.Decide(context.Background(), "cursor", "shell", "ls", 5*time.Second); !v.Allow {
			b.Fatal(v.Reason)
		}
	}
}

// A hook round trip through the relay must stay far below the 5 ms budget.
func TestHookRoundTripBudget(t *testing.T) {
	if raceOn {
		t.Skip("timings under the race detector mean nothing")
	}
	r := testing.Benchmark(BenchmarkHookRoundTrip)
	if per := time.Duration(r.NsPerOp()); per > 2*time.Millisecond {
		t.Errorf("a hook round trip takes %v, over the 2 ms limit", per)
	} else {
		t.Logf("hook round trip: %v/op", per)
	}
}
