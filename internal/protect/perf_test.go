package protect

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Footprint budget (founder decision 31, 5 Nov 2026): under 5 ms added per AI tool hook call. These
// benchmarks cover the checks one hook runs inside the hook process. TestHookCheckBudget fails the
// build when one of them gets near the budget; the limits leave room for a slow CI machine.

var (
	hookRead  = []byte(`{"tool_name":"Read","tool_input":{"file_path":"/home/sam/proj/internal/server/handler.go"},"cwd":"/home/sam/proj","session_id":"s1"}`)
	hookBash  = []byte(`{"tool_name":"Bash","tool_input":{"command":"go test ./... && git status --short | head -20"},"cwd":"/home/sam/proj","session_id":"s1"}`)
	hookWrite = []byte(`{"tool_name":"Write","tool_input":{"file_path":"/home/sam/proj/main.go","content":"package main\n\nfunc main() {}\n"},"cwd":"/home/sam/proj","session_id":"s1"}`)
	mcpCall   = []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"search","arguments":{"query":"golang benchmark","limit":10}}}`)
)

func BenchmarkGuardInputRead(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GuardInput("claude-code", "tool", hookRead)
	}
}

func BenchmarkGuardInputBash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GuardInput("claude-code", "tool", hookBash)
	}
}

func BenchmarkGuardInputWrite(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GuardInput("claude-code", "tool", hookWrite)
	}
}

func BenchmarkClassify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = Classify("claude-code", "tool", hookBash)
	}
}

func BenchmarkMCPGuard(b *testing.B) {
	allow := func(context.Context, string, string) Verdict { return Verdict{Allow: true} }
	for i := 0; i < b.N; i++ {
		screen(mcpCall, "search-server", allow)
	}
}

// BenchmarkOfflineVerdict is the hook deciding from the saved policy: read, verify and look up.
func BenchmarkOfflineVerdict(b *testing.B) {
	state := filepath.Join(b.TempDir(), "state")
	Configure(state)
	save := readTrusted
	readTrusted = func(s string) ([]byte, error) { return readFileForBench(offlineFile(s)) }
	defer func() { readTrusted = save }()
	rec.mu.Lock()
	rec.snap, rec.loaded = offlineSnapshot{}, true
	rec.mu.Unlock()
	for i := 0; i < offlineKeep; i++ {
		recordOfflineDecision("host.claude-code", "uid:1", "bash", "cmd "+string(rune('a'+i%26))+time.Duration(i).String(), "", "ALLOW")
	}
	flushOffline()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offlineVerdict("claude-code", "bash", "cmd a0s")
	}
}

// TestHookCheckBudget fails when a hook check costs more than a tenth of the 5 ms budget
// (GuardInput, Classify and the MCP guard each run once per hook call).
func TestHookCheckBudget(t *testing.T) {
	if raceOn {
		t.Skip("timings under the race detector mean nothing")
	}
	const limit = 500 * time.Microsecond
	for name, fn := range map[string]func(*testing.B){
		"GuardInputRead":  BenchmarkGuardInputRead,
		"GuardInputBash":  BenchmarkGuardInputBash,
		"GuardInputWrite": BenchmarkGuardInputWrite,
		"Classify":        BenchmarkClassify,
		"MCPGuard":        BenchmarkMCPGuard,
		"OfflineVerdict":  BenchmarkOfflineVerdict,
	} {
		r := testing.Benchmark(fn)
		per := time.Duration(r.NsPerOp())
		t.Logf("%s: %v/op, %d allocs/op", name, per, r.AllocsPerOp())
		if per > limit {
			t.Errorf("%s takes %v per call, over the %v limit (hook budget is 5 ms in total)", name, per, limit)
		}
	}
}
