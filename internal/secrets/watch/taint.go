package watch

import "sync"

// Tainter knows processes that descend from an AI tool even after the process tree was cut
// (setsid, a double fork, a re-parent to init). A ProcSource that implements it is asked for every
// pid of the opener's chain.
type Tainter interface {
	TaintOf(pid int) (tool Proc, toolID string, ok bool)
}

// taintTable is the bounded memory of "this pid descends from an AI tool" (blockable tools only).
// Entries are keyed by pid and checked against the process start time, so a reused pid is not
// mistaken for its predecessor. When the table is full it is cleared: attribution then falls back
// to ancestry, which never denies more, only less.
type taintTable struct {
	mu sync.Mutex
	m  map[int]taintEntry
}

type taintEntry struct {
	tool  Proc
	id    string
	start uint64 // process start time (clock ticks since boot); 0 when unknown
}

const maxTaint = 1 << 16

func (t *taintTable) put(pid int, start uint64, tool Proc, id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil || len(t.m) >= maxTaint {
		t.m = map[int]taintEntry{}
	}
	t.m[pid] = taintEntry{tool: tool, id: id, start: start}
}

func (t *taintTable) get(pid int) (taintEntry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[pid]
	return e, ok
}

func (t *taintTable) drop(pid int) {
	t.mu.Lock()
	delete(t.m, pid)
	t.mu.Unlock()
}
