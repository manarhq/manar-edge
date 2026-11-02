package daemon

import (
	"strings"
	"testing"
)

func TestModulesReportsOnlyModulesAndCutsTheDetail(t *testing.T) {
	stMu.Lock()
	saved := cur.Components
	cur.Components = map[string]Component{}
	stMu.Unlock()
	defer func() { stMu.Lock(); cur.Components = saved; stMu.Unlock() }()

	if Modules() != nil {
		t.Fatal("no module yet must be nil, not an empty list")
	}
	SetComponent("module:jail", Component{State: "problem", Detail: strings.Repeat("x", 300), Fix: "run something"})
	SetComponent("module:door", Component{State: "ok"})
	SetComponent("door", Component{State: "off"})

	m := Modules()
	if len(m) != 2 || m["door"].State != "ok" || m["jail"].State != "problem" {
		t.Fatalf("%+v", m)
	}
	if len(m["jail"].Detail) != 200 {
		t.Fatalf("detail not cut: %d", len(m["jail"].Detail))
	}
}
