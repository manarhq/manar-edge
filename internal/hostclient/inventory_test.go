package hostclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInventorySendsModulesOnlyWhenKnown(t *testing.T) {
	var bodies []map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":0}`))
	}))
	t.Cleanup(srv.Close)
	c := &Client{Info: &Info{}, http: srv.Client(), base: srv.URL, stateDir: t.TempDir(), removed: make(chan struct{})}
	if err := c.Inventory(context.Background(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Inventory(context.Background(), nil, nil, map[string]ModuleState{"jail": {State: "problem", Detail: "stopped"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := bodies[0]["modules"]; ok {
		t.Fatalf("modules sent without any: %s", bodies[0]["modules"])
	}
	if got := string(bodies[1]["modules"]); got != `{"jail":{"state":"problem","detail":"stopped"}}` {
		t.Fatalf("modules = %s", got)
	}
}
