package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/daemon"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func probes(snap *daemon.Snapshot, info *hostclient.Info, ierr error, svc string, door bool) statusProbes {
	var serr error
	if snap == nil {
		serr = os.ErrNotExist
	}
	return statusProbes{
		now: func() time.Time { return t0 }, service: func() string { return svc },
		snapshot: func() (*daemon.Snapshot, error) { return snap, serr },
		hostInfo: func() (*hostclient.Info, error) { return info, ierr },
		doorUp:   func() bool { return door }, hostname: "pc", goos: "linux", ver: "test",
	}
}

func healthy() *daemon.Snapshot {
	sync := t0.Add(-time.Minute)
	return &daemon.Snapshot{UpdatedAt: t0.Add(-10 * time.Second), HostID: "h1", TenantSlug: "acme", Status: "APPROVED",
		LastSyncAt: &sync, Tools: []daemon.ToolStatus{{Name: "Cursor", Protected: true, Mode: "hook"}}}
}

func fixes(r statusReport) string {
	var b strings.Builder
	for _, p := range r.Problems {
		b.WriteString(p.What + " | " + p.Fix + "\n")
	}
	return b.String()
}

func TestHealthyDevice(t *testing.T) {
	r := buildStatus(probes(healthy(), nil, os.ErrPermission, "active", true))
	if !r.OK || len(r.Problems) != 0 || r.Enrolment["state"] != "enrolled" || r.Parts["door"].State != "ok" {
		t.Fatalf("%+v", r)
	}
}

func TestNotEnrolled(t *testing.T) {
	r := buildStatus(probes(nil, nil, os.ErrNotExist, "inactive", false))
	if r.OK || len(r.Problems) != 1 || !strings.Contains(r.Problems[0].Fix, "Add device") {
		t.Fatalf("%s", fixes(r))
	}
}

func TestEveryProblemHasAFix(t *testing.T) {
	stale := healthy()
	stale.UpdatedAt = t0.Add(-time.Hour)
	pending := healthy()
	pending.Status = "PENDING"
	revoked := healthy()
	revoked.Status = "REVOKED"
	unprot := healthy()
	unprot.Tools = []daemon.ToolStatus{{Name: "Cursor", Mode: "none"}}
	failing := healthy()
	failing.LastError = "dial tcp: lookup failed"
	part := healthy()
	part.Components = map[string]daemon.Component{"jail": {State: "problem", Detail: "filter not loaded"}, "door": {State: "ok"}}
	for name, c := range map[string]statusReport{
		"service stopped": buildStatus(probes(healthy(), nil, nil, "inactive", false)),
		"service failed":  buildStatus(probes(healthy(), nil, nil, "failed", false)),
		"stale status":    buildStatus(probes(stale, nil, nil, "active", true)),
		"pending":         buildStatus(probes(pending, nil, nil, "active", true)),
		"revoked":         buildStatus(probes(revoked, nil, nil, "active", true)),
		"unprotected":     buildStatus(probes(unprot, nil, nil, "active", true)),
		"sync error":      buildStatus(probes(failing, nil, nil, "active", true)),
		"jail problem":    buildStatus(probes(part, nil, nil, "active", true)),
		"no status file":  buildStatus(probes(nil, &hostclient.Info{HostID: "h"}, nil, "active", true)),
	} {
		if c.OK || len(c.Problems) == 0 {
			t.Errorf("%s: expected a problem", name)
		}
		for _, p := range c.Problems {
			if p.What == "" || p.Fix == "" {
				t.Errorf("%s: problem without a fix: %+v", name, p)
			}
		}
	}
}

func TestDoorDownIsShownButOnlyAComponentReportMakesItAProblem(t *testing.T) {
	r := buildStatus(probes(healthy(), nil, nil, "active", false))
	if r.Parts["door"].State != "off" || !r.OK {
		t.Fatalf("%+v", r)
	}
	s := healthy()
	s.Components = map[string]daemon.Component{"door": {State: "problem", Detail: "port 8480 is in use", Fix: "stop the program using port 8480"}}
	r = buildStatus(probes(s, nil, nil, "active", false))
	if r.OK || !strings.Contains(fixes(r), "stop the program using port 8480") {
		t.Fatalf("%s", fixes(r))
	}
}

func TestOutputAndJSON(t *testing.T) {
	p := probes(healthy(), nil, errors.New("x"), "active", true)
	r := buildStatus(p)
	var b bytes.Buffer
	printStatusReport(r, p, &b)
	for _, want := range []string{"Enrolment    enrolled, workspace acme, approved", "Last sync    1 min ago", "Cursor: protected (hook)", "DOOR", "All good."} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
	var back map[string]any
	j, _ := json.Marshal(r)
	if err := json.Unmarshal(j, &back); err != nil || back["ok"] != true || back["problems"] == nil {
		t.Fatalf("%s", j)
	}
	if strings.ContainsAny(b.String(), "—–") {
		t.Fatal("dashes in user text")
	}
}
