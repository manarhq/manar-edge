package undo

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

type fakeAPI struct {
	cfg      hostclient.Config
	restores []restoreItem
	posted   map[string]any
}

func (f *fakeAPI) Config(context.Context) (*hostclient.Config, error) { return &f.cfg, nil }
func (f *fakeAPI) Do(_ context.Context, method, path string, in, out any) error {
	if f.posted == nil {
		f.posted = map[string]any{}
	}
	if method == "GET" && path == "/undo/restores" {
		o := out.(*struct {
			Items []restoreItem `json:"items"`
		})
		o.Items = f.restores
		return nil
	}
	f.posted[path] = in
	return nil
}

func newSvc(run func(int, string, ...string) ([]byte, error)) *Service {
	if run == nil {
		run = func(int, string, ...string) ([]byte, error) { return []byte(`{"ok":true}`), nil }
	}
	return &Service{owners: map[string]owner{}, runAs: run, exe: "/bin/manar-edge", pollEvery: time.Second}
}

func rec(id string) Record {
	return Record{ID: id, Tool: "claude-code", Path: "/etc/hosts", SHA256: strings.Repeat("a", 64), Taken: time.Now()}
}

const id1 = "0123456789abcdef0123456789abcdef"

func TestReportRejectsBadRecordsAndUnknownCallers(t *testing.T) {
	s := newSvc(nil)
	bad := rec(id1)
	bad.Path = "relative/x"
	if s.Report("uid:1000", bad) == nil {
		t.Fatal("relative path accepted")
	}
	if s.Report("unknown", rec(id1)) == nil {
		t.Fatal("unknown caller accepted")
	}
	if err := s.Report("uid:1000", rec(id1)); err != nil {
		t.Fatal(err)
	}
}

func TestNothingLeavesTheDeviceUnlessApprovedAndEnabled(t *testing.T) {
	s := newSvc(nil)
	s.Report("uid:1000", rec(id1))
	for _, cfg := range []hostclient.Config{
		{Status: "PENDING", Features: []string{"undo"}},
		{Status: "APPROVED"},
	} {
		api := &fakeAPI{cfg: cfg}
		s.tick(context.Background(), api)
		if len(api.posted) != 0 {
			t.Fatalf("posted %v for %+v", api.posted, cfg)
		}
	}
}

func TestReportSendsMetadataOnly(t *testing.T) {
	s := newSvc(nil)
	s.Report("uid:1000", rec(id1))
	api := &fakeAPI{cfg: hostclient.Config{Status: "APPROVED", Features: []string{"undo"}}}
	s.tick(context.Background(), api)
	body := api.posted["/undo/changes"].(map[string]any)["changes"].([]wireChange)
	if len(body) != 1 || body[0].SnapshotID != id1 || body[0].Path != "/etc/hosts" {
		t.Fatalf("%+v", body)
	}
	if len(s.queue) != 0 {
		t.Fatal("queue not drained after a good send")
	}
}

func TestRestoreRunsAsTheSnapshotOwnerAndReportsTheResult(t *testing.T) {
	var gotUID int
	var gotArgs []string
	s := newSvc(func(uid int, _ string, args ...string) ([]byte, error) {
		if args[1] == "restore" {
			gotUID, gotArgs = uid, args
		}
		return []byte(`{"ok":true}`), nil
	})
	s.Report("uid:1234", rec(id1))
	api := &fakeAPI{
		cfg:      hostclient.Config{Status: "APPROVED", Features: []string{"undo"}},
		restores: []restoreItem{{ID: "c1", SnapshotID: id1, Path: "/etc/hosts"}},
	}
	s.tick(context.Background(), api)
	if gotUID != 1234 || strings.Join(gotArgs, " ") != "__undo restore "+id1+" /etc/hosts" {
		t.Fatalf("uid %d args %v", gotUID, gotArgs)
	}
	if api.posted["/undo/restores/c1/result"].(map[string]string)["status"] != "RESTORED" {
		t.Fatalf("%v", api.posted)
	}
}

func TestRestoreOfAnUnknownSnapshotFailsAndNeverRuns(t *testing.T) {
	ran := false
	s := newSvc(func(int, string, ...string) ([]byte, error) { ran = true; return nil, nil })
	api := &fakeAPI{
		cfg:      hostclient.Config{Status: "APPROVED", Features: []string{"undo"}},
		restores: []restoreItem{{ID: "c1", SnapshotID: id1, Path: "/etc/shadow"}},
	}
	s.tick(context.Background(), api)
	if ran || api.posted["/undo/restores/c1/result"].(map[string]string)["status"] != "FAILED" {
		t.Fatalf("ran=%v %v", ran, api.posted)
	}
}

func TestHelperErrorIsPassedOn(t *testing.T) {
	s := newSvc(func(int, string, ...string) ([]byte, error) {
		return []byte(`{"ok":false,"error":"the path does not match the snapshot"}`), errors.New("exit 1")
	})
	s.Report("uid:1", rec(id1))
	err := s.restore(restoreItem{ID: "c", SnapshotID: id1, Path: "/etc/hosts"})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("%v", err)
	}
}
