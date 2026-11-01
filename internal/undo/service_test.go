package undo

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	s := &Service{index: map[string]entry{}, rate: map[string][]time.Time{}, runAs: run, exe: "/bin/manar-edge",
		pollEvery: time.Second, now: time.Now}
	s.key = []byte("0123456789abcdef0123456789abcdef")
	return s
}

const (
	id1  = "0123456789abcdef0123456789abcdef"
	id2  = "fedcba9876543210fedcba9876543210"
	sha1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	root = "/home/u/.local/state/manar-edge/undo"
)

func rec(id string) Record {
	return Record{ID: id, Tool: "claude-code", Path: "/etc/hosts", SHA256: sha1, Taken: time.Now(), Store: root}
}

func approved() hostclient.Config {
	return hostclient.Config{Status: "APPROVED", Features: []string{"undo"}}
}

func TestReportRejectsBadRecordsAndUnknownCallers(t *testing.T) {
	s := newSvc(nil)
	bad := rec(id1)
	bad.Path = "relative/x"
	noStore := rec(id1)
	noStore.Store = ""
	if s.Report("uid:1000", bad) == nil || s.Report("uid:1000", noStore) == nil {
		t.Fatal("bad record accepted")
	}
	if s.Report("unknown", rec(id1)) == nil {
		t.Fatal("unknown caller accepted")
	}
	if err := s.Report("uid:1000", rec(id1)); err != nil {
		t.Fatal(err)
	}
}

func TestAnotherAccountCannotTakeOverASnapshotId(t *testing.T) {
	s := newSvc(nil)
	if err := s.Report("uid:1000", rec(id1)); err != nil {
		t.Fatal(err)
	}
	hijack := rec(id1)
	hijack.Path = "/etc/shadow"
	if s.Report("uid:2000", hijack) == nil {
		t.Fatal("a second account took over the id")
	}
	if s.index[id1].Caller != "uid:1000" || s.index[id1].Path != "/etc/hosts" {
		t.Fatalf("%+v", s.index[id1])
	}
	if err := s.Report("uid:1000", rec(id1)); err != nil || len(s.queue) != 1 {
		t.Fatalf("the owner sending twice must be harmless: %v %d", err, len(s.queue))
	}
}

func TestReportsAreCappedAndRateLimited(t *testing.T) {
	s := newSvc(nil)
	var err error
	for i := 0; i < reportsPerMin+1 && err == nil; i++ {
		err = s.Report("uid:1000", rec(fmt.Sprintf("%032x", i+1)))
	}
	if err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("rate limit: %v", err)
	}
	if s.Report("uid:2000", rec(id2)) != nil {
		t.Fatal("one account's flood must not block another")
	}
	s = newSvc(nil)
	for i := 0; i < maxPerCaller; i++ {
		s.index[fmt.Sprintf("%032x", i+1)] = entry{Caller: "uid:1000"}
	}
	if s.Report("uid:1000", rec(id1)) == nil {
		t.Fatal("per-account cap not enforced")
	}
}

func TestIndexIsAppendOnlyAndSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	s := newSvc(nil)
	s.stateDir = dir
	s.Report("uid:1000", rec(id1))
	st1, _ := os.Stat(s.indexPath())
	s.Report("uid:1000", rec(id2))
	b, _ := os.ReadFile(s.indexPath())
	if st2, _ := os.Stat(s.indexPath()); st2.Size() <= st1.Size() || strings.Count(string(b), "\n") != 2 {
		t.Fatal("a report must append one line")
	}
	again := newSvc(nil)
	again.stateDir = dir
	again.loadIndex()
	if len(again.index) != 2 || again.index[id1].Store != root {
		t.Fatalf("%+v", again.index)
	}
}

func TestManarNeverSeesAContentHash(t *testing.T) {
	s := newSvc(nil)
	s.Report("uid:1000", rec(id1))
	if got := s.queue[0].SHA256; got == sha1 || len(got) != 64 || got != s.mac(sha1) {
		t.Fatalf("queued %s", got)
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
	api := &fakeAPI{cfg: approved()}
	s.tick(context.Background(), api)
	body := api.posted["/undo/changes"].(map[string]any)["changes"].([]wireChange)
	if len(body) != 1 || body[0].SnapshotID != id1 || body[0].Path != "/etc/hosts" {
		t.Fatalf("%+v", body)
	}
	if len(s.queue) != 0 {
		t.Fatal("queue not drained after a good send")
	}
}

func item(id string) restoreItem {
	s := newSvc(nil)
	return restoreItem{ID: "c1", SnapshotID: id, Path: "/etc/hosts", SHA256: s.mac(sha1)}
}

func TestRestoreRunsAsTheOwnerWithTheRecordedStoreAndHash(t *testing.T) {
	var gotUID int
	var gotArgs []string
	s := newSvc(func(uid int, _ string, args ...string) ([]byte, error) {
		if args[1] == "restore" {
			gotUID, gotArgs = uid, args
		}
		return []byte(`{"ok":true,"note":"The file was changed after the AI tool edited it."}`), nil
	})
	s.Report("uid:1234", rec(id1))
	api := &fakeAPI{cfg: approved(), restores: []restoreItem{item(id1)}}
	s.tick(context.Background(), api)
	if gotUID != 1234 || strings.Join(gotArgs, " ") != "__undo restore "+id1+" /etc/hosts "+root+" "+sha1 {
		t.Fatalf("uid %d args %v", gotUID, gotArgs)
	}
	res := api.posted["/undo/restores/c1/result"].(map[string]string)
	if res["status"] != "RESTORED" || !strings.Contains(res["note"], "changed after") {
		t.Fatalf("%v", res)
	}
}

func TestRestoreRefusesWhatManarAndTheIndexDisagreeOn(t *testing.T) {
	ran := false
	s := newSvc(func(int, string, ...string) ([]byte, error) { ran = true; return nil, nil })
	s.Report("uid:1", rec(id1))
	for name, it := range map[string]restoreItem{
		"other path": {ID: "c", SnapshotID: id1, Path: "/etc/shadow", SHA256: s.mac(sha1)},
		"wrong hash": {ID: "c", SnapshotID: id1, Path: "/etc/hosts", SHA256: strings.Repeat("0", 64)},
		"unknown id": {ID: "c", SnapshotID: id2, Path: "/etc/hosts", SHA256: s.mac(sha1)},
		"raw sha":    {ID: "c", SnapshotID: id1, Path: "/etc/hosts", SHA256: sha1},
	} {
		if _, err := s.restore(it); err == nil {
			t.Errorf("%s: restore ran", name)
		}
	}
	if ran {
		t.Fatal("the helper started for a request that does not match the index")
	}
}

func TestHelperErrorIsPassedOn(t *testing.T) {
	s := newSvc(func(int, string, ...string) ([]byte, error) {
		return []byte(`{"ok":false,"error":"the path does not match the snapshot"}`), errors.New("exit 1")
	})
	s.Report("uid:1", rec(id1))
	_, err := s.restore(item(id1))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("%v", err)
	}
}

func TestPruneAndCleanupUseTheRecordedStores(t *testing.T) {
	var calls []string
	s := newSvc(func(uid int, _ string, args ...string) ([]byte, error) {
		calls = append(calls, fmt.Sprint(uid, " ", strings.Join(args, " ")))
		return nil, nil
	})
	s.Report("uid:7", rec(id1))
	s.maybePrune()
	s.Cleanup(context.Background())
	want := []string{"7 __undo prune " + root, "7 __undo purge " + root}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("%v", calls)
	}
}
