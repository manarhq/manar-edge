package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakePolicy struct {
	success, failure bool
	sets             []string
}

func (f *fakePolicy) Get() (bool, bool, error) { return f.success, f.failure, nil }
func (f *fakePolicy) Set(s, fl bool) error {
	f.success, f.failure = s, fl
	f.sets = append(f.sets, strings.Join([]string{map[bool]string{true: "s", false: "-"}[s], map[bool]string{true: "f", false: "-"}[fl]}, ""))
	return nil
}

type rec struct {
	calls   []string
	present bool
}

func (r *rec) run(name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if r.present && strings.Contains(strings.Join(args, " "), "AddAuditRule") {
		return []byte("PRESENT"), nil
	}
	return []byte("ADDED"), nil
}

func TestAuditEnableThenRestoreToThePriorValue(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "audit.json")
	f := filepath.Join(dir, "credentials")
	_ = os.WriteFile(f, nil, 0o600)
	r, pol := &rec{}, &fakePolicy{failure: true}
	if _, err := EnableAudit(r.run, pol, state, []string{f}); err != nil {
		t.Fatal(err)
	}
	if !pol.success || !pol.failure || !strings.Contains(strings.Join(r.calls, "\n"), "AddAuditRule") {
		t.Fatalf("policy %+v calls %v", pol, r.calls)
	}
	r.calls = nil
	if err := RestoreAudit(r.run, pol, state); err != nil {
		t.Fatal(err)
	}
	if pol.success || !pol.failure {
		t.Fatalf("policy not back to failure-only: %+v", pol)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "RemoveAuditRuleSpecific") || strings.Contains(joined, "RemoveAuditRuleAll") {
		t.Fatalf("must remove only its own entry:\n%s", joined)
	}
	if _, err := os.Stat(state); err == nil {
		t.Fatal("state file must go once everything is undone")
	}
}

func TestAuditAlreadyOnIsLeftAlone(t *testing.T) {
	state := filepath.Join(t.TempDir(), "audit.json")
	r, pol := &rec{}, &fakePolicy{success: true, failure: true}
	if _, err := EnableAudit(r.run, pol, state, nil); err != nil {
		t.Fatal(err)
	}
	_ = RestoreAudit(r.run, pol, state)
	if len(pol.sets) != 0 {
		t.Fatalf("the policy was already on and must not be touched: %v", pol.sets)
	}
}

func TestAnAuditEntryThatWasAlreadyThereIsNeverRemoved(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "audit.json")
	f := filepath.Join(dir, "credentials")
	_ = os.WriteFile(f, nil, 0o600)
	r := &rec{present: true}
	st, err := EnableAudit(r.run, &fakePolicy{success: true}, state, []string{f})
	if err != nil || len(st.AuditedPaths) != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	r.calls = nil
	_ = RestoreAudit(r.run, &fakePolicy{success: true}, state)
	for _, c := range r.calls {
		if strings.Contains(c, "Remove") {
			t.Fatal("removed an entry Manar did not add")
		}
	}
}

func TestAuditScriptsTouchOnlyTheAuditSection(t *testing.T) {
	for _, add := range []bool{true, false} {
		s := auditRuleScript(`C:\Users\Bo'b\.aws\credentials`, add)
		if !strings.Contains(s, "AccessControlSections]::Audit") || strings.Contains(s, "Set-Acl") || !strings.Contains(s, "S-1-1-0") {
			t.Fatalf("script rewrites more than the audit section or uses a localised name:\n%s", s)
		}
		if !strings.Contains(s, "Bo''b") {
			t.Fatal("path not quoted")
		}
	}
}

func TestParse4663(t *testing.T) {
	x := `<Event><System><TimeCreated SystemTime='2026-11-01T10:00:00.123456700Z'/></System><EventData>` +
		`<Data Name='ObjectName'>C:\Users\Bob\.aws\credentials</Data><Data Name='ProcessId'>0x1a4</Data>` +
		`<Data Name='ProcessName'>C:\Program Files\cursor\Cursor.exe</Data></EventData></Event>`
	evs, err := parse4663(x + x)
	if err != nil || len(evs) != 2 || evs[0].PID != 420 || !strings.HasSuffix(evs[0].ProcessName, "Cursor.exe") || evs[0].At.IsZero() {
		t.Fatalf("%+v %v", evs, err)
	}
	if got := query4663Args(time.Unix(0, 0)); !strings.Contains(got[2], "EventID=4663") {
		t.Fatal(got)
	}
}
