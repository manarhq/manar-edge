package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const csvNone = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\nPC,System,File System,{0CCE921D-69AE-11D9-BED3-505054503030},No Auditing,\r\n"
const csvFail = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\nPC,System,File System,{0CCE921D-69AE-11D9-BED3-505054503030},Failure,\r\n"

type rec struct {
	calls []string
	out   string
}

func (r *rec) run(name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "auditpol" && args[0] == "/get" {
		return []byte(r.out), nil
	}
	return nil, nil
}

func TestAuditEnableThenRestoreToThePriorValue(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "audit.json")
	f := filepath.Join(dir, "credentials")
	_ = os.WriteFile(f, nil, 0o600)
	r := &rec{out: csvFail}
	if _, err := EnableAudit(r.run, state, []string{f}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "/success:enable /failure:enable") || !strings.Contains(joined, "AddAuditRule") {
		t.Fatalf("calls:\n%s", joined)
	}
	r.calls = nil
	if err := RestoreAudit(r.run, state); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "/success:disable /failure:enable") || !strings.Contains(joined, "RemoveAuditRuleAll") {
		t.Fatalf("restore calls:\n%s", joined)
	}
	if _, err := os.Stat(state); err == nil {
		t.Fatal("state file must go once everything is undone")
	}
}

func TestAuditAlreadyOnIsLeftAlone(t *testing.T) {
	state := filepath.Join(t.TempDir(), "audit.json")
	r := &rec{out: strings.Replace(csvNone, "No Auditing", "Success and Failure", 1)}
	if _, err := EnableAudit(r.run, state, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "/set") {
			t.Fatal("policy was already on: must not be set, so it is not unset either")
		}
	}
	r.calls = nil
	_ = RestoreAudit(r.run, state)
	for _, c := range r.calls {
		if strings.Contains(c, "/set") {
			t.Fatal("restore changed a policy the installer never changed")
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
