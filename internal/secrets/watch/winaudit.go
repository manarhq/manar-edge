package watch

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The Windows side is written so its decisions can be tested anywhere: it builds the commands
// and reads the output, a Runner executes them.

// Runner runs a command and returns its output.
type Runner func(name string, args ...string) ([]byte, error)

// Policy reads and sets the File System success/failure audit setting. The Windows version uses
// AuditQuerySystemPolicy and AuditSetSystemPolicy, which do not depend on the display language.
type Policy interface {
	Get() (success, failure bool, err error)
	Set(success, failure bool) error
}

// AuditState is what the installer changed, kept so uninstall can undo exactly that.
type AuditState struct {
	PolicyKnown   bool `json:"policyKnown"`
	PriorSuccess  bool `json:"priorSuccess"`
	PriorFailure  bool `json:"priorFailure"`
	PolicyChanged bool `json:"policyChanged"`
	// AuditedPaths are files where Manar added its own audit entry. A file that already had an
	// identical entry is not listed, so uninstall never removes what was there before.
	AuditedPaths []string `json:"auditedPaths"`
}

// psQuote single-quotes a value for PowerShell.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// auditRuleScript adds (or removes) one audit entry: Everyone (S-1-1-0), read data, success. It
// reads and writes only the audit part of the security descriptor, so the owner and the access
// list are not rewritten. Removal takes out exactly this entry. Output: ADDED, PRESENT (an
// identical entry was already there; nothing is changed) or REMOVED.
func auditRuleScript(path string, add bool) string {
	head := "$ErrorActionPreference='Stop'; $p=" + psQuote(path) +
		"; $s=[System.IO.File]::GetAccessControl($p,[System.Security.AccessControl.AccessControlSections]::Audit)" +
		"; $sid=New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')" +
		"; $r=New-Object System.Security.AccessControl.FileSystemAuditRule($sid,'ReadData','None','None','Success')"
	if !add {
		return head + "; $s.RemoveAuditRuleSpecific($r) | Out-Null; [System.IO.File]::SetAccessControl($p,$s); 'REMOVED'"
	}
	return head + "; $have=@($s.GetAuditRules($true,$false,[System.Security.Principal.SecurityIdentifier]) | Where-Object {" +
		" $_.IdentityReference.Value -eq 'S-1-1-0' -and $_.FileSystemRights -eq 'ReadData' -and $_.AuditFlags -eq 'Success' })" +
		"; if($have.Count -gt 0){ 'PRESENT' } else { $s.AddAuditRule($r); [System.IO.File]::SetAccessControl($p,$s); 'ADDED' }"
}

// EnableAudit turns File System success auditing on (remembering the old value) and puts an
// audit entry on each existing file. The state is saved before the first change.
func EnableAudit(run Runner, pol Policy, stateFile string, files []string) (*AuditState, error) {
	st := &AuditState{}
	if b, err := os.ReadFile(stateFile); err == nil {
		_ = json.Unmarshal(b, st)
	}
	if !st.PolicyKnown {
		s, f, err := pol.Get()
		if err != nil {
			return nil, fmt.Errorf("reading the audit policy: %w", err)
		}
		st.PolicyKnown, st.PriorSuccess, st.PriorFailure = true, s, f
		if err := saveAuditState(stateFile, st); err != nil {
			return nil, err
		}
		if !s {
			if err := pol.Set(true, f); err != nil {
				return st, fmt.Errorf("enabling File System auditing: %w", err)
			}
			st.PolicyChanged = true
			if err := saveAuditState(stateFile, st); err != nil {
				return st, err
			}
		}
	}
	have := map[string]bool{}
	for _, p := range st.AuditedPaths {
		have[p] = true
	}
	for _, p := range files {
		if have[p] {
			continue
		}
		// Record first: if the command half-works, uninstall still tries to undo it.
		st.AuditedPaths = append(st.AuditedPaths, p)
		if err := saveAuditState(stateFile, st); err != nil {
			return st, err
		}
		out, err := run("powershell", "-NoProfile", "-NonInteractive", "-Command", auditRuleScript(p, true))
		if err != nil || strings.Contains(string(out), "PRESENT") {
			// Not ours (already there) or not possible: do not claim it, so it is never removed.
			st.AuditedPaths = st.AuditedPaths[:len(st.AuditedPaths)-1]
			if err := saveAuditState(stateFile, st); err != nil {
				return st, err
			}
		}
	}
	return st, nil
}

// RestoreAudit removes the audit entries it added and puts the audit policy back to the value it
// had. It tries every step and returns all failures.
func RestoreAudit(run Runner, pol Policy, stateFile string) error {
	b, err := os.ReadFile(stateFile)
	if err != nil {
		return nil // nothing was changed
	}
	var st AuditState
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	var errs []error
	var left []string
	for _, p := range st.AuditedPaths {
		if _, err := os.Stat(p); err != nil {
			continue // file is gone, so is its entry
		}
		if _, err := run("powershell", "-NoProfile", "-NonInteractive", "-Command", auditRuleScript(p, false)); err != nil {
			errs = append(errs, fmt.Errorf("audit entry on %s: %w", p, err))
			left = append(left, p)
		}
	}
	if st.PolicyChanged {
		if err := pol.Set(st.PriorSuccess, st.PriorFailure); err != nil {
			errs = append(errs, fmt.Errorf("restoring the audit policy: %w", err))
		} else {
			st.PolicyChanged = false
		}
	}
	st.AuditedPaths = left
	if len(errs) == 0 {
		return os.Remove(stateFile)
	}
	_ = saveAuditState(stateFile, &st)
	return errors.Join(errs...)
}

func saveAuditState(path string, st *AuditState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(st)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Win4663 is the part of a Security 4663 event the watcher uses.
type Win4663 struct {
	PID         int
	ProcessName string
	ObjectName  string
	At          time.Time
}

type xmlEvent struct {
	System struct {
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// parse4663 reads the XML `wevtutil qe Security /f:xml` prints (events side by side, no root).
func parse4663(out string) ([]Win4663, error) {
	var res struct {
		Events []xmlEvent `xml:"Event"`
	}
	if err := xml.Unmarshal([]byte("<Events>"+out+"</Events>"), &res); err != nil {
		return nil, err
	}
	var evs []Win4663
	for _, e := range res.Events {
		var w Win4663
		for _, d := range e.Data {
			switch d.Name {
			case "ObjectName":
				w.ObjectName = d.Value
			case "ProcessName":
				w.ProcessName = d.Value
			case "ProcessId":
				n, err := strconv.ParseInt(strings.TrimPrefix(d.Value, "0x"), map[bool]int{true: 16, false: 10}[strings.HasPrefix(d.Value, "0x")], 32)
				if err == nil {
					w.PID = int(n)
				}
			}
		}
		w.At, _ = time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime)
		if w.ObjectName != "" {
			evs = append(evs, w)
		}
	}
	return evs, nil
}

// query4663Args reads the 4663 events since a time, oldest first.
func query4663Args(since time.Time) []string {
	return []string{"qe", "Security", "/q:*[System[(EventID=4663) and TimeCreated[@SystemTime>='" +
		since.UTC().Format("2006-01-02T15:04:05.000Z") + "']]]", "/f:xml", "/rd:false", "/c:500"}
}
