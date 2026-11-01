package jail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestRestoreRecordedPutsBackOnlyTheSameProcess(t *testing.T) {
	dir := t.TempDir()
	oldRoot, oldFile := cgRoot, movedFile
	cgRoot, movedFile = filepath.Join(dir, "cg"), filepath.Join(dir, "moved.json")
	defer func() { cgRoot, movedFile = oldRoot, oldFile }()
	os.MkdirAll(filepath.Join(cgRoot, "user.slice"), 0o755)

	self := os.Getpid()
	start, err := procStart(self)
	if err != nil || start == 0 {
		t.Fatalf("procStart: %d %v", start, err)
	}
	write := func(v map[string]moved) {
		b, _ := json.Marshal(v)
		os.WriteFile(movedFile, b, 0o600)
	}
	pidFile := filepath.Join(cgRoot, "user.slice", "cgroup.procs")

	// a pid that was reused by another process (different start time) is left alone
	write(map[string]moved{strconv.Itoa(self): {Tool: claude, From: "/user.slice", Start: start + 1}})
	restoreRecorded()
	if _, err := os.Stat(pidFile); err == nil {
		t.Fatal("moved a process that is not the one that was recorded")
	}
	if _, err := os.Stat(movedFile); err == nil {
		t.Fatal("the record was not cleared")
	}

	// the same process goes back to the cgroup it came from
	write(map[string]moved{strconv.Itoa(self): {Tool: claude, From: "/user.slice", Start: start}})
	restoreRecorded()
	if b, _ := os.ReadFile(pidFile); string(b) != strconv.Itoa(self) {
		t.Fatalf("not restored to its own cgroup: %q", b)
	}
}
