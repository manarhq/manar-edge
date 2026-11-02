package protect

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/manarhq/manar-edge/internal/undo"
)

func TestSnapshotBeforeEditOnlyOutsideTheProject(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("LOCALAPPDATA", state)
	proj, other := t.TempDir(), t.TempDir()
	inside, outside := filepath.Join(proj, "a.go"), filepath.Join(other, "hosts")
	os.WriteFile(inside, []byte("1"), 0o600)
	os.WriteFile(outside, []byte("2"), 0o600)
	in := func(p string) []byte {
		return []byte(fmt.Sprintf(`{"tool_name":"Edit","cwd":%q,"tool_input":{"file_path":%q}}`, proj, p))
	}
	SnapshotBeforeEdit("claude-code", in(inside))
	s, err := undo.OpenDefault()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.List(time.Now())); n != 0 {
		t.Fatalf("a file inside the project was saved (%d)", n)
	}
	SnapshotBeforeEdit("claude-code", in(outside)) // the relay is not running: still saved, no error
	recs := s.List(time.Now())
	if len(recs) != 1 || recs[0].Path != outside || recs[0].Tool != "claude-code" {
		t.Fatalf("%+v", recs)
	}
	SnapshotBeforeEdit("claude-code", []byte(`{"tool_name":"Bash","cwd":"/","tool_input":{"command":"rm x"}}`))
	if len(s.List(time.Now())) != 1 {
		t.Fatal("a shell command was treated as an edit")
	}
}
