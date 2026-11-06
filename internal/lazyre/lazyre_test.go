package lazyre

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildsOnFirstUseOnly(t *testing.T) {
	r := New(`^a+(b)$`)
	if r.re != nil {
		t.Fatal("compiled before use")
	}
	if !r.MatchString("aab") || r.FindStringSubmatch("aab")[1] != "b" || r.re == nil {
		t.Fatal("does not match like a regexp")
	}
	if r.String() != `^a+(b)$` {
		t.Fatal(r.String())
	}
}

func TestInvalidPatternPanicsOnUse(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic")
		}
	}()
	New(`(`).MatchString("x")
}

// Every start of the program, and so every AI tool hook call (a fresh process), pays for each
// regexp compiled at package initialisation: about 3 ms for the ~80 this program has. They must go
// through lazyre.New.
func TestNoRegexpCompiledAtStartup(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.Contains(p, "lazyre") {
			return err
		}
		b, _ := os.ReadFile(p)
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "regexp.MustCompile(") && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				t.Errorf("%s:%d compiles a regexp eagerly: use lazyre.New", p, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
