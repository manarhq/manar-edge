//go:build linux

package watch

import (
	"os"
	"testing"
)

func TestParseStat(t *testing.T) {
	p, err := parseStat("123 (we) ird) S 45 123 123 34816 123 4194560")
	if err != nil || p.Comm != "we) ird" || p.PPID != 45 || !p.TTY {
		t.Fatalf("%+v %v", p, err)
	}
	p, _ = parseStat("1 (x) S 0 1 1 0 -1")
	if p.TTY {
		t.Fatal("tty_nr 0 means no terminal")
	}
}

func TestProcfsReadsThisProcess(t *testing.T) {
	p, err := newProcSource().Get(os.Getpid())
	if err != nil || p.PPID != os.Getppid() || p.Exe == "" || len(p.Cmdline) == 0 {
		t.Fatalf("%+v %v", p, err)
	}
	self := selfFunc(newProcSource())
	if !self(os.Getpid()) {
		t.Fatal("own pid is self")
	}
}
