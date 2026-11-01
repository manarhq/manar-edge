//go:build linux

package watch

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// procfs reads /proc.
type procfs struct{ root string }

func newProcSource() ProcSource { return procfs{root: "/proc"} }

func (p procfs) Get(pid int) (Proc, error) {
	dir := p.root + "/" + strconv.Itoa(pid)
	stat, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return Proc{}, err
	}
	pr, err := parseStat(string(stat))
	if err != nil {
		return Proc{}, err
	}
	pr.PID = pid
	pr.Exe, _ = os.Readlink(dir + "/exe")
	pr.Exe = strings.TrimSuffix(pr.Exe, " (deleted)")
	if b, err := os.ReadFile(dir + "/cmdline"); err == nil {
		if len(b) > 8192 {
			b = b[:8192]
		}
		pr.Cmdline = strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	}
	return pr, nil
}

// parseStat reads "pid (comm) S ppid pgrp session tty_nr ...". comm may hold spaces and
// parentheses, so the fields start after the last ')'.
func parseStat(s string) (Proc, error) {
	i := strings.LastIndexByte(s, ')')
	o := strings.IndexByte(s, '(')
	if i < 0 || o < 0 || i < o {
		return Proc{}, fmt.Errorf("bad stat")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 5 {
		return Proc{}, fmt.Errorf("short stat")
	}
	ppid, err1 := strconv.Atoi(f[1])
	tty, err2 := strconv.Atoi(f[4])
	if err1 != nil || err2 != nil {
		return Proc{}, fmt.Errorf("bad stat numbers")
	}
	return Proc{Comm: s[o+1 : i], PPID: ppid, TTY: tty != 0}, nil
}

// selfFunc reports Manar's own process and any process running Manar's own binary (the
// credential_process helper). It does NOT cover processes Manar merely started: exempting
// descendants would let anything launched from the service, including a test's fake AI tool, read
// secrets unseen. The Linux vault runs no child that reads a watched file.
func selfFunc(procs ProcSource) func(int) bool {
	me := os.Getpid()
	exe, _ := os.Executable()
	return func(pid int) bool {
		if pid == me {
			return true
		}
		if exe == "" {
			return false
		}
		pr, err := procs.Get(pid)
		return err == nil && pr.Exe == exe
	}
}
