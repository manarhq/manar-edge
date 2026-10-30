package watch

import (
	"errors"
	"testing"
)

type fakeProcs map[int]Proc

func (f fakeProcs) Get(pid int) (Proc, error) {
	if p, ok := f[pid]; ok {
		return p, nil
	}
	return Proc{}, errors.New("gone")
}

func TestAttributeAndDeny(t *testing.T) {
	cursorHost := Proc{PID: 10, PPID: 1, Exe: "/opt/Cursor/cursor", Cmdline: []string{"/opt/Cursor/cursor", "--type=extensionHost"}}
	for name, tc := range map[string]struct {
		procs fakeProcs
		pid   int
		tool  string
		deny  bool
		inter bool
	}{
		"extension host reading directly is denied": {
			fakeProcs{10: cursorHost}, 10, "host.cursor", true, false},
		"agent's non-interactive sh -c child is denied": {
			fakeProcs{10: cursorHost,
				11: {PID: 11, PPID: 10, Exe: "/bin/sh", Cmdline: []string{"sh", "-c", "cat ~/.aws/credentials"}, TTY: true},
				12: {PID: 12, PPID: 11, Exe: "/usr/bin/cat", Cmdline: []string{"cat", "x"}, TTY: true}},
			12, "host.cursor", true, false},
		"child of an interactive terminal shell is allowed": {
			fakeProcs{10: cursorHost,
				11: {PID: 11, PPID: 10, Exe: "/bin/bash", Cmdline: []string{"bash", "-l"}, TTY: true},
				12: {PID: 12, PPID: 11, Exe: "/usr/bin/ssh", Cmdline: []string{"ssh", "host"}, TTY: true}},
			12, "host.cursor", false, true},
		"CLI tool started by the user's shell, own process, is denied": {
			fakeProcs{5: {PID: 5, PPID: 1, Exe: "/bin/bash", Cmdline: []string{"bash"}, TTY: true},
				6: {PID: 6, PPID: 5, Exe: "/usr/bin/node", Cmdline: []string{"node", "/usr/lib/node_modules/@openai/codex/bin/codex.js"}, TTY: true}},
			6, "host.codex-cli", true, false},
		"the user's own ssh, no tool in the chain, is allowed": {
			fakeProcs{5: {PID: 5, PPID: 1, Exe: "/bin/bash", Cmdline: []string{"bash"}, TTY: true},
				6: {PID: 6, PPID: 5, Exe: "/usr/bin/ssh", Cmdline: []string{"ssh", "h"}, TTY: true}},
			6, "", false, false},
		"hook-governed claude code is alert-only": {
			fakeProcs{6: {PID: 6, PPID: 1, Exe: "/usr/bin/node", Cmdline: []string{"node", "/x/node_modules/@anthropic-ai/claude-code/cli.js"}}},
			6, "host.claude-code", false, false},
		"plain vscode is alert-only": {
			fakeProcs{6: {PID: 6, PPID: 1, Exe: "/usr/share/code/code", Cmdline: []string{"/usr/share/code/code"}}},
			6, "host.vscode-copilot", false, false},
		"unreadable process is allowed": {fakeProcs{}, 99, "", false, false},
	} {
		t.Run(name, func(t *testing.T) {
			a := Attribute(tc.procs, tc.pid)
			if a.ToolID != tc.tool || a.Deny() != tc.deny || a.Interactive != tc.inter {
				t.Fatalf("tool=%q deny=%v interactive=%v, want %q %v %v", a.ToolID, a.Deny(), a.Interactive, tc.tool, tc.deny, tc.inter)
			}
		})
	}
}

func TestChainLoopTerminates(t *testing.T) {
	a := Attribute(fakeProcs{2: {PID: 2, PPID: 3}, 3: {PID: 3, PPID: 2}}, 2)
	if a.Deny() || len(a.Chain) != 2 {
		t.Fatalf("%+v", a)
	}
}

func TestLoginShellRunningACommandIsNotInteractive(t *testing.T) {
	sh := Proc{Exe: "/bin/bash", Cmdline: []string{"bash", "-lc", "cat x"}, TTY: true}
	if interactiveShell(sh) {
		t.Fatal("bash -lc is a command run, not a typing user")
	}
}
