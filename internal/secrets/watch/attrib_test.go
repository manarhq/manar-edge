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
	agent := Proc{PID: 10, PPID: 1, Exe: "/home/alice/.local/share/cursor-agent/cursor-agent", Cmdline: []string{"cursor-agent"}}
	editor := Proc{PID: 20, PPID: 1, Exe: "/opt/Cursor/cursor", Cmdline: []string{"/opt/Cursor/cursor", "--type=extensionHost"}}
	for name, tc := range map[string]struct {
		procs fakeProcs
		pid   int
		tool  string
		deny  bool
		inter bool
	}{
		"the agent reading directly is denied": {fakeProcs{10: agent}, 10, "host.cursor", true, false},
		"the agent's non-interactive sh -c child is denied": {
			fakeProcs{10: agent,
				11: {PID: 11, PPID: 10, Exe: "/bin/sh", Cmdline: []string{"sh", "-c", "cat ~/.aws/credentials"}, TTY: true},
				12: {PID: 12, PPID: 11, Exe: "/usr/bin/cat", Cmdline: []string{"cat", "x"}, TTY: true}},
			12, "host.cursor", true, false},
		"the agent's child behind an interactive terminal shell is allowed": {
			fakeProcs{10: agent,
				11: {PID: 11, PPID: 10, Exe: "/bin/bash", Cmdline: []string{"bash", "-l"}, TTY: true},
				12: {PID: 12, PPID: 11, Exe: "/usr/bin/ssh", Cmdline: []string{"ssh", "host"}, TTY: true}},
			12, "host.cursor", false, true},
		"the editor's own git and ssh are reported, never denied": {
			fakeProcs{20: editor, 21: {PID: 21, PPID: 20, Exe: "/usr/bin/ssh", Cmdline: []string{"ssh", "h"}}},
			21, "host.cursor", false, false},
		"codex native binary is denied": {
			fakeProcs{6: {PID: 6, PPID: 1, Exe: "/usr/lib/node_modules/@openai/codex/vendor/x86_64/codex/codex", Cmdline: []string{"codex"}}},
			6, "host.codex-cli", true, false},
		"a node CLI is recognised by its script but only reported": {
			fakeProcs{6: {PID: 6, PPID: 1, Exe: "/usr/bin/node", Cmdline: []string{"node", "/usr/lib/node_modules/@google/gemini-cli/bin/gemini.js"}}},
			6, "host.gemini-cli", false, false},
		"an argument that merely mentions a tool is not a match": {
			fakeProcs{6: {PID: 6, PPID: 1, Exe: "/usr/bin/git", Cmdline: []string{"git", "clone", "https://x/@openai/codex/"}}},
			6, "", false, false},
		"a folder named like a tool in the user's projects is not a match": {
			fakeProcs{6: {PID: 6, PPID: 1, Exe: "/home/alice/code/opt/claude/bin/tool", Cmdline: []string{"tool"}}},
			6, "", false, false},
		"claude desktop app is denied": {
			fakeProcs{6: {PID: 6, PPID: 1, Exe: "/opt/Claude/claude", Cmdline: []string{"claude"}}},
			6, "host.claude-desktop", true, false},
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
