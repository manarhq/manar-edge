package watch

import (
	"path"
	"path/filepath"
	"strings"
)

// Proc is what the watcher knows about one process. Fields the OS could not give stay zero.
type Proc struct {
	PID      int
	PPID     int
	Exe      string   // full path of the executable
	Comm     string   // short name
	Cmdline  []string // arguments, argv[0] first
	TTY      bool     // has a controlling terminal
	UID      int      // owner of the process (real uid)
	UIDKnown bool
}

// ProcSource reads process info. Get must return an error for a process that is gone.
type ProcSource interface {
	Get(pid int) (Proc, error)
}

// Tool is one entry of the AI tool catalogue. It is matched on the executable's install path,
// never on arguments, with one exception: a script-run CLI (node, bun, python) is recognised by
// the path of its script (argv[1]), and is only ever reported.
//
// Patterns work on the lower-case, slash-normalised path: "^x" must start with x, "$x" must end
// with x, otherwise x must be a piece of the path made of whole folder names.
//
// Block says whether the open may be denied (Linux). It is true only for processes that belong to
// an AI agent alone: its desktop app and its stand-alone CLI. Editors (Cursor, Windsurf, VS Code)
// are the person's own tools: the git and ssh they run for the person must keep working, so they
// are reported, never denied. Claude Code is governed through its hook.
//
// Limit worth knowing: a process can make itself look like a person's terminal (a pty with an
// interactive shell), and the watcher then treats it as the person. That is why this is policy for
// honest tools, not a security boundary against a hostile one.
type Tool struct {
	ID     string
	Exe    []string
	Script []string
	Block  bool
}

var interpreters = map[string]bool{"node": true, "nodejs": true, "bun": true, "deno": true, "python": true, "python3": true}

// Catalogue is the discovery catalogue as the watcher sees processes. The ids are the shared
// tool ids (src/tools/host-actions.ts in manar-api).
//
// ponytail: install-path patterns for the usual locations; add exact paths from the discovery
// package when it exposes them.
var Catalogue = []Tool{
	{ID: "host.claude-code", Script: []string{"/@anthropic-ai/claude-code/"}, Exe: []string{"/.local/share/claude/versions/"}},
	{ID: "host.claude-desktop", Block: true, Exe: []string{"^/opt/claude/", "^/usr/lib/claude-desktop/", "/anthropicclaude/", "/appdata/local/programs/claude/", "^/applications/claude.app/"}},
	{ID: "host.cursor", Block: true, Exe: []string{"$/cursor-agent", "/.local/share/cursor-agent/"}},
	{ID: "host.cursor", Exe: []string{"^/opt/cursor/", "^/usr/share/cursor/", "/.cursor-server/", "/appdata/local/programs/cursor/", "^/applications/cursor.app/"}},
	{ID: "host.windsurf", Exe: []string{"^/opt/windsurf/", "/.windsurf-server/", "/appdata/local/programs/windsurf/", "^/applications/windsurf.app/"}},
	{ID: "host.vscode-copilot", Exe: []string{"^/usr/share/code/", "^/opt/visual-studio-code/", "/.vscode-server/", "/microsoft vs code/", "^/applications/visual studio code.app/", "/.vscode/extensions/github.copilot"}},
	{ID: "host.copilot-cli", Script: []string{"/@github/copilot/"}, Exe: []string{"/@github/copilot/"}},
	{ID: "host.codex-cli", Block: true, Exe: []string{"/@openai/codex/"}},
	{ID: "host.codex-cli", Script: []string{"/@openai/codex/"}},
	{ID: "host.chatgpt-desktop", Block: true, Exe: []string{"^/opt/chatgpt/", "/appdata/local/programs/chatgpt/", "/windowsapps/openai.chatgpt", "^/applications/chatgpt.app/"}},
	{ID: "host.gemini-cli", Script: []string{"/@google/gemini-cli/"}},
}

var shells = map[string]bool{"bash": true, "zsh": true, "fish": true, "sh": true, "dash": true,
	"ksh": true, "tcsh": true, "csh": true, "nu": true, "pwsh": true, "powershell": true, "cmd": true}

// Attribution is the result for one opener.
type Attribution struct {
	ToolID      string // "" when no AI tool is in the chain
	Process     string // the opener's name
	Interactive bool   // a shell the user types in sits between the opener and the tool
	Block       bool   // policy allows denying (before the setting is applied)
	Chain       []Proc // opener first
	ToolProc    Proc   // the process of the chain that matched the catalogue
}

const maxChain = 40

// Attribute walks from pid up to the root and finds the first AI tool process. An unreadable
// chain gives no tool and so never a denial.
func Attribute(src ProcSource, pid int) Attribution {
	var a Attribution
	seen := map[int]bool{}
	for p := pid; p > 1 && !seen[p] && len(a.Chain) < maxChain; {
		seen[p] = true
		pr, err := src.Get(p)
		if err != nil {
			break
		}
		a.Chain = append(a.Chain, pr)
		p = pr.PPID
	}
	if len(a.Chain) == 0 {
		return a
	}
	a.Process = procName(a.Chain[0])
	for i, pr := range a.Chain {
		if t := match(pr); t != nil {
			a.ToolID, a.Block, a.ToolProc = t.ID, t.Block, pr
			for _, below := range a.Chain[:i] {
				if interactiveShell(below) {
					a.Interactive = true
				}
			}
			break
		}
	}
	return a
}

// Deny is the whole policy: deny only an AI tool's own non-interactive chain, only where the
// catalogue allows blocking. Everything else, and every doubt, is allow.
func (a Attribution) Deny() bool { return a.ToolID != "" && a.Block && !a.Interactive }

func norm(p string) string { return strings.ToLower(strings.ReplaceAll(p, `\`, "/")) }

func pat(path, p string) bool {
	switch {
	case strings.HasPrefix(p, "^"):
		return strings.HasPrefix(path, p[1:])
	case strings.HasPrefix(p, "$"):
		return strings.HasSuffix(path, p[1:])
	}
	return strings.Contains(path, p)
}

func match(p Proc) *Tool {
	exe := norm(p.Exe)
	script := ""
	if interpreters[strings.TrimSuffix(path.Base(exe), ".exe")] && len(p.Cmdline) > 1 {
		script = norm(p.Cmdline[1])
	}
	for i := range Catalogue {
		for _, m := range Catalogue[i].Exe {
			if exe != "" && pat(exe, m) {
				return &Catalogue[i]
			}
		}
		for _, m := range Catalogue[i].Script {
			if script != "" && pat(script, m) {
				return &Catalogue[i]
			}
		}
	}
	return nil
}

// interactiveShell is a shell with a controlling terminal that was not started to run one command.
func interactiveShell(p Proc) bool {
	if !p.TTY || !shells[strings.TrimSuffix(strings.ToLower(procName(p)), ".exe")] {
		return false
	}
	for _, a := range p.Cmdline[min(1, len(p.Cmdline)):] {
		if strings.EqualFold(a, "-command") || strings.EqualFold(a, "/c") || runsCommand(a) {
			return false
		}
	}
	return true
}

func procName(p Proc) string {
	if p.Exe != "" {
		return filepath.Base(strings.ReplaceAll(p.Exe, `\`, "/"))
	}
	return p.Comm
}

// runsCommand matches short option clusters that include c: -c, -lc, -ic, -ec.
func runsCommand(a string) bool {
	return len(a) >= 2 && len(a) <= 5 && a[0] == '-' && a[1] != '-' && strings.Contains(a, "c")
}
