package watch

import (
	"path/filepath"
	"strings"
)

// Proc is what the watcher knows about one process. Fields the OS could not give stay zero.
type Proc struct {
	PID     int
	PPID    int
	Exe     string   // full path of the executable
	Comm    string   // short name
	Cmdline []string // arguments, argv[0] first
	TTY     bool     // has a controlling terminal
}

// ProcSource reads process info. Get must return an error for a process that is gone.
type ProcSource interface {
	Get(pid int) (Proc, error)
}

// Tool is one entry of the AI tool catalogue, matched against the executable path and command
// line. Block says whether the open may be denied (Linux): false for tools that are also the
// user's own editor, and for tools that are governed through a hook.
type Tool struct {
	ID    string
	Match []string // lower-case substrings of "exe cmdline"
	Block bool
}

// Catalogue is the discovery catalogue as the watcher sees processes. The ids are the shared
// tool ids (src/tools/host-actions.ts in manar-api).
//
// ponytail: substring matching on exe and command line; add exact install-path matching from the
// discovery package when it exposes the paths.
var Catalogue = []Tool{
	// Governed through its PreToolUse hook: the hook asks, so the open is never denied here.
	{ID: "host.claude-code", Match: []string{"/claude-code/", "@anthropic-ai/claude-code", "/bin/claude ", "/.claude/local/", `\claude-code\`}, Block: false},
	{ID: "host.claude-desktop", Match: []string{"/claude-desktop", "/anthropic-claude", `\anthropicclaude\`, `\claude\claude.exe`, "/claude.app/"}, Block: true},
	{ID: "host.cursor", Match: []string{"/cursor/", "/cursor-agent", `\cursor\`, "/cursor.app/", "/.cursor-server/", "cursor-agent"}, Block: true},
	{ID: "host.windsurf", Match: []string{"/windsurf", `\windsurf\`, "/.windsurf-server/", "codeium"}, Block: true},
	// Copilot's own agent processes can be denied; the editor itself is the user's, so it is only
	// reported.
	{ID: "host.vscode-copilot", Match: []string{"copilot-agent", "copilot-language-server", "github.copilot"}, Block: true},
	{ID: "host.vscode-copilot", Match: []string{"/code/", "/visual studio code/", `\microsoft vs code\`, "/.vscode-server/", "/code-insiders"}, Block: false},
	{ID: "host.copilot-cli", Match: []string{"@github/copilot", "/gh-copilot", "/copilot-cli", "github-copilot-cli"}, Block: true},
	{ID: "host.codex-cli", Match: []string{"@openai/codex", "/codex-cli", "/bin/codex "}, Block: true},
	{ID: "host.chatgpt-desktop", Match: []string{"/chatgpt", `\chatgpt\`, "/chatgpt.app/"}, Block: true},
	{ID: "host.gemini-cli", Match: []string{"@google/gemini-cli", "/gemini-cli", "/bin/gemini "}, Block: true},
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
			a.ToolID, a.Block = t.ID, t.Block
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

func match(p Proc) *Tool {
	hay := strings.ToLower(filepath.ToSlash(p.Exe) + " " + strings.Join(p.Cmdline, " ") + " ")
	// Windows paths compare with backslashes in the catalogue, so test the raw form as well.
	raw := strings.ToLower(p.Exe)
	for i := range Catalogue {
		for _, m := range Catalogue[i].Match {
			if strings.Contains(hay, m) || strings.Contains(raw, m) {
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
