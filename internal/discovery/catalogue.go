package discovery

// Spec is one AI tool Manar knows how to find. Paths use {home}, {config} (Linux ~/.config,
// Windows AppData\Roaming) and {local} (Windows AppData\Local); a * is a glob.
type Spec struct {
	Key  string // cursor
	ID   string // host.cursor
	Name string
	// User paths exist only where a person uses the tool; System paths are absolute installs.
	User   []string
	System []string
	// VersionFiles are package.json or product.json files with a "version" key. Binaries are
	// never run to ask: the service runs as root and the binary may belong to a user.
	VersionFiles []string
	// Procs are lower-case process names that mean the tool is running.
	Procs []string
}

// Catalogue is the maintained list (public launch spec 4.5). Order is the order shown.
var Catalogue = []Spec{
	{
		Key: "claude-code", ID: "host.claude-code", Name: "Claude Code",
		User:         []string{"{home}/.claude", "{home}/.local/bin/claude", "{home}/.local/bin/claude.exe", "{config}/npm/claude.cmd"},
		System:       []string{"/usr/bin/claude", "/usr/local/bin/claude", "/usr/lib/node_modules/@anthropic-ai/claude-code", "/usr/local/lib/node_modules/@anthropic-ai/claude-code"},
		VersionFiles: []string{"/usr/lib/node_modules/@anthropic-ai/claude-code/package.json", "/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json", "{config}/npm/node_modules/@anthropic-ai/claude-code/package.json"},
	},
	{
		Key: "claude-desktop", ID: "host.claude-desktop", Name: "Claude desktop",
		User: []string{"{config}/Claude/claude_desktop_config.json", "{config}/Claude/Local Storage", "{local}/AnthropicClaude", "{local}/Programs/claude"},
	},
	{
		Key: "cursor", ID: "host.cursor", Name: "Cursor",
		User:         []string{"{home}/.cursor", "{local}/Programs/cursor"},
		System:       []string{"/opt/Cursor", "/opt/cursor", "/usr/share/cursor", "/usr/bin/cursor", "/usr/local/bin/cursor"},
		VersionFiles: []string{"/opt/Cursor/resources/app/package.json", "/usr/share/cursor/resources/app/package.json", "{local}/Programs/cursor/resources/app/package.json"},
		Procs:        []string{"cursor", "cursor.exe"},
	},
	{
		Key: "windsurf", ID: "host.windsurf", Name: "Windsurf",
		User:         []string{"{home}/.codeium/windsurf", "{local}/Programs/Windsurf"},
		System:       []string{"/opt/Windsurf", "/usr/share/windsurf", "/usr/bin/windsurf", "/usr/local/bin/windsurf"},
		VersionFiles: []string{"/opt/Windsurf/resources/app/package.json", "/usr/share/windsurf/resources/app/package.json", "{local}/Programs/Windsurf/resources/app/package.json"},
		Procs:        []string{"windsurf", "windsurf.exe"},
	},
	{
		Key: "vscode-copilot", ID: "host.vscode-copilot", Name: "VS Code with Copilot",
		User:  []string{"{home}/.vscode/extensions/github.copilot-*"},
		Procs: nil,
	},
	{
		Key: "copilot-cli", ID: "host.copilot-cli", Name: "Copilot CLI",
		User:         []string{"{home}/.copilot", "{config}/npm/copilot.cmd"},
		System:       []string{"/usr/bin/copilot", "/usr/local/bin/copilot", "/usr/lib/node_modules/@github/copilot", "/usr/local/lib/node_modules/@github/copilot"},
		VersionFiles: []string{"/usr/lib/node_modules/@github/copilot/package.json", "/usr/local/lib/node_modules/@github/copilot/package.json", "{config}/npm/node_modules/@github/copilot/package.json"},
	},
	{
		Key: "codex-cli", ID: "host.codex-cli", Name: "Codex CLI",
		User:         []string{"{home}/.codex", "{config}/npm/codex.cmd"},
		System:       []string{"/usr/bin/codex", "/usr/local/bin/codex", "/usr/lib/node_modules/@openai/codex", "/usr/local/lib/node_modules/@openai/codex"},
		VersionFiles: []string{"/usr/lib/node_modules/@openai/codex/package.json", "/usr/local/lib/node_modules/@openai/codex/package.json", "{config}/npm/node_modules/@openai/codex/package.json"},
	},
	{
		Key: "chatgpt-desktop", ID: "host.chatgpt-desktop", Name: "ChatGPT desktop",
		User: []string{"{config}/ChatGPT", "{local}/Programs/ChatGPT", "{local}/Packages/OpenAI.ChatGPT*"},
	},
	{
		Key: "gemini-cli", ID: "host.gemini-cli", Name: "Gemini CLI",
		User:         []string{"{home}/.gemini", "{config}/npm/gemini.cmd"},
		System:       []string{"/usr/bin/gemini", "/usr/local/bin/gemini", "/usr/lib/node_modules/@google/gemini-cli", "/usr/local/lib/node_modules/@google/gemini-cli"},
		VersionFiles: []string{"/usr/lib/node_modules/@google/gemini-cli/package.json", "/usr/local/lib/node_modules/@google/gemini-cli/package.json", "{config}/npm/node_modules/@google/gemini-cli/package.json"},
	},
}

// Others are tools outside the catalogue that are reported as "other" when running.
var Others = map[string]string{
	"aider": "Aider", "ollama": "Ollama", "goose": "Goose", "lm-studio": "LM Studio", "jan": "Jan", "zed": "Zed",
}
