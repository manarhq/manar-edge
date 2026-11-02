// Command manar-edge enrolls an agent, builds its network jail and runs it behind Manar.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/manarhq/manar-edge/internal/door"
	"github.com/manarhq/manar-edge/internal/protect"
	"github.com/manarhq/manar-edge/internal/secrets/host"
	"github.com/manarhq/manar-edge/internal/secrets/vault"
	"github.com/manarhq/manar-edge/internal/telemetry"
	"github.com/manarhq/manar-edge/internal/undo"
)

var version = "dev"

const usage = `usage:
  manar-edge enroll --api <url> [--state-dir D]   (token on stdin or in MANAR_ENROLL_TOKEN)
  manar-edge enrol --server <url> --tenant <slug> [--machine-id ID]   (Windows, domain-joined: computer certificate)
  manar-edge install --code <code> --tenant <slug> [--api URL] [--host-url URL]   (personal device: enrol and install the service)
  manar-edge uninstall   (stop the service, restore what Manar changed, remove its files)
  manar-edge service run|install|remove
  manar-edge secret aws <profile>   (credential_process helper for vaulted AWS keys)
  manar-edge secret restore --all   (administrator: put every vaulted secret back in its file)
  manar-edge vault add <key>        (move one of your ssh keys into the Manar vault; undo with vault restore)
  manar-edge vault restore <key>|--all   (put ssh keys back exactly as they were; works offline)
  manar-edge up <agent> [--task <taskId>]` + upUsageExtra + `
  manar-edge down <agent> [--purge]
  manar-edge run <agent> [--task <taskId>] -- <command> [args...]
  manar-edge status [--json]   (is this computer protected? one line to fix each problem; no root needed)
  manar-edge status <agent>   (jail status of an enrolled gateway agent)
  manar-edge hook claude-code <agent>
  manar-edge install-claude-code <agent> [--force-coexist]
  manar-edge protect list|restore [<tool>]   (what Manar changed in other AI tools; undo it)
  manar-edge hook-tool <tool> <event>   (internal: the hook installed in Cursor, Gemini CLI and the others)
  manar-edge mcp-wrap <tool> <server> -- <command> [args...]   (internal: asks Manar before each MCP tool call)
  manar-edge warden [windows-ui on|off]   (per-user prompt helper, started at logon)
  manar-edge undo list|restore <id>   (put back a file an AI tool changed outside its project folder)
  manar-edge jail-restore   (internal: give the protected tools their network back)
  manar-edge version

Global: --state-dir D before the subcommand (default ` + defaultStateBase + `).`

func main() {
	defer telemetry.CrashGuard()
	args := os.Args[1:]
	base := defaultStateBase
	// A --state-dir before the subcommand applies to every subcommand.
	if len(args) >= 2 && (args[0] == "--state-dir" || args[0] == "-state-dir") {
		base, args = args[1], args[2:]
	}
	host.SetStateDir(base)
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]
	telemetry.Configure(base, version)
	protect.Configure(base)
	door.Configure(base)
	undo.Configure(base, exeForHelpers())
	protect.ClaudeSettingsPath = managedSettingsPath
	var err error
	switch cmd {
	case "version":
		fmt.Println(version)
	case "enroll":
		if base != defaultStateBase {
			rest = append([]string{"--state-dir", base}, rest...)
		}
		err = cmdEnroll(rest)
	case "enrol":
		err = cmdEnrolHost(base, rest)
	case "install":
		err = cmdInstall(base, rest, os.Stdout)
	case "uninstall":
		err = cmdUninstall(base, os.Stdout)
	case "service":
		err = cmdService(base, rest)
	case "jail-restore":
		err = jailRestore(os.Stdout)
	case "warden":
		err = cmdWarden(base, rest)
	case "secret":
		switch {
		case len(rest) == 2 && rest[0] == "aws":
			err = vault.RunHelper(rest[0], rest[1], os.Stdout)
		case len(rest) == 2 && rest[0] == "restore" && rest[1] == "--all":
			err = cmdSecretRestoreAll()
		default:
			err = errors.New("usage: manar-edge secret aws <profile> | secret restore --all")
		}
	case "vault":
		err = cmdVault(rest)
	case "up":
		err = cmdUp(base, rest)
	case "down":
		fs := flag.NewFlagSet("down", flag.ContinueOnError)
		purge := fs.Bool("purge", false, "also delete the agent's home directory (Linux)")
		var agent string
		if agent, err = parseAgentFlags(fs, rest); err == nil {
			err = cmdDown(base, agent, *purge)
		}
	case "run":
		err = cmdRun(base, rest)
	case "status":
		var problems int
		if problems, err = routeStatus(base, rest, os.Stdout); err == nil && problems > 0 {
			os.Exit(1)
		}
	case "hook":
		os.Exit(cmdHook(rest))
	case "hook-tool":
		os.Exit(cmdHookTool(rest))
	case "__userfs": // internal: runs as a user's own uid to touch that user's files (Linux service)
		os.Exit(protect.ServeUserFS(os.Stdin, os.Stdout))
	case "__undo": // internal: runs as the snapshot owner (Linux service)
		os.Exit(undo.Helper(rest, os.Stdout))
	case "undo":
		err = undo.Command(rest, os.Stdout)
	case "mcp-wrap":
		os.Exit(cmdMCPWrap(rest))
	case "protect":
		err = cmdProtect(base, rest, os.Stdout)
	case "install-claude-code":
		err = cmdInstallClaudeCode(base, rest)
	case "gateway": // internal: started by the systemd unit or the Windows service
		err = withAgent(rest, "gateway", func(a string) error { return runGatewayService(base, a) })
	case "__jail-exec": // internal: the child `run` starts inside the jail (Linux)
		err = jailExec(rest)
	case "help", "-h", "--help":
		fmt.Println(usage)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "manar-edge:", err)
		os.Exit(1)
	}
}

func withAgent(args []string, cmd string, fn func(string) error) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: manar-edge %s <agent>", cmd)
	}
	return fn(args[0])
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// parseAgentFlags accepts `<agent>` before or after the flags.
func parseAgentFlags(fs *flag.FlagSet, args []string) (string, error) {
	var agent string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		agent, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if agent == "" && fs.NArg() > 0 {
		agent = fs.Arg(0)
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return "", err
		}
	}
	if agent == "" {
		return "", errors.New("missing <agent>")
	}
	return agent, nil
}

// agentEnv is the environment of a jailed agent: the caller's environment without credentials,
// proxy settings or sudo variables, plus the Manar endpoints from the contract.
func agentEnv(base []string, proxyAddr string) []string {
	var env []string
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		u := strings.ToUpper(k)
		if strings.HasPrefix(u, "SUDO_") || strings.HasPrefix(u, "MANAR_") ||
			strings.Contains(u, "KEY") || strings.Contains(u, "TOKEN") || strings.Contains(u, "SECRET") ||
			strings.Contains(u, "PASSWORD") || strings.Contains(u, "CREDENTIAL") || strings.Contains(u, "PROXY") ||
			strings.HasPrefix(u, "OPENAI_") || strings.HasPrefix(u, "ANTHROPIC_") ||
			// host session sockets: none of them is reachable from the jail, and none should be
			strings.HasPrefix(u, "DBUS_") || strings.HasPrefix(u, "SSH_A") || strings.HasPrefix(u, "XDG_RUNTIME") ||
			u == "DISPLAY" || u == "WAYLAND_DISPLAY" || u == "GPG_AGENT_INFO" {
			continue
		}
		env = append(env, kv)
	}
	proxy := "http://" + proxyAddr
	return append(env,
		"OPENAI_BASE_URL="+gatewayURL+"/v1", "OPENAI_API_KEY=manar",
		"ANTHROPIC_BASE_URL="+gatewayURL, "ANTHROPIC_API_KEY=manar",
		"MANAR_MCP_URL="+gatewayURL+"/mcp",
		"HTTPS_PROXY="+proxy, "HTTP_PROXY="+proxy, "NO_PROXY=127.0.0.1,localhost",
		"https_proxy="+proxy, "http_proxy="+proxy, "no_proxy=127.0.0.1,localhost",
	)
}

// setEnv replaces or adds KEY=value entries.
func setEnv(env []string, kvs ...string) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		keep := true
		for _, n := range kvs {
			if strings.HasPrefix(n, k+"=") {
				keep = false
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	return append(out, kvs...)
}

// exeForHelpers is the running binary, which the device service starts for per-user helpers.
func exeForHelpers() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "manar-edge"
}
