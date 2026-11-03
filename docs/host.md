# manar-edge on the host: what it enforces and where it stops

The contract is [design.md](design.md) section 5. This page says what the host binary does beyond
it, and its limits, so an operator knows what is and is not covered.

## Linux

`manar-edge up <agent>` (root) builds the jail and is idempotent; `down <agent> [--purge]` reverses
it.

| Layer | What it does |
|---|---|
| User | System user `manar-<name>`, no login shell, home `/var/lib/manar-edge-home/<name>` (0700, owned by the agent; outside the root-only state dir). `down` keeps the home unless `--purge`. A home left by an earlier uid is never re-owned and nothing is killed (the uid may belong to another account now): the home is moved to `<home>.stale-<time>` (root 0700) for an administrator. |
| Network | Netns `manar-<name>` whose only route is WireGuard `manar0`; nftables in the netns allow `lo` and the two overlay endpoints, drop everything else (IPv6 included). |
| Root namespace | nftables `inet manar_edge`: sockets owned by any agent uid are dropped (set `agent_uids`), so the user reaches nothing even outside the netns. |
| ptrace | The agent runs as the same uid as Claude Code, so with `kernel.yama.ptrace_scope=0` (the RHEL default) a command Claude Code runs could attach to Claude Code or write its `/proc/<pid>/mem` and skip the hook. `up` raises it to 1 (only descendants can be traced) and persists it in `/etc/sysctl.d/60-manar-edge.conf`, printing what it changed; `--allow-ptrace-scope-0` keeps 0 with a warning; `status` reports it. A process cannot shield itself from its own children with `PR_SET_DUMPABLE` without breaking them, so this sysctl is the control. |
| `run` | Refuses to start unless both nftables layers and the uid set entry are present. Then: setns, private mount namespace, `setgroups([])`, `setresgid`, `setresuid`, `PR_SET_NO_NEW_PRIVS`, a new session; when any of stdin, stdout or stderr is a terminal the agent gets its own pty as controlling terminal (never root's). |
| Filesystem view | `/etc/resolv.conf` (`nameserver 127.0.0.1`, nothing listens) and `/etc/nsswitch.conf` (`hosts: files`) from `/etc/netns/manar-<name>/`; fresh tmpfs over `/run`, `/var/run`, `/tmp`, `/var/tmp`, so host unix sockets (systemd-resolved, D-Bus, nscd, Docker, X11) are out of reach; only the gateway socket directory is bound back. |
| Gateway | `manar-edge-gw@<name>.service` in the netns, no capabilities. LLM and MCP on `127.0.0.1:8480`. The Claude Code hook uses `/run/manar-edge/<name>/gw.sock`, which serves only health, authorize and approvals: the directory is root 0755 (nobody else can create or replace the socket), the socket is 0666 and the gateway accepts only the agent uid and root (`SO_PEERCRED`); the hook in turn requires the server to be root. Authorize bodies are parsed strictly (exact keys, no duplicates) and re-encoded with the gateway's task. |
| Boot | `manar-edge-jail@<name>.service` (enabled by `up`) rebuilds the jail after a reboot, before the gateway unit starts. |
| `down` | Kills every process of the agent uid until none is left (bounded; `down` fails and leaves the jail in place otherwise), then removes units, netns, files, the uid from the drop set and the user. |

Units and the hook run the binary from a path only root can change (`/usr/local/bin/manar-edge`
when the current location does not qualify).

## Claude Code

On an enrolled device Claude Code is protected like the other tools: once the owner approves the
device, and while its switch in the console (AI tools) is on, the device service adds a
`PreToolUse` hook (`matcher: "*"`, `manar-edge hook-tool claude-code tool`, `timeout: 600`) to each
person's `~/.claude/settings.json`, keeps a backup, and takes it out again when the switch is
turned off or the device is removed. Every tool call then goes to `POST /host/v1/authorize` and
shows in the console's Sessions view, with the command redacted (see
`testdata/contract/host-contract.json`). The hook has `onFailure: "block"`, so a hook that cannot
start, crashes or times out blocks the call (Claude Code versions without `onFailure` let it run).

What personal mode cannot stop: it writes no managed settings, so a project's own
`.claude/settings.json` or `.claude/settings.local.json` (`disableAllHooks`), `claude --settings`,
`CLAUDE_CONFIG_DIR`, or the person editing `~/.claude/settings.json` can take the hook out of play.
This is the honest "hook" level, not a lock. What Manar does about it:

- Every hook Manar installs (all tools, Claude Code included) refuses an AI tool's edit to a hook or
  settings file (`**/.claude/settings*.json`, `.cursor/hooks.json`, `.cursor/mcp.json`,
  `.codeium/windsurf/hooks.json`, `.windsurf/hooks.json`, `.gemini/settings.json`,
  `.codex/hooks.json`, `.codex/config.toml`, `.copilot/hooks/*.json`, `.github/hooks/*.json`, the
  MCP files Manar wraps, managed settings). Every file an edit names is checked: path arguments of
  any editing or MCP tool, and the files in a patch (`*** Add/Update/Delete File:`, `*** Move to:`,
  diff `---`/`+++`, `rename`/`copy` lines), also when the patch is piped to `apply_patch` in a
  shell. An editing call whose files Manar cannot find is refused. Paths are compared after
  removing Windows stream suffixes (`name::$DATA`) and trailing dots and spaces, collapsing `.` and
  repeated separators. Each path is checked as text (with `..` applied to the text, as Windows does)
  and as its real target: resolved one element at a time with links followed before `..` is
  applied (as Linux does), 8.3 short names expanded, and any part that does not exist yet appended.
  It fails closed: a path that cannot be resolved (a broken or looping link, an unreadable folder)
  is refused. An ordinary relative edit such as `../README.md` is not.
- A shell command is refused when it names one of those files, names `CLAUDE_CONFIG_DIR` or
  `disableAllHooks`, runs `claude --settings`, or names a tool's settings folder next to something
  that writes or removes files (file commands, redirection, `tee`, `dd`, `sed -i`, `awk`, or an
  interpreter such as python, node or perl), or names such a folder together with a `..` path
  element. This check is best effort, not a security boundary:
  it reads the command's text, so a command that builds the name at run time (variables,
  encodings, a script written first and run later) is not caught. Cursor has no edit hook, so
  Cursor's own file edits are not checked.
- The device reports to the console (`POST /host/v1/events`), and the console marks the device as
  tampered: `protect.tamper.settings_write` (a hook refused such a change; edits carry the path,
  shell commands do not), `protect.tamper.hook_removed` (Manar's hook was taken out of a file it
  protects; the service puts it back within a minute), and on Linux only, for a running Claude Code,
  `protect.tamper.hooks_disabled` (`disableAllHooks` in the project's settings, from its working
  folder up to the project root), `protect.tamper.settings_flag` (`--settings`) and
  `protect.tamper.config_dir` (`CLAUDE_CONFIG_DIR` other than `~/.claude`). The same thing is
  reported at most every 6 hours. On Windows the service cannot read another process's arguments,
  environment or working folder, so only the first two are reported there.

For a locked-down agent account (agent mode), `manar-edge install-claude-code <agent>` merges this
into the managed settings instead; when that hook is present the device leaves the person's own
settings alone
(`/etc/claude-code/managed-settings.json`; Windows `C:\Program Files\ClaudeCode\managed-settings.json`):

| Key | Value | Why |
|---|---|---|
| `hooks.PreToolUse` | `matcher: "*"`, the manar-edge hook, `timeout: 690`, `onFailure: "block"` | every tool call asks Manar; a hook that fails, times out, is killed or cannot start blocks the call |
| `allowManagedHooksOnly` | `true` | no user, project or plugin hook runs |
| `allowManagedPermissionRulesOnly` | `true` | no user or project allow rule |
| `permissions.defaultMode` | `dontAsk` | anything that would prompt is denied unless the hook allowed it |
| `permissions.disableBypassPermissionsMode`, `permissions.disableAutoMode` | `disable` | no bypass or auto mode |
| `requiredMinimumVersion` | `2.1.295` | older Claude Code (which ignores `onFailure`) refuses to start |
| `env.ANTHROPIC_BASE_URL` | `http://127.0.0.1:8480` | model calls go through the local gateway |

It refuses to install while another managed policy source exists, because Claude Code would apply
that source instead of this file or merge it in: files in `managed-settings.d/` (merged after
`managed-settings.json`), the Windows `HKLM\SOFTWARE\Policies\ClaudeCode` `Settings` value, or a
user's cached server-managed settings (`~/.claude/remote-settings.json`). `--force-coexist` installs
anyway, after you have checked those sources. Sessions started by `manar-edge run` export
`ANTHROPIC_BASE_URL`, which makes Claude Code skip the server-managed fetch. Verify with `/status`
in Claude Code: "Setting sources" must show the managed settings file, and `/hooks` must list the
manar-edge hook.

Resulting behaviour (sources: [hooks](https://code.claude.com/docs/en/hooks) "Block the action
when a hook fails" and PreToolUse decision control; [permissions](https://code.claude.com/docs/en/permissions)
"Precedence among rules, hooks, and mods"; [permission modes](https://code.claude.com/docs/en/permission-modes)
dontAsk; [settings reference](https://code.claude.com/docs/en/settings-reference) for
`allowManagedHooksOnly` and `requiredMinimumVersion`):

- Hook answers `allow`: the call runs (in `dontAsk` a hook approval counts as pre-approval), except
  where a managed deny or ask rule matches, and except critical-path `rm` and network-path reads,
  which no hook can approve.
- Hook answers `deny`: the call is blocked in every mode.
- Hook missing, killed, crashing, non-JSON, or past its timeout: `onFailure: "block"` blocks the call.
- The hook itself denies on any error: gateway unreachable, Manar error, no task, unknown decision,
  approval denied, expired or not decided within 10 minutes, and any input longer than Manar can
  check (2048 characters; it is refused, never truncated).
- `--permission-mode` on the command line still changes the starting mode; the hook runs before
  every tool call in every mode, so the decisions above do not depend on it.

## Windows

- `up --program <exe>` (repeatable) adds outbound block rules for each program, grouped as
  `Manar Edge <name>`: every address except `100.88.0.1` and `127.0.0.1`; on those, every TCP port
  except `100.88.0.1:443`, `100.88.0.1:3128` and `127.0.0.1:8480`; all UDP to them; all of IPv6.
- **Rules follow the program path.** Any other program, or a copy or rename of a covered one, is not
  confined. Running the agent as a dedicated local account with user-scoped rules is the stronger
  follow-up.
- Rules are written with `powershell -EncodedCommand` (UTF-16, so non-ASCII paths survive), every
  `--program` must be an existing file, and `up` reads the rules back and fails unless each program
  has exactly its rules under the exact path.
- **The local gateway on `127.0.0.1:8480` is reachable by every local process**, which can use the
  agent's identity for LLM and MCP calls under the agent's task.
- The Claude Code hook does not use that port: it talks to the gateway service over the named pipe
  `\\.\pipe\manar-edge-<name>`. The pipe's DACL gives SYSTEM full control and Users read and write
  but not instance creation; the service creates the first instance with
  `FILE_FLAG_FIRST_PIPE_INSTANCE` (if anyone squats the name, the service fails to start); the hook
  opens it with identification-only impersonation and checks that the pipe's server process is the
  running `manar-edge-gw-<name>` service. `up` waits for health over the same pipe.
- Other IP protocols to the allowed addresses are not filtered (sending them needs raw sockets,
  that is administrator rights).
- `run` needs an elevated prompt (the state dir is SYSTEM and Administrators only), so the program
  it starts is elevated too.

## DOOR (device-level LLM gateway)

`manar-edge service run` starts DOOR on `127.0.0.1:848` (ports are named in `internal/ports`; the per-agent
JAIL gateway keeps `127.0.0.1:8480`). The port is below 1024 on purpose: on Linux only root can bind it, so a
user program cannot take it while the service restarts and read the API key a tool sends. Tools are routed
to DOOR (Codex `openai_base_url`) only while that holds (`ip_unprivileged_port_start` above 848) and DOOR
answers a fresh challenge; otherwise Manar removes the route it wrote. Windows has no equivalent guarantee
(an HTTP.sys reservation does not stop raw sockets), so Manar writes no route there. DOOR names the calling
local user from the kernel TCP table (Linux) or the owning process token (Windows) and refuses callers it cannot
name. Pauses are by provider. The secrets guard catches accidental leaks in JSON strings; it does not decode
base64 or find a secret split across fields.

## Undo AI file changes

Before an AI tool edits a file outside the folder it was started in, its pre-tool hook (which runs
as the signed-in user) saves a copy in that user's own folder (`$XDG_STATE_HOME/manar-edge/undo`,
Windows `%LOCALAPPDATA%\manar-edge\undo`). The hook opens files with `O_NOFOLLOW` after an `lstat`
(no links, no folders, no devices), copies at most 10 MiB per file and 256 MiB per user, and the
copies expire after 7 days. File contents never leave the device: the hook sends the device
service only the path, size, SHA-256 and time (over the local relay, which learns the user from
the kernel), and the service forwards that record to `POST /host/v1/undo/changes`.

A restore starts in the console. The service polls `GET /host/v1/undo/restores` and runs
`manar-edge __undo restore <id> <path>` in a child process that has become the user who took the
snapshot (no other groups), so a link the user planted can only reach what the user could already
reach. The path must equal the one recorded with the snapshot, the saved copy's hash is checked,
the file is written to a temporary name and renamed, and a file the tool created is removed. The
result goes to `POST /host/v1/undo/restores/:id/result`. `manar-edge undo list|restore <id>` does
the same for the person at the keyboard on any OS.

Covered: file edit tools whose hook input names one file (Claude Code Edit, MultiEdit, Write and
NotebookEdit; the same tool names in Gemini CLI, Codex CLI and Copilot CLI hooks). Not covered:
changes made through the shell, and patch tools that name several files. On Windows the service
cannot act as the user, so the console button reports that the restore must be run on the device.
The feature is the `undo` entry of `features` in `GET /host/v1/config`.

## `manar-edge status`

`manar-edge status [--json]` needs no root. The service writes a status file
(`/run/manar-edge/status.json`, Windows `%ProgramData%\manar-edge\status.json`, world-readable, no
secrets), and the command adds the service manager's answer and a probe of DOOR on
`127.0.0.1:848`. Every problem is one line with one fix; the exit code is 1 when there is a
problem. Other modules publish their state with `daemon.SetComponent("door" | "jail" | "warden" |
"secrets", daemon.Component{State, Detail, Fix})`; a part nobody reports is shown as "not reported
by this version" and is not counted as a problem.
