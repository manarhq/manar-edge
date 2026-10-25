# manar-edge on the host: what it enforces and where it stops

The contract is [design.md](design.md) section 5. This page says what the host binary does beyond
it, and its limits, so an operator knows what is and is not covered.

## Linux

`manar-edge up <agent>` (root) builds the jail and is idempotent; `down <agent> [--purge]` reverses
it.

| Layer | What it does |
|---|---|
| User | System user `manar-<name>`, no login shell, home `/var/lib/manar-edge-home/<name>` (0700, owned by the agent; outside the root-only state dir). `down` keeps the home unless `--purge`. A home left by an earlier uid is never re-owned: that uid's processes are killed and the home is moved to `<home>.stale-<time>` (root 0700) for an administrator. |
| Network | Netns `manar-<name>` whose only route is WireGuard `manar0`; nftables in the netns allow `lo` and the two overlay endpoints, drop everything else (IPv6 included). |
| Root namespace | nftables `inet manar_edge`: sockets owned by any agent uid are dropped (set `agent_uids`), so the user reaches nothing even outside the netns. |
| `run` | Refuses to start unless both nftables layers and the uid set entry are present. Then: setns, private mount namespace, `setgroups([])`, `setresgid`, `setresuid`, `PR_SET_NO_NEW_PRIVS`, a new session; on a terminal the agent gets its own pty as controlling terminal (never root's). |
| Filesystem view | `/etc/resolv.conf` (`nameserver 127.0.0.1`, nothing listens) and `/etc/nsswitch.conf` (`hosts: files`) from `/etc/netns/manar-<name>/`; fresh tmpfs over `/run`, `/var/run`, `/tmp`, `/var/tmp`, so host unix sockets (systemd-resolved, D-Bus, nscd, Docker, X11) are out of reach; only the gateway socket directory is bound back. |
| Gateway | `manar-edge-gw@<name>.service` in the netns, only `CAP_CHOWN` (to hand the hook socket to the agent's group). LLM and MCP on `127.0.0.1:8480`. The Claude Code hook uses `/run/manar-edge/<name>/gw.sock`, which serves only health, authorize and approvals: the directory is root 0755 (nobody else can create or replace the socket), the socket is `root:<agent group>` 0660 and the gateway accepts only the agent uid and root (`SO_PEERCRED`); the hook in turn requires the server to be root. Authorize bodies are parsed strictly (exact keys, no duplicates) and re-encoded with the gateway's task. |
| Boot | `manar-edge-jail@<name>.service` (enabled by `up`) rebuilds the jail after a reboot, before the gateway unit starts. |
| `down` | Kills every process of the agent uid until none is left (bounded; `down` fails and leaves the jail in place otherwise), then removes units, netns, files, the uid from the drop set and the user. |

Units and the hook run the binary from a path only root can change (`/usr/local/bin/manar-edge`
when the current location does not qualify).

## Claude Code

`manar-edge install-claude-code <agent>` merges this into the managed settings
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
- **The local gateway on `127.0.0.1:8480` is reachable by every local process**, which can use the
  agent's identity for LLM and MCP calls under the agent's task. The Claude Code hook also uses it
  on Windows.
- Other IP protocols to the allowed addresses are not filtered (sending them needs raw sockets,
  that is administrator rights).
- `run` needs an elevated prompt (the state dir is SYSTEM and Administrators only), so the program
  it starts is elevated too.
