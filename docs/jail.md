# JAIL on a personal device (egress filter for protected AI tools)

On by default. Policy: **ask on new sites**. Spec: public launch design 4.4, brief section 2.

## What is filtered

| OS | Filtered | Not filtered |
|---|---|---|
| Linux | Claude Code, Codex CLI, Gemini CLI, Copilot CLI, and every process they start | Cursor, Windsurf, VS Code + Copilot, Claude desktop, ChatGPT desktop (their own backends need many hosts), and everything else you run |
| Windows | Claude Code's native install (`claude.exe`) only, see Windows below | everything else |

Only processes of those tools are touched. A process is the tool's when its name is the tool's
(`claude`, `codex`, `gemini`, `copilot`) or it is `node`/`bun`/`deno` running the tool's script or
package. Root's processes and the service's own are never moved.

## How it works (Linux)

1. `manar-edge service run` reads `jail` from `GET /host/v1/config` every 20 s (enabled, tools, rules).
2. For each tool it starts a local proxy on `127.0.0.1` and `::1` and creates a cgroup
   `/sys/fs/cgroup/manar-jail/<tool>`.
3. It installs one nftables table `inet manar_jail_tools`. For sockets created in a tool's cgroup:
   TCP (except loopback and TCP to the DNS servers in `/etc/resolv.conf`) is redirected to that tool's
   proxy; everything else except loopback and port 53 of those DNS servers is rejected (so QUIC fails fast
   and falls back to TCP, and port 53 of any other address is not a way out). The table is rebuilt when
   `resolv.conf` changes. After the redirect a packet's destination is `127.0.0.1` but its output interface
   is still the real one, so loopback is matched by address.
4. New processes of the tools are moved into the cgroup on the kernel's exec event (and a 250 ms scan as a
   safety net). Their children inherit it. A socket keeps the cgroup it was created in, so a connection
   that was already open when the tool was found is not cut.
5. The proxy reads the site from the TLS SNI or the HTTP Host header and decides: a DENY rule, an ALLOW
   rule, the built-in list, otherwise **ask**. It connects to the **name** it resolved itself, never to the
   address the client meant, so a client cannot name one site and be sent to another. Plain HTTP is checked
   **request by request** (a second request naming another site, an absolute URL, CONNECT or an upgrade
   ends the connection). With ECH, no SNI, an odd request or a protocol that shows no name, the site is
   the **address and is asked about**; the only address allowed without asking is an ssh connection to
   github.com / gitlab.com (their addresses are theirs alone, unlike registries behind shared CDNs, which
   are never allowed by address).
   A program that opens the proxy port by hand (not redirected) has no original destination and is dropped.
6. Names that resolve to loopback, link-local (cloud metadata) or unspecified addresses are refused; a
   private LAN address is reachable only for a site a person allowed by hand.

Built-in allow list: the tool's own AI provider; npm, PyPI, crates.io, Go proxy, Maven, NuGet, RubyGems;
GitHub and GitLab (`internal/jail/policy.go`).

## Asking

A new site opens a WARDEN approval (`kind` = tool id, action `site.connect`, resource = the site) through
`POST /host/v1/jail/ask` and the proxy polls `GET /host/v1/approvals/:id`.

- Every answer to a `site.connect` prompt comes from the **console or the phone**: Allow once, 8 hours, or
  Always for this site. WARDEN on the desktop shows "Claude Code wants to connect to example.org" (long names
  are cut from the left) and "Open the console to decide", but has no button for it. The review showed why:
  a jailed tool can kill the user's prompt helper and run the real helper on a session bus of its own that
  approves everything, so a desktop button is not consent. 8 hours and Always create a site rule for this
  device and tool and need the role that can write site rules (owner or security admin); an approver without
  it gives Allow once.
- No answer in 2 minutes: deny, the approval is withdrawn (denied by the device), the log says
  `denied_no_answer`, and the same site is refused for a minute so a retrying agent does not raise a prompt
  every second. An API that cannot be reached is a refusal too.
- One prompt per site however many connections wait. "Allow once" holds for 60 s so the connections a
  command opens next do not ask again.

## Fail-safe

- Only the tools' processes are filtered. If the service stops or dies, `ExecStopPost` runs
  `manar-edge jail-restore`: the table and cgroups are removed and the tools have their network again; the
  filter is put back within seconds when the service restarts.
- A device that is not approved yet, a tool the owner turned Protect off for, `MANAR_JAIL_ENABLED=false` on
  the API, or a machine without cgroup v2 / `nft` / root: nothing is filtered and nothing is changed.
- After installing the rules the service connects from itself (never in a tool cgroup) to one of the
  machine's own addresses. If that is redirected or refused, the rules hit more than the tools: they are
  removed again and the filter stays off. Every config poll also puts the table back if a firewall reload
  flushed it.
- `manar-edge service remove` and `manar-edge uninstall` both run the same restore. It works from the state on
  the machine, not from memory, so it also cleans up after a crashed service.

## What Manar changes on your computer (JAIL)

- nftables table `inet manar_jail_tools` (root network namespace). Needs the `nft` program.
- cgroup directory `/sys/fs/cgroup/manar-jail/`.
- Processes of the tools above are moved into a cgroup under it, and back to the cgroup each came from on
  restore (recorded in `/run/manar-edge/jail-moved.json` with the process start time, so a reused pid is
  not touched).
- systemd unit `manar-edge.service` has `ExecStopPost=-<manar-edge> jail-restore`.

## Known limits

- A tool process is filtered from its first instructions only when the exec event arrives (a few
  milliseconds); without the proc connector it is found within 250 ms.
- DNS to the configured resolvers is allowed (a DNS tunnel through them is not stopped).
- Programs that talk to non-TCP, non-DNS network are rejected for the tools.
- IDE agents and desktop apps are not filtered. Processes in another network namespace (containers) are
  skipped.
- **A jailed tool can still leave the filter** by starting something outside its cgroup: `systemd-run
  --user`, `docker run`, a tmux server or other daemon that was already running, `xdg-open`, `cron`/`at`,
  or by talking to a proxy or tunnel that listens on loopback (loopback is open to the tools, because DOOR
  and local MCP servers live there). JAIL limits a protected tool's own network use and what it starts
  directly; it is not a sandbox. Tools are filtered by process name, so a renamed binary is not.
- Names of a long Unicode look-alike or a very long subdomain are shown cut from the left.

## Windows

Scope: **Claude Code's native install (`claude.exe`) only.** Windows has no transparent redirect without a
driver, so the tool is pointed at a local proxy through its own settings and Windows blocks everything else
for its exe. That needs a tool whose own proxy setting is documented and whose exe is its own program:

| Tool | Windows | Why |
|---|---|---|
| Claude Code, native install | filtered | `settings.json` `env` takes `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` (code.claude.com network-config: "All environment variables shown on this page can also be configured in settings.json") |
| Claude Code through npm | not filtered | it runs as `node.exe`; blocking node would block every Node program |
| Codex CLI, Gemini CLI, Copilot CLI | not filtered | no documented setting for the tool's own proxy (checked in their docs) |
| Cursor, Windsurf, VS Code, desktop apps | not filtered | as on Linux |

What is installed, per account that has a native `claude.exe` (`~\.local\bin\claude.exe`,
`~\.local\share\claude\versions\*`, or a running `claude.exe` under the profile):

1. The proxy variables in `~\.claude\settings.json` `env` (`HTTPS_PROXY=HTTP_PROXY=http://127.0.0.1:8491`,
   `NO_PROXY=localhost,127.0.0.1`), backed up through the same store as the other tools' edits; the original
   comes back byte for byte, or, if you changed the file since, only these variables are taken out.
   A settings file that cannot be edited safely (not JSON, a link, unreadable) leaves that account alone:
   nothing is blocked for it.
2. A CONNECT proxy on `127.0.0.1:8491`. It sees the host name and port of each tunnel; the TLS inside stays
   between the tool and the site. The policy is the same as on Linux (built-in list, remembered rules, ask).
3. Windows Filtering Platform filters at the ALE connect layers (IPv4 and IPv6) under the provider
   "Manar JAIL" and sublayer "Manar JAIL egress", matched by application id: **permit** loopback, **permit**
   port 53 of the DNS servers the machine is configured with, **block** everything else. They are not
   persistent across a reboot (the service starts at boot and puts them back); a service that died leaves
   them, so the tool stays blocked (fail closed) until the service is back or `manar-edge jail-restore` runs.

The block is installed only after the proxy has answered a **fresh HMAC challenge**: a random per-process
key signs a nonce, so a program that took the port while the service was down cannot pass for the proxy,
and nothing is blocked behind it. `jail-restore`, `service remove` and `uninstall` delete the filters of the
sublayer, then the sublayer and provider, and then restore the settings, in that order.

Residual exposure: the port is fixed because the settings file names it. While the service is down and the
filters are not (or after a reboot before the service starts) another program could bind `127.0.0.1:8491`
and receive Claude Code's CONNECT requests. It would see host names and ports and could refuse them; it could
not read the TLS traffic. A running Claude Code started before the setting was written keeps its old
environment: restart it. Children Claude Code starts inherit the proxy variables and use the proxy if they
honour them; they are not blocked.

Switch: the API sends `jail.windows` (`MANAR_JAIL_WINDOWS`, on by default; see the API's `docs/jail.md`).

Tested on the Manar lab Windows VM (Windows Server 2022, SYSTEM) with `go test -tags jailwin` against real WFP
filters: direct connects from the tool's exe blocked (this machine's address and the internet), an allowed host
reachable through the proxy, a new host asked about, the configured DNS server reachable on port 53 and other
addresses' port 53 blocked, other programs unaffected, a repeated poll a no-op, a removed filter set put back,
turning the tool off removes the filters and restores `settings.json` byte for byte, a dead service leaves the
tool blocked, a fresh process restores everything, an impostor on the port gets nothing blocked, and
`netsh wfp show filters` shows no Manar filter afterwards. Not tested there: a real Claude Code (not installed
on the VM) reading the `env` block, which rests on its documentation.

## Test

`scripts/test-jail-linux.sh` builds the test binary and runs it in a throwaway privileged container (own
network namespace; the host's cgroup tree):

- a tool process reaches an allowed site through the proxy, is refused a new site, and is asked once;
- the same user's other programs, and root's, are not filtered and the proxy never sees their traffic;
- a crash-style `Teardown()` from a fresh process removes the table and cgroups and puts processes back;
- the exec-event watcher sees a process start (needs the host network and pid namespaces).

`scripts/test-jail-windows.md` is not a script: the Windows test (`go test -tags jailwin`) installs real
filters for a copy of the test binary named `claude.exe` in a throwaway profile, so it must run on a Windows
machine as administrator or SYSTEM; it checks the direct connect is blocked, an allowed host works through
the proxy, a new host asks, other programs are unaffected, a dead service leaves the tool blocked, a fresh
process restores everything, and an impostor on the port blocks nothing.
