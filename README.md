# manar-edge

Puts an agent's network path under Manar's control. On a governed host the agent can reach only
Manar's agent listener and the hostnames an admin allowed for it; Manar adds the path at enrollment
and cuts it on quarantine, kill switch or revocation. The design and the contract with manar-api
are in [docs/design.md](docs/design.md).

Two binaries:

- `manar-edge` (Linux, Windows): enrolls an agent, builds its jail (a network namespace whose only
  interface is a WireGuard tunnel to the Manar gateway on Linux; WireGuard plus per-program
  firewall rules on Windows), runs the local gateway on `127.0.0.1:8480` (OpenAI, Anthropic and
  MCP endpoints that forward to Manar over mTLS) and starts the agent inside the jail.
- `manar-edge-gateway` (container, runs in the Manar cluster): the WireGuard server, the relay to
  manar-api's agent listener and the hostname-filtered egress proxy, kept in sync with manar-api.

## Host quick start (Linux, as root)

```bash
manar-edge enroll --api https://manar.example --token -   # paste <tenant>:<agent>:<secret>
manar-edge up <agent> --task <taskId>
manar-edge run <agent> -- claude
manar-edge status <agent>
manar-edge down <agent>
```

`install-claude-code <agent>` writes the managed settings (`/etc/claude-code/managed-settings.json`,
Windows `C:\Program Files\ClaudeCode\managed-settings.json`) with a PreToolUse hook that asks Manar
before every tool call and denies on any error (`onFailure: "block"`, needs Claude Code 2.1.295 or
later). The hook runs as the agent user, so it reaches Manar through the local gateway.

Limits to know:

- Windows: firewall rules follow the program path; a copied or renamed binary is not covered.
  Running the agent as a dedicated local account with a user-scoped rule is the stronger follow-up.
  `run` on Windows needs an elevated prompt (the state dir is SYSTEM and Administrators only), so
  the program it starts is elevated too.
- The local gateway is reachable by anything that shares its loopback: inside the netns on Linux,
  the whole host on Windows.
- The jail does not survive a reboot (`/run/netns` is cleared); run `up` again after boot.

## Build and test

```bash
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build -trimpath -o bin/ ./cmd/...
```

Tests that need root and network namespaces are tagged `jail` and run only when asked:
`sudo -E go test -tags jail ./...`.
