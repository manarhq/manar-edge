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
manar-edge enroll --api https://manar.example        # paste <tenant>:<agent>:<secret> (hidden)
manar-edge up <agent> --task <taskId>
manar-edge install-claude-code <agent>               # optional: Claude Code hook and policy
manar-edge run <agent> -- claude
manar-edge status <agent>
manar-edge down <agent> [--purge]
```

What the host binary enforces, the Claude Code policy it installs and the Windows limits are in
[docs/host.md](docs/host.md).

## Build and test

```bash
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build -trimpath -o bin/ ./cmd/...
```

Tests that need root and network namespaces are tagged `jail` and run only when asked:
`sudo -E go test -tags jail ./...`.
