# manar-edge: every agent goes through Manar

Status: accepted by the founder 2026-10-25 (decisions in the questions round). This file is the
contract between manar-edge (host binary, gateway), manar-api, manar-web and manar-infra. Change it
by MR only, and change every side in the same round.

## Goal

An agent on a governed host can reach exactly two things: Manar's agent listener and the hostnames
an admin allowed for that agent in Manar. Nothing else, by construction, not by agent cooperation.
Manar is the admin of the agent's network path: it adds the path at enrollment and cuts it on
quarantine, kill switch or revocation; only a person's release restores it.

Three layers, all required (the network alone is not the control):

1. **Credentials**: tool and LLM keys live only in Manar (unchanged).
2. **Network**: the jail below.
3. **Detection**: traffic to LLM APIs from outside Manar is an unmanaged-agent signal (later).

## Names and defaults

| Thing | Value |
|---|---|
| Overlay network | `MANAR_EDGE_CIDR`, default `100.88.0.0/16` (install.env) |
| Gateway overlay IP | first host of the CIDR, `100.88.0.1` |
| Gateway WireGuard port | UDP `51820`, `MANAR_EDGE_ENDPOINT` = `<host>:51820` (install.env) |
| Manar through the tunnel | `100.88.0.1:443`, TCP passthrough to manar-api `:3443` (mTLS stays end to end; client sets SNI/servername to `MANAR_AGENTS_HOST`) |
| Egress proxy through the tunnel | `100.88.0.1:3128`, HTTP `CONNECT` only |
| Host interface name | `manar0` (Linux, inside the netns); tunnel name `manar-<agent>` (Windows) |
| Linux netns | `manar-<agentSlug>` |
| Linux run-as user | `manar-<agentSlug>` (system user, created by `manar-edge up`) |
| Local gateway | `127.0.0.1:8480` inside the netns (Linux) or on the host loopback (Windows) |
| State dir | Linux `/var/lib/manar-edge/<agentSlug>/` root 0700; Windows `%ProgramData%\manar-edge\<agentSlug>\` SYSTEM+Administrators only |

`agentSlug` is the agent's slug from its certificate URI SAN `agent://<tenantSlug>/<agentSlug>`.
Two tenants can share an agent slug, so on-disk names use `<tenantSlug>-<agentSlug>` truncated to
15 chars plus a 4-hex hash when longer (Linux interface and netns name limit). The full pair is in
`state.json`.

## 1. Enrollment (manar-api, extends `POST /agents/enroll`)

Request adds an optional `edge` object:

```json
{ "token": "...", "csr": "-----BEGIN CERTIFICATE REQUEST-----...", "edge": { "wgPublicKey": "<base64 32 bytes>" } }
```

Response adds `edge` when the request had one and the install has edge enabled
(`MANAR_EDGE_ENABLED=true`):

```json
{
  "certificate": "...", "caChain": "...", "serialNumber": "...", "notBefore": "...", "notAfter": "...",
  "edge": {
    "peerId": "uuid",
    "address": "100.88.0.17/32",
    "gatewayPublicKey": "<base64>",
    "gatewayEndpoint": "edge.manar.vax.sh:51820",
    "manarAddress": "100.88.0.1:443",
    "manarServerName": "agents.manar.vax.sh",
    "proxyAddress": "100.88.0.1:3128",
    "keepaliveSeconds": 25
  }
}
```

Rules: the WireGuard private key is generated on the host and never sent. One active peer per agent;
re-enrolling the same agent replaces its peer (old key removed). Edge disabled + `edge` sent: 400
`edge_not_enabled`. Invalid key: 400. Address allocation is unique across all tenants (platform
DB), never reused while a peer row holds it.

Enrollment is the only call that does not go through the tunnel; it uses the HTTP API (`--api`).

## 2. Peer state (manar-api)

Platform-level registry (the gateway serves all tenants):

`EdgePeer { id, tenantId, tenantSlug, agentId, agentSlug, publicKey, address, state, allowHosts[], version, updatedAt }`

`state` is `active | cut`. `cut` while ANY of: agent quarantined, agent kill switch, agent group
kill switch, tenant kill switch, platform kill switch, agent revoked/certificate revoked, agent
suspended. Back to `active` only when none applies (a release, a deactivation; both are already
human-only API calls). `version` is a global monotonic counter bumped on every change to any peer.

`allowHosts[]` is the agent's egress allow-list projected from the tenant DB (section 4).

### Gateway sync API (internal, not on any ingress)

`GET /internal/v1/edge/peers?after=<version>` on manar-api's HTTP port, `Authorization: Bearer
<MANAR_EDGE_GATEWAY_TOKEN>` (OpenBao kv/prod/manar-edge `gateway_token`; constant-time compare;
NetworkPolicy admits only the gateway pod). Long poll: returns at once if anything is newer than
`after`, else holds up to 25 s, then 200 with the same version and no changes.

```json
{ "version": 1042, "full": false,
  "peers": [ { "id": "...", "publicKey": "...", "address": "100.88.0.17/32", "state": "active",
               "tenantSlug": "acme", "agentSlug": "soc-1", "allowHosts": ["graph.microsoft.com"] } ] }
```

`after=0` or a version older than the server's retained history returns `full: true` with every
peer (cut ones included, so the gateway removes them). The gateway applies `full` as a replacement
set and deltas as upserts. Target: a cut reaches the gateway within 2 s.

`POST /internal/v1/edge/events` (same auth): batch of egress connection records from the gateway,
written as audit events `agent.egress.allowed` / `agent.egress.denied` in the agent's tenant:
`{ events: [ { peerId, at, host, port, decision: "allowed"|"denied", reason, bytesUp, bytesDown, durationMs } ] }`.
At most 500 per call; the gateway batches every 2 s. No payloads, no paths, hostnames only.

## 3. Gateway (manar-edge, `cmd/manar-edge-gateway`, runs in the Manar cluster)

- WireGuard interface `wg0` (kernel module when present, else wireguard-go), private key from a
  Secret (`manar-edge-gateway`), address `100.88.0.1/16`, listen UDP 51820.
- Peers = sync API peers with `state: active`, `AllowedIPs = address`. Cut or missing = removed.
- nftables on `wg0` input/forward: from the overlay only `tcp dport {443, 3128}` to `100.88.0.1`;
  no peer-to-peer, no forwarding anywhere else, drop + counter otherwise.
- `:443` listener on `100.88.0.1`: raw TCP relay to `manar-api.manar-prod.svc:3443` (no TLS
  termination). Connection refused for a source address that is not an active peer.
- `:3128` listener: `CONNECT host:port` only (port 443 only, configurable). Source WireGuard IP
  identifies the peer (WireGuard cryptokey routing makes it authentic). Allow when `host` matches
  the peer's `allowHosts` (exact, or `*.suffix` wildcard one label or more). After the CONNECT is
  accepted, read the TLS ClientHello and require SNI == host (case-insensitive), else close and log
  `denied sni_mismatch`. Resolve DNS on the gateway, refuse private/loopback/link-local/overlay
  results (`denied private_address`). Log every attempt (section 2 events).
- On cut: remove the peer AND close its open relay and proxy connections.
- Health: `/healthz`, `/readyz` (ready after the first full sync), Prometheus `/metrics` on :9090
  (peers active, cuts applied, sync lag, proxy decisions by result).
- Runs as non-root with `NET_ADMIN` only; image distroless/static.
- Namespace `manar-gateway` (privileged Pod Security label: `NET_ADMIN` is outside baseline), pod
  label `app.kubernetes.io/name: manar-edge-gateway`. Service `manar-edge-gateway` type
  LoadBalancer, UDP 51820. manar-api's NetworkPolicy admits this label from `manar-gateway` on
  3443 (relay) and on the HTTP port (sync API); nothing else may call `/internal/v1/edge/*`, and
  manar-api serves `/internal/*` only on the HTTP port, never on the agent mTLS listener.

## 4. Per-agent egress allow-list (manar-api + manar-web)

Tenant DB: `AgentEgressRule { id, agentId, host, createdBy, createdAt, reason }`. `host` is a DNS
name or `*.` + DNS name; no IPs, no ports, no paths, lowercase, max 253.
API (tenant admin role, human auth): `GET/POST /agents/:id/egress-rules`, `DELETE
/agents/:id/egress-rules/:ruleId`. Audit events `agent.egress_rule.added` / `.removed`. Each change
updates the EdgePeer projection and bumps the version. AI or agents cannot add rules (human only;
same rule as "AI may tighten, only people loosen").

Console (manar-web): on the agent page, a "Network" panel: edge status (enrolled on edge, active
or cut and why, overlay address, last handshake when the gateway reports it later), the allow-list
editor, and the recent egress decisions from the audit trail.

## 5. Host binary (manar-edge, `cmd/manar-edge`, Linux and Windows)

```
manar-edge enroll --api https://<console-or-api> --token <tenant:agent:secret> [--state-dir D]
manar-edge up <agent> [--task <taskId>]          # build the jail, start the local gateway
manar-edge down <agent>
manar-edge run <agent> [--task <taskId>] -- <command> [args...]
manar-edge status [<agent>]
manar-edge hook claude-code <agent>              # Claude Code PreToolUse hook (stdin JSON)
manar-edge install-claude-code <agent>           # writes managed settings with the hook
manar-edge version
```

`enroll`: generate ECDSA P-256 key + CSR (SAN URI `agent://<tenant>/<agent>` from the token, same
as manar-agents and sdk-node), generate a WireGuard key pair, call `/agents/enroll` with `edge`,
store key, cert, CA chain, WireGuard key and the `edge` response in the state dir (0600).

### Machine enrolment with the AD CS computer certificate (Windows, `enrol`)

```
manar-edge enrol --server https://<api> --tenant <slug> [--machine-id ID] [--issuer TEXT] [--state-dir D]
```

Contract: manar-api `docs/hosts.md`, "Key-less enrolment with an AD CS computer certificate"
(`POST /hosts/register/adcs`). Run as Administrator on a domain-joined machine.

1. Find the computer certificate in `LocalMachine\My`: not self-signed, Client Authentication EKU,
   in date, a DNS SAN, RSA 2048+ or P-256/P-384, and a private key. `--issuer` narrows by issuer
   text. The newest match wins. Intermediates come from `LocalMachine\CA`; the root is not sent.
2. Host key: ECDSA P-256, persisted as machine key `ManarEdgeHostKey` in the Microsoft Software Key
   Storage Provider, non-exportable. It is a software key: the request says `keyType: SOFTWARE`, there
   is no TPM key and no attestation yet. The same key is reused on later runs, so re-enrolling is not
   a rekey.
3. CSR for the host key, SAN URI `host://<tenant>/<machineId>` only.
4. Proof: the computer certificate's key signs
   `manar-adcs-register-v2\n<tenant>\n<machineId>\n<SHA-256 of the CSR SPKI, hex>\n<os>\nSOFTWARE\n<ISO time>`
   (SHA-256; RSA PKCS#1 v1.5 or ECDSA DER). The key is non-exportable, so the signature is made by
   CNG (`NCryptSignHash`) through `CryptAcquireCertificatePrivateKey`.
5. `machineId` is the `MachineGuid` registry value (`HKLM\SOFTWARE\Microsoft\Cryptography`) unless
   `--machine-id` is given. It is stable across reboots and changes when Windows is reinstalled; a
   machine cloned from an image without sysprep shares it, so give such machines an explicit id.
   `os` is `Windows <major>.<minor>.<build>`.
6. POST, then save `host.cert.pem`, `host-ca.pem` and `host.json` under `<state-dir>\host\` and print
   the host id and status (`PENDING` waits for an admin; `APPROVED` was auto-approved by a rule).
   `401` means the certificate was not accepted (CA, template, revocation, proof); `409` means the
   machine is known with another key or group and an admin must approve the change.

### Linux jail (`up`)

1. Create system user `manar-<name>` (no login shell, no home) if missing.
2. `ip netns add manar-<name>`; create WireGuard link `manar0` in the root namespace (so its UDP
   socket stays in the root namespace and can reach the gateway), then move it into the netns.
3. In the netns: `lo` up, `manar0` address from enrollment, default route via `manar0`, WireGuard
   peer = gateway (`AllowedIPs = 100.88.0.1/32`, endpoint, keepalive). No DNS: the netns gets an
   `/etc/netns/manar-<name>/resolv.conf` with `nameserver 127.0.0.1` and nothing listens on 53.
4. nftables in the netns: output accept `oif lo`; accept `oif manar0 ip daddr 100.88.0.1 tcp dport
   {443,3128}`; drop everything else (IPv6 included).
5. Root namespace nftables table `manar_edge`: `meta skuid <uid of manar-<name>> drop` on output
   (so the agent user cannot reach anything even if started outside the jail).
6. Start the local gateway inside the netns as a systemd unit `manar-edge-gw@<name>.service`
   (`NetworkNamespacePath=/run/netns/manar-<name>`), reading the identity from the state dir.
7. `up` is idempotent; `down` reverses it all. `status` shows handshake age, peer state as seen
   (gateway reachable or not), local gateway health.

`run`: `nsenter`/`setns` into the netns, drop to user `manar-<name>` (setresuid/setresgid,
no supplementary groups, `PR_SET_NO_NEW_PRIVS`), exec the command with:

```
OPENAI_BASE_URL=http://127.0.0.1:8480/v1    OPENAI_API_KEY=manar
ANTHROPIC_BASE_URL=http://127.0.0.1:8480    ANTHROPIC_API_KEY=manar
MANAR_MCP_URL=http://127.0.0.1:8480/mcp
HTTPS_PROXY=http://100.88.0.1:3128  HTTP_PROXY=http://100.88.0.1:3128  NO_PROXY=127.0.0.1,localhost
```

The agent user cannot read the state dir (root 0700), so it never holds the identity key.

### Local gateway (both OSes)

Listens on `127.0.0.1:8480`, talks to Manar over mTLS at `manarAddress` with `manarServerName`,
the enrollment CA chain as the only trust anchor, no proxy env. Injects `X-Manar-Task-Id` from
`--task` (or `MANAR_TASK_ID` in the unit) on every call; without a task, LLM and MCP calls get 412
`manar_task_required` locally.

| Local | Manar |
|---|---|
| `POST /v1/chat/completions` | `POST /agent/v1/llm/chat/completions` |
| `POST /v1/messages` (Anthropic) | `POST /agent/v1/llm/anthropic/v1/messages` |
| `GET /v1/models` | `GET /agent/v1/llm/models` (or a fixed list until it exists) |
| `POST|GET|DELETE /mcp` | `/agent/v1/tasks/{task}/mcp` |
| `GET /healthz` | local |

Streaming responses (SSE) are passed through unbuffered. Request bodies capped at 10 MiB. The
local gateway never rewrites bodies; the incoming `Authorization`/`x-api-key` is dropped.

### Windows (`up`)

- Requires WireGuard for Windows installed (checked, clear error otherwise). Writes
  `manar-<name>.conf` (Address, PrivateKey, peer = gateway, `AllowedIPs = 100.88.0.1/32`, no DNS)
  and runs `wireguard.exe /installtunnelservice`.
- Local gateway runs as a Windows service `manar-edge-gw-<name>`.
- Per-program outbound firewall rules for each path given by `up --program <exe>` (repeatable):
  block outbound to every address except `100.88.0.1` and `127.0.0.1` (computed complement ranges,
  IPv6 blocked entirely). Rules grouped as `Manar Edge <name>` so `down` removes them.
- `run` on Windows starts the program with the same env vars (proxy at `100.88.0.1:3128`).
- Limitation stated in the docs: per-program rules follow the path; a copied binary is not
  covered. Running the agent as a dedicated local account with a user-scoped rule is the stronger
  follow-up.

### Claude Code hook (`hook claude-code`)

Reads the PreToolUse JSON from stdin. Calls `POST /agent/v1/authorize` over mTLS (through the
tunnel) with `{taskId, toolId: "host.claude-code", actionId: <tool_name lowercased, e.g. bash,
edit, write, read, webfetch>, resource: <command for bash, file_path for file tools, url for
webfetch, else tool name>}`, resource truncated to 2048. Maps the decision:
`ALLOW` -> `permissionDecision: "allow"`; `DENY` -> `"deny"` with Manar's reason;
`APPROVAL_REQUIRED` -> polls the approval (`GET /agent/v1/approvals/{id}`) up to 10 min with
backoff, then allow on `APPROVED`, deny otherwise. Any error -> deny (fail closed) with the reason.
`install-claude-code` writes `/etc/claude-code/managed-settings.json` (root-owned, 0644) with the
hook and `allowManagedHooksOnly: true`, and sets `ANTHROPIC_BASE_URL` to the local gateway via the
managed `env`.

## 6. LLM: Anthropic format (manar-api)

`POST /agent/v1/llm/anthropic/v1/messages` (mTLS, `X-Manar-Task-Id`), same gates as chat
completions (task gate, DLP before and after, budget, audit, stop codes). Upstream per install:
`LLM_ANTHROPIC_PROVIDER` = `anthropic` (default; key kv/prod/llm-anthropic `api_key`) |
`azure_foundry` (endpoint + key) | `openai_translate` (convert to the configured OpenAI-format
upstream) | `none` (404 `anthropic_disabled`). Streaming supported. `GET /agent/v1/llm/models`
lists what the install serves.

## 7. Cloud agents (manar-api): public MCP with OAuth

For agents that run in a vendor's cloud (Copilot Studio, ChatGPT): `https://<MANAR_MCP_HOST>/mcp`
(new host `mcp.<domain>`, public through the tunnel; bearer tokens, no client certificates).
MCP authorization per the MCP spec: `/.well-known/oauth-protected-resource` names the tenant's
Keycloak realm as the authorization server; Keycloak brokers the tenant's Entra ID; dynamic client
registration allowed for ChatGPT, a pre-registered client for Copilot Studio. A token maps to a
Manar agent of kind `cloud` (created in the console: "Connect a cloud agent", which shows the MCP
URL and client details) and its standing task. From there the same tools/call path, decisions,
approvals, DLP and audit apply. The tenant is resolved from the token issuer, never from the
request.

## 8. Kubernetes agents (later in this round)

Sidecar `manar-edge gateway-sidecar` (same local gateway on 127.0.0.1:8480 in the pod) plus a
NetworkPolicy allowing only the sidecar's egress to manar-api:3443 and the in-cluster egress proxy;
remote clusters run the WireGuard gateway path. Chart snippet in manar-edge `deploy/`.

## Out of scope now

TLS inspection; laptops; IPv6 in the overlay; detection of unmanaged LLM traffic (layer 3).
