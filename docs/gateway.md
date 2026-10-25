# manar-edge-gateway: operating notes and residual risks

The contract is [design.md](design.md), section 3. This file records how the gateway behaves where
the contract is silent, and the risks it accepts.

## Limits

| Limit | Default | Flag / env |
|---|---|---|
| Open relay plus proxy connections per peer | 64 | `--max-conns-per-peer` |
| Open relay plus proxy connections in total | 2048 | `--max-conns` |
| Idle timeout (no byte either way) | 5 min | `--idle-timeout` / `MANAR_IDLE_TIMEOUT` |
| CONNECT line and headers | 8 KiB | fixed |
| CONNECT, DNS, dial and ClientHello together | 15 s | fixed |
| ClientHello read | 64 KiB | fixed |
| Egress events kept while manar-api is down | 10000, oldest dropped | `--events-queue` |
| Refuse ClientHellos with ECH | off | `--deny-ech` / `MANAR_PROXY_DENY_ECH`, chart `proxy.denyEch` |

A connection over a cap is closed at once; the proxy records it as `denied too_many_connections`.

## Proxy decisions

Denied reasons: `invalid_host` (not a DNS name of at most 253 characters), `port_not_allowed`,
`host_not_allowed`, `dns_failed`, `private_address` (any answer private, loopback, link-local,
CGNAT, overlay, reserved, IPv4-mapped or NAT64), `sni_mismatch` (no ClientHello, or its SNI is
not the CONNECT host), `ech_not_allowed` (only with `--deny-ech`), `dial_failed`, `peer_cut` (cut during the handshake),
`too_many_connections`, `bad_request`, `method_not_allowed`. Allowed connections are reported
when they end, with byte counts.

When the ClientHello carries the `encrypted_client_hello` extension (0xfe0d, real ECH or GREASE)
the event has `"ech": true`. The field is an addition to the contract's event shape (design.md,
section 2) and is omitted when false, so every other event is unchanged; manar-api may ignore
unknown fields.

A cut closes the peer's relay and proxy connections. Removing a host from a peer's allow-list
closes that peer's open proxy connections to hosts no longer allowed.

Events the API rejects as invalid or too large (400, 413, 422) are split in halves until the one
bad event is found and dropped (counted in `manar_edge_gateway_events_dropped_total`).

## Residual risks (accepted)

- **Domain fronting through shared CDN addresses.** The gateway checks the CONNECT host, the DNS
  answer and the TLS SNI, but not the HTTP `Host` header inside TLS (no TLS inspection, out of
  scope). An agent allowed `allowed.example` that is served by a CDN can send `Host:
  other-tenant.example` to the same edge and reach any site that CDN fronts. Allow-listing a
  CDN-hosted name therefore allows, in practice, what that CDN serves to unauthenticated
  requests.
- **ECH is allowed by default.** With ECH the SNI the gateway checks is the outer (cover) name of
  the allowed host's client-facing server; the real destination is another site on that same
  server. That is the same exposure as the domain fronting above, and GREASE ECH (sent by every
  Chromium, Electron and Playwright client) cannot be told apart from real ECH, so refusing it
  would break those agents. Such connections are recorded with `"ech": true`. `--deny-ech`
  refuses them (`ech_not_allowed`) for installs that accept breaking Chromium-based agents.
- **Plaintext HTTP to manar-api inside the cluster.** The sync and events API (and the bearer
  token) travel over manar-api's HTTP port. NetworkPolicy admits only this pod on that path; a
  party able to read pod traffic on the node can read the token and the peer list.
- **`allowPrivilegeEscalation: true`.** The binary runs as uid 65532 and gets `CAP_NET_ADMIN`
  from a file capability, which the kernel grants only without `no_new_privs`. The capability
  bounding set holds NET_ADMIN only, so nothing beyond it can be gained.
- **Event flooding by one peer.** A peer can produce many denied events; the queue is bounded and
  drops the oldest, so a flood can push out other agents' records while manar-api is unreachable.
  The drop counter shows it.
- **One replica.** An upgrade or crash interrupts every tunnel until the new pod is ready.
