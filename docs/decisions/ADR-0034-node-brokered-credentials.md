# ADR-0034 — Credentials as node capabilities: leased by the node, injected by its proxy

Status: **Proposed; first slice of [#267](https://github.com/hexrift/WardOS/issues/267) for
`ward-node` (stage 3 of [migration-to-node.md](../migration-to-node.md) §3.4, #332).**
Approvals as a hold the node enforces are not part of this decision.

## Context

[ADR-0032](ADR-0032-credential-provider-interface.md) gave the session broker one
credential-provider interface: leases issued, renewed and revoked at a Vault/OpenBao
backend under rules the broker enforces, injected by the egress proxy so the secret never
enters the sandbox, failing closed with a named state. A `ward-node` workload got none of
it: `credentials.proxy_injection` was `false` and node-security-limitations.md §3.2 listed
"no credential injection" as a gap, ordered after the per-attempt network allowlist
([node-integration.md](../node-integration.md) §9), which is now in place. A control plane
running an agent on a node needs to grant that agent a scoped, short-lived credential for
one service without ever handing it the secret, and to know the credential ends with the
attempt.

## Decision

### 1. The grant names a service, a host and a lifetime; never a secret

The capability manifest gains an optional `credentials` field, additive within protocol
1.3 like `output`, `resources` and `actions`:

```json
{"network":{"custom":["artifacts.example.com"]},
 "credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]}
```

1 to 4 grants, no service twice; `service` is `[a-z][a-z0-9-]{0,31}`; `host` a lowercase
DNS name, no wildcard, not an address literal, that one of the manifest's own
`network.custom` patterns covers; `ttl_secs` at least 1; no other field. A manifest
outside this grammar fails decoding (`authority_denied`), so a credential can never be
granted for a host the attempt may not reach, and an offline manifest can grant none. The
envelope never names a provider, an engine, a header or a secret: those are the operator's.

### 2. Providers and services are the operator's, in a file of the node's own

`ward-node --credentials <file>` (it needs `--network-allowlist`, and with it
`--task-root`) reads a TOML file whose `[provider.<name>]` tables are exactly the session
broker's (ADR-0032 §4: address, token file, CA bundle, timeout, maximum TTL) and whose
`[service.<name>]` tables name the provider and engine (a token role, or a KV v2 secret),
the permissions and resource paths the lease is scoped to, `upstream` (`host:port`, the
only place the credential goes, over TLS), `header` and `value_prefix`, `max_ttl_secs` (the
longest grant the node honours for it, never more than the provider's) and `renew`. The
file must be the node user's own regular file, not a symlink, writable by no one else and
at most 64 KiB; the provider token stays in its own 0600 file. A provider call on a node is
bounded at 5 seconds, so revoking an attempt's leases fits within the bound `stop` and
`revoke` wait for the reap. A malformed file stops the node. The provider interface, its
rules and the Vault/OpenBao backend move from `ward-daemon` into a crate of their own,
`ward-credentials`, unchanged, so both runtimes enforce the same rules.

`admit` honours a grant only on a node started with the file and the allowlist, for a
configured service, whose host is that service's upstream host, with a TTL within the
service's ceiling; any other grant is refused `unsupported_grant` after authority is
proven and before the version is consumed, as every grant the node cannot honour is
(node-integration.md §8.1 step 16). No provider is asked at `admit`.

### 3. Injection only by the attempt's proxy, only for an allowlisted host

At `start`, before the spawn, the node asks the provider for one lease per grant
(`issue_bound`, ADR-0032 §5), bound to the attempt (the session is the attempt id), the
service and the upstream host as the audience, and adds one gateway route per grant to
the attempt's egress proxy: a request for `/<service>/…` on `WARD_PROXY_SOCKET` is
forwarded to the service's upstream with the configured header set to the value prefix and
the leased value, any header of that name the workload sent replaced, within the service's
paths and read-only unless `write` was granted (credential-broker.md §4, route scope). The
proxy refuses to start if a route forwards to a host its allowlist does not cover. Nothing
about the credential enters the sandbox: no variable, file or socket is added; a `CONNECT`
tunnel is never injected into; a request to any other host carries nothing the proxy added.
On a node with the operator's `ward-agent` shim the same route is reachable by a stock HTTP
client as `http://127.0.0.1:3128/<service>/…` through the shim's loopback relay
([ADR-0037](ADR-0037-node-agent-shim-and-relay.md) §7, #267): a Git workload clones the
gateway URL `http://127.0.0.1:3128/<service>/<repo>.git` and the route sets
`Authorization: Bearer <lease>`; the relay decides nothing.

### 4. The lease is bounded by the attempt and revoked when it ends

A lease lives at most the shortest of the grant's `ttl_secs`, the service's and the
provider's maximum, and the attempt's wall-clock budget; a service configured to renew is
renewed by the attempt's reaper once a third of its period is left, outside the registry
lock, never past that maximum, and a renewal takes effect only once its record is kept. A
renewal the provider refuses or cannot serve stops renewing that lease, which runs out on
time. While the attempt is paused its proxy refuses every request, so nothing is injected;
the lease is kept, since the budget, which bounds it, keeps running.

When the attempt ends — its own exit, the budget kill, `stop`, `revoke`, an ambiguous
launch, a `revoke` whose reap is unconfirmed — every route is withdrawn at once (its
deadline moves to the epoch, ADR-0032's `LeaseDeadline`) and every lease is revoked at its
provider, concurrently, before the attempt's end is recorded. A lease issued for a `start`
that is refused is revoked as well. To revoke what a node that dies leaves behind, the node
keeps the provider's revocation handle (a token accessor, never the leased value) of each
live lease in `<task-root>/<task>/<attempt>.credentials/leases.json` (0600, in a 0700
directory beside the workspace), written and synced before the workload starts and removed
once the leases are revoked; a restarted node revokes every lease it finds there before it
serves, recording it before `NodeAttemptRecovered`. This amends ADR-0032 §8 for the node
only: the handle is written to a private file for exactly the lease's lifetime, because a
revocation that must survive the node has to be somewhere outside it; it cannot
authenticate to the upstream.

### 5. A provider that cannot serve fails closed, by name

A provider in a degraded state (ADR-0032 §7) issues nothing: the grant gets a route that
answers every request `403 credential lease expired` before anything is resolved or
connected, recorded as a `NetworkDenied` verdict, and a `CredentialDenied` record names the
state. The attempt still runs; there is no fallback to another credential and no retry.

### 6. Evidence records, without a secret

The attempt's evidence log records every grant with the credential kinds the catalogue
already has, origin `node`, so the catalogue and every reader of it are unchanged:

- `CredentialGranted` when a lease is issued (subject `issued <host> lease <id>`) or renewed
  (`renewed <host> lease <id>`), with the permissions and the lifetime, before
  `NodeAttemptLaunched` for an issue;
- `CredentialDenied` with the rule `credential-provider:<provider>:<state>` when no lease
  could be issued, `credential-renew:<provider>:<state>` when a renewal failed;
- `CredentialRevoked` (reason `UserRevoked` for `revoke`, `SessionEnded` otherwise) when
  the route is withdrawn, followed by a `CredentialDenied` with the rule
  `credential-revoke:<provider>:<state>` when the provider did not confirm the revocation.

A lease id is `b3:` and the first 32 hex digits of the `BLAKE3-256` digest of the
provider's revocation handle, or `static` for a lease the provider cannot revoke (a KV
read): it binds the record to the provider's lease without carrying the handle. No digest
of a leased value is ever recorded, since a static secret's digest would be a guessing
oracle. The denial and revocation records may use the log's terminal reserve, bounded by
the grant count.

### 7. The capability document says whether the node brokers credentials

At 1.3 the existing flags `credentials.proxy_injection` and
`credentials.scoped_http_gateway` are `true` exactly when the node executes, enforces an
allowlist and was started with a credentials file, and `false` otherwise; the document's
shape is unchanged, so a strict decoder of any 1.3 revision reads it. Which services a node
offers is the operator's to tell the control plane; a grant for anything else is refused
`unsupported_grant`.

## Alternatives

- **The envelope names the header, the provider or the secret.** Rejected: whoever signs
  envelopes could then send the provider token, or the leased value, wherever the header
  reaches; the envelope names a service, the operator decides what it means.
- **Inject into `CONNECT` tunnels.** Impossible without intercepting TLS, which the proxy
  never does (ADR-0014). A route is a plain-HTTP request on the socket the proxy forwards
  over TLS itself.
- **Refuse `start` when a provider is down.** Rejected for the same reason the session
  broker does not: the attempt may need the credential for one step only; the request that
  needs it is refused and recorded, and the workload's exit status carries the rest.
- **Revoke on pause, as the session broker does.** Rejected for the node: the budget keeps
  running through a pause and bounds the lease, and the paused proxy injects nothing.
- **New `NodeCredential*` record kinds.** Deferred: the event catalogue is protected and
  asserted by count; the existing kinds carry everything the node records, and a dedicated
  kind belongs with the next catalogue change.
- **Keep the handles only in memory.** Rejected: a node killed outright would leave every
  lease alive until its TTL, which ADR-0032 accepted for the session mode and the node can
  do better on.

## Security consequences

- G2 holds for node workloads: the sandbox sees a socket and a path prefix, never the
  value; the evidence log, the state directory, the task root and every node answer carry
  neither the leased value nor the provider token.
- A lease never outlives the attempt's budget, reaches only its configured upstream, which
  must be on the attempt's allowlist, and is revoked at the provider when the attempt ends
  or a restarted node finds it; a provider unreachable at that moment is recorded and its
  own TTL ends the lease.
- New attack surface: the node's credentials file and the kept handles. Both are the node
  user's private files beside the state it already protects.

## Performance consequences

One provider call per grant at `start` (bounded at 5 seconds each, in the start's spawn
window), one per renewal and one per revocation, concurrent at the end; nothing per
request. A node without the file does nothing new.

## Compatibility

Additive within 1.3: a node without `--credentials` emits exactly the earlier document and
refuses the grant; an older node fails to decode a manifest that carries one
(`authority_denied`). `ward-node`'s inputs change (`ward-credentials` and `toml` join its
closure), so the next release must raise the node version (CONTRIBUTING.md, #275).

## How it is validated

`ward-node-protocol` unit tests of the grammar; `ward-node` unit tests of the
configuration, lease bounds, renewal, revocation, outage, recovery (`credentials`), the
route allowlist (`egress`), `admit` (`admit`) and the capability document (`lib`); and
`ward-node`'s `tests/node_credentials_cli.rs`, a real node with a real sandbox, proxy, an
in-process fake OpenBao and a fake upstream: the upstream sees the injected value while the
workload, the log, the state and the answers never do; the end of the attempt, `revoke` and
a restart after a kill revoke at the provider; a sealed provider fails closed with a
recorded denial and a `403`; a node without the file advertises and admits nothing. The
end-to-end acceptance with a stock client is `tests/node_git_capability_cli.rs`
(ADR-0037 §7): `git` clones and pushes with a leased token through the relay, the token is
revoked when the attempt ends, and the next attempt of the task cannot clone.
