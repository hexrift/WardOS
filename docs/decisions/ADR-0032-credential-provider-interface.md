# ADR-0032 — Credential providers: one interface, broker-enforced lease rules, fail closed

Status: **Proposed.** The first slice of
[#267](https://github.com/hexrift/WardOS/issues/267) implements §1–§8 for local
sessions; §9 is what remains. It refines
[ADR-0008](ADR-0008-credential-broker.md) ("the backend is a trait") without changing
its delivery modes.

## Context

ADR-0008 decided that the broker owns long-lived secrets and that its backend is a
trait. Until #267 there was no such trait: the gateways read one host variable or one
vault file (`$WARD_STATE_DIR/vault/<NAME>`), the grant was recorded with a nominal 24 h
bound, and nothing could revoke a credential at its source. #267 asks for
just-in-time, short-lived credentials from Vault/OpenBao-compatible and cloud backends,
bound to the task, resource, TTL and audience, revoked centrally, with provider outages
failing closed and secrets never in logs or answers.

## Decision

### 1. One provider interface

`ward-daemon::credentials::CredentialProvider` has four operations and a name:
`issue(LeaseRequest) -> Lease`, `renew(Lease, increment) -> Lease`,
`revoke(Lease) -> Revocation` and `health() -> Health`. A `LeaseRequest` names the
session (the task), the service, the scope (resource paths at the upstream, a
permission set, whether writes are allowed), a TTL, a maximum TTL and an audience. A
`Lease` carries the secret and the provider's revocation handle as `LeasedSecret`s —
no `Display`, a redacted `Debug`, zeroed on drop, readable only inside the crate — and
whether the provider can revoke it at the source. Every call is bounded in time by the
implementation.

### 2. The host vault is the first implementation

`LocalVault` is exactly what the gateways always read (the host variable, else the
vault file, trimmed). `Gateway::resolve` now issues through it; behaviour for existing
users is unchanged. Its leases are static: renewal is client-side and `revoke` answers
`NotRevocable` rather than claiming a revocation that did not happen.

### 3. A Vault/OpenBao backend over the HTTP API, no new dependency

`VaultProvider` speaks the Vault/OpenBao HTTP API with two engines that need no cloud
account: **KV v2** (a static secret read with a client-side lease; not revocable at the
source) and **token roles** (`auth/token/create/<role>` with `ttl`,
`explicit_max_ttl`, `policies`, `no_default_policy` and `meta` naming session, service
and audience; `auth/token/renew`; `auth/token/revoke-accessor`). The client is a small
HTTP/1.1 implementation over the `rustls` (`ring`) stack the proxy already uses, with
the host trust store or a configured CA bundle; no HTTP or TLS crate is added. Every
call has one deadline covering resolution, connect, handshake, write and read. TLS is
required; plain HTTP is accepted only with an explicit `insecure_loopback = true` *and*
a loopback IP literal, for tests.

### 4. Configuration is the host's, and enters the policy as the system layer

Providers and provider-backed services are configured in
`$WARD_STATE_DIR/credentials.toml` (Zone 0): address, CA bundle, timeout, the
provider's maximum TTL, and the path of the broker's provider token — never the token
itself. The token file must be the user's own regular file with no group or other
access; the configuration file must be the user's and writable by no one else, since
it decides where that token is sent. A project policy cannot introduce a service a
higher layer did not permit (`ward-policy` merges unlisted services to `deny`), so the
host's service rules (`ask`/`allow` and a permission set) enter the merge as the
system layer; `.ward/policy.yaml` can then only narrow them. A repository therefore can
never point the broker at a provider or widen what it grants.

### 5. The broker enforces the lease rules, not the provider

`issue_bound` and `renew_within_bounds` are the only paths to a lease. A lease's TTL is
the shortest of the service's TTL and the provider's maximum; its maximum is the
shortest of the service's maximum and the provider's; it must name the requested
session, service and audience; its scope must be covered by the requested one. A
provider that grants more time is clamped; one that grants more scope or another
binding is refused, and the lease it issued is revoked at once. A renewal is refused
without asking the provider when the lease is at its maximum or has run out, never
reaches past the original maximum, and never widens scope. The audience is the
upstream host, and the proxy injects the lease into that upstream only, on the
service's resource paths, read-only unless `write` was granted. The proxy route is
bound to the lease's deadline (`ward_proxy::LeaseDeadline`): past it the route is
refused before anything is resolved, connected or injected, whether or not anything
else withdrew it.

### 6. The launch keeps custody; revocation is pushed to the provider

The process that runs the egress proxy holds a launch's leases (`LeaseKeeper`): it
renews a lease configured to renew once a third of its period is left, revokes it at
the provider when the lease expires, when its grant is revoked (`ward session revoke`:
the proxy withdraws the route and acknowledges first, then the keeper revokes), when
the session pauses (credentials are suspended: the route is withdrawn on the spot and
the lease revoked rather than held across the pause), and when the launch ends —
which a `ward stop` causes. A lease issued for a launch that never starts is revoked
when it is dropped. Each outcome — renewed, renewal refused or failed, revoked at the
provider, revoke unconfirmed with the provider's state, not revocable at the source —
is sent to the session daemon (`Request::LeaseNote`) and shown on the grant's line in
`ward session grants [--history]`; a withdrawn grant is retired into the history.
Provider calls never run on the proxy's threads or under the daemon's lock.

### 7. Outage is a named degraded state that fails closed

A provider that cannot serve is in one of `unreachable`, `timed-out`, `tls-failed`,
`auth-rejected`, `sealed`, `misconfigured` or `bad-response`. Nothing is issued from
it: the launch gets no route for that service, a `CredentialDenied` record whose rule
is `credential-provider:<provider>:<state>`, and a note naming the state. There is no
fallback to another credential. `ward doctor` reports each configured provider's
health by the same names. A renewal that fails leaves the lease to run out on time; a
revocation that fails is recorded as unconfirmed with the state.

### 8. Secret values never leave the broker

The leased value and the revocation handle are never formatted, logged, written to the
event log, to the grant history or to any answer; provider errors carry the step and
the status, never a body. The integration tests scan the event log, the state
directory, the worktree, the sandbox's environment and output, and the daemon's
answers for the leased bytes.

### 9. Not decided here (what remains of #267)

Cloud-native STS backends; dynamic database and other engines; the explicit
materialisation path (delivery B) with a sandbox-local lifetime; central revocation
with node acknowledgement for `ward-node` workloads (no credential reaches a node
workload yet, [node-security-limitations.md](../node-security-limitations.md));
durable records of provider outcomes in the event log (they live in the daemon's
bounded grant history today); re-issuing a lease after a pause; and the encrypted vault
ADR-0008 still names.

## Alternatives

- **Trust each backend to enforce TTL and scope.** Rejected: a misconfigured role or a
  compromised provider would silently broaden what the agent gets. The rules are cheap
  to enforce in one place.
- **Configure providers in `.ward/policy.yaml`.** Rejected: the worktree is writable by
  the agent and chosen by whoever wrote the repository; it could send the broker's
  provider token anywhere.
- **Let `wardd` hold the leases.** Deferred: the proxy that injects them lives in the
  launching process, which already owns the route's lifetime; the daemon learns
  outcomes through `LeaseNote`. A daemon-held custody is the natural shape once node
  acknowledgement (§9) exists.
- **A full HTTP client crate (reqwest, ureq).** Rejected for now: two JSON calls per
  lease do not justify a second TLS stack or an async runtime in Zone 0.

## Consequences

- Security: G2 now holds for provider-backed services as it does for the model-API key:
  the sandbox sees a relay URL, never the leased value. A static secret (KV, the host
  vault) cannot be revoked at its source; the route's withdrawal is all the revocation
  there is, and every surface says so. A lease's provider-side lifetime outlives the
  route by at most the time the keeper needs to reach the provider; an outage at that
  moment is recorded as unconfirmed, and the provider's own TTL ends it. If the
  launching process is killed outright, nothing revokes the lease early: the
  provider's TTL (which the broker asked for, and which is the lease's) ends it.
- Performance: one provider call per lease at launch (bounded by the configured
  timeout, 2 s by default), one per renewal and one per revocation; nothing per
  request. Injection cost is unchanged.
- Compatibility: no change for users without `credentials.toml`. `Request::LeaseNote`
  is new; an older daemon rejects it and the outcome is then not recorded.

## How it is validated

`ward-daemon` unit tests for the rules (`credentials::tests`), the HTTP client's
bounds, TLS verification and parsing (`credentials::http::tests`), the configuration's
validation and file checks (`credentials::config::tests`), the keeper's renewal,
expiry, withdrawal and pause handling (`credentials::keeper::tests`) and the grant
history (`approvals::lease_note_tests`); `ward-proxy`'s `tests/lease_deadline.rs`; and
`ward-daemon`'s `tests/credential_providers.rs` against an in-process fake OpenBao on
an ephemeral loopback port, through a real sandbox, proxy and daemon.
