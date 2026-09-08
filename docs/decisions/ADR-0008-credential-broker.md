# ADR-0008 — Credential broker: proxy injection first, minted tokens second

## Decision
`ward-broker` (inside `wardd`) owns all long-lived secrets. Delivery to a session is (A)
**proxy injection** by `ward-proxy` for granted `(host, path-prefix, method)` tuples so the
secret never enters Zone 3, or (B) a **minted short-lived, scoped, session-bound token**
delivered once over the control socket when a tool requires a literal credential.
Agents' own model-API credentials use (A) via gateway/base-URL configuration. SSH is served
via an `ssh-agent`-protocol proxy that signs only for approved hosts. Backend is a trait
with an encrypted local vault as the 0.1 implementation.

## Alternatives
- Mount `~/.ssh`, `~/.aws`, `~/.config/gh` read-only into the sandbox.
- Environment-variable injection of long-lived tokens.
- Agent-side credential helper that asks the user each time (no scoping).
- External secret managers only (1Password/Vault) with no local vault.

## Advantages
- (A) makes credential theft from a compromised sandbox impossible for HTTP services.
- (B) bounds damage by scope and time; revocation at `ward stop`.
- Evidence records every grant and every injected request.

## Disadvantages
- Some tools bypass proxies or pin certificates; they need (B) or a per-tool adapter.
- GitHub App tokens require a GitHub App installation; a fallback with a user OAuth
  token loses some scoping (repository-level scope is still enforced by the proxy path
  filter).
- OAuth refresh flows for agents' own auth may not fit gateway mode (E-07).

## Security consequences
G2 in the security model depends on this. Fails closed when the broker is unavailable.
Token values are unprintable by type.

## Performance consequences
Injection adds microseconds per request. Approval prompts are the only latency the user
notices and are policy-controlled.

## Why selected
Mounting real credential files is exactly the leak the brief forbids. Environment tokens
are copied by tools into caches and logs. A broker with injection is the only design where
a compromised Zone 3 gains nothing durable.

## How it will be validated
ST-012 (persistence), ST-024 (scope overreach), E-07 (agent compatibility).

## Addendum (Phase 2): gateway routes as implemented

`ward-proxy` gateway routes and the `ward claude` wiring implement delivery (A) for the
model API. Points decided during implementation:

* **The gateway upstream is host-chosen, so the session allowlist does not apply to
  it.** The sandbox cannot pick the destination of a `/anthropic` request; `wardd`
  did, when it built the route. Subjecting it to the network capability would make
  `localhost_only` projects (the default for the demo) unable to use the model API at
  all, for no isolation gain. `offline` still refuses every gateway request and no
  grant is made, and the upstream is resolved and pinned like any other destination.
* **One spec per service.** A gateway is `(service, prefix, upstream, header, value
  prefix, headers to strip, key variable, base-URL variable and path)`: Anthropic is
  `x-api-key` on `/anthropic`; OpenAI (Codex) is `Authorization: Bearer` on `/openai`
  with the agent's base URL ending in `/v1`. Adding a provider is adding a spec.
* **Key sources**, in order: the host variable named by the route (`ANTHROPIC_API_KEY`),
  then `$WARD_STATE_DIR/vault/<NAME>`. The encrypted vault of the decision text is
  still Phase 3; the file is the 0.1 stand-in.
* **Placeholder, not empty.** The sandbox gets `ANTHROPIC_API_KEY=ward-gateway` so the
  agent's own "is a key configured?" check passes; the proxy strips `x-api-key` and
  `authorization` before injecting, so the placeholder never reaches the upstream.
* **Explicit opt-out.** `--pass-env ANTHROPIC_API_KEY` hands the agent the real key and
  disables the gateway; the CLI prints that it did.
* **Grant record.** Each launch with a gateway emits `CredentialGranted { service,
  scope: upstream host:port, expires: 24h, delivery: ProxyInjected }` before the
  command starts; the route is torn down with the session proxy when the command
  exits, so the recorded TTL is an upper bound.

