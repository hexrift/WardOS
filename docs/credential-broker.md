# Credential Broker

Status: living document; the project's phase is in docs/status.toml and the README.
Implemented: the model-API gateways (Anthropic, OpenAI; see
[agent-integration.md](agent-integration.md) §3), the GitHub adapter in gateway
mode (§4), the credential-provider interface with a Vault/OpenBao backend for
short-lived, proxy-injected leases (§5, #267), and the same providers brokering leases to
`ward-node` workloads (§8). Registry and SSH adapters, cloud STS backends, minted tokens
and the encrypted vault are ahead. Decision records:
[ADR-0008](decisions/ADR-0008-credential-broker.md),
[ADR-0032](decisions/ADR-0032-credential-provider-interface.md),
[ADR-0034](decisions/ADR-0034-node-brokered-credentials.md).

## 1. Problem

Agents need to push to GitHub, read issues, install packages from private registries and
call their own model API. Today that is done by putting long-lived tokens in the agent's
environment or home directory. In WardOS, Zone 3 is assumed compromised, so a long-lived
secret in Zone 3 is a leaked secret.

## 2. Model

```text
                     Zone 3                       Zone 0
   agent ── needs GitHub ──▶ ward-request ──▶ ward-broker
                                                   │  policy (Deny | Ask | Allow(scope))
                                                   │  approval (Ward Shell / TUI)
                                                   │  backend (vault) → mint / lease
                                                   ▼
                              ┌────────────────────┴────────────────────┐
                              │ delivery A: proxy injection             │  preferred
                              │  ward-proxy adds Authorization for       │
                              │  (host, path-prefix, method) ∈ grant     │
                              │  → token never enters Zone 3            │
                              ├─────────────────────────────────────────┤
                              │ delivery B: minted short-lived token     │  when a tool insists
                              │  ≤ 10 min, scoped, session-bound, sent   │
                              │  once over the control socket            │
                              └─────────────────────────────────────────┘
```

## 3. Grant object

```yaml
grant:
  id: grant_01J…
  session: sess_01J…
  service: github
  subject: repo:hexrift/tamperward
  permissions: [contents:read, issues:read]
  delivery: proxy-injection
  hosts: [api.github.com, github.com]
  expires_in: 10m
  approved_by: user:once       # policy:allow | user:once | user:session
```

Grants are events (`CredentialGranted`) minus the secret. Revocation on `ward stop`,
on policy change, on explicit `ward revoke`, and on expiry.

## 4. Service adapters (initial set)

| Service | Backend secret (Zone 0) | Delivery | Scoping |
| --- | --- | --- | --- |
| GitHub | GitHub App private key or user OAuth token | A: proxy injection for `api.github.com` and HTTPS git; B: installation token for `gh` | Repository + permission set; tokens are GitHub App installation tokens (native expiry ≤ 1 h; broker requests ≤ 10 min where supported, otherwise revokes at expiry). **Implemented (A, 0.1):** `ward claude --grant github` routes `https://github.com/` and `git@github.com:` remotes to `/github` on the relay (a seeded `~/.gitconfig` `insteadOf`) and `GITHUB_API_URL` to `/github-api`; the proxy injects `Authorization: Basic x-access-token:<token>` / `Bearer <token>` from the host's `GITHUB_TOKEN` (or the vault). The manifest's `credentials.github` rule gates it: `deny` refuses and records `CredentialDenied`, `ask` needs the explicit `--grant`, `allow` is automatic; the scope's repositories (`current` resolves once from the worktree at session start — following a linked worktree's or submodule's `gitdir:`/`commondir` indirection where needed — and is persisted in `SessionMeta::origin_repo` rather than re-read from the live worktree afterward, so an agent's own `.git/config` edit mid-session cannot redirect it — issue #196) and permissions are recorded in `CredentialGranted` and enforced at the route. |
| Git over SSH | Host `~/.ssh` keys stay in Zone 0 | `ssh-agent` protocol proxy in the sandbox: signs only for approved `(host, user)`; every signature is an event | Per-host; `ask` by default |
| npm / PyPI / crates.io (read) | Registry tokens | A | Read-only by default; publish is `deny` |
| Agent model API (Anthropic / OpenAI / Google) | The user's API key or OAuth token | **A, via gateway mode**: sandbox gets `ANTHROPIC_BASE_URL=http://127.0.0.1:3128/anthropic` or `OPENAI_BASE_URL=http://127.0.0.1:3128/openai/v1` and a placeholder key; proxy injects auth | Implemented for Anthropic and OpenAI; keeps the user's long-lived model credential out of Zone 3 entirely **[experiment E-07]** |
| Cloud (AWS/GCP/Azure) | Never for production; dev accounts via STS-style short leases | B (lease) | `deny` hard by default for anything tagged production |
| Arbitrary env secret | Vault entry | A for HTTP; B otherwise | Explicit policy entry per secret |

**Route scope: where `CredentialScope` is enforced at the proxy.** A gateway route
carries a scope (`GatewayRoute::scope(paths, write)`): the path prefixes, after the
route prefix is stripped, that the injected credential may act on, and whether writes
are granted. `wardd` derives it from the grant's `CredentialScope` — a GitHub grant for
`hexrift/WardOS` with `contents:read` becomes a `/github` route scoped to
`/hexrift/WardOS.git` (git over HTTPS) and `/repos/hexrift/WardOS` (the REST API) with
`write = false`. Path prefixes match at segment boundaries only (`/hexrift/WardOS.gitx`
is not under `/hexrift/WardOS.git`; the query string is ignored); an empty list means
every path. A read-only route passes `GET`, `HEAD`, `OPTIONS` and a `POST` to
`…/git-upload-pack` (a fetch) and refuses everything else, including `POST
…/git-receive-pack` (a push), `PUT`, `PATCH` and `DELETE`. A refused request is answered
`403 Forbidden` with the fixed body `request outside credential scope` and recorded as a
`NetworkDenied` decision (`gateway /github: outside credential scope` or `gateway
/github: write not granted`) before the upstream is resolved or connected, so the secret
is never sent for a request the grant did not cover. The check is a pure function of the
route and the request line; the upstream's own authorisation still applies on top.

## 5. Backend: credential providers

Every brokered credential comes from a **credential provider**
(`ward_credentials::CredentialProvider`, ADR-0032, re-exported as
`ward_daemon::credentials`; the node uses the same crate, §8): `issue(request) -> lease`,
`renew`, `revoke` and `health`. A request names the session (the task), the service, the
scope (resource paths at the upstream, a permission set, whether writes are allowed), a
TTL, a maximum TTL and an audience (the upstream host). Two providers exist:

| Provider | Source | Lease | Revocation at the source |
| --- | --- | --- | --- |
| `local-vault` | the host variable named by the route, else `$WARD_STATE_DIR/vault/<NAME>` (`ward vault set`) — what the model-API and GitHub gateways always read | static value, client-side lease (the route's validity) | none: withdrawing the route is the revocation (`not revocable at the source`) |
| Vault / OpenBao (`kind = "vault"` or `"openbao"`), engine `token` | `POST /v1/auth/token/create/<role>` with `ttl`, `explicit_max_ttl`, the granted permissions as `policies`, `no_default_policy`, and `meta` naming session, service and audience | the provider's token TTL, renewed with `auth/token/renew` | `auth/token/revoke-accessor` (an already-gone token, `invalid accessor`, counts as revoked) |
| Vault / OpenBao, engine `kv` | `GET /v1/<mount>/data/<path>`, one field (KV v2) | static value, client-side lease | none, as for the local vault |

The encrypted vault sealed with `systemd-creds` (Phase 7 target) and cloud STS backends
are not implemented yet.

### 5.1 Configuration (host only)

Providers and the services they back are configured in
`$WARD_STATE_DIR/credentials.toml` (`~/.local/state/ward/credentials.toml`), never in a
repository:

```toml
[provider.bao]
kind = "openbao"
address = "https://bao.internal:8200"     # TLS required
token_file = "/home/me/.config/ward/bao.token"   # 0600; the broker's own token
ca_bundle = "/etc/ward/bao-ca.pem"        # optional; the host trust store otherwise
timeout_ms = 2000                         # every call; at most 10 s
max_ttl_secs = 3600                       # the longest lease this provider may issue

[service.artifacts]
provider = "bao"
engine = "token"                          # or "kv" with mount, path, field
role = "ward-artifacts"
rule = "ask"                              # or "allow"
permissions = ["artifacts-read"]          # "write" opens non-read methods on the route
ttl_secs = 600
max_ttl_secs = 900                        # no renewal reaches past this from issue
renew = true
upstream = "artifacts.example.com:443"
prefix = "/artifacts"                     # the route on the sandbox's relay
header = "authorization"
value_prefix = "Bearer "
paths = ["/v1/repos/acme"]                # the resources the route may reach
base_url_env = "ARTIFACTS_URL"            # the sandbox gets http://127.0.0.1:3128/artifacts
```

* The file holds no secret. `token_file` must be the user's own regular file with no
  group or other access (a symlink is refused); `credentials.toml` itself must be the
  user's and writable by no one else, since it decides where that token is sent.
* Plain `http://` is refused unless `insecure_loopback = true` and the address is a
  loopback IP literal — a test mode, not a deployment.
* The host's `rule` and `permissions` enter the policy merge as the **system layer**: a
  project's `.ward/policy.yaml` can narrow them (`credentials: {artifacts: deny}`, a
  smaller permission set) but can never introduce a provider-backed service or widen
  one. `ask` needs `ward claude --grant artifacts`.
* A service may not reuse a built-in service, a default deny class (`cloud-*`) or a
  built-in route prefix; the audience is always the upstream host.

### 5.2 Lease rules

Enforced by the broker for every provider, whatever the provider answers:

* **TTL**: the shortest of the service's `ttl_secs` and the provider's `max_ttl_secs`;
  the maximum the shortest of the service's `max_ttl_secs` and the provider's. A
  provider that grants longer is clamped.
* **Scope and binding**: the lease must name the session, service and audience asked
  for, and its scope must be covered by the requested one; a provider that attaches
  more policies or another binding is refused, and the token it issued is revoked at
  once.
* **Renewal** (`renew = true`): once a third of the current period is left, for up to
  the original period again, never past the original maximum and never with a wider
  scope; at the maximum it is refused without asking the provider. A renewal that
  fails leaves the lease to run out on time.
* **Injection**: the proxy route carries the lease's deadline; past it the route
  answers `403 credential lease expired` before resolving, connecting or injecting.
  Requests outside `paths`, or writing without `write`, are refused as for GitHub (§4).

### 5.3 Revocation

The launching process holds the launch's leases and pushes revocation to the provider
when the grant is revoked (`ward session revoke`: the proxy withdraws the route and
acknowledges first), when the session pauses (credentials are suspended: the route is
withdrawn at once and the lease revoked, not held across the pause — the next launch
gets a fresh one), when the lease expires, and when the launch ends, which `ward stop`
causes. A lease issued for a launch that never starts is revoked too. The outcome is
shown on the grant's line, `ward session grants [--history]`:

```text
4   artifacts   artifacts-read · artifacts.example.com · provider bao: revoked at the provider (grant revoked)   launch   revoked
```

`revoked at the provider`, `revoke unconfirmed (<state>)`, `static secret, not
revocable at the source; route withdrawn`, `renewed`, `renewal refused (max ttl
reached)` and `renewal failed (<state>)` are the outcomes. A withdrawn grant moves to
the history. If the launching process is killed outright, nothing revokes early: the
provider's own TTL, which is the lease's, ends it.

## 6. What the agent sees

```text
$ ward creds
SERVICE      STATE     SCOPE                              EXPIRES
github       granted   repo:hexrift/tamperward ro          8m12s
ssh:github   ask
npm          granted   read                                session
aws-prod     denied    production credentials unavailable
anthropic    proxied   model API via gateway                session
```

No token values are ever printed, by type construction (`Secret<T>` has no `Display`).

## 7. Failure behaviour

* Broker unavailable → requests fail closed; the agent gets a clear error; event logged.
* Provider degraded → no lease, no route, no fallback to another credential. The state
  is named — `unreachable`, `timed-out`, `tls-failed`, `auth-rejected`, `sealed`,
  `misconfigured`, `bad-response` — in the launch's note (`artifacts: provider bao
  unreachable; no credential granted (fail closed)`), in the log as `CredentialDenied`
  with the rule `credential-provider:<provider>:<state>`, and by `ward doctor`
  (`credential providers: bao degraded (unreachable) …`). Every provider call is bounded
  by the provider's `timeout_ms`. A failed renewal or revocation is recorded on the
  grant's line with the same name.
* A value a provider returns that could not be a header (a control byte) is refused,
  never injected. Leased values and the broker's provider token never appear in the
  log, the grant history, `ward doctor`, an error or the sandbox.
* Approval times out (default 120 s) → `Deny(timeout)`; the agent can retry.
* Proxy injection for a host that also appears unauthenticated in the same session: the
  proxy injects only on `(host, path-prefix, method)` tuples of an active grant.
* Injected requests are logged with method, host, path, status; never headers or bodies.

## 8. Credentials for `ward-node` workloads

A `ward-node` started with `--network-allowlist` and `--credentials <file>` brokers the same
providers to admitted attempts
([ADR-0034](decisions/ADR-0034-node-brokered-credentials.md),
[node-integration.md](node-integration.md) §6.8). The differences from a session:

* **Who decides.** The control plane's signed manifest asks for a service by name, for a
  host its own network allowlist covers and a TTL
  (`"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]`);
  the node's operator decides what the service is in the node's own file (the
  `[provider.<name>]` tables of §5.1, and `[service.<name>]` tables naming the engine,
  permissions, paths, upstream, header and the longest TTL honoured). There is no `ask` and
  no project policy: an unconfigured service, another host or a longer TTL is refused
  `unsupported_grant` at `admit`.
* **Lifetime.** A lease lives no longer than the grant, the service, the provider and the
  attempt's budget; it is revoked at the provider when the attempt ends, whatever ended it,
  and a node restarted after it died revokes what it finds in the attempt's kept handles
  (`<task-root>/<task>/<attempt>.credentials/leases.json`, the revocation handles only)
  before it serves. A pause does not revoke it: the paused proxy injects nothing, and the
  budget keeps running.
* **Records.** The attempt's evidence log, not a grant history: `CredentialGranted`
  (`issued` or `renewed <host> lease <id>`), `CredentialDenied` with the rule
  `credential-provider:`, `credential-renew:` or `credential-revoke:<provider>:<state>`, and
  `CredentialRevoked`, all origin `node`, none carrying a secret or a handle.
* **Provider calls** are bounded at 5 seconds on a node, so revoking fits within the bound
  `stop` and `revoke` wait for.
