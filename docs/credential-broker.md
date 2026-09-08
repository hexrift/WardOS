# Credential Broker

Status: Phase 3. Implemented: the model-API gateways (Anthropic, OpenAI; see
[agent-integration.md](agent-integration.md) §3) and the GitHub adapter in gateway
mode (§4). Registry and SSH adapters, minted tokens and the encrypted vault are ahead. Decision record:
[ADR-0008](decisions/ADR-0008-credential-broker.md).

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
| GitHub | GitHub App private key or user OAuth token | A: proxy injection for `api.github.com` and HTTPS git; B: installation token for `gh` | Repository + permission set; tokens are GitHub App installation tokens (native expiry ≤ 1 h; broker requests ≤ 10 min where supported, otherwise revokes at expiry). **Implemented (A, 0.1):** `ward claude --grant github` routes `https://github.com/` and `git@github.com:` remotes to `/github` on the relay (a seeded `~/.gitconfig` `insteadOf`) and `GITHUB_API_URL` to `/github-api`; the proxy injects `Authorization: Basic x-access-token:<token>` / `Bearer <token>` from the host's `GITHUB_TOKEN` (or the vault). The manifest's `credentials.github` rule gates it: `deny` refuses and records `CredentialDenied`, `ask` needs the explicit `--grant`, `allow` is automatic; the scope's repositories (`current` resolves from the worktree's origin remote) and permissions are recorded in `CredentialGranted` and enforced at the route. |
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

## 5. Backend

Phase 2 backend: an encrypted file vault under `/var/lib/ward/vault/`, sealed with
`systemd-creds` (TPM-backed where available, Phase 7) and unlocked at `wardd` start by
the user's login session. The backend is a trait (`CredentialBackend { lease(...) }`) so
that 1Password/Bitwarden/Vault/enterprise brokers are drop-ins later.

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
* Approval times out (default 120 s) → `Deny(timeout)`; the agent can retry.
* Proxy injection for a host that also appears unauthenticated in the same session: the
  proxy injects only on `(host, path-prefix, method)` tuples of an active grant.
* Injected requests are logged with method, host, path, status; never headers or bodies.
