<p align="center">
  <img src="assets/logo.svg" alt="WardOS" width="112" height="112">
</p>

<h1 align="center">WardOS</h1>

<p align="center"><strong>A secure Linux workstation for software engineers working with autonomous coding agents.</strong></p>

WardOS is a purpose-built Linux distribution for agentic software development. It gives
coding agents (Claude Code, Codex, Gemini CLI, Aider, and whatever comes next) everything
they need to work effectively, while keeping the host, policy, credentials, verifier, and
trusted state **outside the agent's authority**.

```bash
git clone project
cd project
ward claude
```

```text
WARD SESSION

Project         project
Agent           Claude Code
Runtime         isolated
Network         restricted
Credentials     none

TamperWard
Policy          protected
Entry state     frozen
Verifier        isolated
Evidence        protected

Observer        LIVE
```

## See it running

The prototype runs today on any Linux host with `bubblewrap`. It merges the project's
policy into a capability manifest, freezes a content-addressed entry snapshot, runs
commands inside an isolated sandbox with live kernel-origin file events, routes every
network request through a per-session policy proxy, and records everything to an
append-only, hash-chained event log that persists across commands.

![A WardOS session: security panel, live observer with network decisions, isolation self-test](assets/ward-session.png)

```bash
cargo build --release
ward up       examples/ward-demo    # start a session: policy → manifest, entry snapshot, log
ward run --dir examples/ward-demo -- cargo test   # run inside the sandbox; live observer
ward claude   examples/ward-demo    # launch Claude Code; ANTHROPIC_API_KEY stays on the host
ward status   examples/ward-demo    # the security panel for the active session
ward selftest examples/ward-demo    # prove the isolation (8/8 hostile probes blocked)
ward stop     examples/ward-demo    # seal the log
ward replay   <events.log>          # replay any sealed session
```

In the session above the sandbox's only way out is a Unix socket to the session proxy:
an allowlisted registry is reached over real HTTPS (`NET`, `http 200`), while a private
address and the cloud metadata endpoint are refused host-side (`DENY`, `403`). The host
home, SSH keys, cloud credentials, Docker socket, and the namespace, cgroup and symlink
escape routes are never reachable, so `ward selftest` shows every probe denied by
construction, and CI reproduces the same result on every pull request.

## Design principle

> Give coding agents everything they need to work effectively, while keeping the host,
> policy, credentials, verifier, and trusted state outside their authority.

WardOS provides **isolation and trustworthy primitives**. TamperWard provides **policy,
protected invariants, tamper detection, independent verification, and evidence**. The two
are designed together but do not duplicate each other:

```text
WardOS policy      = capabilities and isolation   (what the agent CAN reach)
TamperWard policy  = allowed behaviour and verification (what the agent MAY do, and whether
                     the result is acceptable)
```

## Status

**Phase 0 — Architecture.** No implementation exists yet. This repository currently holds
the architecture, threat model, technology decisions, experiment plan, and roadmap that
must be agreed and (where marked) experimentally validated before code is written.

See [`docs/roadmap.md`](docs/roadmap.md) for the phase plan and
[`docs/experiments.md`](docs/experiments.md) for what must be proven before WardOS becomes
a distribution.

## Documentation

| Document | Purpose |
| --- | --- |
| [`docs/architecture.md`](docs/architecture.md) | Components, trust zones, session lifecycle, data flows |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, adversaries, attack surfaces, mitigations, explicit non-goals |
| [`docs/security-model.md`](docs/security-model.md) | Guarantees WardOS makes, guarantees it does not make, capability model, defaults |
| [`docs/snapshots-and-git.md`](docs/snapshots-and-git.md) | Frozen entry state, candidate state, and why `.git` is not trusted |
| [`docs/event-model.md`](docs/event-model.md) | The typed Ward event model, evidence chain, observer and replay |
| [`docs/credential-broker.md`](docs/credential-broker.md) | How agents obtain scoped, short-lived credentials without seeing long-lived secrets |
| [`docs/tamperward-integration.md`](docs/tamperward-integration.md) | The OS-level primitives WardOS exposes to TamperWard |
| [`docs/agent-integration.md`](docs/agent-integration.md) | How `ward claude` / `ward codex` compose the sandbox, proxy, credentials and hooks |
| [`docs/design-language.md`](docs/design-language.md) | Visual and interaction identity of the WardOS desktop |
| [`docs/performance.md`](docs/performance.md) | Latency budgets, benchmark methodology, CI regression gates |
| [`docs/experiments.md`](docs/experiments.md) | Highest-risk assumptions and the experiments that must settle them |
| [`docs/roadmap.md`](docs/roadmap.md) | Phases, first-prototype scope, acceptance criteria, implementation sequence |
| [`docs/repository-structure.md`](docs/repository-structure.md) | Proposed layout of this repository |
| [`docs/decisions/`](docs/decisions/) | Architecture Decision Records for every major technology choice |

## Engineering principles

1. Architecture over micro-optimisation.
2. Isolation over detection, where OS enforcement is appropriate.
3. Independent verification over trusting agent reports.
4. Fail closed for security decisions.
5. No invisible privilege escalation.
6. Performance must be measured.
7. Security claims must be testable.
8. The user should not need to understand the machinery.
9. Use existing Linux primitives before inventing replacements.
10. Do not optimise the benchmark by weakening the product.

## Non-goals

WardOS 0.1 is not a general-purpose desktop, a server OS, a Kubernetes distribution, a
gaming distro, a custom kernel project, a universal-hardware project, a promise of perfect
sandbox security, or an enterprise management platform. See
[`docs/roadmap.md`](docs/roadmap.md#non-goals).


## Brand

The WardOS mark places the [TamperWard](https://github.com/hexrift/tamperward) ward glyph —
four strokes of change stopped at the exact point — inside a rounded host frame. That is the
product relationship in one image: WardOS supplies the containing boundary, TamperWard the
verification core. Assets live in [`assets/`](assets/) (`logo.svg`, `logo-dark.svg`,
`favicon.svg`); the glyph is derived from TamperWard's own logo.

## License

To be decided before the first code commit (Phase 1). Candidate: Apache-2.0 for all crates.
