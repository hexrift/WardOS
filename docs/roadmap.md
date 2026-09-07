# Roadmap

Status: Phase 0 in progress. Phases are sequential in their *gates*; work inside a phase
may overlap with experiments from the next.

## Phase 0 — Architecture (this repository, now)

Deliverables (all in `docs/`): architecture, trust boundaries, threat model, security
model, technology decision records, event model, snapshot model, credential broker model,
TamperWard integration contract, design language, performance methodology, experiment
plan, repository structure, this roadmap, and the development-under-TamperWard model.

Gate: documents reviewed; experiments E-01, E-02, E-06 scheduled.

## Phase 1 — Host runtime prototype

On an existing Linux host (Fedora or Arch with kernel ≥ 6.8, cgroups v2, unprivileged
userns enabled), implement:

```text
ward init      create .ward/ with default policy; register project
ward up        build project environment; create entry snapshot; prepare sandbox
ward shell     interactive shell inside the sandbox
ward status    project/session state
ward stop      teardown
```

Provides: `wardd` (single process), sandbox via generated OCI spec + `crun`, namespaces,
filesystem isolation, network namespace with `ward-proxy` egress, no host Docker socket,
basic event stream (`SessionStarted`, `CommandStarted/Finished`, `NetworkRequested/Denied`,
`FileModified`), `ward watch` TUI in Live mode.

**Narrow scope, explicitly:** one project at a time per user, Linux only, Btrfs or ext4,
no credentials (all `deny`), no TamperWard, no verifier, no GUI, no nested containers,
Claude Code not yet launched by `ward`.

Acceptance:

| Criterion | Measure |
| --- | --- |
| ST-001, 002, 003, 004, 011, 013, 014, 015 pass | `ward selftest` on the dev host |
| Sandbox warm start | < 250 ms (Phase 1 budget; 150 ms by Phase 2) |
| Event latency | < 50 ms p99 (25 ms by Phase 5) |
| `ward status` | < 20 ms |
| Policy merge | Repo policy cannot widen; unit + integration tests |
| Docs | `docs/` updated with measured numbers and any ADR revisions |

## Phase 2 — Agent support

```text
ward claude
ward codex
```

Adds: agent image layers, agent hook adapters (origin=Agent events, step-through hooks),
session IDs and sealed logs, credential broker with GitHub + model-API gateway (E-07),
`development` network mode (E-08), nested rootless containers (E-04) or the documented
fallback, persistent project environments.

Acceptance: Claude Code and Codex complete a real task in `examples/ward-demo` with no
long-lived credential in Zone 3 (ST-012, 024); warm start < 150 ms; a full session replays.

## Phase 3 — TamperWard

Integrate TamperWard control plane in Zone 1 over the TamperWard socket; implement
`session describe`, `snapshot create/attest/diff/cat`, `evidence append/anchor`,
`capability check`. Demonstrate the demo scenario:

```text
agent attempts prohibited shortcut → TamperWard denies → agent fixes implementation →
trusted verifier independently passes
```

At this phase the verifier may still be a Zone 2 *namespace* environment on the same host.

Acceptance: demo passes end-to-end; DENIED originates from TamperWard; ST-007, 009, 010,
016 pass; E-12 recorded.

## Phase 4 — Verifier boundary

Move the verifier into its proven separate trust environment (E-03 decides namespaces vs
microVM default). Hostile tests prove the agent cannot mutate policy, verifier, entry
snapshot, or evidence.

Acceptance: ST-005, 006, 008, 018, 019 pass with a hostile agent *and* a hostile
repository; verifier has no network; verification startup < 500 ms.

## Phase 5 — Observer

Rust observer with Quiet, Live, Step-through and Replay; approval surface; TUI complete;
first Ward Shell components (bar + session panel + approvals) on Hyprland per
[`design-language.md`](design-language.md); E-10 and E-11 recorded.

Acceptance: observer latency < 25 ms p99; step-through holds commands and network
requests; write holds either hard (E-11) or documented as best-effort; ST-020 passes.

## Phase 6 — Immutable image

Fedora bootc image: Hyprland, Ward Shell, `ward*`, container tooling, development
defaults, four official themes, command centre. Built by CI with pinned digests.

Acceptance: boots in QEMU and on the reference desktop; WardOS Security CI runs the ST
suite on the image; performance CI subset green; idle RAM/CPU within budget.

## Phase 7 — Security boot chain

Secure Boot (Fedora shim → systemd-boot → UKI), TPM2-bound LUKS2 with recovery key,
signed updates, boot-counting automatic rollback, `ward system rollback`; evaluate sealed
images (E-09).

Acceptance: RT-001, RT-002 pass on two reference devices; a deliberately broken update
rolls back without user action; Secure Boot stays *on* throughout installation.

## Phase 8 — Installer optimisation

Only after installer correctness: profile, DAG-schedule, deploy prebuilt image, optimise
decompression and storage path, measure and publish with reproducibility records.

Acceptance: < 45 s on reference hardware with FDE and verification; no benchmark-only
code paths.

## Phase 9 — Hardware validation

Reference matrix: AMD desktop, Framework 13 AMD, ThinkPad (AMD), one Intel laptop.
Automated report per device for GPU, Wi-Fi, Bluetooth, suspend/resume, external display,
audio, webcam, battery, fractional scaling.

## Phase 10 — WardOS 0.1 Technical Preview

Not 1.0. Ships with the demo, the threat model, explicit limitations, benchmark records,
and the security-test results. Also ships the portable docker compose runtime as the
adoption path for non-WardOS hosts.

### 0.1 acceptance criteria

* Desktop boots reliably; polished Hyprland environment; keyboard-first; command centre,
  terminal, browser, editor support.
* `ward claude` works.
* Agent cannot: write host, read SSH keys, read host secrets, modify WardOS policy,
  modify TamperWard, modify verifier, modify frozen entry state, modify trusted evidence
  (ST-001..025 green on the release image).
* A real protected-change scenario is demonstrated with TamperWard.
* Trusted verification occurs outside agent authority.
* User can watch actions in real time.
* Previous deployment can be restored.
* Threat model and limitations are explicit and shipped.

## Implementation sequence (first 12 weeks of engineering, after Phase 0 sign-off)

| Weeks | Work | Experiments closed |
| --- | --- | --- |
| 1–2 | Workspace skeleton, `ward-events` types, `ward-policy` merge + tests, `wardd` control socket, `ward status` | — |
| 2–4 | Sandbox builder (OCI spec + crun), `ward-agent` PID 1 with Landlock/seccomp, `ward shell` | E-01, E-06 |
| 4–5 | Network manager: netns, nftables, `ward-proxy` allowlist, DNS stub | E-08 (partial) |
| 5–6 | Snapshot engine: Btrfs + frozen-copy, CAS, `ward up` entry snapshot | E-02 |
| 6–7 | Event capture: eBPF exec, fanotify, proxy log; `ward watch` TUI | E-05 |
| 7–8 | Security tests ST-001..004, 011, 013..015 as a hostile workload + `ward selftest` | — |
| 8 | **Phase 1 gate** | |
| 9–10 | Agent images, hooks adapters, `ward claude`/`ward codex`, sealed logs, replay | E-07, E-08 |
| 10–12 | Credential broker (GitHub, model-API gateway), nested containers | E-04 |
| 12 | **Phase 2 gate**; Phase 3 TamperWard adapter starts | E-12 |

## Non-goals

WardOS 0.1 is not: a replacement for every Linux distribution; a Kubernetes distribution;
a server OS; a gaming distro; a general-purpose family desktop; an attempt to support
every laptop; a custom kernel project; an excuse to rebuild every Linux component; a
promise of perfect sandbox security; an enterprise management platform.

## Enterprise path (reserved, not built)

Fleet management, central policy (a fourth policy layer), SSO, device attestation, agent
permission management, credential broker integration, central audit (evidence
forwarder), remote revocation, approved agent catalogue (image digest allowlist),
security reporting, compliance evidence. Core WardOS and TamperWard remain useful without
any of these.
