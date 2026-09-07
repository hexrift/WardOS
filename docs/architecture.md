# WardOS Architecture

Status: Phase 0 draft. Decisions referenced as `ADR-NNNN` live in
[`decisions/`](decisions/). Anything marked **[experiment]** is an assumption that must be
validated per [`experiments.md`](experiments.md) before it is relied upon.

---

## 1. What WardOS is

WardOS is a workstation operating system in which **an AI coding agent is a first-class,
constrained, observable workload**. It is built from existing Linux technology (an
immutable bootc host, Hyprland, rootless containers, user namespaces, seccomp, Landlock,
cgroups v2, nftables, systemd) plus a small set of WardOS-owned Rust services that
mediate everything the agent touches outside its sandbox.

The product is the *combination*, not any one component:

| Layer | Provides | Owned by |
| --- | --- | --- |
| Immutable host | Secure Boot, TPM-bound full-disk encryption, signed atomic updates, rollback | bootc / Fedora base (ADR-0001) |
| Desktop | Hyprland compositor, Ward Shell (bar, launcher, observer, approvals) | WardOS (Rust) |
| Ward Supervisor (`wardd`) | Sessions, sandboxes, capabilities, network policy, credential broker, snapshots, event bus, verifier broker | WardOS (Rust) |
| Agent runtime | The agent, project tools, project containers, restricted network | Sandbox (untrusted) |
| TamperWard control plane | Semantic policy, protected invariants, agent-action decisions, evidence | TamperWard |
| Trusted verifier | Independent execution of tests/checks against pristine + candidate state | Separate trust domain, spawned by `wardd` on TamperWard's request |

---

## 2. Trust boundaries

WardOS defines five trust zones. Every data flow in the system crosses zero or one
boundary, and every boundary crossing is mediated by a narrow, typed interface owned by
`wardd`.

```text
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ ZONE 0  HOST                                                             │
 │  immutable OS image · kernel · systemd · wardd · Ward Shell · user home  │
 │  Secure Boot · TPM · LUKS · policy store · snapshot store · evidence log │
 │                                                                          │
 │   ┌───────────────────────────┐   ┌────────────────────────────────────┐ │
 │   │ ZONE 1  TAMPERWARD CONTROL│   │ ZONE 2  TRUSTED VERIFIER           │ │
 │   │  policy engine            │   │  own uid, own namespaces           │ │
 │   │  decisions                │   │  own writable FS, no internet      │ │
 │   │  evidence writer (via     │   │  pristine + candidate snapshot     │ │
 │   │  wardd evidence API)      │   │  trusted tests                     │ │
 │   └───────────────────────────┘   └────────────────────────────────────┘ │
 │                                                                          │
 │   ┌────────────────────────────────────────────────────────────────────┐ │
 │   │ ZONE 3  AGENT SANDBOX (assumed compromised)                        │ │
 │   │  agent process · project worktree (rw) · dev tools · nested rootless│ │
 │   │  containers · restricted egress via ward-proxy · no host secrets   │ │
 │   └────────────────────────────────────────────────────────────────────┘ │
 │                                                                          │
 │   ZONE 4  EXTERNAL   internet · package registries · model APIs · GitHub │
 └──────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Zone definitions

| Zone | Trust level | Contains | May be compromised in threat model? |
| --- | --- | --- | --- |
| 0 Host | Trusted (root of trust) | Kernel, systemd, `wardd`, Ward Shell, user's real home, policy store, snapshot store (CAS), evidence log, credential vault | No (kernel/firmware compromise is out of scope; see threat model) |
| 1 TamperWard control | Trusted | Semantic policy, decision engine, TamperWard's own state | No |
| 2 Trusted verifier | Trusted but *disposable*: fresh per verification | Verifier runtime image, pristine snapshot (ro), candidate snapshot (ro), trusted tests, scratch FS | Not by the agent; a hostile repo can attack it, so it is isolated from Zone 0 too |
| 3 Agent sandbox | **Untrusted** | Agent binary + its config, project worktree, toolchains, nested containers, in-sandbox caches | **Yes, fully.** The architecture must hold with Zone 3 attacker-controlled |
| 4 External | Untrusted | Everything past the egress proxy | Yes |

### 2.2 Boundary interfaces

Every crossing has exactly one owner. Nothing in Zone 3 talks to Zones 0/1/2 except
through these:

| Interface | Direction | Transport | Owner | Authority granted |
| --- | --- | --- | --- | --- |
| Project worktree mount | 0 → 3 | bind mount (rw), `nosuid,nodev` | `wardd` | Read/write files of the one project |
| Tool image mounts | 0 → 3 | composefs / overlay lower layers (ro) | `wardd` | Execute approved toolchain |
| `ward-agent` control socket | 3 → 0 | Unix socket, SCM_CREDENTIALS, length-prefixed typed messages | `wardd` | Request capability (net/credential/verify), emit semantic events, query own session |
| Egress proxy | 3 → 4 | HTTP CONNECT + SNI allowlist, per-session netns veth | `ward-proxy` (in `wardd`) | Only allowlisted destinations; credential injection for approved hosts |
| Credential delivery | 0 → 3 | (a) proxy header injection, never in sandbox; (b) short-lived token via control socket | `ward-broker` | Scoped, expiring, session-bound |
| Event capture | 3 → 0 (observed, not requested) | eBPF (exec), fanotify (files), proxy log (net), seccomp-notify (selected syscalls) | `wardd` | None: read-only observation |
| Verification request | 3 → 0 → 2 | Control socket → `wardd` → verifier spawn | `ward-verifier` broker | Ask that a *snapshot ID* be verified. Cannot choose tests, cannot choose verifier image, cannot see verifier FS |
| Verification result | 2 → 0 → 1 → 3 | Evidence log → TamperWard → event bus | `wardd` | Agent sees pass/fail summary only |
| Approval prompt | 0 → user | Ward Shell / TUI | Ward Shell | Human decision |

### 2.3 What never crosses into Zone 3

```text
host /                      ~/.ssh          ~/.aws           ~/.config/* secrets
/var/run/docker.sock        /run/user/*/    TPM devices      LUKS keys
wardd state                 policy store    snapshot store   evidence log
verifier FS or sockets      TamperWard sockets/state         other projects' worktrees
Wayland socket              D-Bus session bus                PipeWire (unless granted)
```

---

## 3. Component model

```text
                                   USER
                                     │
              ┌──────────────────────┼───────────────────────┐
              ▼                      ▼                       ▼
        ┌───────────┐         ┌────────────┐          ┌────────────┐
        │  ward CLI │         │ Ward Shell │          │ ward watch │
        │  (Rust)   │         │ bar/launch │          │ (TUI obs.) │
        └─────┬─────┘         │ /observer  │          └─────┬──────┘
              │               └─────┬──────┘                │
              │  wardd control API  │  event subscription   │
              └──────────┬──────────┴───────────────────────┘
                         ▼
   ┌────────────────────────────────────────────────────────────────────┐
   │ wardd  (system service, Rust, runs as `ward` system user + CAP_*)  │
   │                                                                    │
   │  session manager   sandbox builder    network manager (netns,      │
   │  capability store  snapshot engine    nftables, ward-proxy)        │
   │  credential broker verifier broker    event bus + evidence log     │
   │  policy loader     TamperWard adapter approval router              │
   └───┬────────────────────┬──────────────────────┬────────────────────┘
       │ spawns             │ spawns               │ IPC
       ▼                    ▼                      ▼
 ┌────────────┐      ┌──────────────┐      ┌─────────────────┐
 │ Agent      │      │ Trusted      │      │ TamperWard      │
 │ sandbox    │      │ verifier     │      │ control plane   │
 │ (Zone 3)   │      │ (Zone 2)     │      │ (Zone 1)        │
 │            │      │              │      │                 │
 │ ward-agent │      │ ward-verify  │      │ policy engine   │
 │ shim (PID1)│      │ runner (PID1)│      │ decision API    │
 │ agent      │      │ tests        │      │ evidence writer │
 │ tools      │      │              │      │                 │
 └────────────┘      └──────────────┘      └─────────────────┘
```

### 3.1 `wardd` — the Ward Supervisor

A single privileged system service. It is the *only* component that:

* creates namespaces, cgroups, mounts and network devices for sessions;
* reads project policy (`.ward/`) and turns it into a **capability manifest**;
* takes and stores snapshots;
* holds the credential vault handle and mints scoped credentials;
* spawns verifiers;
* writes the evidence log;
* talks to TamperWard.

`wardd` runs as a dedicated `ward` system user with a minimal ambient capability set
(`CAP_SYS_ADMIN` for namespaces/mounts, `CAP_NET_ADMIN` for netns/nftables, `CAP_BPF` +
`CAP_PERFMON` for exec tracing, `CAP_SETUID/SETGID` for uid mapping, `CAP_KILL` for
lifecycle). It is systemd-hardened (`ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`
for children, `SystemCallFilter`). `wardd` itself is in Zone 0; if `wardd` is compromised
the system is compromised, so it must stay small and have no parsing of agent-controlled
data outside of typed, length-bounded message decoders.

Sub-modules are internal to the crate structure (`ward-daemon` depends on `ward-policy`,
`ward-snapshot`, `ward-credentials`, `ward-verifier`, `ward-events`); they are not
separate processes in Phase 1 (see ADR-0009 for the process-split decision).

### 3.2 `ward` CLI

Thin, fast Rust client for the `wardd` control socket. Target: `ward status` renders in
< 10 ms warm. All security decisions live in `wardd`; the CLI only formats and forwards.

### 3.3 `ward-agent` — the in-sandbox shim

PID 1 inside the agent sandbox. Responsibilities:

* reap children, forward signals, hold the session alive;
* apply the **inner** hardening the OCI runtime cannot (Landlock ruleset, final seccomp
  filter, `PR_SET_NO_NEW_PRIVS`, drop remaining capabilities) before `exec`ing the agent;
* expose the control socket to the agent and its tools as `$WARD_SOCKET`;
* provide helper binaries: `ward-git-credential` (git credential helper), `ward-request`
  (capability request), agent hook adapters (e.g. Claude Code `PreToolUse`/`PostToolUse`
  hooks that emit semantic events and honour step-through approvals).

`ward-agent` runs *inside* Zone 3 and is therefore **untrusted after start**. Nothing in
Zone 0 relies on it for enforcement. It exists for correctness and UX, not security. All
enforcement that matters is applied from outside (namespaces, mounts, nftables, proxy,
cgroups) or is applied in a way that cannot be undone from inside (Landlock and seccomp are
irreversible once set for the process tree).

### 3.4 Trusted verifier

A fresh, disposable environment per verification (ADR-0004). Not a long-lived service.

* Separate uid range (distinct subuid allocation from the agent's).
* Own mount/PID/net/IPC/UTS/user namespaces. **No** shared writable path with the agent.
* Inputs: verifier runtime image (ro, from host CAS), pristine snapshot (ro), candidate
  snapshot (ro), trusted test set (ro, provided by TamperWard from Zone 1, not from the
  candidate), verification manifest.
* Output: a single signed result record appended to the evidence log by `wardd`, never
  written by the verifier directly to anything the agent can read.
* Network: **none** by default. Optional allowlist only when the verification manifest
  requests it and policy permits.

### 3.5 TamperWard control plane

Runs in Zone 1 as a separate system service with its own uid. Communicates with `wardd`
over a Unix socket that only `tamperward` and `ward` uids can open. See
[`tamperward-integration.md`](tamperward-integration.md) for the contract. WardOS does not
implement semantic policy; it forwards observations and executes decisions.

### 3.6 Ward Shell

Rust desktop components on Hyprland (ADR-0007, [`design-language.md`](design-language.md)):
top bar, launcher/command centre, agent activity panel, approval surface, verification
phase display, settings. Consumes events from `wardd` over the same subscription API as
`ward watch`; has no privileged filesystem access.

### 3.7 Event bus and evidence log

One append-only, hash-chained log per session, owned by `ward` uid, stored under
`/var/lib/ward/sessions/<id>/events.log`. Live subscribers receive the same records over
a Unix socket. Details in [`event-model.md`](event-model.md).

---

## 4. Session lifecycle

`ward claude` in a project directory:

```text
 step  actor            action                                            budget
 ────  ───────────────  ────────────────────────────────────────────────  ───────
  1    ward CLI         resolve project root (.ward/ or git toplevel)     <2 ms
  2    wardd            load .ward/policy + user policy + system policy   <5 ms
                        → capability manifest (deny-by-default merge)
  3    wardd            TamperWard: session-open (policy hash, manifest)  <20 ms
  4    wardd            ENTRY SNAPSHOT of worktree → CAS → snapshot ID    see §5
  5    wardd            build sandbox: userns/mountns/pidns/netns/ipc,     <60 ms warm
                        cgroup scope, ro tool layers, rw worktree bind,
                        tmpfs /tmp, seccomp, ward-agent as PID1
  6    wardd            netns: veth → ward-bridge, nftables egress rules, <20 ms
                        per-session proxy listener, DNS stub
  7    wardd            credential broker: pre-authorise policy-allowed
                        scopes (no secrets materialised yet)              <1 ms
  8    wardd            event log open, chain genesis record, subscribers
                        notified (SessionStarted)                         <1 ms
  9    ward-agent       inner hardening (Landlock, final seccomp), exec
                        agent with hooks configured                       <30 ms
 10    agent            runs. Events flow. Requests mediated.
 11    agent/user       `ward verify` or TamperWard trigger → CANDIDATE
                        SNAPSHOT → verifier spawn → result → evidence
 12    user             `ward stop` → freeze cgroup, final snapshot
                        (optional), teardown, SessionEnded, log sealed
```

Warm-start budget for steps 1–9: **< 150 ms** ([`performance.md`](performance.md)).
"Warm" means tool images already present in the CAS and the project environment already
built. Cold start (first `ward up` for a project) is dominated by image fetch and is
budgeted separately.

### 4.1 Persistent project environments

To make step 5 fast and keep `node_modules`/`target`/venvs warm, each project has a
persistent **project environment**: a `wardd`-owned directory tree holding the writable
upper layer for toolchains and caches, keyed by project ID. Agent sessions mount it. It
is agent-writable and therefore untrusted; the verifier never mounts it. `ward up` builds
it; `ward stop` leaves it in place; `ward clean` discards it. **[experiment E-06]** measures
whether a suspended-sandbox (cgroup freezer) model beats rebuild-on-start.

---

## 5. Snapshots: frozen state as a first-class object

Detailed in [`snapshots-and-git.md`](snapshots-and-git.md). Summary:

* A **Ward Snapshot** is a content-addressed, immutable capture of a project worktree
  (tracked, untracked, staged, unstaged, symlinks, submodule worktrees; ignored files per
  policy) taken by `wardd` from Zone 0 while the agent cgroup is **frozen**.
* Snapshot ID = BLAKE3 Merkle root over a canonical manifest. Independent of `.git`.
* Stored in a `ward`-owned CAS at `/var/lib/ward/cas/`. Agent has no path to it.
* Roles: `entry` (session start), `candidate` (verification request), `accepted`
  (post-verification, if TamperWard accepts), `final` (session end).
* Materialisation for the verifier is a fresh checkout from the CAS, never a bind mount of
  the agent's worktree.

---

## 6. Sandbox construction (ADR-0002, ADR-0003)

The agent sandbox is a rootless OCI container executed by `crun`, with a `wardd`-generated
runtime spec, plus WardOS-specific inner hardening.

| Primitive | Use |
| --- | --- |
| User namespace | Agent runs as uid 1000 inside, mapped to a per-project subuid range on the host. Host root and user home are not mapped. |
| Mount namespace | Root is a composefs/overlay of ro tool layers + rw project-environment upper. Worktree bind-mounted rw at `/work`. `/tmp` tmpfs. Everything else absent. |
| PID namespace | Agent cannot see or signal host, verifier, or TamperWard processes. |
| Network namespace | Only a veth to `ward-bridge`; nftables forces all egress through `ward-proxy`. Localhost inside the netns is the agent's own. Project services run in the same netns. |
| IPC/UTS/cgroup namespaces | Isolation of SysV IPC, hostname (`ward-<session>`), and cgroup view. |
| cgroups v2 | Per-session scope under `ward.slice`: CPU weight, memory cap, pids cap, freezer for snapshots, `cgroup.kill` for teardown. |
| seccomp | Two layers: OCI runtime profile (deny `mount` family, `ptrace` of foreign, `bpf`, `keyctl`, `add_key`, `kexec`, `reboot`, module syscalls, `userfaultfd`, io_uring by default) then a tighter `ward-agent` final filter with user-notification on `connect` for observation **[experiment E-05]**. |
| Landlock | Applied by `ward-agent` before exec: rw only under `/work`, `/env`, `/tmp`, `$HOME` (sandbox home); ro elsewhere; no access to control socket dir except the socket. Belt-and-braces over the mount namespace. |
| Capabilities | Bounding set empty except when a project explicitly needs `CAP_NET_BIND_SERVICE` (never granted by default). `NoNewPrivs` set. |
| Devices | None except `/dev/null,zero,random,urandom,tty,pts`. `/dev/fuse` only if nested containers enabled. No GPU by default. |

Nested project containers (Docker Compose workflows) run as **rootless Podman inside the
sandbox** with nested user namespaces and native overlayfs-in-userns (ADR-0005)
**[experiment E-04]**. The host Docker/Podman socket is never mounted.

---

## 7. Network model (ADR-0006)

```text
 agent netns                        host (Zone 0)                      external
 ┌───────────────┐    veth    ┌──────────────────────────┐
 │ agent         │───────────▶│ ward-bridge              │
 │ 10.99.<s>.2   │            │  nftables: DROP all      │
 │ localhost ok  │            │  except → ward-proxy:3128│
 │ services ok   │            │  DNS → ward-dns (stub)   │
 └───────────────┘            │  ward-proxy              │
                              │   allowlist by SNI/host  │───────▶ github.com
                              │   deny RFC1918/link-local│         registry.npmjs.org
                              │   credential injection   │         api.anthropic.com
                              │   event: NetworkRequested│
                              └──────────────────────────┘
```

Modes: `offline`, `localhost-only`, `package-registries`, `development` (registries +
VCS hosts + the agent's own model API), `custom`, `unrestricted` (requires explicit
per-session user approval and is shown in the bar as `NET OPEN`).

The proxy is the *only* egress path; nftables enforces that, not the proxy. Private
network destinations are denied both at nftables and at the proxy. All decisions are
events.

The verifier netns has **no** veth by default.

---

## 8. Credential broker (ADR-0008)

See [`credential-broker.md`](credential-broker.md). Two delivery modes, preferred first:

1. **Proxy injection**: the agent never holds a token. `ward-proxy` adds `Authorization`
   for approved (host, scope, session) tuples. Works for HTTPS Git, GitHub REST, package
   registries.
2. **Minted short-lived token**: when a tool needs a literal token (e.g. `gh` CLI), the
   broker mints one (GitHub App installation token scoped to the repo, or a
   vault-provided lease) with expiry ≤ 10 min, delivered over the control socket, bound
   to the session, revoked at `ward stop`.

Long-lived secrets stay in a `ward`-owned vault (systemd-creds / TPM-sealed file in
Phase 2; pluggable later). SSH private keys are never delivered; SSH is served through an
`ssh-agent`-protocol proxy that signs only for approved hosts and logs each signature, or
projects use HTTPS.

---

## 9. Verifier flow (ADR-0004)

```text
 agent: "please verify"           wardd                       TamperWard          verifier
 ─────────────────────────        ───────────────────────     ──────────────      ──────────
 VerifyRequest{}      ─────────▶  freeze agent cgroup
                                  CANDIDATE snapshot → cid
                                  thaw
                                  VerificationRequested(cid) ─▶ decide manifest:
                                                                pristine=eid,
                                                                candidate=cid,
                                                                tests=trusted set,
                                                                image=verifier:v
                                  ◀──────────────────────────── VerifyManifest
                                  spawn verifier(manifest)  ───────────────────▶ materialise
                                                                                 eid, cid from CAS
                                                                                 run
                                  ◀────────────────────────────────────────────  result (signed)
                                  evidence append
                                  VerificationPassed/Failed ─▶ TamperWard decision
 ◀── summary event                (to observer, agent)
```

The agent supplies nothing but the request. It cannot influence which tests run, which
image runs them, or what state is compared. The verifier cannot reach the agent, the
network, or Zone 0 state beyond its ro inputs.

---

## 10. Observer and replay

The observer (TUI first, then Ward Shell panel) is a pure consumer of the event stream. It
has three modes: **Quiet**, **Live**, **Step-through**. Step-through works by the
capability manifest marking certain actions as `ask`, causing `wardd` to hold the request
until an approval event arrives from the shell. Replay reads the sealed log for a past
session. See [`event-model.md`](event-model.md).

---

## 11. Desktop

Hyprland on Wayland (ADR-0007). Ward Shell is Rust. The desktop is organised around three
visual layers, **Host / Workspace / Agent**, and the top bar communicates trust state, not
system trivia. The full identity is specified in [`design-language.md`](design-language.md).

Default bindings (final set decided in Phase 6, with the presentation deliberately not
copied from any existing distribution):

```text
Super + Enter     terminal
Super + Space     Ward command centre
Super + B         browser
Super + C         coding workspace
Super + A         agent workspace
Super + V         verify current project
Super + 1..9      workspace
```

---

## 12. Immutable host (ADR-0001)

Fedora-based **bootc** image. Boot chain target (Phase 7): Fedora shim (Microsoft-signed)
→ systemd-boot → UKI (kernel + initramfs + cmdline, signed) → composefs root with
fs-verity → LUKS2 data volume unlocked by TPM2 with PCR policy + recovery key. Updates are
signed OCI images; `bootc upgrade` stages, `ward system rollback` reverts. The
composefs/sealed-image backend of bootc is experimental as of mid-2026, so Phase 6 ships on
the stable ostree backend and Phase 7 evaluates sealed images **[experiment E-09]**.

Nothing developer-facing is installed on the host image beyond the desktop, `ward*`,
container tooling and a terminal. Toolchains live in project environments (OCI layers in
the CAS), never in the host image.

---

## 13. Portable runtime (non-distro path)

The same trust-zone split runs on macOS/Windows/Linux via containers:

```text
docker compose / podman compose
   ├── ward-supervisor   (Zone 0 equivalent: privileged only within its VM/host)
   ├── agent             (Zone 3: rootless, restricted egress via ward-proxy)
   ├── tamperward        (Zone 1)
   └── verifier          (Zone 2, spawned per verification, no network)
```

Guarantees are weaker on non-Linux hosts (the VM boundary replaces the host boundary; no
TPM, no Secure Boot claims). The document [`security-model.md`](security-model.md) states
exactly which guarantees hold in each deployment mode.

---

## 14. Enterprise extension points (reserved, not built)

Policy sources are already layered (system → user → project) so a **central policy**
source is a fourth layer. The evidence log has a stable schema so **central audit** is a
forwarder. Credential broker backends are a trait. Session identity records agent image
digests, so an **approved agent catalogue** is an allowlist on those digests. None of this
is implemented in 0.1.
