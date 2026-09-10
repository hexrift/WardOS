# ADR-0022 — Capsules: isolation as a first-class OS primitive, proportional to risk

## Decision
WardOS exposes one user-facing abstraction for isolated execution — the **Capsule** — and
makes it a first-class operating-system primitive rather than a feature of any one tool. A
Capsule is a disposable execution environment created for a task; the user does not normally
need to know which mechanism backs it. WardOS chooses the **lightest isolation boundary
appropriate to the risk**:

```
user intent → WardOS policy → select boundary → agent executes → TamperWard verifies
            → approved result promoted to the workspace → Capsule destroyed
```

The boundary ladder, cheapest first:

| Risk / task | Boundary |
|---|---|
| Read / search a repository | native sandbox (bubblewrap, ADR-0013) |
| Normal coding task | container / strong namespace isolation (ADR-0002) |
| Install packages from an unfamiliar project | Capsule with stronger isolation |
| Run unknown repository code | microVM (KVM/QEMU) |
| Browser automation against untrusted content | isolated Capsule, network-scoped |
| Kernel / OS experimentation | full VM |

**A stable `Ward Capsule API` sits above a policy engine, which selects a backend** — so the
UX and the ward-shell never couple to one virtualization technology:

```
Ward Capsule API → policy engine → { sandbox | container | microVM/KVM | full VM }
```

On x86_64 Linux, **KVM/QEMU is the virtualization foundation** for the microVM and VM rungs;
the lighter rungs reuse the sandbox of ADR-0002/0013. The verifier (ADR-0004) is itself a
Capsule.

**Promotion, not copy-back.** Capsule state is never silently copied onto the host. WardOS
promotes only controlled outputs — intended source changes, explicitly approved files,
verified outputs — through a review:

```
Dependency upgrade complete · 37 packages changed · 182 tests passed · no policy violations
[Review]   [Apply to workspace]   [Discard]
```

Destroying a Capsule removes its transient execution state.

**UX (ADR-0021, no separate visual language).** Isolation is not a VM-manager dashboard. The
normal experience shows at most `Isolated` / `Capsule active · network restricted`; the Proof
Rail exposes isolation state contextually, and a Capsule detail is available on demand
(filesystem, network, devices, privilege, lifetime). It uses the Ward Field relationships:
violet `intent → Capsule → affected files`, green `Capsule result → TamperWard proof →
promoted result`.

**Performance.** Isolation is adaptive: fast common operations stay fast; not everything goes
in a VM. Warm/cached Capsules aim to become usable in ~1–2 s where technically realistic, and
Capsule creation/destruction must not block the desktop. Capsules feel like ordinary OS
operations, not infrastructure administration.

**Trust model.** Favour constraint, isolation, evidence and reversibility over warning
dialogs, permission fatigue and blanket blocking. Capsules and TamperWard are complementary:
the Capsule limits what execution can affect; TamperWard (ADR-0011, ADR-0019) verifies what
actually happened.

Product principle: **every agent receives the minimum safe computer it needs** — and WardOS
makes that native, fast and nearly invisible.

## Context
WardOS already has the pieces — a bubblewrap sandbox (ADR-0013), a rootless-container plan
(ADR-0002), nested Podman (ADR-0005), a disposable verifier (ADR-0004), per-session network
policy (ADR-0006) — but they are separate mechanisms without one user-facing name or one
policy that picks among them. Agentic work needs isolation to be a routine, legible primitive:
a user asking an agent to "try this upgrade" should get a right-sized disposable computer
without learning virtualization, and should get their machine back untouched unless they
promote a reviewed result. Naming the abstraction (Capsule) and fixing the API boundary now
lets the backend evolve (namespaces today, microVMs later) without churning the UX.

## Consequences
* A `Ward Capsule API` is specified (create/describe/exec/promote/destroy, with a policy-chosen
  boundary and a declared filesystem/network/device/privilege/lifetime profile). `wardd` owns
  it; `ward` and the shell are clients (consistent with ADR-0015).
* Command Weave gains isolation intents: *isolate this project*, *run this safely*, *let the
  agent try this upgrade in isolation*, *open a disposable environment*, *test this branch
  without touching my machine*.
* The Proof Rail and a Decision-Receipt-style promotion surface (Apply / Discard / Review)
  render Capsule lifetime and results in the Ward Field language (ADR-0021); no VM dashboard
  ships by default.
* Existing ADRs are unified under the Capsule abstraction: ADR-0002/0013 (sandbox), ADR-0004
  (verifier is a Capsule), ADR-0005 (nested containers as a Capsule backend), ADR-0006
  (per-Capsule network policy). This ADR supersedes none; it names and sequences them.
* microVM/KVM support is new engineering (a KVM/QEMU backend behind the policy engine); it is
  gated behind the lighter rungs shipping first and behind the relevant experiments.

## Alternatives considered
* **One boundary for everything (always a container, or always a VM).** A single container is
  too weak for unknown code; a VM for everything is too slow for read/search and normal
  edits and breaks the "fast common operations stay fast" requirement. Proportional isolation
  is the point.
* **Expose the VM manager (libvirt/virt-manager style).** Turns isolation into infrastructure
  administration and contradicts the calm, minimal ADR-0021 UX. Rejected as a default; a
  power-user inspection view is enough.
* **Auto-sync Capsule state back to the host.** Convenient but unsafe — it lets a disposable,
  possibly-compromised environment write the trusted workspace. Controlled promotion of
  reviewed outputs is the trust boundary.
* **Leave the mechanisms un-unified.** Keeps today's code but never gives users the primitive
  or WardOS the stable API; every UX and policy decision would re-litigate which mechanism to
  use.

## How it will be validated
* A user can, from Command Weave, run a task in a Capsule and get their host left untouched
  unless they promote a reviewed result; destroying the Capsule leaves no execution state.
* The policy engine selects the ladder rung matching the task's risk, and the choice is
  inspectable (filesystem/network/devices/privilege/lifetime) without a VM dashboard.
* A warm Capsule for a common task becomes usable in ~1–2 s on x86_64 KVM hardware, and
  Capsule create/destroy does not stall the desktop.
* TamperWard verifies a Capsule's result independently of the agent's claim, and promotion
  carries that evidence (ties to ADR-0019).
