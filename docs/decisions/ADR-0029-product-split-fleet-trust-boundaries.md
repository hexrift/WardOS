# ADR-0029 — Product split and fleet trust boundaries

Status: **Accepted architecture; implementation tracked by #258–#280.**

## Decision

WardOS is one security architecture delivered through four explicit layers:

1. **WardOS distribution / reference host** — the Fedora bootc desktop and reference
   appliance. It packages the portable runtime and supplies a hardened, measured host,
   but it is not required in order to use Ward execution/security.
2. **Ward runtime / security primitives** — the portable libraries and local mechanisms
   that implement capability manifests, snapshots, evidence, sandboxing, egress,
   credentials, pause/stop/revoke and verification.
3. **`ward-node`** — a long-lived execution worker that owns one or more tasks on one
   machine. It schedules local work, creates execution boundaries, enforces authority,
   brokers local resources, produces evidence and remains authoritative for enforcement
   when the remote control plane is unavailable.
4. **Ward control plane** — an optional distributed coordination plane for identity and
   delegation, desired policy, worker registration, placement, approvals, audit/evidence
   indexing and fleet operations. It grants bounded authority to nodes; it is not on the
   synchronous path for each filesystem, process or network action.

Local mode is a **single-node deployment**. The CLI may connect to a local `ward-node`
without any remote control plane, identity provider, database or Kubernetes cluster.
Existing local workflows remain supported while their process ownership migrates behind
the node boundary.

The security rule is:

> The control plane may narrow, expire or revoke authority, but loss of the control
> plane must never silently widen authority already present on a node.

TamperWard remains an **independent verification and tamper-evidence layer**. WardOS must
not weaken, bypass or absorb TamperWard verification merely to make the distributed
runtime easier to operate.

## Target component and trust model

```text
 Developer / CI / API / Web
           |
           | authenticated intent, approvals, fleet queries
           v
 +-------------------------------+
 | Ward control plane            |
 | identity / delegation         |
 | policy distribution           |
 | scheduler / worker registry   |
 | approvals / audit index       |
 +---------------+---------------+
                 |
                 | versioned node protocol:
                 | task lease + capability manifest,
                 | lifecycle commands, events/evidence,
                 | health/capacity, revocation
                 v
 +---------------+---------------+
 | ward-node                     |  trusted execution authority for this host
 | local scheduler/admission     |
 | lifecycle + recovery          |
 | local policy enforcement      |
 | credential / egress broker    |
 | evidence + verifier broker    |
 +-----+-------------------+-----+
       |                   |
       | local typed IPC   | independent verification request/result
       v                   v
 +-------------+      +------------------+
 | task capsule|      | verifier /       |
 | agent + repo|      | TamperWard path  |
 | UNTRUSTED   |      | outside agent    |
 +-------------+      +------------------+
```

The reference WardOS distribution contains `ward-node`, the runtime and desktop, but
the node/runtime boundary must also work on supported non-WardOS Linux hosts. Portable
deployments inherit the security properties of their host and do not inherit WardOS
boot-chain or disk-encryption claims.

## Ownership and API boundaries

| Boundary | Authoritative owner | Contract | Must not do |
| --- | --- | --- | --- |
| Human/service principal -> control plane | Control plane | authenticated principal, RBAC, delegation request | infer authority from model/provider identity |
| Control plane -> node | Control plane issues; node validates/enforces | versioned signed task lease + capability manifest + expiry/version; lifecycle and revocation commands | grant unbounded ambient authority; require a round-trip per syscall/action |
| Node -> control plane | Node | worker capability/capacity, task state, event/evidence stream, health | treat upload success as a prerequisite for local enforcement |
| CLI/desktop -> local node | Node | same semantic lifecycle API used by remote orchestration, over local authenticated IPC | maintain a second weaker local security path |
| Node -> task capsule | Node | narrowly scoped task interface, project mounts, proxy/credential endpoints, lifecycle signals | expose node/admin socket, other task state, host credential material |
| Task -> external network | Node egress broker | policy-constrained destination + credential injection | expose host network namespace or raw long-lived credentials |
| Node -> verifier | Node broker; verifier independently isolated | immutable snapshot IDs, protected verify inputs, bounded result | let the task choose protected tests or writable verifier state |
| TamperWard -> Ward evidence | TamperWard produces independent decisions; node persists/forwards | authenticated evidence record bound to task/attempt/authority | let the agent forge TamperWard origin or make verification optional |
| Node -> artifact/cache storage | Node | content-addressed or immutable reads; scoped writes owned by one task/build identity | share mutable writable trust between unrelated tasks |

Every remotely created task must be representable by the same local contract. The node
must be able to reject an unsupported lease before starting a capsule.

## Authority and offline behaviour

A node accepts work only from an authenticated source it trusts and only while the
presented authority is valid for that node, task and execution attempt. Authority is
explicit data, not a property of a process being alive.

The minimum task authority envelope contains:

- issuer and subject identity;
- task ID and execution-attempt ID;
- node/audience binding where required;
- capability manifest and resource/isolation requirements;
- issued-at and expiry;
- monotonic version/nonce sufficient to reject stale replay;
- delegation lineage needed to prove authority contraction;
- verification/evidence requirements.

The exact wire representation is defined by #259 and the node protocol by #258.

A node **continues already-admitted work only within the last valid local authority it can
prove**. It never invents new grants during a partition. Expiry, locally known revocation,
resource limits, credential TTLs and fail-closed policy continue to apply without the
control plane.

## Failure modes

| Failure | Node behaviour | Control-plane behaviour | Security outcome |
| --- | --- | --- | --- |
| Control plane unreachable before admission | reject remote task creation; local mode may admit only locally authorized work | mark node unavailable | no remote authority guessed |
| Control plane lost during a running task | continue only within unexpired cached authority; keep local enforcement/evidence; queue bounded telemetry | reconcile when node returns | outage does not widen authority |
| Lease expires while partitioned | revoke/stop capabilities according to lease semantics; credentials expire; task cannot renew itself | later observes expiry outcome | fail closed at expiry |
| Revocation received | persist before acknowledging; stop/revoke locally; emit evidence | retry until durable acknowledgement | revocation is not best-effort UI state |
| Stale/replayed manifest | reject by task/audience/version/nonce/expiry checks | issue fresh authority if appropriate | no stale policy widening |
| Node restart | reconstruct only from durable node-owned state; capsules without valid recoverable authority are stopped/quarantined | reconcile task attempts | process lifetime is not authority |
| Control plane restarts | rebuild desired state from durable store; nodes keep enforcing local valid authority | reconcile workers/tasks | nodes are not forced open |
| Event/evidence upload blocked | keep bounded durable local spool and surface pressure; admission may stop before evidence would be lost | ingest after recovery | evidence loss is visible, not silent |
| Local disk/memory pressure | scheduler/admission rejects or queues new work; enforcement reserves verifier capacity | expose pressure/backpressure | availability degrades before isolation |
| Node identity cannot be authenticated | do not join fleet or accept remote work | quarantine/reject node | no unauthenticated worker placement |
| Verifier unavailable | task may run only if policy permits, but cannot claim verified completion; protected flows fail closed | surface verification unavailable | no synthetic green status |

## Migration map

This ADR deliberately keeps working primitives and changes their ownership over time.

| Current component/path | Target owner | Migration |
| --- | --- | --- |
| `ward` CLI local commands | CLI client | preserve command semantics; route lifecycle through local `ward-node` |
| per-session `wardd` single writer | `ward-node` task/session service | first extract lifecycle/protocol (#258), then retire in-process fallback once node ownership is authoritative |
| sandbox builder / pause / stop / proxy / hooks | `ward-node` | move modules behind node APIs; do not rewrite proven enforcement merely for process separation |
| capability manifest / policy merge | portable runtime + authority layer | retain contraction rules; bind manifests to task/delegation leases (#259) |
| snapshot/CAS and verifier broker | portable runtime, node-owned orchestration | keep immutable inputs and independent verifier boundary |
| credential vault / proxy injection | node credential broker | keep credentials outside task; later add JIT remote backends (#267) |
| local session event log | node evidence writer + durable spool | retain single-writer ordering per task; stream/index remotely later (#268/#271) |
| desktop session registry / approvals | local node client first, control-plane client when remote | one semantic model; local mode remains complete |
| WardOS bootc image | distribution/reference host | package the same runtime/node APIs used elsewhere |
| TamperWard integration | independent verifier/evidence path | preserve independent authority and provenance; extend across workers in #270 |

Compatibility policy:

- Existing `ward` commands are not removed merely because a control plane exists.
- Local mode does not require remote sign-in or fleet infrastructure.
- Protocol changes are versioned and either backwards-compatible for the supported
  window or rejected explicitly before authority is accepted.
- Deprecations require a migration path and a documented release boundary; there is no
  silent fallback from a stronger node-mediated path to a weaker in-process path.

## Non-goals

WardOS does not become its own Kubernetes, PKI, enterprise SSO, secret store, database
or hypervisor. It defines the security/execution contracts it needs and integrates with
established systems for those infrastructure functions.

This ADR does not choose the final distributed scheduler, database, PKI implementation,
identity provider, Kubernetes operator or Capsule backend. Those are child workstreams of
#256 and must obey these boundaries.

## Alternatives

### Make the current per-session daemon the distributed control plane

Rejected. It mixes host enforcement, per-task lifecycle, fleet coordination and durable
enterprise state into one trust domain and would put remote availability too close to
local enforcement.

### Require Kubernetes for every WardOS deployment

Rejected. Kubernetes is a useful deployment target and scheduling substrate for some
installations, but local developer mode must remain first-class and WardOS security must
not disappear when Kubernetes is absent.

### Put all policy decisions in the remote control plane

Rejected. Per-action remote authorization creates a network dependency in the security
critical path and makes partitions ambiguous. Nodes instead receive bounded, expiring
authority and enforce it locally.

### Build a machine/VM per agent

Rejected as the default scaling model. Tasks receive the lightest isolation boundary
that satisfies policy (ADR-0022), allowing many concurrent tasks per worker while keeping
stronger microVM/VM placement available where risk requires it.

## Advantages

- Preserves the working local security primitives and current CLI.
- Gives #258/#259 a stable ownership and authority contract.
- Scales to many tasks without one physical machine per agent.
- Makes partition behaviour and fail-closed semantics explicit.
- Allows WardOS distribution users and portable runtime users to share one security model.
- Keeps TamperWard independent from the agent and from convenience-oriented fleet logic.

## Disadvantages

- Introduces protocol/versioning and node-recovery complexity.
- Requires careful durable state at the node rather than treating processes as state.
- Local and remote modes must remain semantically compatible, increasing test surface.
- Some enterprise features depend on external infrastructure integrations rather than a
  single self-contained WardOS binary.

## Security consequences

The trusted computing base is separated by responsibility: the control plane is trusted
to issue bounded authority and coordinate the fleet; each node is trusted to enforce only
authority it can validate; agent capsules remain hostile; the verifier/TamperWard path
remains outside agent authority. A control-plane compromise is therefore serious, but
node-side lease validation, expiry, contraction and local hard policy remain meaningful
containment boundaries rather than being replaced by ambient remote trust.

Cross-task isolation, replay resistance, node authentication, partition behaviour and
evidence continuity become mandatory security-test categories for the fleet work.

## Performance consequences

Normal filesystem/process/network enforcement remains local, avoiding a control-plane RTT
per action. Fleet coordination adds admission, scheduling and evidence-stream overhead.
Node-level resource accounting and bounded verifier concurrency are therefore part of the
P0 scheduler work (#260), and existing single-agent latency remains a regression gate.

## Why selected

This is the smallest evolution that supports hundreds of concurrent agent tasks without
discarding WardOS's existing enforcement model. It separates coordination from
enforcement, keeps local mode useful, and makes authority and failure semantics testable
before distributed features are added.

## How it will be validated

The child issues under #256 supply the validation:

- #258: one node owns multiple sessions through a versioned protocol and survives client
  restarts without orphaning enforcement.
- #259: task/delegation identity, contraction, expiry, revocation and replay rejection.
- #260: at least 25 concurrent local task sandboxes with measured resource enforcement,
  admission and backpressure.
- #261–#274: multi-node control plane, node enrolment, policy, identity, credentials,
  persistence, intervention, TamperWard, observability, Kubernetes and 100+ task
  security/chaos/load qualification.
- #277/#278: documentation and backwards-compatible migration remain consistent with the
  implemented system.

No child implementation may bypass these boundaries merely to pass CI or simplify a demo.
