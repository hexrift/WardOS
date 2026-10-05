# ADR-0030 — ward-node task admission, execution ownership and exit semantics

Status: **Accepted; implementation tracked by #324 (with #259 and #262), under #332
slices 5–7.**

This records the decisions #326 asked for before `ward-node` may execute anything. It
follows ADR-0029: the node is the trusted execution authority on its host, and an
external control plane — or, in local mode, a local issuer — only ever hands it bounded,
expiring, provable authority.

## Decision

### 1. Workload and authority arrive in one versioned admission envelope

Protocol 1.2 `create` and `inspect` stay identity-only (task, attempt, lease ids). A new
protocol minor, **1.3**, adds an `admit` verb carrying one `TaskAdmissionEnvelope`:

- the exact `TaskBinding` (task, execution attempt, lease), the `AgentId`, the target
  `NodeId` (audience) and the `SessionId` — the identity `TaskAdmissionIdentity` (#345)
  already binds;
- the `AuthorityLease` and the lineage needed to prove contraction (#302, #307);
- the workload: a bounded argv, the capability manifest the sandbox is built from, the
  content id of the project snapshot to materialise (ADR-0010), and a **mandatory**
  wall-clock budget;
- issued-at, expiry and a per-task monotonic version.

The envelope never names a host path. The node materialises the snapshot into a
workspace it allocates itself, `<task-root>/<task>/<attempt>/`, under a task root fixed
by node configuration; nothing outside that directory is bound writable. `admit` moves a
task `Created → Ready`; a 1.2 connection never sees the verb.

### 2. Admission requires a trusted issuer proof

An envelope is admitted only with a detached Ed25519 signature over the exact envelope
bytes carried on the wire (the UTF-8 bytes of the `admit` request's `envelope_json`
string value), made by an issuer key in the node's configured trust store. Signing the
transmitted bytes rather than a re-encoding means an issuer in any language signs what it
sends, with no canonicalisation step. The node verifies the signature over those bytes
before it decodes them, then checks, before anything is materialised or spawned:

1. the signature against a trusted issuer key;
2. the audience is this node's `NodeId`;
3. binding, agent and lease agree exactly (`TrustedTaskAdmission`, #335/#345);
4. the envelope and the lease are unexpired at the node's clock;
5. the version is strictly greater than the last one durably accepted for the task;
6. no locally known revocation covers the lease or its lineage, read from a durable
   revocation store.

A bare `LeaseId`, an unsigned lease, or merely holding a socket connection never proves
authority. In local mode the `ward` CLI signs as a **local issuer** whose key is created
when the node is installed and is readable only by the node's operator account; it is
held to exactly the same checks. Key format, rotation and the remote trust bootstrap are
#262. Every failure is a typed refusal (`AuthorityDenied`, `LeaseExpired`,
`LeaseRevoked`, `StaleOperation`) with nothing materialised.

### 3. The node owns spawn, reaping, budget and evidence for what it admits

- The node spawns through the owned launch handle (`Launch::spawn`, #339/#343) and a
  node-owned reaper waits on it promptly; `Running` is reported only after a confirmed
  spawn with the recorded host pid.
- The admitted budget is always enforced; there is no unbounded node task.
- The node is the single evidence writer for each attempt it admits (one hash-chained log
  per attempt under its task root). ADR-0015 is unchanged for local sessions: per-session
  `wardd` remains their single writer until ownership migrates (ADR-0029 migration map).
- `ward-node` does not depend on `ward-daemon`. The launch, freeze and kill primitives the
  node needs move into a shared crate first; `ward-daemon` re-exports them unchanged.

### 4. `start` and `stop` ship together

`start` stays unsupported until node-owned stop and reaping exist. They are enabled in the
same change and advertised together by capability discovery; a node never offers a way to
begin execution without its own way to end it.

### 5. Natural exit is its own state with a real receipt

Protocol 1.3 adds an `Exited` state, distinct from `Stopped` (an operator stop). The
reaper records the attempt's `TaskExecutionReceipt` (#333):

- `Completed` — exit status 0 within budget;
- `Failed` — non-zero exit, or killed at the budget;
- `Unknown` — the node cannot establish what happened, for example it lost the child
  across a crash.

`seal` is accepted from `Exited`, `Stopped` and `Revoked`.

### 6. Ambiguity fails closed and is never retried

An attempt whose launch outcome is ambiguous (an error after a possible exec, or a node
restart while `Running`) is recorded `Unknown`. Any surviving process in its workspace is
killed, and the attempt is never re-run. Retrying needs a new execution attempt and a new
envelope. Recovering or resuming across a node restart is #332 slice 7.

## Alternatives

- **Workload as a 1.3 field on `start`, separate from authority.** Rejected. It splits
  what is run from the authority to run it, so a valid lease could be paired with a
  workload it was never issued for.
- **A node-local spec referenced by id.** Rejected. It moves the trust question to
  whoever wrote the spec, and it still needs an authenticated binding to the lease.
- **Client-supplied host paths.** Rejected. Anything that can reach the socket could
  choose writable host paths.
- **Unsigned envelopes over the local socket in local mode.** Rejected. Local and remote
  admission would then differ semantically, and same-host processes could forge
  authority.
- **`ward-node` depending on `ward-daemon`.** Rejected. It pulls the proxy, TLS stack and
  session machinery into the node's trusted computing base.

## Advantages

- One object binds what runs to who may run it, where, and until when.
- Local and remote admission share one code path and one set of checks.
- Every reported state is backed by an observed fact: a spawn, a reap or a receipt.

## Disadvantages

- Local mode needs a key on the host, and signing is added to the CLI path.
- Protocol 1.3 adds a verb and a state that clients must negotiate.
- Extracting the launch crate comes before any visible feature.

## Security consequences

- The node never executes on authority it cannot verify locally.
- Workspaces cannot escape the node-configured task root.
- Stale, replayed, revoked and foreign-audience envelopes are refused before any effect.
- A compromised client can at most hold a stolen, still-valid, audience-bound envelope
  until it expires or is revoked.
- The node's trusted computing base grows by a signature verifier and a durable
  revocation and version store, and does not grow by the daemon's network stack.

## Performance consequences

Admission adds one signature verification and two durable reads per task. These are
negligible next to sandbox start (`docs/performance.md`, about 50–100 ms) and are paid
once per attempt, not once per action.

## Why selected

It is the owner's #326 proposal (2026-10-02), made concrete enough to implement in small
TDD slices without guessing at semantics inside a feature PR.

## How it will be validated

#324 lands in this order, one PR per slice, each RED then GREEN:

1. Protocol 1.3 types: the envelope, `admit`, the `Exited` state, fixtures and version
   negotiation.
2. Issuer verification and the durable version and revocation stores. `admit` moves
   `Created → Ready`, and every refusal case is tested.
3. Extract the launch, freeze and kill primitives into the shared crate, with no
   behaviour change.
4. `start`, `stop` and the reaper together. Then `Exited` with its receipt, and budget
   enforcement.
5. `pause`/`resume`, `revoke` and `seal`; the full invalid-transition matrix; disconnect
   during a transition.

Steps 1–5 are written down as the external contract in
[node-integration.md](../node-integration.md).

Cross-system acceptance — isolation, interruption, no duplicate effect — is #332 slice 9.
