# ADR-0030 — ward-node task admission, execution ownership and exit semantics

Status: **Accepted; implemented under #332 slices 5–10 (tracked by #324, with #259
and #262).** Steps 1–11 below are done; what the implementation does not enforce yet is
[node-security-limitations.md](../node-security-limitations.md).

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
envelope. Across a node restart the node recovers every task from a durable per-task
record written before each transition is answered, with a launch intent written before
each spawn: an attempt that may have been executing (launching, `Running`, `Paused`, or a
stop or revoke awaiting its reap) becomes `Exited` with an `Unknown` receipt and any
survivor of its recorded process is killed; it is never resumed or re-run. A `Ready` task
becomes `Created` again and must be re-admitted under a higher version; ended tasks keep
their state, receipt and applied operation ids (#332 slice 7).

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
- The control-plane side fails closed too (step 9): the shipped client and adapter never
  guess at a lost answer (they inspect and replay the same operation id once, then report
  `unknown` for the caller to treat as failed), never re-admit under another envelope or
  start a second attempt on their own, and withdraw authority with `revoke`, not `stop`,
  when the caller's lease or deadline is gone. Their issuer key is read only from a
  private seed file; a pre-signed envelope is transported byte for byte.
- The node's trusted computing base grows by a signature verifier and a durable
  revocation and version store, and does not grow by the daemon's network stack.
- What is not enforced at this revision is stated, not implied: no remote transport or
  mTLS, no network grants, no result return, no callback channel, a receipt the protocol
  does not bind to the evidence head, a manually bootstrapped trust store, same-uid
  co-location of client and node, and no resource limit beyond the wall-clock budget.
  Each gap, its impact for a control plane, the mitigation available today and the
  issue that closes it is a row of
  [node-security-limitations.md](../node-security-limitations.md) §3.

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
6. Durable task records and recovery across a node restart (#332 slice 7): every
   transition recorded before it is answered, a launch intent before every spawn, and on
   restart ambiguous attempts recovered `Exited`/`Unknown` with survivors killed and
   never re-run, `Ready` tasks `Created` again, and ended tasks, receipts and replays
   preserved.
7. Per-attempt evidence logs (§3): the node, as the single writer, keeps one hash-chained
   `ward-events` log per admitted attempt beside its workspace under the task root, with a
   record of admission, launch, every pause and resume, the end with its receipt outcome,
   recovery after a restart and seal. Each record is durable before its verb is answered,
   a restarted node reconciles the log before it serves, and sealing the task seals the
   log.
8. The capability manifest is read (#332): its bytes are one typed, bounded manifest
   (`network`: `offline`, or a `custom` host allowlist in `ward-policy`'s spelling), a
   manifest outside the grammar fails envelope decoding, and `admit` refuses
   `unsupported_grant`, after authority is proven and before the version is committed,
   any grant the node cannot enforce. Every workload runs offline, so only `offline` is
   honoured until the proxy-backed allowlist lands; the node never runs a workload under
   less than its manifest says.

9. A transport-backed client for the external control plane (#332 slice 8): the
   `ward-node-client` crate speaks the local socket framing with its bounds and
   timeouts, negotiates 1.3 or later and refuses less, signs envelopes exactly as §7.4 of
   the contract prescribes (reproducing its test vector), bounds the institution-owned
   inputs before signing, and drives an attempt to its sealed end with caller-supplied,
   replayable operation ids, revoking on cancellation or an overrun budget and reporting
   `unknown` rather than retrying when the transport fails. Its `ward-node-adapter`
   binary exposes the same over stdin/stdout JSON lines for control planes in other
   languages, accepts pre-signed envelopes so key custody stays with the control plane,
   and turns `SIGTERM` into revoke-and-seal. Both are tested against a real node:
   completion with a verifying evidence log, a replay that runs nothing twice, and a
   revocation that leaves no process behind.

10. Cross-system acceptance (#332 slice 9): a real node, driven over its real socket by
    `ward-node-client` and by the `ward-node-adapter` process, proves the completion gate
    of #332 as named, repeatable cases with their pass criteria stated in code and in
    [node-acceptance.md](../node-acceptance.md): bounded execution (a budget kill and a
    completion, each within a stated bound, with the cause in the evidence log),
    isolation (an in-sandbox probe whose exit status is the verdict: no route off the
    host, no read of a host secret, the node's state or its own evidence log, no write
    into a bound host directory, nothing written to `/tmp` or `$HOME` on the host, the
    contract's environment and nothing of the node's), interruption (`revoke` leaves no
    process and a sealed log, `pause`/`resume` leave the workload alive, a node `SIGKILL`
    recovers `Exited`/`Unknown` and never re-runs), authorization failure (an untrusted
    key, an expired lease, a wrong audience, a network manifest, a stale version and a
    revoked lease, each with the contract's reason and nothing materialised), replay
    safety (the same operation ids from the same process and from a new adapter process
    run nothing twice; a retired attempt is never re-created) and recovery (a sealed
    attempt's receipt and evidence survive a restart and verify). The suite runs under
    the merge gate with isolation required and through `scripts/acceptance/node.sh`,
    which prints one verdict per case.

11. Integration documentation, security limitations and release-readiness evidence
    (#332 slice 10): an operator and control-plane walk from an empty host to a
    verified attempt ([node-integration-guide.md](../node-integration-guide.md)), the
    security statement of what the node enforces and what it does not, each gap with
    its impact, mitigation and closing issue
    ([node-security-limitations.md](../node-security-limitations.md)), and the
    statement of what CI proves on every change, what a release publishes and what is
    not proven ([node-release-readiness.md](../node-release-readiness.md)).

Steps 1–9 are written down as the external contract in
[node-integration.md](../node-integration.md); step 10 is its acceptance,
[node-acceptance.md](../node-acceptance.md); step 11 is the guide, the limitations and
the release-readiness evidence beside them.
