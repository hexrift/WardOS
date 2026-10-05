# Ward Event Model

Status: living document; the project's phase is in docs/status.toml and the README.
Decision records: [ADR-0011](decisions/ADR-0011-event-capture.md),
[ADR-0012](decisions/ADR-0012-observer.md).

## 1. Purpose

One typed event stream serves four consumers with different trust needs:

| Consumer | Needs | Reads |
| --- | --- | --- |
| Observer (TUI / Ward Shell) | Low latency, human-readable | Live subscription |
| TamperWard | Reliable enforcement facts, ordering | Live subscription + evidence anchors |
| Replay (`ward replay`) | Complete, ordered, immutable | Sealed log |
| Evidence export | Tamper-evident, verifiable offline | Sealed log + chain head signature |

## 2. Envelope

```rust
// ward-events (concept; wire format is a versioned, length-prefixed binary encoding
// with a bounded schema — candidate: postcard or CBOR with strict size limits)
pub struct EventRecord {
    pub session: SessionId,
    pub seq: u64,                 // dense, per session, assigned by wardd
    pub ts_mono: Duration,        // monotonic since session genesis, taken when the fact was captured
    pub ts_wall: Option<SystemTime>, // informational
    pub origin: Origin,           // Kernel | Proxy | Wardd | Verifier | TamperWard | Agent | User | Node
    pub prev: Blake3Hash,         // hash of previous record (genesis: hash of manifest)
    pub event: WardEvent,
    pub hash: Blake3Hash,         // BLAKE3(prev || seq || origin || event bytes)
}
```

`origin` is the single most important field. Only `Kernel`, `Proxy`, `Wardd`, `Verifier`,
`TamperWard`, `User` and `Node` records are **enforcement facts**. `Node` (hash tag 8) is
`ward-node`, the single writer of each execution attempt's evidence log (§3, ADR-0030 §3);
it never appears in a session log. An attempt log may also carry `NetworkRequested`,
`NetworkDenied` and `ObservationsDropped` records with origin `Node`, when the node ran
the attempt behind its own egress proxy (node-integration.md §9): the node records the
proxy's verdicts itself, as the attempt's single writer. `Agent` records (from hooks and
`ward-request`) are *claims*: useful for step-through UX and semantics, never used by
`wardd` or the verifier to decide anything, and rendered with a distinct marker in the
observer.

## 3. Event catalogue

```rust
pub enum WardEvent {
    // lifecycle
    SessionStarted { project: ProjectId, agent: AgentIdentity, manifest_hash: Blake3Hash,
                     entry_snapshot: SnapshotId, policy_hash: Blake3Hash, tool_images: Vec<ImageDigest> },
    SessionEnded   { reason: EndReason, final_snapshot: Option<SnapshotId> },
    AgentStateChanged { state: AgentState },          // Idle | Working | Waiting | Blocked | Verifying | Finished

    // filesystem (origin: Kernel via fanotify on /work; Agent via hooks)
    FileRead      { path: SandboxPath, by: ProcessRef },
    FileModified  { path: SandboxPath, by: ProcessRef, kind: Create | Write | Delete | Rename | Chmod | Symlink },

    // processes (origin: Kernel via eBPF sched_process_exec / exit)
    CommandStarted  { pid: Pid, parent: Pid, argv: BoundedArgv, cwd: SandboxPath, exe_digest: Option<Blake3Hash> },
    CommandFinished { pid: Pid, exit: ExitStatus, duration: Duration },

    // network (origin: Proxy; Kernel for nftables drops)
    NetworkRequested { host: HostName, port: u16, decision: Allow | Deny, rule: RuleRef, by: ProcessRef },
    NetworkDenied    { dst: DeniedDst, reason: DenyReason },         // includes private-range and non-proxy attempts

    // capabilities and credentials (origin: Wardd / User)
    CapabilityRequested { cap: CapabilityRequest, reason: Option<BoundedText> },
    CapabilityDecided   { cap: CapabilityRequest, decision: Decision, by: DecisionSource, grant: Option<GrantScope> },
    CredentialRequested { service: ServiceId, scope: Scope },
    CredentialGranted   { service: ServiceId, scope: Scope, expires: Duration, delivery: ProxyInjected | MintedToken },
    CredentialDenied    { service: ServiceId, scope: Scope, reason: DenyReason },
    CredentialRevoked   { service: ServiceId, reason: RevokeReason },

    // snapshots (origin: Wardd)
    SnapshotCreated { role: SnapshotRole, id: SnapshotId, entries: u64, bytes: u64, capture: CaptureMode, stall: Duration },

    // TamperWard (origin: TamperWard)
    PolicyDecision  { subject: PolicySubject, decision: Decision, rule: RuleRef, detail: BoundedText },
    PolicyDenied    { subject: PolicySubject, rule: RuleRef, detail: BoundedText },   // convenience projection
    TamperDetected  { subject: PolicySubject, detail: BoundedText },

    // verification (origin: Wardd / Verifier)
    VerificationRequested { candidate: SnapshotId, requested_by: Agent | User | TamperWard },
    VerificationStarted   { candidate: SnapshotId, pristine: SnapshotId, verifier_image: ImageDigest, manifest_hash: Blake3Hash },
    VerificationProgress  { step: BoundedText, status: Running | Pass | Fail },
    VerificationPassed    { candidate: SnapshotId, summary: VerifySummary, result_hash: Blake3Hash },
    VerificationFailed    { candidate: SnapshotId, summary: VerifySummary, result_hash: Blake3Hash },
    // Appended, not grouped above: postcard identifies WardEvent variants by
    // declaration index, so a new one is always added at the end (#139).
    VerificationErrored   { candidate: SnapshotId, reason: BoundedText },   // infra failure, not a test failure
    StateAccepted         { snapshot: SnapshotId, by: TamperWard },

    // verification attempts, continued (origin: Wardd / Verifier; #139) — also
    // appended at the end, after StateAccepted, for the same reason.
    VerificationAttemptStarted { attempt: AttemptId, requested_by: Agent | User | TamperWard },
    VerificationCancelled      { attempt: AttemptId, candidate: Option<SnapshotId> },
    VerificationInterrupted    { attempt: AttemptId, candidate: Option<SnapshotId>, reason: BoundedText },
    VerificationTimedOut       { attempt: AttemptId, candidate: SnapshotId, summary: VerifySummary, result_hash: Blake3Hash, budget_secs: u64 },   // killed at the budget, not a test failure

    // agent claims (origin: Agent) — never enforcement facts
    AgentClaim { kind: ToolUse | Note | Plan, payload: BoundedText },

    // integrity
    Anchor { chain_head: Blake3Hash, seq: u64, countersigned_by: Option<TamperWardSig> },

    // host intervention (origin: Wardd; ADR-0019 §3)
    SessionPaused   { method: CgroupFreezer | Sigstop, reason: BoundedText },
    SessionResumed  { paused_for: Duration },
    EntryRestored   { snapshot: SnapshotId, files: u64, backup: BoundedText },

    // observer health (origin: Wardd) — see §9
    ObservationsDropped { source: Filesystem | Network | Hook, dropped: u64, capacity: u64 },

    // Appended at the end of the catalogue, same reason as VerificationErrored above
    // (#145 items 3-4, PR #207): the daemon decides whether a pause's freeze settled
    // *before* appending anything, so a pause attempt is recorded as exactly one of
    // SessionPaused xor SessionPauseUnsettled, never both and never the confirmed one
    // first — this is the terminal record for an unsettled SIGSTOP-fallback pause,
    // carrying the same fields SessionPaused would have (so it never depends on a
    // prior SessionPaused record to make sense of it), plus how many processes were
    // still not confirmed stopped when the daemon's settle bound expired.
    SessionPauseUnsettled { method: CgroupFreezer | Sigstop, reason: BoundedText, pending: u32 },

    // credentials, continued (origin: Wardd; PR #318 review round 3) — appended at the
    // end, not folded into CredentialGranted's own fields (see the wire compatibility
    // rule below): attributes the CredentialGranted record immediately before it in
    // the ordered stream to the open launch that grant belongs to. Always appended by
    // wardd itself, as a second record in the same append call that just wrote the
    // grant it attributes; absent when the daemon has no tracked launch to attribute
    // that grant to.
    CredentialGrantedLaunch { launch_seq: u64 },

    // Appended after CredentialGrantedLaunch (#145 item 5): `ward stop` terminated the
    // session's sandboxed workloads before sealing — `ended` confirmed gone, `pending`
    // killed but not confirmed gone within `pause::STOP_SETTLE`, and
    // `barrier_confirmed` records whether the pre-kill membership/fork barrier was
    // proved stable. A completed stop requires `pending == 0 && barrier_confirmed`;
    // then AgentStateChanged { Finished } and SessionEnded follow. Either `pending > 0`
    // or `barrier_confirmed == false` means the stop was refused: the log is not
    // sealed, no Finished is recorded, and the session is held for the stop (not paused:
    // `ward resume` refuses it) until a later `ward stop` re-scans and confirms it.
    // The barrier-false/pending-zero shape is intentionally durable: replay after a
    // daemon restart must still show STOP? rather than losing the reason the stop is held.
    WorkloadsTerminated { ended: u32, pending: u32, barrier_confirmed: bool },

    // node execution attempts (origin: Node; ADR-0030 §3, #332) — appended after
    // WorkloadsTerminated. Written only by ward-node, one log per admitted attempt at
    // <task-root>/<task>/<attempt>.evidence/events.log, never into a session log; see
    // node-integration.md §6.5. Metadata only: workload output is never recorded.
    NodeAttemptAdmitted { task: TaskId, attempt: ExecutionAttemptId, lease: LeaseId,
                          session: SessionId, operation: u64, envelope: Blake3Hash,
                          issuer_key: Blake3Hash, version: u64 },
    NodeAttemptLaunched { operation: u64, host_pid: u32 },
    NodeAttemptIntervened { action: NodeIntervention, operation: u64 },  // Pause | Resume
    NodeAttemptEnded { state: NodeAttemptState, outcome: NodeAttemptOutcome,
                       end: NodeAttemptEnd, operation: Option<u64> },
    NodeAttemptRecovered { state: NodeAttemptState, outcome: Option<NodeAttemptOutcome> },
    NodeAttemptSealed { operation: u64 },  // the log is sealed after this record
}
```

Type notes:

* `BoundedText`, `BoundedArgv`, `SandboxPath`, `HostName` are length-capped, sanitised
  at ingest (control characters removed, bidi isolates applied, invalid UTF-8 replaced
  with a marker). The raw bytes of an over-long argv are hashed and the hash kept so
  replay can prove truncation.
* `SandboxPath` is always relative to `/work` or `/env`; host paths never appear in
  events.
* Secrets never appear: `CredentialGranted` carries scope and expiry, not the token.

### 3.1 Wire compatibility

The hash in every `EventRecord` (§2) covers the event's own encoded bytes
(`BLAKE3(prev || seq || origin || event bytes)`), and `WardEvent` is encoded with
postcard, which identifies an enum variant by its declaration index and encodes that
variant's own fields **positionally** — there is no field name or tag on the wire, only
field order. Two rules follow directly from that, and both are load-bearing for every
already-persisted session log, not just newly written ones:

1. **Never reorder or remove a variant, and never add, remove or reorder a field on a
   variant that has already shipped.** Doing either changes what postcard produces for
   every record of that kind — including one a session log already persisted under an
   earlier build. `EventRecord::verify_hash` recomputes the hash from the record's
   *current* decoded event, so a record whose bytes silently changed underneath it
   fails verification and reads as tampered, even though nothing about the record
   itself was ever touched. This is not merely a style preference: PR #318 briefly
   added a field to the existing `CredentialGranted` variant (round 2 of that PR's
   review) specifically to carry a launch identity, and that change alone was enough to
   make a `wardd` built from it fail to verify session logs its own earlier builds had
   already written and sealed. Round 3 reverted it in favor of the new-trailing-variant
   pattern below, exactly the pattern `VerificationErrored`, `LaunchAborted`,
   `ObservationsDropped`, `SessionPauseUnsettled` and the verification-attempt kinds
   above already establish, and which PR #253's own `WorkloadsTerminated` addition
   followed without incident.
2. **A new capability is always a brand new variant, appended at the end of the
   catalogue.** Appending never touches how any existing variant encodes, so it can
   never invalidate a record any earlier build already wrote. `CredentialGrantedLaunch`
   above is this rule applied to the exact case round 2 got wrong: rather than widening
   `CredentialGranted` itself, the launch identity travels as its own trailing variant,
   emitted as a second record immediately after the grant it attributes.

A change of this kind needs no `WIRE_VERSION` bump (`ward-events::wire::WIRE_VERSION`):
that constant guards the frame header, not the event catalogue, and the crate's own
append-only convention is what keeps the catalogue itself backwards compatible without
one. A change that cannot be made this way — reordering, removing, or changing an
existing variant's own fields — is not a case this crate's wire format supports at all,
and needs a version bump and an explicit migration, not a silent field change.

## 4. Capture sources (ADR-0011)

| Source | Mechanism | Overhead target | Notes |
| --- | --- | --- | --- |
| Exec/exit | eBPF on `sched_process_exec` / `sched_process_exit`, filtered by session cgroup id | < 2% on `npm test`-style workloads | argv read from tracepoint args, bounded |
| File modify | `fanotify` (`FAN_CLOSE_WRITE`, `FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_*`, `FAN_ATTRIB`) on the `/work` mount from Zone 0 | negligible | Reads via `FAN_OPEN` optional in Live; `FAN_ACCESS` never (too hot) |
| Network | Proxy decision log; nftables `log` group via nflog for drops | negligible | Every CONNECT is one event |
| Syscall-level | seccomp user-notification on a *small* set (`connect` to non-proxy, `ptrace`) — deny + event | measured in E-05 | Fallback: plain seccomp kill + audit |
| Semantic | Agent hooks (Claude Code `PreToolUse`/`PostToolUse`/`PermissionRequest`, Codex equivalents) via `ward-request` | none | origin=Agent |
| Verifier | Runner stdout protocol over a pipe to `wardd` | — | Verifier never writes the log |

## 5. Storage and integrity

* Path: `/var/lib/ward/sessions/<session>/events.log`, owner `ward:ward`, mode 0600, opened
  `O_APPEND`, fsynced on lifecycle/verification/credential events and every 250 ms
  otherwise.
* Hash chain as in §2. `Anchor` records are emitted every N events and on every
  verification; TamperWard may countersign anchors so that even a later `wardd` compromise
  cannot silently rewrite history *before* the anchor.
* At `SessionEnded` the log is sealed: chain head written to
  `sessions/<session>/HEAD`, the file made read-only, and (Phase 7) the head signed with a
  TPM-resident key.
* Rotation: none within a session. Size cap per session (default 512 MiB) after which
  file-level events are sampled and a `Anchor{…, degraded: true}`-style marker is written.

## 6. Subscription API

`wardd` exposes `/run/ward/events.sock`. A subscriber sends
`Subscribe { session, from_seq, filter }` and receives records in order. Backpressure:
slow subscribers are dropped and must resubscribe from a sequence number; the log is the
source of truth, not the socket. Latency budget from kernel event to subscriber delivery:
**< 25 ms p99**, target 8 ms median.

## 7. Observer modes

| Mode | Shows | Blocks? |
| --- | --- | --- |
| Quiet | `AgentStateChanged`, `PolicyDenied`, `Capability*` needing approval, `Verification{Passed,Failed,Errored,Cancelled,Interrupted}`, the host's interventions (`SessionPaused`, `SessionPauseUnsettled`, `WorkloadsTerminated`, `SessionResumed`, `EntryRestored`), `ObservationsDropped`, `SessionEnded` | Only on `Ask` |
| Live | Everything except `AgentClaim{Note}` | Only on `Ask` |
| Step-through | Everything; additionally the manifest's `step_policy` marks actions (`FileModified` under given globs, `CommandStarted` matching patterns, any `NetworkRequested`) as `Ask` | Yes, on configured actions |

Step-through is implemented in `wardd`, not in the UI: the sandbox request (or the
agent hook, for actions the kernel cannot hold) blocks until a `CapabilityDecided` record
exists. For file writes there is no kernel-level "hold" without a FUSE layer; the
agent's hook layer (origin=Agent, best-effort) is what holds today: under
`step_through`, the hook adapter answers the agent's `PreToolUse` hook with `ask`
before writes and network tools, and the exchange is recorded as an `AgentClaim`
(`agent-integration.md` §4). **[experiment E-11]** evaluates a FUSE or `fanotify`
permission-event (`FAN_OPEN_PERM`) layer for hard holds.

Implemented (ADR-0016, `agent-integration.md` §4.1): with a `wardd` serving the
session the `ask` is held by the daemon and recorded with the two capability records
the catalogue already has, so no new kind was needed and `ward replay` shows the
question and the answer as it shows every other decision:

| Record | Origin | Fields |
| --- | --- | --- |
| `CapabilityRequested` | `Wardd` | `cap.kind` from the tool (`FileWrite` for `Write`/`Edit`/`MultiEdit`/`NotebookEdit`, `Network` for `WebFetch`/`WebSearch`, `Exec` for `Bash`, `FileRead` for `Read`/`Grep`/`Glob`, else `Other`); `cap.target` = `<tool> <summary>`; `reason` = the hook's reason (`step-through: pause before writes`) |
| `CapabilityDecided` | `Wardd` | the same `cap`; `decision` `Allow`/`Deny`; `by` `User` for an answer (grant `Once` for `allow`, `Session` for `allow-session` and for a request a standing `allow-session` covered), `Timeout` (deny, no grant), or `SessionEnded` (deny, no grant — #146) |

The approval's id is the `seq` of its `CapabilityRequested` record: a subscriber
that sees the record can answer it (`Request::Approve { id, decision }`) without a
second lookup, and `Request::Pending` lists what is still open. A question the
session's end releases is denied to the agent, and (#146) is given its own
`CapabilityDecided` record — `by: SessionEnded` — *before* `SessionEnded` and the seal
itself, so it is never silently dropped from the persistent record the way it was
before #146. `Request::Approvals` (`ward session approvals`) lists every approval the
session has asked, pending or decided, not only what is still open — the daemon's own
bounded in-memory history, so a request survives a client missing or dismissing
whatever first announced it, for the rest of the session (the event log itself, via
`ward replay`, is the durable, unbounded record). Without a daemon the agent's own
permission prompt remains the hold, and only the `AgentClaim` is written.

## 8. Replay

`ward replay <session>` reads the sealed log, verifies the chain, and renders:

```text
sess_01J…   payments-api   Claude Code   2026-09-07 22:14 → 22:18   VERIFIED ✓

00:00 ──────────────────────────────────────────────────────── 04:18
        read   edit    denied    edit   run     verify
──────────●──────●───────■────────●──────●───────●────────────

 files changed   6        commands   14      network   3 allowed / 1 denied
 credentials     1 (github, contents:read, 10m)          policy denials  1
 entry   blake3:9f1c…   candidate  blake3:77ab…   accepted  blake3:77ab…
```

with `--json` for tooling, `--verify` to check the chain and anchors offline, and
`--stats` for the approval-load statistics of experiment E-13
([`experiments.md`](experiments.md)): every `CapabilityRequested` paired to its terminal
outcome by identity, a still-pending request reported as censored rather than decided,
and a figure the log cannot support reported as unmeasured; `--stats --json` is one
versioned object.

## 9. Live ingestion and bounded buffering

The observers that watch a running command — the inotify watch over the worktree, the
session proxy's decision recorder, the agent hook broker — each run on their own
thread. None of them writes the log. Each hands what it sees to a **bounded queue**,
and the one thread that owns the session's `Sink` drains those queues *while the
command is still running* and appends what it takes through the same append path as
every other record. There is still exactly one writer (§5, ADR-0015).

| Property | What it means |
| --- | --- |
| Drain cadence | Every 250 ms, or as soon as 256 observations are queued, whichever comes first. Batching amortises the append; the interval bounds how long an observation can sit unrecorded |
| Terminal flush | When the command ends, each producer is **quiesced before its own last drain** — stopped from accepting new work, then waited on (bounded, 2 s) until what it already had in flight has reached its queue — and only then drained, so a decision or claim completed across the cutover is flushed rather than discarded with the producer. The tails are appended **exactly once**, before the `CommandFinished` record. Nothing this command observed can be appended twice, and a producer still busy when the bound runs out is counted and marked like any other gap. Giving up is one atomic step: the proxy and the hook broker close their cutovers with the same queue primitive, which seals the queue and counts whatever is still in flight under the one lock a producer has to take to hand an observation over — so each in-flight producer ends up on exactly one side of the cutover, in the final batch or in the marker, never both. *In flight* is the window in which an observation may still be produced and has not been handed over yet, never the producer's whole lifetime: the proxy announces each connection it accepts before it serves it and retires it at its verdict, so a tunnel that is still relaying is not a decision outstanding (it was recorded when the connection was allowed) while a connection that has not decided yet is. Nothing can join that set once the cutover has begun, because announcing a connection and stopping the proxy are mutually exclusive: once the call that stops the proxy has returned, an acceptor still parked on the listening socket can no longer announce anything, so it cannot serve anything either. That holds however the acceptor is scheduled and whether or not it was woken out of its blocking accept — which is why the count the seal takes is complete, and why the one terminal drain that follows carries every gap |
| Timestamps | A record carries the time its source *observed* the fact, never the time it reached the log, so a live-drained timeline reads exactly as the batched one did |
| Ordering | Each queue is FIFO and the drain visits its sources in a fixed order (files, network, agent claims), so no drain reorders observations relative to an earlier one |
| Backpressure | A queue that is full **refuses** the new observation rather than evicting one already accepted. The refusal is counted *under the same lock that saw the queue full*, so the queued observations and the refusals are one atomic drain epoch and a refusal cannot be split across two markers, attached to a batch it did not accompany, or lost to a drain that reset the count between the refusal and its being recorded. The next drain appends `ObservationsDropped { source, dropped, capacity }` immediately after the batch it accompanies, so an incomplete window is bounded by its neighbours in the log and is never silent. Every bounded source has its own `source` — filesystem, network **and the hook broker** — so no gap is reported as something an observer mode may hide |
| Enforcement | Independent of all of the above. A proxy thread's `Observer::decision` call does one lock, one length comparison and returns; it never waits on the log, on disk or on a UI consumer, so allow/deny decisions are made and answered in real time however far behind ingestion has fallen (`security-model.md` G14) |
| Failure paths | The producers are owned by one RAII value. A launch that fails before or during the child — the sandbox could not be prepared, the process could not be spawned — still stops every thread, removes the run directory and its sockets, and appends what the producers had already recorded |

`ObservationsDropped` is `origin=Wardd` (an enforcement fact, not an agent claim: it is
the daemon's own statement that its record of a window is incomplete), is fsynced as a
critical kind, and is visible in **every** observer mode including Quiet, for the same
reason `TamperDetected` is.

Not yet built on this: an observer-health panel in the desktop shell (delivery lag,
last successful drain, cumulative overflow) — issues #138/#141 — and a repeatable p50/p99
ingestion-latency benchmark against `performance.md`, which is issue #150's subject.

Implemented (Phase 1): the observer rows and a one-line footer (`session · records ·
entry · files changed · commands · network allowed / denied`); `--json` emits one
object per record (`seq`, `ts_mono_ms`, `origin`, `kind`, `summary`; credential
records summarise to service, subject and permissions, never a secret); `--verify`
prints a verdict (`chain VERIFIED · N records · head …` and whether the sealed `HEAD`
matches) and exits 1 on a broken chain, truncated tail, missing or mismatched `HEAD`,
or an empty log. Every mode exits 1 when the chain is broken, so a tampered log never
replays silently. The timeline strip and anchors are still to come.
