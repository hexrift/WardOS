# Ward Event Model

Status: Phase 0. Decision records: [ADR-0011](decisions/ADR-0011-event-capture.md),
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
    pub ts_mono: Duration,        // monotonic since session genesis
    pub ts_wall: Option<SystemTime>, // informational
    pub origin: Origin,           // Kernel | Proxy | Wardd | Verifier | TamperWard | Agent | User
    pub prev: Blake3Hash,         // hash of previous record (genesis: hash of manifest)
    pub event: WardEvent,
    pub hash: Blake3Hash,         // BLAKE3(prev || seq || origin || event bytes)
}
```

`origin` is the single most important field. Only `Kernel`, `Proxy`, `Wardd`, `Verifier`,
`TamperWard` and `User` records are **enforcement facts**. `Agent` records (from hooks and
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
    StateAccepted         { snapshot: SnapshotId, by: TamperWard },

    // agent claims (origin: Agent) — never enforcement facts
    AgentClaim { kind: ToolUse | Note | Plan, payload: BoundedText },

    // integrity
    Anchor { chain_head: Blake3Hash, seq: u64, countersigned_by: Option<TamperWardSig> },
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
| Quiet | `AgentStateChanged`, `PolicyDenied`, `Capability*` needing approval, `Verification{Passed,Failed}`, `SessionEnded` | Only on `Ask` |
| Live | Everything except `AgentClaim{Note}` | Only on `Ask` |
| Step-through | Everything; additionally the manifest's `step_policy` marks actions (`FileModified` under given globs, `CommandStarted` matching patterns, any `NetworkRequested`) as `Ask` | Yes, on configured actions |

Step-through is implemented in `wardd`, not in the UI: the sandbox request (or the
agent hook, for actions the kernel cannot hold) blocks until a `CapabilityDecided` record
exists. For file writes there is no kernel-level "hold" without a FUSE layer; Phase 5
implements step-through for writes via the agent's hook layer (origin=Agent, best-effort)
and documents this honestly. **[experiment E-11]** evaluates a FUSE or `fanotify`
permission-event (`FAN_OPEN_PERM`) layer for hard holds.

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

with `--json` for tooling and `--verify` to check the chain and anchors offline.
