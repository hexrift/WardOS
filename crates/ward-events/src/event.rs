//! The typed event catalogue (`event-model.md` §3) and its supporting types.
//!
//! Wire stability: events are encoded with postcard, which identifies enum variants by
//! their declaration index. **Never reorder or remove variants**; append new ones at the
//! end and bump [`crate::wire::WIRE_VERSION`] when a change is not backwards compatible.

use core::fmt;
use core::net::IpAddr;
use core::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::ids::{
    AttemptId, Blake3Hash, ImageDigest, Pid, ProjectId, RuleRef, ServiceId, SnapshotId,
};
use crate::text::{BoundedArgv, BoundedText, HostName, SandboxPath};

/// Short free text (reasons, targets, subjects).
pub type ShortText = BoundedText<256>;
/// Longer free text (policy detail).
pub type DetailText = BoundedText<1024>;
/// Agent claim payloads.
pub type PayloadText = BoundedText<4096>;
/// Names and versions.
pub type NameText = BoundedText<64>;

// ---------------------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------------------

/// Which agent product is running in the sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentKind {
    /// Claude Code.
    ClaudeCode,
    /// `OpenAI` Codex CLI.
    Codex,
    /// Any other agent; see `name`.
    Other,
}

/// Identity of the agent running in a session.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Product family.
    pub kind: AgentKind,
    /// Product name as reported.
    pub name: NameText,
    /// Product version as reported.
    pub version: NameText,
    /// Digest of the agent tool image, when the agent runs from an image.
    pub image: Option<ImageDigest>,
}

/// Why a session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndReason {
    /// `ward stop` or equivalent user action.
    UserStop,
    /// The agent process exited on its own.
    AgentExited {
        /// Exit code.
        code: i32,
    },
    /// Policy or `TamperWard` killed the session.
    PolicyKill,
    /// The session exceeded its time budget.
    Timeout,
    /// `wardd` shut down.
    DaemonShutdown,
    /// An internal error tore the session down.
    Error,
}

/// Coarse agent state as shown in the Quiet observer mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentState {
    /// Waiting for input.
    Idle,
    /// Actively working.
    Working,
    /// Waiting on an external response (model API, user).
    Waiting,
    /// Blocked on a capability decision.
    Blocked,
    /// A verification is running.
    Verifying,
    /// The agent has finished.
    Finished,
    /// The host paused the session (ADR-0019 §3): every sandbox process is
    /// frozen; the agent is neither working nor waiting.
    Paused,
    /// The host attempted to pause the session but could not confirm, within
    /// the settle bound, that every sandbox process actually stopped (#145
    /// items 3-4, PR #207 review finding 1): the marker is written and
    /// approvals are held exactly as for [`Self::Paused`], but at least one
    /// process's `SIGSTOP` was not yet confirmed delivered. Deliberately
    /// distinct from [`Self::Paused`] so a viewer never shows an unconfirmed
    /// freeze as a clean, confirmed one — the false-confirmation issue #145
    /// itself is about. Appended at the end: like [`WardEvent`], this enum is
    /// wire-encoded (`AgentStateChanged`) and postcard identifies variants by
    /// declaration index, so an existing variant's position must never move.
    PauseUnsettled,
}

// ---------------------------------------------------------------------------------------
// Filesystem / processes
// ---------------------------------------------------------------------------------------

/// Reference to the process that performed an action.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessRef {
    /// Pid inside the session pid namespace.
    pub pid: Pid,
    /// Kernel `comm` of the process, when known.
    pub comm: Option<BoundedText<32>>,
}

/// Kind of filesystem modification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileChangeKind {
    /// A file or directory was created.
    Create,
    /// A file was written (`FAN_CLOSE_WRITE`).
    Write,
    /// A file or directory was deleted.
    Delete,
    /// A file or directory was renamed or moved.
    Rename,
    /// Permissions or attributes changed.
    Chmod,
    /// A symbolic link was created.
    Symlink,
}

/// How a process terminated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExitStatus {
    /// Normal exit.
    Exited {
        /// Exit code.
        code: i32,
    },
    /// Terminated by a signal.
    Signaled {
        /// Signal number.
        signal: i32,
        /// Whether a core dump was produced.
        core_dumped: bool,
    },
}

// ---------------------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------------------

/// Outcome of a policy evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Decision {
    /// Permitted.
    Allow,
    /// Held for user approval (step-through / `ask` policy).
    Ask,
    /// Refused.
    Deny,
}

/// The destination of a denied network attempt.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeniedDst {
    /// A named host.
    Host {
        /// Destination host.
        host: HostName,
        /// Destination port.
        port: u16,
    },
    /// A literal IP address (including private-range and non-proxy attempts).
    Ip {
        /// Destination address.
        addr: IpAddr,
        /// Destination port.
        port: u16,
    },
    /// A destination that could not be parsed as either.
    Raw {
        /// Sanitised rendering of the target.
        target: ShortText,
    },
}

/// Why something was denied.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DenyReason {
    /// Destination is in a private, link-local, or loopback range.
    PrivateRange,
    /// Destination is not on the allowlist.
    NotAllowlisted,
    /// Egress attempted other than through `ward-proxy` (nftables drop).
    NonProxyEgress,
    /// The session is in `offline` network mode.
    Offline,
    /// An explicit policy rule denied it.
    PolicyDeny {
        /// The denying rule.
        rule: RuleRef,
    },
    /// The user denied an `ask`.
    UserDenied,
    /// An `ask` timed out with no UI attached (timeout → deny).
    Timeout,
    /// The grant or credential had expired.
    Expired,
    /// The grant or credential had been revoked.
    Revoked,
    /// Rate limit exceeded.
    RateLimited,
    /// No specific reason is known. Unknown → deny, logged.
    Unknown,
}

/// Kind of capability being requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityKind {
    /// Network egress to a host.
    Network,
    /// Reading a path.
    FileRead,
    /// Writing a path.
    FileWrite,
    /// Executing a command.
    Exec,
    /// Using a credential.
    Credential,
    /// Access to a device.
    Device,
    /// Running nested containers.
    NestedContainer,
    /// Anything else; see `target`.
    Other,
}

/// A capability request as seen by `wardd`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// What kind of capability.
    pub kind: CapabilityKind,
    /// Sanitised description of the target (host, path glob, command pattern, ...).
    pub target: ShortText,
}

/// Who or what made a capability decision.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecisionSource {
    /// A policy rule decided without asking.
    Policy {
        /// The deciding rule.
        rule: RuleRef,
    },
    /// The user answered an `ask`.
    User,
    /// `TamperWard` decided.
    TamperWard,
    /// No answer arrived in time; the request was denied.
    Timeout,
    /// The session ended with the question still open; nothing ever answered
    /// it (#146). Appended at the end: postcard identifies enum variants by
    /// declaration index, so an existing one must never move.
    SessionEnded,
}

/// How long a granted capability remains valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GrantScope {
    /// This one request only.
    Once,
    /// Until the session ends.
    Session,
    /// For a fixed duration from the decision.
    Until {
        /// Validity period.
        expires_in: Duration,
    },
}

// ---------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------

/// The scope of a credential request or grant (`credential-broker.md` §3).
///
/// Carries the subject and permission set only — never the secret.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Scope {
    /// Subject, e.g. `repo:hexrift/tamperward`.
    pub subject: ShortText,
    /// Permissions, e.g. `contents:read`.
    pub permissions: Vec<NameText>,
}

/// How a credential reaches the agent's traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialDelivery {
    /// `ward-proxy` injects the header; the agent never holds a token.
    ProxyInjected,
    /// A short-lived token was minted and delivered over the control socket.
    MintedToken,
}

/// Why a credential grant was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevokeReason {
    /// The session ended.
    SessionEnded,
    /// Policy changed underneath the grant.
    PolicyChanged,
    /// `ward revoke` or equivalent.
    UserRevoked,
    /// The grant expired.
    Expired,
    /// `TamperWard` detected tampering.
    TamperDetected,
}

// ---------------------------------------------------------------------------------------
// Snapshots / TamperWard / verification
// ---------------------------------------------------------------------------------------

/// Role of a snapshot in the session lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnapshotRole {
    /// Taken at session start.
    Entry,
    /// Taken on a verification request.
    Candidate,
    /// The candidate `TamperWard` accepted.
    Accepted,
    /// Taken at session end.
    Final,
}

/// How the host froze a session's processes (`SessionPaused`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PauseMethod {
    /// `cgroup.freeze = 1` on a delegated cgroup v2 freezer holding the sandbox.
    CgroupFreezer,
    /// `SIGSTOP` to every process of the sandbox's tree, children first.
    Sigstop,
}

impl PauseMethod {
    /// The word the observer and the log text use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CgroupFreezer => "cgroup-freezer",
            Self::Sigstop => "sigstop",
        }
    }
}

/// How a snapshot was captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaptureMode {
    /// Atomic btrfs snapshot.
    BtrfsSnapshot,
    /// Copy taken while the session cgroup was frozen.
    FrozenCopy,
}

/// The protected surface a `TamperWard` decision concerns.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicySubject {
    /// The session as a whole.
    Session,
    /// The capability manifest.
    Manifest,
    /// Policy files.
    Policy,
    /// Protected tests.
    ProtectedTests,
    /// Verification configuration or scripts.
    VerifyConfig,
    /// CI configuration.
    Ci,
    /// Hook / control-plane wiring.
    Hooks,
    /// Golden fixtures or expected outputs.
    Fixtures,
    /// A specific snapshot.
    Snapshot {
        /// The snapshot.
        id: SnapshotId,
    },
    /// A specific path.
    Path {
        /// The path.
        path: SandboxPath,
    },
    /// Anything else.
    Other {
        /// Sanitised description.
        detail: ShortText,
    },
}

/// Who asked for a verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerifyRequester {
    /// The agent (`ward-request`).
    Agent,
    /// The user (`ward verify`).
    User,
    /// `TamperWard`.
    TamperWard,
}

/// Status of one verification step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepStatus {
    /// Still running.
    Running,
    /// Passed.
    Pass,
    /// Failed.
    Fail,
}

/// Aggregate outcome of a verification run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct VerifySummary {
    /// Steps in the verification manifest.
    pub steps_total: u32,
    /// Steps that passed.
    pub steps_passed: u32,
    /// Steps that failed.
    pub steps_failed: u32,
    /// Individual tests executed, when the runner reports them.
    pub tests_run: u64,
    /// Individual tests that failed.
    pub tests_failed: u64,
    /// Wall-clock duration of the run.
    pub duration: Duration,
}

/// Who accepted a state. Only `TamperWard` can, but the field is an enum so the catalogue
/// can grow without changing the record shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Acceptor {
    /// `TamperWard` accepted the candidate.
    TamperWard,
}

/// Kind of agent claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimKind {
    /// A tool invocation reported by a hook.
    ToolUse,
    /// A free-form note.
    Note,
    /// A plan.
    Plan,
}

/// Which live observer lost observations on the way to the log
/// (`ObservationsDropped`, `event-model.md` §9).
///
/// The observer is the *producer* side of the bounded hand-off queue the daemon's
/// single log writer drains while a command runs; it is not the enforcement path.
/// A full queue never changes a decision — the proxy keeps allowing and denying in
/// real time — it only means the daemon's record of that window is incomplete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObserverSource {
    /// The live filesystem watch over the worktree (`FileModified` / `FileRead`).
    Filesystem,
    /// The session egress proxy's decision recorder (`NetworkRequested` /
    /// `NetworkDenied`).
    Network,
    /// The agent hook broker's claim buffer (`AgentClaim`). A hook request the
    /// broker could not record — the pending-claim buffer full, a connection
    /// refused at the handler cap, or a handler still in flight when the final
    /// flush cut over — is reported here rather than as an agent note, so the
    /// gap is visible in every observer mode including Quiet.
    Hook,
}

impl ObserverSource {
    /// Stable lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Hook => "hook",
        }
    }
}

impl fmt::Display for ObserverSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error for over-long signature bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("signature must be 1–{max} bytes, found {found}")]
pub struct SignatureLength {
    /// Cap in bytes.
    pub max: usize,
    /// Length found.
    pub found: usize,
}

/// Opaque signature bytes, 1–128 bytes.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct SignatureBytes(Vec<u8>);

impl SignatureBytes {
    /// Maximum signature length in bytes.
    pub const MAX_BYTES: usize = 128;

    /// Wraps signature bytes.
    ///
    /// # Errors
    /// Returns [`SignatureLength`] if empty or longer than [`MAX_BYTES`](Self::MAX_BYTES).
    pub fn new(bytes: Vec<u8>) -> Result<Self, SignatureLength> {
        if bytes.is_empty() || bytes.len() > Self::MAX_BYTES {
            return Err(SignatureLength {
                max: Self::MAX_BYTES,
                found: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignatureBytes({} bytes)", self.0.len())
    }
}

impl TryFrom<Vec<u8>> for SignatureBytes {
    type Error = SignatureLength;
    fn try_from(bytes: Vec<u8>) -> Result<Self, SignatureLength> {
        Self::new(bytes)
    }
}

impl From<SignatureBytes> for Vec<u8> {
    fn from(s: SignatureBytes) -> Vec<u8> {
        s.0
    }
}

/// A `TamperWard` countersignature over an anchor.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TamperWardSig {
    /// Identifier (hash) of the signing key.
    pub key_id: Blake3Hash,
    /// Signature bytes; the algorithm is bound to the key.
    pub signature: SignatureBytes,
}

// ---------------------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------------------

/// Every event `WardOS` records (`event-model.md` §3).
///
/// No variant carries secret material. See the `Origin` requirements on each variant's
/// documentation; they are conventions enforced by `wardd`, not by this type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WardEvent {
    // -- lifecycle (origin: Wardd) --
    /// A session opened. First record after genesis.
    SessionStarted {
        /// Project the session runs in.
        project: ProjectId,
        /// The agent.
        agent: AgentIdentity,
        /// Hash of the capability manifest (also the chain genesis).
        manifest_hash: Blake3Hash,
        /// Entry snapshot of the worktree.
        entry_snapshot: SnapshotId,
        /// Hash of the merged policy.
        policy_hash: Blake3Hash,
        /// Digests of tool images mounted into the sandbox.
        tool_images: Vec<ImageDigest>,
    },
    /// A session closed; the log is sealed after this record.
    SessionEnded {
        /// Why.
        reason: EndReason,
        /// Final snapshot, if one was taken.
        final_snapshot: Option<SnapshotId>,
    },
    /// The agent's coarse state changed.
    AgentStateChanged {
        /// New state.
        state: AgentState,
    },

    // -- filesystem (origin: Kernel via fanotify; Agent via hooks) --
    /// A file was opened for reading.
    FileRead {
        /// Path relative to its sandbox mount.
        path: SandboxPath,
        /// Acting process.
        by: ProcessRef,
    },
    /// A file was modified.
    FileModified {
        /// Path relative to its sandbox mount.
        path: SandboxPath,
        /// Acting process.
        by: ProcessRef,
        /// Kind of modification.
        kind: FileChangeKind,
    },

    // -- processes (origin: Kernel via eBPF) --
    /// A process executed a new image.
    CommandStarted {
        /// The process.
        pid: Pid,
        /// Its parent.
        parent: Pid,
        /// Bounded argv.
        argv: BoundedArgv,
        /// Working directory.
        cwd: SandboxPath,
        /// Digest of the executable, when computed.
        exe_digest: Option<Blake3Hash>,
    },
    /// A process exited.
    CommandFinished {
        /// The process.
        pid: Pid,
        /// How it exited.
        exit: ExitStatus,
        /// Lifetime.
        duration: Duration,
    },

    // -- network (origin: Proxy; Kernel for nftables drops) --
    /// The proxy evaluated a CONNECT.
    NetworkRequested {
        /// Destination host.
        host: HostName,
        /// Destination port.
        port: u16,
        /// Outcome.
        decision: Decision,
        /// Deciding rule.
        rule: RuleRef,
        /// Requesting process, when attributable.
        by: ProcessRef,
    },
    /// A connection attempt was refused (including private-range and non-proxy attempts).
    NetworkDenied {
        /// Destination.
        dst: DeniedDst,
        /// Why.
        reason: DenyReason,
    },

    // -- capabilities and credentials (origin: Wardd / User) --
    /// A capability was requested.
    CapabilityRequested {
        /// The request.
        cap: CapabilityRequest,
        /// Requester-supplied reason, sanitised.
        reason: Option<ShortText>,
    },
    /// A capability request was decided.
    CapabilityDecided {
        /// The request.
        cap: CapabilityRequest,
        /// Outcome.
        decision: Decision,
        /// Who decided.
        by: DecisionSource,
        /// Validity of an allow.
        grant: Option<GrantScope>,
    },
    /// A credential was requested from the broker.
    CredentialRequested {
        /// Service.
        service: ServiceId,
        /// Requested scope.
        scope: Scope,
    },
    /// A credential grant was issued.
    ///
    /// **Carries scope, expiry and delivery mode only — never the token or any other
    /// secret material.** The broker's secret types have no path into this crate.
    CredentialGranted {
        /// Service.
        service: ServiceId,
        /// Granted scope.
        scope: Scope,
        /// Time until expiry from the moment of the grant.
        expires: Duration,
        /// How the credential reaches the agent's traffic.
        delivery: CredentialDelivery,
    },
    /// A credential request was refused.
    CredentialDenied {
        /// Service.
        service: ServiceId,
        /// Requested scope.
        scope: Scope,
        /// Why.
        reason: DenyReason,
    },
    /// A credential grant was revoked.
    CredentialRevoked {
        /// Service.
        service: ServiceId,
        /// Why.
        reason: RevokeReason,
    },

    // -- snapshots (origin: Wardd) --
    /// A snapshot was captured.
    SnapshotCreated {
        /// Role.
        role: SnapshotRole,
        /// Snapshot id.
        id: SnapshotId,
        /// Number of manifest entries.
        entries: u64,
        /// Total bytes captured.
        bytes: u64,
        /// Capture mechanism.
        capture: CaptureMode,
        /// How long the agent cgroup was frozen.
        stall: Duration,
    },

    // -- TamperWard (origin: TamperWard) --
    /// `TamperWard` evaluated a protected surface.
    PolicyDecision {
        /// What was evaluated.
        subject: PolicySubject,
        /// Outcome.
        decision: Decision,
        /// Deciding rule.
        rule: RuleRef,
        /// Sanitised detail.
        detail: DetailText,
    },
    /// Convenience projection of a `PolicyDecision` with `Deny`, for Quiet mode.
    PolicyDenied {
        /// What was denied.
        subject: PolicySubject,
        /// Denying rule.
        rule: RuleRef,
        /// Sanitised detail.
        detail: DetailText,
    },
    /// `TamperWard` detected tampering with a protected surface.
    TamperDetected {
        /// What was tampered with.
        subject: PolicySubject,
        /// Sanitised detail.
        detail: DetailText,
    },

    // -- verification (origin: Wardd / Verifier) --
    /// A verification was requested.
    VerificationRequested {
        /// Candidate snapshot.
        candidate: SnapshotId,
        /// Who asked.
        requested_by: VerifyRequester,
    },
    /// The verifier was spawned.
    VerificationStarted {
        /// Candidate snapshot.
        candidate: SnapshotId,
        /// Pristine (entry) snapshot it is compared against.
        pristine: SnapshotId,
        /// Verifier image.
        verifier_image: ImageDigest,
        /// Hash of the verification manifest.
        manifest_hash: Blake3Hash,
    },
    /// A verification step reported progress.
    VerificationProgress {
        /// Step name.
        step: ShortText,
        /// Status.
        status: StepStatus,
    },
    /// Verification passed.
    VerificationPassed {
        /// Candidate snapshot.
        candidate: SnapshotId,
        /// Summary.
        summary: VerifySummary,
        /// Hash of the signed result document.
        result_hash: Blake3Hash,
    },
    /// Verification failed.
    VerificationFailed {
        /// Candidate snapshot.
        candidate: SnapshotId,
        /// Summary.
        summary: VerifySummary,
        /// Hash of the signed result document.
        result_hash: Blake3Hash,
    },
    /// `TamperWard` accepted a verified state.
    StateAccepted {
        /// Accepted snapshot.
        snapshot: SnapshotId,
        /// Who accepted.
        by: Acceptor,
    },

    // -- agent claims (origin: Agent) — never enforcement facts --
    /// A claim from the agent's hook layer.
    AgentClaim {
        /// Kind of claim.
        kind: ClaimKind,
        /// Sanitised payload.
        payload: PayloadText,
    },

    // -- integrity --
    /// A chain anchor, emitted periodically and on every verification.
    Anchor {
        /// Hash of the record preceding this anchor.
        chain_head: Blake3Hash,
        /// Sequence number of that record.
        seq: u64,
        /// `TamperWard` countersignature, when present.
        countersigned_by: Option<TamperWardSig>,
        /// Set once the per-session size cap has been reached and file-level events are
        /// being sampled (`event-model.md` §5).
        degraded: bool,
    },

    // -- intervention (origin: Wardd; ADR-0019 §3) --
    /// The host paused the session as one operation: processes frozen, the proxy
    /// closed to new traffic, credential injection suspended, approvals held.
    SessionPaused {
        /// How the processes were frozen.
        method: PauseMethod,
        /// Why, in the user's words (`ward pause --reason`), sanitised.
        reason: ShortText,
    },
    /// The host resumed a paused session: everything `SessionPaused` held is released.
    SessionResumed {
        /// How long the session was paused.
        paused_for: Duration,
    },
    /// The entry snapshot was materialised over the worktree (`ward stop --restore-entry`).
    EntryRestored {
        /// The snapshot written.
        snapshot: SnapshotId,
        /// Paths written or removed to match it.
        files: u64,
        /// Worktree-relative directory holding what the restore replaced (`.ward/restore-<ts>`),
        /// empty when nothing differed.
        backup: ShortText,
    },

    // -- verification, continued (origin: Wardd; #139) --
    /// Verification could not run to a pass/fail result: the verifier failed to launch, a
    /// preparation step failed, or the run was otherwise cut short by an infrastructure
    /// error rather than by the trusted command exiting non-zero. Recorded so a
    /// `VerificationStarted` is never the last verification-kind record for a candidate —
    /// every attempt gets a terminal record, distinct from a test failure. Appended at the
    /// end of the catalogue, not grouped with `VerificationFailed` above, because postcard
    /// identifies variants by declaration index and existing indices must never move.
    VerificationErrored {
        /// Candidate snapshot the attempt concerned.
        candidate: SnapshotId,
        /// Sanitised, bounded description of what stopped the run (e.g. "sandbox: bubblewrap
        /// (bwrap) is not installed"). Never a secret; drawn from the daemon's own error text.
        reason: ShortText,
    },

    // -- processes, continued (origin: Kernel; #140 / PR #197 review) --
    /// A launch could not be carried through to a `CommandFinished`: the sandbox or hook
    /// setup failed, or the child failed to spawn, after `CommandStarted` (and any credential
    /// grant scoped to it) was already on the log. Recorded so `CommandStarted` is never the
    /// last record for a pid — every launch gets a terminal record, and a launch-scoped grant
    /// does not outlive a launch that never even started, not just one that ran and exited.
    /// Appended at the end of the catalogue, not grouped with `CommandFinished` above, because
    /// postcard identifies variants by declaration index and existing indices must never move
    /// (see the module doc comment); the same discipline `VerificationErrored` follows for an
    /// unrunnable verification attempt.
    LaunchAborted {
        /// The process this closes out (`CommandStarted`'s own pid).
        pid: Pid,
        /// Sanitised, bounded description of what stopped the launch (e.g. "egress proxy:
        /// address already in use"). Never a secret; drawn from the daemon's own error text.
        reason: ShortText,
    },

    // -- observer health (origin: Wardd; `event-model.md` §9) --
    /// A live observer could not hand every observation to the log: the bounded
    /// queue between it and the single writer was full, so `dropped` observations
    /// were refused rather than silently lost.
    ///
    /// Appended immediately after the batch the same drain did take, so the
    /// incomplete window is bounded by its neighbours in the log. Enforcement is
    /// unaffected: the proxy keeps deciding in real time whether or not this
    /// queue is backed up, and a refused observation is a lost *record*, never a
    /// changed decision.
    ObservationsDropped {
        /// Which observer lost them.
        source: ObserverSource,
        /// How many observations this marker accounts for.
        dropped: u64,
        /// Capacity of the queue that refused them, so a reader can tell a tight
        /// bound from a genuine burst.
        capacity: u64,
    },

    // -- intervention, continued (origin: Wardd; #145 items 3-4) --
    /// The host paused the session (ADR-0019 §3, same operation `SessionPaused`
    /// records), but could not confirm the freeze settled within the bound the
    /// daemon gives it (`pause::FREEZE_SETTLE`): at least one of the session's
    /// sandboxed processes had not yet responded to `SIGSTOP` when the bound
    /// expired. Only possible for `PauseMethod::Sigstop` — the cgroup freezer
    /// path is synchronous by construction and always settles before either
    /// this or `SessionPaused` would be written.
    ///
    /// This is the *terminal* record of an unsettled pause attempt — the daemon
    /// decides the settle outcome before appending anything, so a pause is
    /// recorded as exactly one of `SessionPaused` xor `SessionPauseUnsettled`,
    /// never both (PR #207 review finding 1: publishing a confirmed
    /// `SessionPaused` and only then finding out it was not actually confirmed
    /// let every reader that stops at the first record — the desktop's trust
    /// bar included — believe a false confirmation, if only for the settle
    /// window and, on a failed qualifier append, forever after). Carries the
    /// same fields `SessionPaused` would have carried, plus `pending`, so a
    /// reader never needs a prior `SessionPaused` record to make sense of it.
    ///
    /// The pause is not undone and nothing here is a failure of the pause itself: the
    /// marker, the held approvals and the SIGSTOPs already sent all still stand, the
    /// safest state the daemon can preserve without more information. What this record
    /// says is narrower and just as important — that the daemon cannot yet confirm every
    /// process actually stopped, so a reader must not treat this as proof every process
    /// is frozen, and must not treat it as a `SessionPaused` it merely qualifies. Per
    /// #145 item 4 ("do not report a full success after a partial operation"), this must
    /// never render, or be derived into shell state, identically to a confirmed pause.
    ///
    /// Purely additive, exactly like `VerificationErrored` above: postcard identifies
    /// variants by declaration index, so a new one is always appended at the end, never
    /// inserted into or merged with an existing variant's fields. Its own fields are
    /// free to be shaped however this record needs them (unlike an already-shipped
    /// variant's fields, which must never change): this variant has not shipped
    /// anywhere outside this still-open PR, so nothing on any real log has ever carried
    /// the earlier, `pending`-only shape.
    SessionPauseUnsettled {
        /// How the processes were frozen — always `PauseMethod::Sigstop` in practice
        /// (see above), carried anyway so this record never depends on a prior
        /// `SessionPaused` having been read to make sense of it.
        method: PauseMethod,
        /// Why, in the user's words (`ward pause --reason`), sanitised — the same
        /// text `SessionPaused` would have carried.
        reason: ShortText,
        /// Number of the session's sandboxed processes that had not confirmed stopped
        /// (or exited) when the settle bound expired. Never the pid list itself: this is
        /// a durable log record, and which pids they were is meaningful only in the
        /// moment a human or `ward resume` might act on it, not worth keeping forever.
        /// Always nonzero: a recount of zero pending is a settled freeze, reported as
        /// `SessionPaused` instead (`pause::settle_outcome` normalizes `Some(0)` to
        /// `None` for exactly this reason).
        pending: u32,
    },

    // -- verification attempts (origin: Wardd / Verifier; #139) --
    /// A verification attempt was allocated: the earliest record of an attempt, written
    /// before any expensive preparation (candidate capture, sandbox launch) begins, so a
    /// subscriber sees progress from the very first action rather than only once capture
    /// has already succeeded. No candidate is known yet — [`WardEvent::VerificationRequested`]
    /// follows once capture succeeds; [`WardEvent::VerificationInterrupted`] follows instead,
    /// with no candidate, if a step before capture succeeds fails (preparation, opening the
    /// snapshot store, allocating scratch, …) — the attempt still ends in exactly one
    /// terminal record even though it never reached a candidate for a subscriber to be told
    /// about.
    VerificationAttemptStarted {
        /// The attempt.
        attempt: AttemptId,
        /// Who asked.
        requested_by: VerifyRequester,
    },
    /// A verification attempt was cancelled by the user before it reached a pass/fail
    /// result (#139) — a distinct terminal outcome from `VerificationErrored` (an
    /// infrastructure failure) and from `VerificationFailed` (the trusted command ran and
    /// exited non-zero). `candidate` is `Some` once capture had already succeeded by the
    /// time the cancellation took effect, `None` if it was cancelled before that. Cancelling
    /// is cooperative, checked between the attempt's steps: a cancel requested while the
    /// verifier command itself is running takes effect only once that command returns.
    VerificationCancelled {
        /// The attempt.
        attempt: AttemptId,
        /// Candidate snapshot, when capture had already succeeded.
        candidate: Option<SnapshotId>,
    },
    /// A verification attempt ended without reaching a candidate-bearing terminal result
    /// (`Passed`/`Failed`/`Errored`/`Cancelled`), for either of two reasons (#139): the
    /// attempt's own `verify()` call reached a step before capture succeeds that failed —
    /// emitted directly by that same call, as its own terminal record, with `candidate:
    /// None`; or the process that had been running an earlier attempt (the session daemon,
    /// or a daemonless `ward` invocation) died, was killed, or was restarted mid-attempt,
    /// leaving the attempt's own record as the last verification-kind record for it —
    /// emitted by the reconciliation pass a session/daemon runs against its own log
    /// whenever it opens or reopens it, so a dangling attempt is never left showing
    /// "running" forever.
    VerificationInterrupted {
        /// The attempt.
        attempt: AttemptId,
        /// Candidate snapshot, when known.
        candidate: Option<SnapshotId>,
        /// Sanitised, bounded description of what was found (e.g. "the process serving
        /// this session ended before the attempt reached a terminal result").
        reason: ShortText,
    },
    /// The trusted verifier command was started but did not finish within the configured
    /// `verify.budget_secs`, so it was killed (#139 item 1). A distinct terminal outcome
    /// from `VerificationFailed` (the command ran to completion and exited non-zero): an
    /// exhausted budget says nothing about whether the tests pass, so it is never shown as
    /// a test failure. `summary` holds whatever the runner reported before it was killed
    /// (usually partial), and `result_hash` covers the retained output exactly as it does
    /// for `VerificationFailed`. Appended at the end of the catalogue, not grouped with
    /// `VerificationFailed` above, because postcard identifies variants by declaration
    /// index and existing indices must never move.
    VerificationTimedOut {
        /// The attempt.
        attempt: AttemptId,
        /// Candidate snapshot.
        candidate: SnapshotId,
        /// Counts the runner reported before it was killed.
        summary: VerifySummary,
        /// Hash of the retained result document.
        result_hash: Blake3Hash,
        /// The budget, in seconds, the command exceeded.
        budget_secs: u64,
    },

    // -- intervention, continued (origin: Wardd; #145 item 5) --
    /// `ward stop` (`Request::Stop`) terminated the session's sandboxed workloads
    /// before evidence sealing: every process of the session's sandboxes was frozen
    /// (or already was, from a pause), killed, and then watched for a bounded time
    /// (`pause::STOP_SETTLE`) until it was confirmed gone. Appended only when there
    /// was something to terminate — a stop with no sandbox running writes only the
    /// usual `SessionEnded`, as before.
    ///
    /// `pending == 0` is the confirmed outcome: every process the stop found is
    /// gone, and `SessionEnded` follows immediately. `pending > 0` means the daemon
    /// could not confirm that many processes ended within the bound (a process
    /// stuck in uninterruptible sleep, typically). The stop is then *refused*
    /// rather than reported as done: the log is **not** sealed, the session is held
    /// paused (marker written, so the proxy refuses; approvals held) as the safest
    /// state it can preserve, and a later `ward stop` retries. A reader must never
    /// treat a `pending > 0` record as a completed stop (#145 item 4, "do not
    /// report a full success after a partial operation").
    ///
    /// This is the explicit difference between stopping and log-only closure
    /// (#145 item 5): `Request::Seal` still seals without touching a running
    /// sandbox; `Request::Stop` does not seal until this confirmation holds.
    ///
    /// Appended at the end of the catalogue for the same reason every other
    /// late variant is: postcard identifies variants by declaration index.
    WorkloadsTerminated {
        /// Processes the stop found and confirmed gone.
        ended: u32,
        /// Processes killed but not confirmed gone when the bound expired. Never
        /// the pid list itself, for the same reason `SessionPauseUnsettled` keeps
        /// only a count.
        pending: u32,
    },
}

/// The kind (variant) of a [`WardEvent`], for filtering.
///
/// The discriminant is the bit position in [`EventKindSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum EventKind {
    SessionStarted = 0,
    SessionEnded = 1,
    AgentStateChanged = 2,
    FileRead = 3,
    FileModified = 4,
    CommandStarted = 5,
    CommandFinished = 6,
    NetworkRequested = 7,
    NetworkDenied = 8,
    CapabilityRequested = 9,
    CapabilityDecided = 10,
    CredentialRequested = 11,
    CredentialGranted = 12,
    CredentialDenied = 13,
    CredentialRevoked = 14,
    SnapshotCreated = 15,
    PolicyDecision = 16,
    PolicyDenied = 17,
    TamperDetected = 18,
    VerificationRequested = 19,
    VerificationStarted = 20,
    VerificationProgress = 21,
    VerificationPassed = 22,
    VerificationFailed = 23,
    StateAccepted = 24,
    AgentClaim = 25,
    Anchor = 26,
    SessionPaused = 27,
    SessionResumed = 28,
    EntryRestored = 29,
    VerificationErrored = 30,
    LaunchAborted = 31,
    ObservationsDropped = 32,
    SessionPauseUnsettled = 33,
    VerificationAttemptStarted = 34,
    VerificationCancelled = 35,
    VerificationInterrupted = 36,
    VerificationTimedOut = 37,
    WorkloadsTerminated = 38,
}

impl EventKind {
    /// Every kind, in declaration order.
    pub const ALL: [EventKind; 39] = [
        EventKind::SessionStarted,
        EventKind::SessionEnded,
        EventKind::AgentStateChanged,
        EventKind::FileRead,
        EventKind::FileModified,
        EventKind::CommandStarted,
        EventKind::CommandFinished,
        EventKind::NetworkRequested,
        EventKind::NetworkDenied,
        EventKind::CapabilityRequested,
        EventKind::CapabilityDecided,
        EventKind::CredentialRequested,
        EventKind::CredentialGranted,
        EventKind::CredentialDenied,
        EventKind::CredentialRevoked,
        EventKind::SnapshotCreated,
        EventKind::PolicyDecision,
        EventKind::PolicyDenied,
        EventKind::TamperDetected,
        EventKind::VerificationRequested,
        EventKind::VerificationStarted,
        EventKind::VerificationProgress,
        EventKind::VerificationPassed,
        EventKind::VerificationFailed,
        EventKind::StateAccepted,
        EventKind::AgentClaim,
        EventKind::Anchor,
        EventKind::SessionPaused,
        EventKind::SessionResumed,
        EventKind::EntryRestored,
        EventKind::VerificationErrored,
        EventKind::LaunchAborted,
        EventKind::ObservationsDropped,
        EventKind::SessionPauseUnsettled,
        EventKind::VerificationAttemptStarted,
        EventKind::VerificationCancelled,
        EventKind::VerificationInterrupted,
        EventKind::VerificationTimedOut,
        EventKind::WorkloadsTerminated,
    ];

    /// Bit position of this kind in an [`EventKindSet`].
    #[must_use]
    pub const fn bit(self) -> u64 {
        1 << (self as u8)
    }

    /// Stable lowercase name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            EventKind::SessionStarted => "session_started",
            EventKind::SessionEnded => "session_ended",
            EventKind::AgentStateChanged => "agent_state_changed",
            EventKind::FileRead => "file_read",
            EventKind::FileModified => "file_modified",
            EventKind::CommandStarted => "command_started",
            EventKind::CommandFinished => "command_finished",
            EventKind::NetworkRequested => "network_requested",
            EventKind::NetworkDenied => "network_denied",
            EventKind::CapabilityRequested => "capability_requested",
            EventKind::CapabilityDecided => "capability_decided",
            EventKind::CredentialRequested => "credential_requested",
            EventKind::CredentialGranted => "credential_granted",
            EventKind::CredentialDenied => "credential_denied",
            EventKind::CredentialRevoked => "credential_revoked",
            EventKind::SnapshotCreated => "snapshot_created",
            EventKind::PolicyDecision => "policy_decision",
            EventKind::PolicyDenied => "policy_denied",
            EventKind::TamperDetected => "tamper_detected",
            EventKind::VerificationRequested => "verification_requested",
            EventKind::VerificationStarted => "verification_started",
            EventKind::VerificationProgress => "verification_progress",
            EventKind::VerificationPassed => "verification_passed",
            EventKind::VerificationFailed => "verification_failed",
            EventKind::StateAccepted => "state_accepted",
            EventKind::AgentClaim => "agent_claim",
            EventKind::Anchor => "anchor",
            EventKind::SessionPaused => "session_paused",
            EventKind::SessionResumed => "session_resumed",
            EventKind::EntryRestored => "entry_restored",
            EventKind::VerificationErrored => "verification_errored",
            EventKind::LaunchAborted => "launch_aborted",
            EventKind::ObservationsDropped => "observations_dropped",
            EventKind::SessionPauseUnsettled => "session_pause_unsettled",
            EventKind::VerificationAttemptStarted => "verification_attempt_started",
            EventKind::VerificationCancelled => "verification_cancelled",
            EventKind::VerificationInterrupted => "verification_interrupted",
            EventKind::VerificationTimedOut => "verification_timed_out",
            EventKind::WorkloadsTerminated => "workloads_terminated",
        }
    }

    /// Whether the log must be fsynced immediately after a record of this kind
    /// (`event-model.md` §5: lifecycle, verification and credential events; anchors and
    /// tamper detections are included because they are integrity points).
    #[must_use]
    pub const fn is_critical(self) -> bool {
        matches!(
            self,
            EventKind::SessionStarted
                | EventKind::SessionEnded
                | EventKind::CredentialRequested
                | EventKind::CredentialGranted
                | EventKind::CredentialDenied
                | EventKind::CredentialRevoked
                | EventKind::VerificationRequested
                | EventKind::VerificationStarted
                | EventKind::VerificationPassed
                | EventKind::VerificationFailed
                | EventKind::VerificationErrored
                | EventKind::VerificationAttemptStarted
                | EventKind::VerificationCancelled
                | EventKind::VerificationInterrupted
                | EventKind::VerificationTimedOut
                | EventKind::StateAccepted
                | EventKind::TamperDetected
                | EventKind::Anchor
                | EventKind::SessionPaused
                | EventKind::SessionResumed
                | EventKind::EntryRestored
                | EventKind::ObservationsDropped
                | EventKind::SessionPauseUnsettled
                | EventKind::WorkloadsTerminated
        )
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Error returned when an [`EventKindSet`] bitmask contains unknown bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("event kind set contains unknown bits: {0:#018x}")]
pub struct UnknownKindBits(pub u64);

/// A set of [`EventKind`]s as a bitmask. Backed by a `u64` (not the `u32` a 32-kind
/// catalogue would technically still fit in): the catalogue reached the full 32-kind
/// capacity of a `u32` backing once `ObservationsDropped` (#202) landed, and #139's
/// three verification-attempt kinds appended after it need that same headroom
/// immediately, not eventually.  Widening past `u64` in turn needs the same treatment
/// this commit gives `u32`: a wider backing type, `bit()`'s shift, `MASK`, and this
/// wire-compatibility contract all revisited together, not just the shift arithmetic
/// in isolation.
///
/// Wire compatibility: postcard's integer encoding is a plain unsigned varint with no
/// width tag, so a value that previously fit in the `u32` backing (every kind index
/// `0..32`, i.e. the entire catalogue as it stood before this widening) serializes to
/// byte-for-byte the same output whether encoded as a `u32` or a `u64` -- see
/// `a_u32_encoded_set_decodes_identically_as_the_widened_u64_type` below, which proves
/// this against real postcard bytes rather than asserting it from the format's docs.
/// No `WIRE_VERSION` bump: this is the same kind of pure-capacity change the crate's
/// own append-only `WardEvent` convention already treats as backwards compatible, not
/// a change to what any existing bit means. #139's three new kinds are additive on top
/// of that same already-widened `u64` catalogue and need no `WIRE_VERSION` bump either.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(into = "u64")]
pub struct EventKindSet(u64);

impl EventKindSet {
    // `EventKind::ALL.len()` can reach exactly 64 (the full width of the backing
    // `u64`, one bit per kind), at which point `1u64 << 64` would overflow -- checked
    // explicitly rather than computed in a still-wider type (there is no wider
    // primitive integer to borrow the headroom from this time), so this stays correct
    // right up to the set's structural capacity rather than panicking one kind short
    // of it or silently wrapping past it.
    // `EventKind::ALL.len()` is at most a few dozen and known at compile time, so
    // this narrowing to the `u32` `checked_shl` requires is always exact.
    #[allow(clippy::cast_possible_truncation)]
    const MASK: u64 = match 1u64.checked_shl(EventKind::ALL.len() as u32) {
        Some(one_past) => one_past - 1,
        None => u64::MAX,
    };

    /// The empty set.
    pub const EMPTY: Self = Self(0);
    /// Every kind.
    pub const ALL: Self = Self(Self::MASK);

    /// A set containing exactly `kind`.
    #[must_use]
    pub const fn only(kind: EventKind) -> Self {
        Self(kind.bit())
    }

    /// This set with `kind` added.
    #[must_use]
    pub const fn with(self, kind: EventKind) -> Self {
        Self(self.0 | kind.bit())
    }

    /// This set with `kind` removed.
    #[must_use]
    pub const fn without(self, kind: EventKind) -> Self {
        Self(self.0 & !kind.bit())
    }

    /// Whether `kind` is a member.
    #[must_use]
    pub const fn contains(self, kind: EventKind) -> bool {
        self.0 & kind.bit() != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Raw bitmask.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Iterates members in declaration order.
    pub fn iter(self) -> impl Iterator<Item = EventKind> {
        EventKind::ALL
            .into_iter()
            .filter(move |k| self.contains(*k))
    }
}

impl fmt::Debug for EventKindSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl TryFrom<u64> for EventKindSet {
    type Error = UnknownKindBits;
    fn try_from(bits: u64) -> Result<Self, UnknownKindBits> {
        // Written as "masking to the known bits changes the value" rather than
        // "masking to the unknown bits is non-zero" (`bits & !MASK != 0`): if the
        // catalogue is ever at exactly 64 kinds, `MASK` is `u64::MAX` and `!MASK`
        // is zero -- a mask of zero is always clippy::bad_bit_mask, even though
        // the check is correct (there are no unknown bits left to have).
        if bits & Self::MASK != bits {
            return Err(UnknownKindBits(bits));
        }
        Ok(Self(bits))
    }
}

impl From<EventKindSet> for u64 {
    fn from(set: EventKindSet) -> u64 {
        set.0
    }
}

impl<'de> Deserialize<'de> for EventKindSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u64::deserialize(deserializer)?;
        Self::try_from(bits).map_err(serde::de::Error::custom)
    }
}

impl FromIterator<EventKind> for EventKindSet {
    fn from_iter<I: IntoIterator<Item = EventKind>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl WardEvent {
    /// The variant of this event.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        match self {
            WardEvent::SessionStarted { .. } => EventKind::SessionStarted,
            WardEvent::SessionEnded { .. } => EventKind::SessionEnded,
            WardEvent::AgentStateChanged { .. } => EventKind::AgentStateChanged,
            WardEvent::FileRead { .. } => EventKind::FileRead,
            WardEvent::FileModified { .. } => EventKind::FileModified,
            WardEvent::CommandStarted { .. } => EventKind::CommandStarted,
            WardEvent::CommandFinished { .. } => EventKind::CommandFinished,
            WardEvent::NetworkRequested { .. } => EventKind::NetworkRequested,
            WardEvent::NetworkDenied { .. } => EventKind::NetworkDenied,
            WardEvent::CapabilityRequested { .. } => EventKind::CapabilityRequested,
            WardEvent::CapabilityDecided { .. } => EventKind::CapabilityDecided,
            WardEvent::CredentialRequested { .. } => EventKind::CredentialRequested,
            WardEvent::CredentialGranted { .. } => EventKind::CredentialGranted,
            WardEvent::CredentialDenied { .. } => EventKind::CredentialDenied,
            WardEvent::CredentialRevoked { .. } => EventKind::CredentialRevoked,
            WardEvent::SnapshotCreated { .. } => EventKind::SnapshotCreated,
            WardEvent::PolicyDecision { .. } => EventKind::PolicyDecision,
            WardEvent::PolicyDenied { .. } => EventKind::PolicyDenied,
            WardEvent::TamperDetected { .. } => EventKind::TamperDetected,
            WardEvent::VerificationRequested { .. } => EventKind::VerificationRequested,
            WardEvent::VerificationStarted { .. } => EventKind::VerificationStarted,
            WardEvent::VerificationProgress { .. } => EventKind::VerificationProgress,
            WardEvent::VerificationPassed { .. } => EventKind::VerificationPassed,
            WardEvent::VerificationFailed { .. } => EventKind::VerificationFailed,
            WardEvent::StateAccepted { .. } => EventKind::StateAccepted,
            WardEvent::AgentClaim { .. } => EventKind::AgentClaim,
            WardEvent::Anchor { .. } => EventKind::Anchor,
            WardEvent::SessionPaused { .. } => EventKind::SessionPaused,
            WardEvent::SessionResumed { .. } => EventKind::SessionResumed,
            WardEvent::EntryRestored { .. } => EventKind::EntryRestored,
            WardEvent::VerificationErrored { .. } => EventKind::VerificationErrored,
            WardEvent::LaunchAborted { .. } => EventKind::LaunchAborted,
            WardEvent::ObservationsDropped { .. } => EventKind::ObservationsDropped,
            WardEvent::SessionPauseUnsettled { .. } => EventKind::SessionPauseUnsettled,
            WardEvent::VerificationAttemptStarted { .. } => EventKind::VerificationAttemptStarted,
            WardEvent::VerificationCancelled { .. } => EventKind::VerificationCancelled,
            WardEvent::VerificationInterrupted { .. } => EventKind::VerificationInterrupted,
            WardEvent::VerificationTimedOut { .. } => EventKind::VerificationTimedOut,
            WardEvent::WorkloadsTerminated { .. } => EventKind::WorkloadsTerminated,
        }
    }

    /// Shorthand for `self.kind().is_critical()`.
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        self.kind().is_critical()
    }

    /// The claim kind, for `AgentClaim` events.
    #[must_use]
    pub const fn claim_kind(&self) -> Option<ClaimKind> {
        match self {
            WardEvent::AgentClaim { kind, .. } => Some(*kind),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn kind_bits_are_dense_and_cover_the_mask() {
        for (i, k) in EventKind::ALL.iter().enumerate() {
            assert_eq!(k.bit(), 1u64 << i, "{k}");
        }
        assert_eq!(EventKindSet::ALL.iter().count(), EventKind::ALL.len());
        // The catalogue is currently 38 kinds wide, well inside the `u64` backing's
        // 64-bit capacity -- so, unlike when the backing type was exactly saturated
        // at `u32`, there IS a first unused bit right now (bit 38), and a value that
        // sets it must be rejected as an unknown kind rather than silently accepted.
        // This is the same "no room past the known kinds to smuggle a bit through"
        // property `kind_bits_are_dense...`'s name promises, just checked against
        // the current headroom instead of an exhausted capacity.
        assert_eq!(
            EventKindSet::try_from(EventKindSet::ALL.bits() | (1 << EventKind::ALL.len())),
            Err(UnknownKindBits(
                EventKindSet::ALL.bits() | (1 << EventKind::ALL.len())
            ))
        );
        assert!(
            postcard::from_bytes::<EventKindSet>(&postcard::to_allocvec(&u64::MAX).unwrap())
                .is_err()
        );
        let set = EventKindSet::only(EventKind::Anchor).with(EventKind::FileRead);
        let bytes = postcard::to_allocvec(&set).unwrap();
        assert_eq!(postcard::from_bytes::<EventKindSet>(&bytes).unwrap(), set);
        assert_eq!(
            set.without(EventKind::Anchor),
            EventKindSet::only(EventKind::FileRead)
        );
    }

    /// Proves the wire-compatibility claim on `EventKindSet`'s own doc comment: data
    /// serialized back when the type was backed by `u32` decodes identically through
    /// the widened `u64` `Deserialize` impl — checked against real postcard bytes,
    /// not asserted from the varint format's spec.
    ///
    /// Deliberately does not use `EventKindSet::ALL` (grows with the catalogue) or
    /// any of the recently-appended kinds (`ObservationsDropped`, `SessionPauseUnsettled`,
    /// and this branch's own three verification-attempt kinds): a wire-compatibility fixture has to stay
    /// meaningful as the catalogue keeps growing, not just against today's exact
    /// size. Uses only kinds declared long before any of that instead --
    /// `EventKind::bit()`'s own contract (never reorder, only append) is what
    /// guarantees their bit positions are fixed forever, independent of how many
    /// more kinds get appended after them.
    #[test]
    fn a_u32_encoded_set_decodes_identically_as_the_widened_u64_type() {
        let session_started = EventKind::SessionStarted; // bit 0
        let file_read = EventKind::FileRead; // bit 3
        let anchor = EventKind::Anchor; // bit 26

        // A value spanning the low, middle and high end of that stable range:
        // postcard-encode it as a bare `u32`, the exact wire shape any
        // `EventKindSet` produced before this change would have had
        // (`#[serde(into = "u32")]` at the time), then decode those bytes through
        // today's `u64`-backed `Deserialize` impl.
        let pre_widening_bits: u32 =
            u32::try_from(session_started.bit() | file_read.bit() | anchor.bit()).unwrap();
        let old_wire_bytes = postcard::to_allocvec(&pre_widening_bits).unwrap();
        let expected = EventKindSet::EMPTY
            .with(session_started)
            .with(file_read)
            .with(anchor);
        assert_eq!(
            postcard::from_bytes::<EventKindSet>(&old_wire_bytes).unwrap(),
            expected,
            "a set of long-stable kinds encoded under the old u32 representation \
             must decode to the same set today, not merely to a numerically equal \
             but distinct value"
        );

        // And the reverse direction: a value round-tripped through today's type
        // produces the same bytes postcard would have produced for the bare integer
        // under the old representation, proving the wire shape genuinely didn't
        // change — not just that both sides happen to parse each other's output.
        assert_eq!(postcard::to_allocvec(&expected).unwrap(), old_wire_bytes);
    }

    #[test]
    fn critical_kinds_match_the_fsync_policy_in_the_design() {
        assert!(EventKind::SessionStarted.is_critical());
        assert!(EventKind::CredentialGranted.is_critical());
        assert!(EventKind::VerificationPassed.is_critical());
        assert!(EventKind::SessionPaused.is_critical());
        assert!(EventKind::SessionPauseUnsettled.is_critical());
        assert!(EventKind::WorkloadsTerminated.is_critical());
        assert!(!EventKind::FileRead.is_critical());
        assert!(!EventKind::AgentClaim.is_critical());
    }

    #[test]
    fn signature_bytes_are_bounded() {
        assert!(SignatureBytes::new(vec![]).is_err());
        assert!(SignatureBytes::new(vec![0; 129]).is_err());
        assert!(SignatureBytes::new(vec![0; 64]).is_ok());
        let bytes = postcard::to_allocvec(&vec![1u8; 200]).unwrap();
        assert!(postcard::from_bytes::<SignatureBytes>(&bytes).is_err());
    }

    #[test]
    fn claim_kind_is_only_reported_for_claims() {
        let claim = WardEvent::AgentClaim {
            kind: ClaimKind::Note,
            payload: PayloadText::new("hi"),
        };
        assert_eq!(claim.claim_kind(), Some(ClaimKind::Note));
        assert_eq!(claim.kind(), EventKind::AgentClaim);
        let other = WardEvent::AgentStateChanged {
            state: AgentState::Idle,
        };
        assert_eq!(other.claim_kind(), None);
    }
}
