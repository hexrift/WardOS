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

use crate::ids::{Blake3Hash, ImageDigest, Pid, ProjectId, RuleRef, ServiceId, SnapshotId};
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
}

impl EventKind {
    /// Every kind, in declaration order.
    pub const ALL: [EventKind; 27] = [
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
    ];

    /// Bit position of this kind in an [`EventKindSet`].
    #[must_use]
    pub const fn bit(self) -> u32 {
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
                | EventKind::StateAccepted
                | EventKind::TamperDetected
                | EventKind::Anchor
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
#[error("event kind set contains unknown bits: {0:#010x}")]
pub struct UnknownKindBits(pub u32);

/// A set of [`EventKind`]s as a bitmask.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(into = "u32")]
pub struct EventKindSet(u32);

impl EventKindSet {
    const MASK: u32 = (1 << EventKind::ALL.len()) - 1;

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
    pub const fn bits(self) -> u32 {
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

impl TryFrom<u32> for EventKindSet {
    type Error = UnknownKindBits;
    fn try_from(bits: u32) -> Result<Self, UnknownKindBits> {
        if bits & !Self::MASK != 0 {
            return Err(UnknownKindBits(bits));
        }
        Ok(Self(bits))
    }
}

impl From<EventKindSet> for u32 {
    fn from(set: EventKindSet) -> u32 {
        set.0
    }
}

impl<'de> Deserialize<'de> for EventKindSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u32::deserialize(deserializer)?;
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
            assert_eq!(k.bit(), 1u32 << i, "{k}");
        }
        assert_eq!(EventKindSet::ALL.iter().count(), EventKind::ALL.len());
        assert!(EventKindSet::try_from(EventKindSet::ALL.bits() << 1).is_err());
        assert!(
            postcard::from_bytes::<EventKindSet>(&postcard::to_allocvec(&u32::MAX).unwrap())
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

    #[test]
    fn critical_kinds_match_the_fsync_policy_in_the_design() {
        assert!(EventKind::SessionStarted.is_critical());
        assert!(EventKind::CredentialGranted.is_critical());
        assert!(EventKind::VerificationPassed.is_critical());
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
