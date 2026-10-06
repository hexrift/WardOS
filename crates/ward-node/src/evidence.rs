//! Per-attempt evidence logs (ADR-0030 §3, #332).
//!
//! An executing node is the single writer of one append-only, hash-chained evidence log
//! per execution attempt it admits: `<task-root>/<task>/<attempt>.evidence/events.log`
//! ([`evidence_dir`]). The directory sits beside the attempt's workspace
//! (`<task-root>/<task>/<attempt>/`), never inside it, so the sandboxed workload, which can
//! write only its workspace, cannot reach it. Both directories on the path are created mode
//! 0700 and refused when they are not private directories; the log is mode 0600.
//!
//! The log is a `ward-events` session log, unchanged: the same frames, hash chain,
//! [`LogWriter`], [`LogReader`] and sealed `HEAD`, so `ward replay --verify` and
//! [`verify`] check it like any other. Its chain is bound to the attempt: the chain's
//! session id carries the execution attempt id's 128-bit value ([`session`]) and its genesis
//! hash is [`genesis`] of the attempt's binding. Every record has origin
//! [`Origin::Node`] and is fsynced before the append returns.
//!
//! Records, all metadata (the workload's output is never logged):
//!
//! * `NodeAttemptAdmitted` once an `admit` verified and its version is durably recorded;
//! * `NodeAttemptLaunched` once a `start`'s spawn is confirmed, with the host pid;
//! * `NodeAttemptIntervened` for every `pause` and `resume` applied;
//! * `NodeAttemptEnded` when the attempt ends: its state, receipt outcome and cause, with
//!   the `stop` or `revoke` operation that ended it;
//! * `NodeAttemptRecovered` when the state the node holds differs from the state the log
//!   shows: after a restart, before the node serves, and before sealing;
//! * `NodeActionRequested`, `NodeActionAnswered` and `NodeActionRefused` for the attempt's
//!   action channel ([`crate::actions`]): sizes and digests, never the text;
//! * `NodeAttemptSealed`, after which the log is sealed (`HEAD` written, files read-only).
//!
//! A log is at most [`MAX_EVIDENCE_LOG_BYTES`]. Records that do not end an attempt are
//! refused once the log would grow past that bound less [`TERMINAL_RESERVE_BYTES`], so the
//! records that end, recover and seal it always fit; an append past the bound is refused
//! with nothing written. A log that does not verify, belongs to another attempt or is
//! sealed refuses every append. A crash can leave only a torn final frame that was never
//! acknowledged; the registry cuts it off when the node restarts.

use std::fs::{DirBuilder, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use thiserror::Error;
use ward_events::log::{head_file_path, parse_head};
use ward_events::{
    Blake3Hash, Chain, ChainError, ChainHead, EventRecord, FsyncPolicy, LogError, LogReader,
    LogWriter, NodeActionDecision, NodeAttemptOutcome, NodeAttemptState, NodeIntervention, Origin,
    SessionId, Timestamp, WardEvent, encode_record,
};
use ward_node_protocol::{TaskBinding, TaskExecutionOutcome, TaskLifecycleState};

/// Suffix of an attempt's evidence directory, beside its workspace.
pub const EVIDENCE_SUFFIX: &str = ".evidence";

/// File name of the evidence log inside an attempt's evidence directory.
pub const EVIDENCE_LOG: &str = "events.log";

/// Upper bound on the bytes of one attempt's evidence log.
pub const MAX_EVIDENCE_LOG_BYTES: u64 = 256 * 1024;

/// Bytes of [`MAX_EVIDENCE_LOG_BYTES`] kept for the records that end, recover and seal an
/// attempt.
pub const TERMINAL_RESERVE_BYTES: u64 = 16 * 1024;

const GENESIS_DOMAIN: &[u8] = b"ward-node attempt evidence v1\0";

/// Why an evidence log could not be read, verified or appended to.
#[derive(Debug, Error)]
pub enum EvidenceError {
    /// Evidence I/O failed.
    #[error("evidence log I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The log does not verify, or a frame could not be written.
    #[error("evidence log does not verify: {0}")]
    Log(#[from] LogError),
    /// A record could not be built.
    #[error("evidence record could not be built: {0}")]
    Chain(#[from] ChainError),
    /// The attempt has no evidence log.
    #[error("the attempt has no evidence log")]
    Absent,
    /// A directory on the evidence path, or the log, is not private or not what it should be.
    #[error("evidence path is not a private directory or regular file")]
    InsecurePath,
    /// The log's chain is not the attempt's, or a record was not written by the node.
    #[error("evidence log does not belong to this attempt")]
    ForeignLog,
    /// The log's sealed `HEAD` does not name the head of its chain.
    #[error("evidence log sealed head does not match its chain")]
    HeadMismatch,
    /// The log is sealed and takes no further record.
    #[error("evidence log is sealed")]
    Sealed,
    /// The record would take the log past its bound; nothing was written.
    #[error("evidence log would exceed its bound")]
    TooLarge,
}

/// The chain session id of the evidence log of `binding`: the execution attempt id's value.
#[must_use]
pub const fn session(binding: TaskBinding) -> SessionId {
    SessionId::from_u128(binding.attempt().as_u128())
}

/// The genesis hash of the evidence log of `binding`: BLAKE3 over a fixed domain string and
/// the task, attempt and lease ids, each as 16 big-endian bytes.
#[must_use]
pub fn genesis(binding: TaskBinding) -> Blake3Hash {
    let mut bytes = GENESIS_DOMAIN.to_vec();
    bytes.extend_from_slice(&binding.task().as_u128().to_be_bytes());
    bytes.extend_from_slice(&binding.attempt().as_u128().to_be_bytes());
    bytes.extend_from_slice(&binding.lease().as_u128().to_be_bytes());
    Blake3Hash::hash(&bytes)
}

/// The evidence directory of `binding` under the task root `root`:
/// `<root>/<task>/<attempt>.evidence`.
#[must_use]
pub fn evidence_dir(root: &Path, binding: TaskBinding) -> PathBuf {
    root.join(binding.task().to_string())
        .join(format!("{}{EVIDENCE_SUFFIX}", binding.attempt()))
}

/// An attempt's evidence log, read and verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEvidence {
    records: Vec<EventRecord>,
    head: ChainHead,
    sealed: bool,
    bytes: u64,
}

impl VerifiedEvidence {
    /// Every record, oldest first.
    #[must_use]
    pub fn records(&self) -> &[EventRecord] {
        &self.records
    }

    /// The verified head of the chain.
    #[must_use]
    pub const fn head(&self) -> ChainHead {
        self.head
    }

    /// Whether the log is sealed and its `HEAD` names exactly [`Self::head`].
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// The attempt's state and receipt outcome as the log last records them.
    #[must_use]
    pub fn state(&self) -> Option<(NodeAttemptState, Option<NodeAttemptOutcome>)> {
        self.records.iter().fold(None, |held, record| {
            let outcome = held.and_then(|(_, outcome)| outcome);
            match &record.event {
                WardEvent::NodeAttemptAdmitted { .. } => Some((NodeAttemptState::Ready, None)),
                WardEvent::NodeAttemptLaunched { .. } => Some((NodeAttemptState::Running, None)),
                WardEvent::NodeAttemptIntervened { action, .. } => Some((
                    match action {
                        NodeIntervention::Pause => NodeAttemptState::Paused,
                        NodeIntervention::Resume => NodeAttemptState::Running,
                    },
                    outcome,
                )),
                WardEvent::NodeAttemptEnded { state, outcome, .. } => {
                    Some((*state, Some(*outcome)))
                }
                WardEvent::NodeAttemptRecovered { state, outcome } => Some((*state, *outcome)),
                WardEvent::NodeAttemptSealed { .. } => Some((NodeAttemptState::Sealed, outcome)),
                _ => held,
            }
        })
    }

    /// The action-channel requests the log records as asked and never answered, oldest
    /// first.
    #[must_use]
    pub fn unanswered_actions(&self) -> Vec<u32> {
        let mut open = Vec::new();
        for record in &self.records {
            match &record.event {
                WardEvent::NodeActionRequested { action, .. } => open.push(*action),
                WardEvent::NodeActionAnswered { action, .. } => open.retain(|open| open != action),
                _ => {}
            }
        }
        open
    }

    fn last_sealed_by(&self, operation: u64) -> bool {
        self.records.last().is_some_and(|record| {
            matches!(record.event, WardEvent::NodeAttemptSealed { operation: by } if by == operation)
        })
    }
}

/// Read and verify the evidence log of `binding` in its evidence directory `dir`: every
/// record has origin [`Origin::Node`] and chains from [`genesis`] of `binding` under
/// [`session`], and a sealed `HEAD`, if there is one, names exactly the chain's head.
///
/// # Errors
///
/// Returns [`EvidenceError::Absent`] when there is no log, and the first reason the log does
/// not verify otherwise.
pub fn verify(dir: &Path, binding: TaskBinding) -> Result<VerifiedEvidence, EvidenceError> {
    load(dir, binding)?.ok_or(EvidenceError::Absent)
}

fn load(dir: &Path, binding: TaskBinding) -> Result<Option<VerifiedEvidence>, EvidenceError> {
    let path = dir.join(EVIDENCE_LOG);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Err(EvidenceError::InsecurePath);
    }
    if metadata.len() > MAX_EVIDENCE_LOG_BYTES {
        return Err(EvidenceError::TooLarge);
    }
    let expected = Chain::genesis(session(binding), genesis(binding)).head();
    let mut reader = LogReader::open(&path)?;
    let mut records = Vec::new();
    while let Some(record) = reader.next_record()? {
        let foreign = record.origin != Origin::Node
            || (records.is_empty()
                && (record.session != expected.session || record.prev != expected.genesis));
        if foreign {
            return Err(EvidenceError::ForeignLog);
        }
        records.push(record);
    }
    let head = reader.head().unwrap_or(expected);
    let sealed = match std::fs::read_to_string(head_file_path(&path)) {
        Ok(text) => {
            if parse_head(&text)? != head {
                return Err(EvidenceError::HeadMismatch);
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    Ok(Some(VerifiedEvidence {
        records,
        head,
        sealed,
        bytes: reader.offset(),
    }))
}

/// The evidence log of one attempt. The registry is its only writer, under its lock.
#[derive(Clone, Debug)]
pub(crate) struct AttemptEvidence {
    dir: PathBuf,
    binding: TaskBinding,
}

impl AttemptEvidence {
    /// The evidence log of `binding` under the task root `root`.
    pub(crate) fn new(root: &Path, binding: TaskBinding) -> Self {
        Self {
            dir: evidence_dir(root, binding),
            binding,
        }
    }

    /// Durably append `event`, creating the log at its first record.
    pub(crate) fn append(&self, event: WardEvent) -> Result<(), EvidenceError> {
        let current = self.open()?;
        if current.as_ref().is_some_and(VerifiedEvidence::is_sealed) {
            return Err(EvidenceError::Sealed);
        }
        self.write(current.as_ref(), event)
    }

    /// Seal the log as `operation` sealed the attempt, which ended `ended` with `outcome`:
    /// record the end first if the log does not show it, then `NodeAttemptSealed`, then the
    /// sealed `HEAD`. Sealing again under the same operation changes nothing.
    pub(crate) fn seal(
        &self,
        operation: u64,
        ended: NodeAttemptState,
        outcome: Option<NodeAttemptOutcome>,
    ) -> Result<(), EvidenceError> {
        let mut current = self.open()?;
        if let Some(log) = current.as_ref().filter(|log| log.is_sealed()) {
            return if log.last_sealed_by(operation) {
                Ok(())
            } else {
                Err(EvidenceError::Sealed)
            };
        }
        if !current
            .as_ref()
            .is_some_and(|log| log.last_sealed_by(operation))
        {
            if current.as_ref().and_then(VerifiedEvidence::state) != Some((ended, outcome)) {
                self.write(
                    current.as_ref(),
                    WardEvent::NodeAttemptRecovered {
                        state: ended,
                        outcome,
                    },
                )?;
                current = self.open()?;
            }
            self.write(current.as_ref(), WardEvent::NodeAttemptSealed { operation })?;
        }
        LogWriter::open(self.dir.join(EVIDENCE_LOG), FsyncPolicy::Always)?.seal()?;
        Ok(())
    }

    /// Bring the log in line with the state a restarted node holds the attempt in, before
    /// the node serves: cut off a torn final frame, answer `cancelled` every action-channel
    /// request the log shows unanswered (a restarted node holds no attempt running, so none
    /// can be answered any more), record `NodeAttemptRecovered` if the log shows another
    /// state or outcome, and seal it if the attempt is sealed. An attempt that was never
    /// admitted and has no log is left without one.
    pub(crate) fn recover(
        &self,
        state: NodeAttemptState,
        outcome: Option<NodeAttemptOutcome>,
        sealed_by: Option<u64>,
    ) -> Result<(), EvidenceError> {
        let current = match self.open() {
            Err(EvidenceError::Log(LogError::TruncatedTail { offset })) => {
                self.cut(offset)?;
                self.open()?
            }
            other => other?,
        };
        let current = self.cancel_unanswered(current)?;
        let held = current.as_ref().and_then(VerifiedEvidence::state);
        if let (NodeAttemptState::Sealed, Some(operation)) = (state, sealed_by) {
            let ended = held
                .filter(|(ended, held_outcome)| ends(*ended) && *held_outcome == outcome)
                .map_or(NodeAttemptState::Sealed, |(ended, _)| ended);
            return self.seal(operation, ended, outcome);
        }
        if current.as_ref().is_some_and(VerifiedEvidence::is_sealed) {
            return Err(EvidenceError::Sealed);
        }
        let unrecorded = current.is_none() && state == NodeAttemptState::Created;
        if unrecorded || held == Some((state, outcome)) {
            return Ok(());
        }
        self.write(
            current.as_ref(),
            WardEvent::NodeAttemptRecovered { state, outcome },
        )
    }

    fn cancel_unanswered(
        &self,
        mut current: Option<VerifiedEvidence>,
    ) -> Result<Option<VerifiedEvidence>, EvidenceError> {
        let unanswered = current
            .as_ref()
            .filter(|log| !log.is_sealed())
            .map(VerifiedEvidence::unanswered_actions)
            .unwrap_or_default();
        for action in unanswered {
            self.write(
                current.as_ref(),
                WardEvent::NodeActionAnswered {
                    action,
                    decision: NodeActionDecision::Cancelled,
                    operation: None,
                    note_bytes: 0,
                    note: None,
                },
            )?;
            current = self.open()?;
        }
        Ok(current)
    }

    fn open(&self) -> Result<Option<VerifiedEvidence>, EvidenceError> {
        if let Some(task_dir) = self.dir.parent() {
            private_dir(task_dir)?;
        }
        private_dir(&self.dir)?;
        load(&self.dir, self.binding)
    }

    fn write(
        &self,
        current: Option<&VerifiedEvidence>,
        event: WardEvent,
    ) -> Result<(), EvidenceError> {
        let path = self.dir.join(EVIDENCE_LOG);
        let fresh = Chain::genesis(session(self.binding), genesis(self.binding)).head();
        let (head, first_wall, bytes) = current.map_or((fresh, None, 0), |log| {
            (
                log.head,
                log.records.first().and_then(|record| record.ts_wall),
                log.bytes,
            )
        });
        let bound = if closes(&event) {
            MAX_EVIDENCE_LOG_BYTES
        } else {
            MAX_EVIDENCE_LOG_BYTES.saturating_sub(TERMINAL_RESERVE_BYTES)
        };
        let now = SystemTime::now();
        let mono = first_wall
            .and_then(|first| now.duration_since(first).ok())
            .unwrap_or_default();
        let record = Chain::resume(head).append(
            Origin::Node,
            event,
            Timestamp {
                mono,
                wall: Some(now),
            },
        )?;
        let frame = encode_record(&record).map_err(LogError::from)?;
        let grown = u64::try_from(frame.len())
            .ok()
            .and_then(|frame| bytes.checked_add(frame));
        if grown.is_none_or(|grown| grown > bound) {
            return Err(EvidenceError::TooLarge);
        }
        let started = current.is_some_and(|log| !log.records.is_empty());
        let mut writer = if started {
            LogWriter::open(&path, FsyncPolicy::Always)?
        } else {
            if current.is_some() {
                std::fs::remove_file(&path)?;
            }
            LogWriter::create(&path, head, FsyncPolicy::Always)?
        };
        writer.append(&record)?;
        if !started {
            File::open(&self.dir)?.sync_all()?;
        }
        Ok(())
    }

    fn cut(&self, offset: u64) -> Result<(), EvidenceError> {
        let log = OpenOptions::new()
            .write(true)
            .open(self.dir.join(EVIDENCE_LOG))?;
        log.set_len(offset)?;
        log.sync_all()?;
        Ok(())
    }
}

pub(crate) fn private_dir(dir: &Path) -> Result<(), EvidenceError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(dir)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(EvidenceError::InsecurePath);
    }
    Ok(())
}

/// Whether `event` may use the reserve kept for ending an attempt: the end, recovery and
/// seal records, and the node's own answers to action-channel requests (`expired`,
/// `cancelled`), which are bounded by the grant's `max_total` and must never be lost.
const fn closes(event: &WardEvent) -> bool {
    matches!(
        event,
        WardEvent::NodeAttemptEnded { .. }
            | WardEvent::NodeAttemptRecovered { .. }
            | WardEvent::NodeAttemptSealed { .. }
            | WardEvent::NodeActionAnswered {
                operation: None,
                ..
            }
    )
}

const fn ends(state: NodeAttemptState) -> bool {
    matches!(
        state,
        NodeAttemptState::Exited | NodeAttemptState::Stopped | NodeAttemptState::Revoked
    )
}

/// The evidence spelling of a lifecycle state.
#[must_use]
pub const fn attempt_state(state: TaskLifecycleState) -> NodeAttemptState {
    match state {
        TaskLifecycleState::Created => NodeAttemptState::Created,
        TaskLifecycleState::Ready => NodeAttemptState::Ready,
        TaskLifecycleState::Running => NodeAttemptState::Running,
        TaskLifecycleState::Paused => NodeAttemptState::Paused,
        TaskLifecycleState::Exited => NodeAttemptState::Exited,
        TaskLifecycleState::Stopped => NodeAttemptState::Stopped,
        TaskLifecycleState::Revoked => NodeAttemptState::Revoked,
        TaskLifecycleState::Sealed => NodeAttemptState::Sealed,
    }
}

/// The evidence spelling of a receipt outcome.
#[must_use]
pub const fn attempt_outcome(outcome: TaskExecutionOutcome) -> NodeAttemptOutcome {
    match outcome {
        TaskExecutionOutcome::Completed => NodeAttemptOutcome::Completed,
        TaskExecutionOutcome::Failed => NodeAttemptOutcome::Failed,
        TaskExecutionOutcome::Unknown => NodeAttemptOutcome::Unknown,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_events::{ExecutionAttemptId, LeaseId, NodeAttemptEnd, TaskId};

    use super::*;

    fn binding() -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        )
    }

    fn paused(operation: u64) -> WardEvent {
        WardEvent::NodeAttemptIntervened {
            action: NodeIntervention::Pause,
            operation,
        }
    }

    fn ended() -> WardEvent {
        WardEvent::NodeAttemptEnded {
            state: NodeAttemptState::Exited,
            outcome: NodeAttemptOutcome::Completed,
            end: NodeAttemptEnd::Exited { code: Some(0) },
            operation: None,
        }
    }

    fn private_root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tasks");
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        (dir, root)
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn the_log_is_created_privately_beside_the_workspace_and_bound_to_the_attempt() {
        let (_dir, root) = private_root();
        let evidence = AttemptEvidence::new(&root, binding());
        assert!(matches!(
            verify(&evidence_dir(&root, binding()), binding()),
            Err(EvidenceError::Absent)
        ));
        evidence.append(paused(1)).unwrap();
        let dir = evidence_dir(&root, binding());
        assert_eq!(
            dir,
            root.join(binding().task().to_string())
                .join(format!("{}.evidence", binding().attempt()))
        );
        assert_eq!(mode(dir.parent().unwrap()), 0o700);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(EVIDENCE_LOG)), 0o600);
        let log = verify(&dir, binding()).unwrap();
        assert_eq!(log.head().session, session(binding()));
        assert_eq!(log.head().genesis, genesis(binding()));
        assert_eq!(log.records()[0].origin, Origin::Node);
        assert!(!log.is_sealed());

        let other = TaskBinding::new(
            binding().task(),
            binding().attempt(),
            LeaseId::from_u128(10),
        );
        assert_ne!(genesis(other), genesis(binding()));
        assert!(matches!(
            verify(&dir, other),
            Err(EvidenceError::ForeignLog)
        ));
    }

    #[test]
    fn an_exposed_evidence_directory_is_refused() {
        let (_dir, root) = private_root();
        let dir = evidence_dir(&root, binding());
        DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&dir)
            .unwrap();
        assert!(matches!(
            AttemptEvidence::new(&root, binding()).append(paused(1)),
            Err(EvidenceError::InsecurePath)
        ));
    }

    #[test]
    fn a_tampered_byte_breaks_verification_and_refuses_appends() {
        let (_dir, root) = private_root();
        let evidence = AttemptEvidence::new(&root, binding());
        evidence.append(paused(1)).unwrap();
        evidence.append(paused(2)).unwrap();
        let dir = evidence_dir(&root, binding());
        let path = dir.join(EVIDENCE_LOG);
        let intact = std::fs::read(&path).unwrap();
        for target in [20, intact.len() / 2, intact.len() - 1] {
            let mut bytes = intact.clone();
            bytes[target] ^= 0x01;
            std::fs::write(&path, &bytes).unwrap();
            assert!(verify(&dir, binding()).is_err(), "byte {target}");
            assert!(LogReader::open(&path).unwrap().verify_all().is_err());
            assert!(evidence.append(paused(3)).is_err(), "byte {target}");
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing appended");
        }
        std::fs::write(&path, &intact).unwrap();
        assert_eq!(verify(&dir, binding()).unwrap().records().len(), 2);
    }

    #[test]
    fn a_record_not_written_by_the_node_is_foreign() {
        let (_dir, root) = private_root();
        let dir = evidence_dir(&root, binding());
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .unwrap();
        let mut chain = Chain::genesis(session(binding()), genesis(binding()));
        let mut writer =
            LogWriter::create(dir.join(EVIDENCE_LOG), chain.head(), FsyncPolicy::Never).unwrap();
        let record = chain
            .append(Origin::Wardd, paused(1), Timestamp::default())
            .unwrap();
        writer.append(&record).unwrap();
        assert!(matches!(
            verify(&dir, binding()),
            Err(EvidenceError::ForeignLog)
        ));
    }

    #[test]
    fn sealing_writes_the_head_makes_the_log_read_only_and_refuses_further_records() {
        let (_dir, root) = private_root();
        let evidence = AttemptEvidence::new(&root, binding());
        evidence.append(ended()).unwrap();
        evidence
            .seal(
                70,
                NodeAttemptState::Exited,
                Some(NodeAttemptOutcome::Completed),
            )
            .unwrap();
        let dir = evidence_dir(&root, binding());
        let log = verify(&dir, binding()).unwrap();
        assert!(log.is_sealed());
        assert_eq!(
            log.records().last().unwrap().event,
            WardEvent::NodeAttemptSealed { operation: 70 }
        );
        assert_eq!(log.records().len(), 2, "the end was already recorded");
        assert_eq!(mode(&dir.join(EVIDENCE_LOG)), 0o400);
        assert_eq!(mode(&head_file_path(&dir.join(EVIDENCE_LOG))), 0o400);

        evidence
            .seal(
                70,
                NodeAttemptState::Exited,
                Some(NodeAttemptOutcome::Completed),
            )
            .unwrap();
        assert!(matches!(
            evidence.seal(
                71,
                NodeAttemptState::Exited,
                Some(NodeAttemptOutcome::Completed)
            ),
            Err(EvidenceError::Sealed)
        ));
        assert!(matches!(
            evidence.append(paused(1)),
            Err(EvidenceError::Sealed)
        ));
        assert_eq!(verify(&dir, binding()).unwrap(), log);

        let head = head_file_path(&dir.join(EVIDENCE_LOG));
        std::fs::set_permissions(&head, std::fs::Permissions::from_mode(0o600)).unwrap();
        let text = std::fs::read_to_string(&head).unwrap();
        std::fs::write(&head, text.replace("next_seq=2", "next_seq=1")).unwrap();
        assert!(matches!(
            verify(&dir, binding()),
            Err(EvidenceError::HeadMismatch)
        ));
    }

    #[test]
    fn sealing_an_attempt_whose_end_the_log_lacks_records_it_first() {
        let (_dir, root) = private_root();
        let evidence = AttemptEvidence::new(&root, binding());
        evidence.append(paused(1)).unwrap();
        evidence
            .seal(
                70,
                NodeAttemptState::Stopped,
                Some(NodeAttemptOutcome::Failed),
            )
            .unwrap();
        let log = verify(&evidence_dir(&root, binding()), binding()).unwrap();
        let events: Vec<_> = log.records().iter().map(|r| r.event.clone()).collect();
        assert_eq!(
            events,
            vec![
                paused(1),
                WardEvent::NodeAttemptRecovered {
                    state: NodeAttemptState::Stopped,
                    outcome: Some(NodeAttemptOutcome::Failed),
                },
                WardEvent::NodeAttemptSealed { operation: 70 },
            ]
        );
        assert_eq!(
            log.state(),
            Some((NodeAttemptState::Sealed, Some(NodeAttemptOutcome::Failed)))
        );
    }

    #[test]
    fn the_log_is_bounded_and_keeps_room_to_end_and_seal_it() {
        let (_dir, root) = private_root();
        let dir = evidence_dir(&root, binding());
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .unwrap();
        let path = dir.join(EVIDENCE_LOG);
        let mut chain = Chain::genesis(session(binding()), genesis(binding()));
        let mut writer = LogWriter::create(&path, chain.head(), FsyncPolicy::Never).unwrap();
        let open_bound = MAX_EVIDENCE_LOG_BYTES - TERMINAL_RESERVE_BYTES;
        let mut operation = 0;
        while std::fs::metadata(&path).unwrap().len() + 200 < open_bound {
            operation += 1;
            let record = chain
                .append(Origin::Node, paused(operation), Timestamp::default())
                .unwrap();
            writer.append(&record).unwrap();
        }
        writer.sync().unwrap();
        drop(writer);

        let evidence = AttemptEvidence::new(&root, binding());
        let mut refused = false;
        for next in operation + 1..operation + 10 {
            let before = std::fs::read(&path).unwrap();
            match evidence.append(paused(next)) {
                Ok(()) => {}
                Err(EvidenceError::TooLarge) => {
                    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");
                    refused = true;
                    break;
                }
                Err(error) => panic!("{error}"),
            }
        }
        assert!(refused);
        assert!(std::fs::metadata(&path).unwrap().len() <= open_bound);

        evidence.append(ended()).unwrap();
        evidence
            .seal(
                70,
                NodeAttemptState::Exited,
                Some(NodeAttemptOutcome::Completed),
            )
            .unwrap();
        let log = verify(&dir, binding()).unwrap();
        assert!(log.is_sealed());
        assert!(std::fs::metadata(&path).unwrap().len() <= MAX_EVIDENCE_LOG_BYTES);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut oversized = std::fs::read(&path).unwrap();
        oversized.resize(usize::try_from(MAX_EVIDENCE_LOG_BYTES).unwrap() + 1, 0);
        std::fs::write(&path, oversized).unwrap();
        assert!(matches!(
            verify(&dir, binding()),
            Err(EvidenceError::TooLarge)
        ));
    }

    #[test]
    fn recovery_cuts_a_torn_tail_and_records_only_a_changed_state() {
        let (_dir, root) = private_root();
        let evidence = AttemptEvidence::new(&root, binding());
        evidence
            .recover(NodeAttemptState::Created, None, None)
            .unwrap();
        assert!(matches!(
            verify(&evidence_dir(&root, binding()), binding()),
            Err(EvidenceError::Absent)
        ));

        evidence.append(paused(1)).unwrap();
        let path = evidence_dir(&root, binding()).join(EVIDENCE_LOG);
        let intact = std::fs::read(&path).unwrap();
        std::fs::write(&path, [intact.as_slice(), &intact[..10]].concat()).unwrap();
        assert!(evidence.append(paused(2)).is_err());

        evidence
            .recover(NodeAttemptState::Paused, None, None)
            .unwrap();
        let log = verify(&evidence_dir(&root, binding()), binding()).unwrap();
        assert_eq!(log.records().len(), 1, "same state: nothing recorded");

        evidence
            .recover(
                NodeAttemptState::Exited,
                Some(NodeAttemptOutcome::Unknown),
                None,
            )
            .unwrap();
        evidence
            .recover(
                NodeAttemptState::Exited,
                Some(NodeAttemptOutcome::Unknown),
                None,
            )
            .unwrap();
        let log = verify(&evidence_dir(&root, binding()), binding()).unwrap();
        assert_eq!(
            log.records().last().unwrap().event,
            WardEvent::NodeAttemptRecovered {
                state: NodeAttemptState::Exited,
                outcome: Some(NodeAttemptOutcome::Unknown),
            }
        );
        assert_eq!(log.records().len(), 2);
    }

    #[test]
    fn recovery_answers_every_unanswered_action_request_cancelled_before_the_recovered_state() {
        let (_dir, root) = private_root();
        let evidence = AttemptEvidence::new(&root, binding());
        let requested = |action| WardEvent::NodeActionRequested {
            action,
            kind: ward_events::NodeActionKind::Approval,
            summary_bytes: 1,
            summary: Blake3Hash::hash(b"s"),
            detail_bytes: 0,
            detail: Blake3Hash::hash(b""),
        };
        evidence
            .append(WardEvent::NodeAttemptLaunched {
                operation: 3,
                host_pid: 1,
            })
            .unwrap();
        evidence.append(requested(1)).unwrap();
        evidence.append(requested(2)).unwrap();
        evidence
            .append(WardEvent::NodeActionAnswered {
                action: 1,
                decision: NodeActionDecision::Approved,
                operation: Some(9),
                note_bytes: 0,
                note: None,
            })
            .unwrap();
        evidence.append(requested(3)).unwrap();
        let dir = evidence_dir(&root, binding());
        assert_eq!(
            verify(&dir, binding()).unwrap().unanswered_actions(),
            [2, 3]
        );
        evidence
            .recover(
                NodeAttemptState::Exited,
                Some(NodeAttemptOutcome::Unknown),
                None,
            )
            .unwrap();
        let log = verify(&dir, binding()).unwrap();
        assert!(log.unanswered_actions().is_empty());
        let tail: Vec<&WardEvent> = log.records()[5..]
            .iter()
            .map(|record| &record.event)
            .collect();
        let cancelled = |action| WardEvent::NodeActionAnswered {
            action,
            decision: NodeActionDecision::Cancelled,
            operation: None,
            note_bytes: 0,
            note: None,
        };
        assert_eq!(
            tail,
            [
                &cancelled(2),
                &cancelled(3),
                &WardEvent::NodeAttemptRecovered {
                    state: NodeAttemptState::Exited,
                    outcome: Some(NodeAttemptOutcome::Unknown),
                },
            ]
        );
        // A second recovery has nothing left to answer.
        evidence
            .recover(
                NodeAttemptState::Exited,
                Some(NodeAttemptOutcome::Unknown),
                None,
            )
            .unwrap();
        assert_eq!(verify(&dir, binding()).unwrap().records().len(), 8);
    }
}
