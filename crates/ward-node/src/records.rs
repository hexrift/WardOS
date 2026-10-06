//! Durable task records: the registry across a node restart (#332 slice 7, ADR-0030 §6).
//!
//! Every task the registry holds has one record, `<state-dir>/tasks/<task>.json` (mode
//! 0600), in a directory created mode 0700 and refused when accessible to group or others.
//! A record is written like every other node state file: to a temporary file in the same
//! directory, fsynced, renamed over the record and the directory fsynced, so a crash leaves
//! the old or the new record. A record is at most [`MAX_STATE_FILE_BYTES`]; a write that
//! would exceed it is refused with nothing changed.
//!
//! A record is `{"format":1,…}` and holds what the node needs to answer for the task
//! after a restart as it did before: the binding and state; every operation id each verb
//! applied to the attempt; the `admit` that took effect (its operation id, the BLAKE3
//! digest of the exact envelope bytes, the issuer proof and the envelope's session); the
//! receipt outcome once the attempt ended; the workspace; and, while its end is not
//! confirmed by the reaper, the host process the workload was spawned as. The state
//! `launching` is a launch intent, recorded before a spawn and replaced once the spawn is
//! confirmed.
//!
//! The `admit` that took effect also records the authority it verified
//! ([`AuthorityRecord`], #259): the admitted lease (its issuing principal, delegation,
//! subject agent, parent lease and delegating agent, grants, validity and version), every
//! ancestor lease in the same terms, nearest parent first, the envelope's validity and
//! version, and the node clock at the admission. With the operation id and the issuer key
//! id already in the record, `ward-node audit` answers who delegated what authority to
//! which task and when from the record alone. The lineage is bounded as the envelope
//! bounds it ([`MAX_ADMISSION_LINEAGE`]) and the grants by how many an envelope of
//! [`MAX_ADMISSION_ENVELOPE_BYTES`] can carry ([`MAX_RECORDED_GRANTS`]). A record written
//! before this field existed loads with no authority facts and audits as such.
//!
//! Records are read once, when the registry is built. Any entry of the directory that is
//! not a regular file named after its task (`task_….json`), a record that is oversized or
//! malformed, and more records than the registry may hold all fail the start closed. The
//! temporary file of a record write a crash interrupted (`.task_….json.tmp`) is ignored.
//! `ward-node audit` reads one record ([`TaskStore::read`]) under the same rules.

use std::fs::File;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ward_authority::{AuthorityLease, GrantSet};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, LeaseId, NodeResourceUsage, PrincipalId, SessionId, TaskId,
};
use ward_node_protocol::{
    IssuerProof, MAX_ADMISSION_ENVELOPE_BYTES, MAX_ADMISSION_LINEAGE, OperationId, TaskBinding,
    TaskExecutionOutcome, TaskLifecycleState,
};

use crate::admit::VerifiedAdmission;
use crate::execution::WorkloadProcess;
use crate::state::{
    MAX_STATE_FILE_BYTES, NodeStateError, StoredFile, open_private_dir, read_bounded, write_atomic,
};
use crate::task::MAX_ATTEMPT_PAUSES;

/// Directory, inside the node state directory, holding one record per registered task.
pub const TASKS_DIR: &str = "tasks";

pub(crate) const RECORD_FORMAT: u32 = 1;

const MIN_GRANT_WIRE_BYTES: usize = r#"{"capability":"a","resource":"a","delegable":true}"#.len();

/// Upper bound on the grants one record's authority facts hold across the lease and its
/// lineage: as many as an envelope of [`MAX_ADMISSION_ENVELOPE_BYTES`] can carry.
pub const MAX_RECORDED_GRANTS: usize = MAX_ADMISSION_ENVELOPE_BYTES / MIN_GRANT_WIRE_BYTES;

/// Why the task records could not be opened, loaded or written.
#[derive(Debug, Error)]
pub enum TaskRecordError {
    /// The records directory is not a private directory.
    #[error("task record directory is unusable: {0}")]
    Directory(#[from] NodeStateError),
    /// Record I/O failed.
    #[error("task record I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// An entry of the records directory is not a valid record.
    #[error("task record {0} is invalid")]
    InvalidRecord(String),
    /// The directory holds more records than the registry may hold.
    #[error("more than {0} task records")]
    TooManyRecords(usize),
    /// The record would be larger than [`MAX_STATE_FILE_BYTES`]; nothing was written.
    #[error("task record for {0} is too large")]
    RecordTooLarge(TaskId),
    /// A recovered attempt's evidence log could not be verified or brought in line with
    /// its recovered state.
    #[error("evidence log of {task} could not be recovered: {source}")]
    Evidence {
        /// The task whose attempt's log failed.
        task: TaskId,
        /// Why.
        source: crate::evidence::EvidenceError,
    },
}

/// A task's state as recorded: the lifecycle state, or a launch intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedState {
    /// Registered, not admitted.
    Created,
    /// Admitted, not started.
    Ready,
    /// A `start` is about to spawn, or was spawning when the record was last written.
    Launching,
    /// The workload is running.
    Running,
    /// The workload's process tree is stopped.
    Paused,
    /// Stopped by `stop`.
    Stopped,
    /// The workload ended on its own, at its budget, or ambiguously.
    Exited,
    /// Revoked by `revoke`.
    Revoked,
    /// Terminal; the evidence log is sealed.
    Sealed,
}

impl std::fmt::Display for RecordedState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Created => "created",
            Self::Ready => "ready",
            Self::Launching => "launching",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Stopped => "stopped",
            Self::Exited => "exited",
            Self::Revoked => "revoked",
            Self::Sealed => "sealed",
        })
    }
}

impl From<TaskLifecycleState> for RecordedState {
    fn from(state: TaskLifecycleState) -> Self {
        match state {
            TaskLifecycleState::Created => Self::Created,
            TaskLifecycleState::Ready => Self::Ready,
            TaskLifecycleState::Running => Self::Running,
            TaskLifecycleState::Paused => Self::Paused,
            TaskLifecycleState::Stopped => Self::Stopped,
            TaskLifecycleState::Exited => Self::Exited,
            TaskLifecycleState::Revoked => Self::Revoked,
            TaskLifecycleState::Sealed => Self::Sealed,
        }
    }
}

/// One lease of an admitted authority chain, as the verified envelope carried it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedLease {
    /// The lease.
    pub lease: LeaseId,
    /// The delegation that created it.
    pub delegation: DelegationId,
    /// The principal at the root of its lineage.
    pub issuer: PrincipalId,
    /// The agent holding it.
    pub subject: AgentId,
    /// The lease it was delegated from; `None` for a root lease.
    pub parent_lease: Option<LeaseId>,
    /// The agent that delegated it; `None` for a root lease.
    pub delegated_by: Option<AgentId>,
    /// Its exact grants.
    pub grants: GrantSet,
    /// Inclusive validity start, Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Exclusive validity end, Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Its lineage version.
    pub version: u64,
}

impl From<&AuthorityLease> for RecordedLease {
    fn from(lease: &AuthorityLease) -> Self {
        Self {
            lease: lease.id(),
            delegation: lease.delegation_id(),
            issuer: lease.issuer(),
            subject: lease.subject(),
            parent_lease: lease.parent_lease_id(),
            delegated_by: lease.delegated_by(),
            grants: lease.grants().clone(),
            issued_at_unix_ms: lease.issued_at_unix_ms(),
            expires_at_unix_ms: lease.expires_at_unix_ms(),
            version: lease.version().get(),
        }
    }
}

/// The authority an `admit` verified: who delegated what to which agent for the task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRecord {
    /// The lease the binding names, held by the envelope's agent.
    pub lease: RecordedLease,
    /// Its ancestors, nearest parent first, ending at the root; empty for a root lease.
    pub lineage: Vec<RecordedLease>,
    /// The envelope's inclusive validity start, Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// The envelope's exclusive validity end, Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// The envelope's per-task admission version.
    pub version: u64,
    /// The node clock, Unix milliseconds, when the envelope was verified and admitted.
    pub admitted_at_unix_ms: u64,
}

impl AuthorityRecord {
    /// The authority facts of a verified admission.
    #[must_use]
    pub fn of(verified: &VerifiedAdmission) -> Self {
        Self {
            lease: RecordedLease::from(verified.authority().lease()),
            lineage: verified
                .ancestors()
                .iter()
                .map(RecordedLease::from)
                .collect(),
            issued_at_unix_ms: verified.envelope().issued_at_unix_ms(),
            expires_at_unix_ms: verified.envelope().expires_at_unix_ms(),
            version: verified.envelope().version().get(),
            admitted_at_unix_ms: verified.verified_at_unix_ms(),
        }
    }

    fn is_well_formed(&self) -> bool {
        let leases = || std::iter::once(&self.lease).chain(&self.lineage);
        let grants: usize = leases().map(|lease| lease.grants.as_slice().len()).sum();
        self.lineage.len() <= MAX_ADMISSION_LINEAGE
            && grants <= MAX_RECORDED_GRANTS
            && leases().all(|lease| lease.parent_lease.is_some() == lease.delegated_by.is_some())
    }
}

/// The `admit` that took effect on an attempt: what a replay of it must match, the
/// session the attempt's receipt names, and the authority it verified (absent in a record
/// written before authority facts were recorded).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmitRecord {
    pub(crate) operation_id: OperationId,
    pub(crate) envelope: Blake3Hash,
    pub(crate) proof: IssuerProof,
    pub(crate) session: SessionId,
    #[serde(default)]
    pub(crate) authority: Option<AuthorityRecord>,
}

/// The `seal` that made a task terminal, and its order among seals for eviction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SealRecord {
    pub(crate) by: OperationId,
    pub(crate) order: u64,
}

/// One task's durable record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskRecord {
    pub(crate) format: u32,
    pub(crate) binding: TaskBinding,
    pub(crate) state: RecordedState,
    pub(crate) created_by: OperationId,
    pub(crate) admitted: Option<AdmitRecord>,
    pub(crate) started_by: Option<OperationId>,
    pub(crate) stopped_by: Option<OperationId>,
    pub(crate) paused_by: Vec<OperationId>,
    pub(crate) resumed_by: Vec<OperationId>,
    pub(crate) revoked_by: Option<OperationId>,
    pub(crate) sealed: Option<SealRecord>,
    pub(crate) outcome: Option<TaskExecutionOutcome>,
    pub(crate) workspace: Option<PathBuf>,
    pub(crate) process: Option<WorkloadProcess>,
    /// What the attempt used, measured from its cgroup once reaped (#260); absent when it
    /// was not measured, so a record without it is byte for byte what it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) usage: Option<NodeResourceUsage>,
}

impl TaskRecord {
    fn is_valid_for(&self, task: TaskId) -> bool {
        self.format == RECORD_FORMAT
            && self.binding.task() == task
            && self.paused_by.len() <= MAX_ATTEMPT_PAUSES
            && self.resumed_by.len() <= self.paused_by.len()
            && self.sealed.is_some() == (self.state == RecordedState::Sealed)
            && self
                .admitted
                .as_ref()
                .and_then(|admitted| admitted.authority.as_ref())
                .is_none_or(AuthorityRecord::is_well_formed)
    }
}

/// The directory of task records inside the node state directory.
#[derive(Debug)]
pub(crate) struct TaskStore {
    dir: PathBuf,
}

impl TaskStore {
    /// Open (creating mode 0700 if absent) the records directory of `state_dir`.
    pub(crate) fn open(state_dir: &Path) -> Result<Self, TaskRecordError> {
        let dir = state_dir.join(TASKS_DIR);
        open_private_dir(&dir)?;
        Ok(Self { dir })
    }

    /// Every record, refusing the whole directory if any entry is invalid or there are more
    /// than `limit`.
    pub(crate) fn load(&self, limit: usize) -> Result<Vec<TaskRecord>, TaskRecordError> {
        let mut records = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if is_interrupted_write(&name) {
                continue;
            }
            let task = name
                .strip_suffix(".json")
                .and_then(|id| id.parse::<TaskId>().ok())
                .filter(|task| record_name(*task) == name)
                .ok_or_else(|| TaskRecordError::InvalidRecord(name.clone()))?;
            if records.len() >= limit {
                return Err(TaskRecordError::TooManyRecords(limit));
            }
            records.push(self.parse(task, &name)?);
        }
        Ok(records)
    }

    /// The record of `task`, or `None` when it has none.
    ///
    /// # Errors
    ///
    /// Returns [`TaskRecordError::InvalidRecord`] when the record is not a regular file,
    /// is oversized, or does not parse as a valid record of `task`.
    pub(crate) fn read(&self, task: TaskId) -> Result<Option<TaskRecord>, TaskRecordError> {
        let name = record_name(task);
        match std::fs::symlink_metadata(self.dir.join(&name)) {
            Ok(_) => self.parse(task, &name).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn parse(&self, task: TaskId, name: &str) -> Result<TaskRecord, TaskRecordError> {
        match read_bounded(&self.dir.join(name))? {
            StoredFile::Bytes(bytes) => serde_json::from_slice::<TaskRecord>(&bytes).ok(),
            StoredFile::Absent | StoredFile::Invalid => None,
        }
        .filter(|record| record.is_valid_for(task))
        .ok_or_else(|| TaskRecordError::InvalidRecord(name.to_owned()))
    }

    /// Durably replace the record of `record`'s task.
    pub(crate) fn write(&self, record: &TaskRecord) -> Result<(), TaskRecordError> {
        let task = record.binding.task();
        let bytes = serde_json::to_vec(record).map_err(std::io::Error::other)?;
        if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_STATE_FILE_BYTES) {
            return Err(TaskRecordError::RecordTooLarge(task));
        }
        Ok(write_atomic(&self.dir, &record_name(task), &bytes)?)
    }

    /// Durably remove the record of `task`; removing an absent record changes nothing.
    pub(crate) fn remove(&self, task: TaskId) -> Result<(), TaskRecordError> {
        match std::fs::remove_file(self.dir.join(record_name(task))) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

fn record_name(task: TaskId) -> String {
    format!("{task}.json")
}

fn is_interrupted_write(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|temporary| temporary.strip_suffix(".tmp"))
        .and_then(|record| record.strip_suffix(".json"))
        .and_then(|task| task.parse::<TaskId>().ok())
        .is_some_and(|task| name == format!(".{}.tmp", record_name(task)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;

    use ward_authority::{CapabilityGrant, CapabilityName, GrantSet, ResourceRef};
    use ward_events::{AgentId, DelegationId, ExecutionAttemptId, LeaseId, PrincipalId};
    use ward_node_protocol::{IssuerSignature, MAX_ADMISSION_LINEAGE};

    use super::*;

    fn binding(task: u128) -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(task),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        )
    }

    fn op(value: u64) -> OperationId {
        OperationId::new(value).unwrap()
    }

    fn record(task: u128) -> TaskRecord {
        TaskRecord {
            format: RECORD_FORMAT,
            binding: binding(task),
            state: RecordedState::Paused,
            created_by: op(10),
            admitted: Some(AdmitRecord {
                operation_id: op(20),
                envelope: Blake3Hash::hash(b"{}"),
                proof: IssuerProof::new(
                    Blake3Hash::from_bytes([0x22; 32]),
                    IssuerSignature::from_bytes([0x33; 64]),
                ),
                session: SessionId::from_u128(5),
                authority: None,
            }),
            started_by: Some(op(30)),
            stopped_by: None,
            paused_by: vec![op(50), op(51)],
            resumed_by: vec![op(55)],
            revoked_by: None,
            sealed: None,
            outcome: None,
            workspace: Some(PathBuf::from("/tasks/t/a")),
            process: Some(WorkloadProcess::new(4242, 77, "boot".to_owned())),
            usage: None,
        }
    }

    fn grants(delegable: bool) -> GrantSet {
        GrantSet::new([CapabilityGrant::new(
            CapabilityName::new("repo.read").unwrap(),
            ResourceRef::new("repo:hexrift/WardOS").unwrap(),
            delegable,
        )])
        .unwrap()
    }

    fn recorded_lease(lease: u128, parent: Option<u128>) -> RecordedLease {
        RecordedLease {
            lease: LeaseId::from_u128(lease),
            delegation: DelegationId::from_u128(lease + 1),
            issuer: PrincipalId::from_u128(2),
            subject: AgentId::from_u128(lease + 2),
            parent_lease: parent.map(LeaseId::from_u128),
            delegated_by: parent.map(|parent| AgentId::from_u128(parent + 2)),
            grants: grants(parent.is_none()),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 9_000,
            version: if parent.is_some() { 2 } else { 1 },
        }
    }

    fn authority() -> AuthorityRecord {
        AuthorityRecord {
            lease: recorded_lease(9, Some(20)),
            lineage: vec![recorded_lease(20, None)],
            issued_at_unix_ms: 2_000,
            expires_at_unix_ms: 8_000,
            version: 1,
            admitted_at_unix_ms: 5_000,
        }
    }

    fn audited_record(task: u128) -> TaskRecord {
        let mut record = record(task);
        if let Some(admitted) = record.admitted.as_mut() {
            admitted.authority = Some(authority());
        }
        record
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn open_store() -> (tempfile::TempDir, TaskStore) {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        open_private_dir(&state).unwrap();
        let store = TaskStore::open(&state).unwrap();
        (dir, store)
    }

    #[test]
    fn a_record_round_trips_privately_and_removal_forgets_it() {
        let (dir, store) = open_store();
        let tasks = dir.path().join("state").join(TASKS_DIR);
        assert_eq!(mode(&tasks), 0o700);
        let (first, mut second) = (record(1), record(2));
        second.state = RecordedState::Sealed;
        second.sealed = Some(SealRecord {
            by: op(70),
            order: 3,
        });
        second.outcome = Some(TaskExecutionOutcome::Failed);
        second.process = None;
        store.write(&first).unwrap();
        store.write(&second).unwrap();
        assert_eq!(
            mode(&tasks.join(format!("{}.json", first.binding.task()))),
            0o600
        );

        let mut loaded = store.load(2).unwrap();
        loaded.sort_by_key(|record| record.binding.task());
        assert_eq!(loaded, vec![first.clone(), second.clone()]);

        store.remove(first.binding.task()).unwrap();
        store.remove(first.binding.task()).unwrap();
        assert_eq!(store.load(2).unwrap(), vec![second]);
        let leftovers: Vec<_> = std::fs::read_dir(&tasks)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn an_interrupted_write_leaves_a_temporary_file_that_loading_ignores() {
        let (dir, store) = open_store();
        store.write(&record(1)).unwrap();
        let tasks = dir.path().join("state").join(TASKS_DIR);
        std::fs::write(
            tasks.join(format!(".{}.json.tmp", binding(1).task())),
            b"{half",
        )
        .unwrap();
        assert_eq!(store.load(1).unwrap(), vec![record(1)]);
    }

    #[test]
    fn invalid_entries_fail_the_whole_load_closed() {
        let valid = serde_json::to_value(record(1)).unwrap();
        let with = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = valid.clone();
            change(&mut value);
            serde_json::to_vec(&value).unwrap()
        };
        let name = format!("{}.json", binding(1).task());
        let cases: Vec<(String, Vec<u8>)> = vec![
            (name.clone(), b"{not json".to_vec()),
            (name.clone(), with(&|value| value["format"] = 2.into())),
            (name.clone(), with(&|value| value["extra"] = true.into())),
            (
                name.clone(),
                with(&|value| value["state"] = "dreaming".into()),
            ),
            (
                name.clone(),
                with(&|value| value["sealed"] = serde_json::json!({"by": 70, "order": 1})),
            ),
            (
                name.clone(),
                with(&|value| {
                    value["paused_by"] = (1..=u64::try_from(MAX_ATTEMPT_PAUSES).unwrap() + 1)
                        .collect::<Vec<_>>()
                        .into();
                }),
            ),
            (format!("{}.json", binding(2).task()), with(&|_| {})),
            (
                format!("{}.json", TaskId::from_u128(u128::MAX)).to_lowercase(),
                with(&|value| {
                    value["binding"]["task"] = TaskId::from_u128(u128::MAX).to_string().into();
                }),
            ),
            ("notes.txt".to_owned(), b"hello".to_vec()),
            (".notes.tmp".to_owned(), b"hello".to_vec()),
            (
                name.clone(),
                vec![b' '; usize::try_from(MAX_STATE_FILE_BYTES).unwrap() + 1],
            ),
        ];
        for (file, content) in cases {
            let (dir, store) = open_store();
            std::fs::write(
                dir.path().join("state").join(TASKS_DIR).join(&file),
                &content,
            )
            .unwrap();
            assert!(
                matches!(store.load(4), Err(TaskRecordError::InvalidRecord(named)) if named == file),
                "{file}: {}",
                String::from_utf8_lossy(&content[..content.len().min(80)])
            );
        }

        let (dir, store) = open_store();
        std::fs::create_dir(dir.path().join("state").join(TASKS_DIR).join(&name)).unwrap();
        assert!(matches!(
            store.load(4),
            Err(TaskRecordError::InvalidRecord(named)) if named == name
        ));

        let (dir, store) = open_store();
        std::os::unix::fs::symlink(
            dir.path().join("elsewhere.json"),
            dir.path().join("state").join(TASKS_DIR).join(&name),
        )
        .unwrap();
        assert!(matches!(
            store.load(4),
            Err(TaskRecordError::InvalidRecord(named)) if named == name
        ));
    }

    #[test]
    fn more_records_than_the_registry_holds_fail_closed() {
        let (_dir, store) = open_store();
        for task in 1..=3 {
            store.write(&record(task)).unwrap();
        }
        assert_eq!(store.load(3).unwrap().len(), 3);
        assert!(matches!(
            store.load(2),
            Err(TaskRecordError::TooManyRecords(2))
        ));
    }

    #[test]
    fn a_shared_records_directory_is_refused() {
        let (dir, _store) = open_store();
        let state = dir.path().join("state");
        std::fs::set_permissions(
            state.join(TASKS_DIR),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(matches!(
            TaskStore::open(&state),
            Err(TaskRecordError::Directory(
                NodeStateError::InsecureDirectory
            ))
        ));
    }

    #[test]
    fn a_record_larger_than_the_state_file_bound_is_refused_unwritten() {
        let (dir, store) = open_store();
        let mut huge = record(1);
        huge.workspace = Some(PathBuf::from(
            "w".repeat(usize::try_from(MAX_STATE_FILE_BYTES).unwrap()),
        ));
        assert!(matches!(
            store.write(&huge),
            Err(TaskRecordError::RecordTooLarge(task)) if task == binding(1).task()
        ));
        assert_eq!(
            std::fs::read_dir(dir.path().join("state").join(TASKS_DIR))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn authority_facts_round_trip_and_a_record_without_them_still_loads() {
        let (dir, store) = open_store();
        let audited = audited_record(1);
        store.write(&audited).unwrap();
        assert_eq!(store.load(1).unwrap(), vec![audited.clone()]);
        assert_eq!(
            store.read(binding(1).task()).unwrap(),
            Some(audited.clone())
        );
        assert_eq!(store.read(binding(2).task()).unwrap(), None);

        let mut value = serde_json::to_value(&audited).unwrap();
        assert!(
            value["admitted"]
                .as_object_mut()
                .unwrap()
                .remove("authority")
                .is_some()
        );
        std::fs::write(
            dir.path()
                .join("state")
                .join(TASKS_DIR)
                .join(format!("{}.json", binding(1).task())),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        let loaded = store.read(binding(1).task()).unwrap().unwrap();
        assert_eq!(loaded.admitted.as_ref().unwrap().authority, None);
        assert_eq!(loaded, record(1));
        assert_eq!(store.load(1).unwrap(), vec![record(1)]);
    }

    #[test]
    fn authority_facts_beyond_the_envelope_bounds_are_refused() {
        let name = format!("{}.json", binding(1).task());
        let too_deep = {
            let mut record = audited_record(1);
            let authority = record
                .admitted
                .as_mut()
                .unwrap()
                .authority
                .as_mut()
                .unwrap();
            authority.lineage = (0..=MAX_ADMISSION_LINEAGE)
                .map(|depth| recorded_lease(100 + u128::try_from(depth).unwrap(), None))
                .collect();
            serde_json::to_vec(&record).unwrap()
        };
        let too_many_grants = {
            let mut value = serde_json::to_value(audited_record(1)).unwrap();
            let grants: Vec<serde_json::Value> = (0..=MAX_RECORDED_GRANTS)
                .map(|index| {
                    serde_json::json!({
                        "capability": "repo.read",
                        "resource": format!("repo:{index:08}"),
                        "delegable": false,
                    })
                })
                .collect();
            value["admitted"]["authority"]["lease"]["grants"] = grants.into();
            serde_json::to_vec(&value).unwrap()
        };
        let unknown_field = {
            let mut value = serde_json::to_value(audited_record(1)).unwrap();
            value["admitted"]["authority"]["extra"] = true.into();
            serde_json::to_vec(&value).unwrap()
        };
        for content in [too_deep, too_many_grants, unknown_field] {
            let (dir, store) = open_store();
            std::fs::write(
                dir.path().join("state").join(TASKS_DIR).join(&name),
                &content,
            )
            .unwrap();
            assert!(matches!(
                store.load(4),
                Err(TaskRecordError::InvalidRecord(named)) if named == name
            ));
            assert!(matches!(
                store.read(binding(1).task()),
                Err(TaskRecordError::InvalidRecord(named)) if named == name
            ));
        }
    }

    #[test]
    fn reading_one_record_refuses_a_truncated_oversized_or_misnamed_one() {
        let name = format!("{}.json", binding(1).task());
        let whole = serde_json::to_vec(&audited_record(1)).unwrap();
        let cases = vec![
            whole[..whole.len() / 2].to_vec(),
            vec![b' '; usize::try_from(MAX_STATE_FILE_BYTES).unwrap() + 1],
            serde_json::to_vec(&audited_record(2)).unwrap(),
        ];
        for content in cases {
            let (dir, store) = open_store();
            std::fs::write(
                dir.path().join("state").join(TASKS_DIR).join(&name),
                &content,
            )
            .unwrap();
            assert!(matches!(
                store.read(binding(1).task()),
                Err(TaskRecordError::InvalidRecord(named)) if named == name
            ));
        }

        let (dir, store) = open_store();
        std::fs::create_dir(dir.path().join("state").join(TASKS_DIR).join(&name)).unwrap();
        assert!(matches!(
            store.read(binding(1).task()),
            Err(TaskRecordError::InvalidRecord(named)) if named == name
        ));
    }
}
