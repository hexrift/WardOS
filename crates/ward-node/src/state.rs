//! Durable node state for admission (ADR-0030 §2).
//!
//! The node keeps a small, file-based state directory (created mode 0700, refused when
//! accessible to group or others) holding:
//!
//! * `node-id` — the node's audience identity (`node_…` and a newline), pinned at first
//!   start; a later start under another id is refused;
//! * `admission-versions.json` — the last admission envelope version durably accepted per
//!   task, as `{"format":1,"versions":{"task_…":N}}`;
//! * `revocations.json` — known lease revocation facts, as
//!   `{"format":1,"revocations":[{"lease":"lease_…","revoked_at_unix_ms":N,"reason":"operator"}]}`
//!   with reasons `operator`, `policy`, `delegation_revoked` or `security`.
//!
//! Every write goes to a temporary file in the same directory, is fsynced, renamed over
//! the target and the directory is fsynced, so a crash leaves either the old or the new
//! content. A store is updated on disk before the in-memory view, so a failed write
//! changes nothing. Malformed or oversized files fail closed when the state is opened.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ward_authority::revocation::{AuthorityRevocation, AuthorityRevocations, RevocationReason};
use ward_events::{LeaseId, NodeId, TaskId};
use ward_node_protocol::AdmissionVersion;

/// File pinning the node identity inside the state directory.
pub const NODE_ID_FILE: &str = "node-id";
/// File holding the last accepted admission version per task.
pub const ADMISSION_VERSIONS_FILE: &str = "admission-versions.json";
/// File holding known revocation facts.
pub const REVOCATIONS_FILE: &str = "revocations.json";
/// Maximum size in bytes of one state file.
pub const MAX_STATE_FILE_BYTES: u64 = 8 * 1024 * 1024;

const STATE_FORMAT: u32 = 1;

/// Why durable node state could not be opened or updated.
#[derive(Debug, Error)]
pub enum NodeStateError {
    /// State I/O failed.
    #[error("node state I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The state path exists but is not a directory.
    #[error("node state path is not a directory")]
    NotADirectory,
    /// The state directory is accessible to group or others.
    #[error("node state directory must be private (mode 0700 or stricter)")]
    InsecureDirectory,
    /// The state directory is pinned to another node identity.
    #[error("node state directory belongs to {recorded}")]
    NodeIdMismatch {
        /// The identity recorded at first start.
        recorded: NodeId,
    },
    /// A state file is not a regular file, is oversized or is malformed.
    #[error("node state file {0} is invalid")]
    InvalidFile(&'static str),
    /// A version was not strictly greater than the last accepted one for its task.
    #[error("admission version is not newer than the last accepted version")]
    NonIncreasingVersion,
    /// The revocation was recorded, and it conflicts with an earlier fact for the same
    /// lease, which is now unusable.
    #[error("conflicting revocation facts for one lease")]
    RevocationConflict,
}

/// Open (creating mode 0700 if absent) the private node state directory `dir`, without
/// reading or pinning anything in it.
///
/// # Errors
///
/// Returns [`NodeStateError`] when `dir` is not a real directory or is accessible to
/// group or others.
pub fn open_private_dir(dir: &Path) -> Result<(), NodeStateError> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(dir)?;
    if !metadata.is_dir() {
        return Err(NodeStateError::NotADirectory);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(NodeStateError::InsecureDirectory);
    }
    Ok(())
}

/// Durable, file-based node state: pinned identity, admission versions and revocations.
#[derive(Debug)]
pub struct NodeState {
    dir: PathBuf,
    node: NodeId,
    versions: BTreeMap<TaskId, AdmissionVersion>,
    revocation_facts: Vec<AuthorityRevocation>,
    revocations: AuthorityRevocations,
}

impl NodeState {
    /// Open (creating mode 0700 if absent) the state directory for node `node`.
    ///
    /// # Errors
    ///
    /// Returns [`NodeStateError`] when the directory is unsafe, pinned to another node or
    /// holds an invalid state file.
    pub fn open(dir: &Path, node: NodeId) -> Result<Self, NodeStateError> {
        open_private_dir(dir)?;

        match read_state_file(dir, NODE_ID_FILE)? {
            Some(text) => {
                let recorded = text
                    .strip_suffix('\n')
                    .and_then(|id| id.parse::<NodeId>().ok())
                    .ok_or(NodeStateError::InvalidFile(NODE_ID_FILE))?;
                if recorded != node {
                    return Err(NodeStateError::NodeIdMismatch { recorded });
                }
            }
            None => write_atomic(dir, NODE_ID_FILE, format!("{node}\n").as_bytes())?,
        }

        let versions = match read_state_file(dir, ADMISSION_VERSIONS_FILE)? {
            Some(text) => {
                serde_json::from_str::<VersionsFile>(&text)
                    .ok()
                    .filter(|file| file.format == STATE_FORMAT)
                    .ok_or(NodeStateError::InvalidFile(ADMISSION_VERSIONS_FILE))?
                    .versions
            }
            None => BTreeMap::new(),
        };

        let mut revocation_facts = Vec::new();
        let mut revocations = AuthorityRevocations::new();
        if let Some(text) = read_state_file(dir, REVOCATIONS_FILE)? {
            let file = serde_json::from_str::<RevocationsFile>(&text)
                .ok()
                .filter(|file| file.format == STATE_FORMAT)
                .ok_or(NodeStateError::InvalidFile(REVOCATIONS_FILE))?;
            for record in file.revocations {
                let fact = AuthorityRevocation::new(
                    record.lease,
                    record.revoked_at_unix_ms,
                    record.reason.into(),
                );
                let _ = revocations.record(fact);
                revocation_facts.push(fact);
            }
        }

        Ok(Self {
            dir: dir.to_path_buf(),
            node,
            versions,
            revocation_facts,
            revocations,
        })
    }

    /// The state directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The pinned node identity.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// The last admission version durably accepted for `task`, if any.
    #[must_use]
    pub fn last_admitted_version(&self, task: TaskId) -> Option<AdmissionVersion> {
        self.versions.get(&task).copied()
    }

    /// Durably record `version` as the last accepted admission version for `task`.
    ///
    /// # Errors
    ///
    /// Returns [`NodeStateError::NonIncreasingVersion`] unless `version` is strictly
    /// greater than the recorded one, or an I/O error; nothing changes on error.
    pub fn record_admitted_version(
        &mut self,
        task: TaskId,
        version: AdmissionVersion,
    ) -> Result<(), NodeStateError> {
        if self
            .versions
            .get(&task)
            .is_some_and(|last| version <= *last)
        {
            return Err(NodeStateError::NonIncreasingVersion);
        }
        let mut versions = self.versions.clone();
        versions.insert(task, version);
        let file = VersionsFile {
            format: STATE_FORMAT,
            versions,
        };
        write_json(&self.dir, ADMISSION_VERSIONS_FILE, &file)?;
        self.versions = file.versions;
        Ok(())
    }

    /// Known revocations, as loaded from and recorded to the durable store.
    #[must_use]
    pub const fn revocations(&self) -> &AuthorityRevocations {
        &self.revocations
    }

    /// Durably record one trusted revocation fact.
    ///
    /// Replaying the exact same fact changes nothing. A different fact for an already
    /// revoked lease is persisted and marks that lease conflicted (and so unusable).
    ///
    /// # Errors
    ///
    /// Returns an I/O error (nothing changes), or
    /// [`NodeStateError::RevocationConflict`] after persisting a conflicting fact.
    pub fn record_revocation(
        &mut self,
        revocation: AuthorityRevocation,
    ) -> Result<(), NodeStateError> {
        if self.revocation_facts.contains(&revocation) {
            return Ok(());
        }
        let records = self
            .revocation_facts
            .iter()
            .chain(std::iter::once(&revocation))
            .map(|fact| RevocationRecord {
                lease: fact.lease_id(),
                revoked_at_unix_ms: fact.revoked_at_unix_ms(),
                reason: fact.reason().into(),
            })
            .collect();
        write_json(
            &self.dir,
            REVOCATIONS_FILE,
            &RevocationsFile {
                format: STATE_FORMAT,
                revocations: records,
            },
        )?;
        self.revocation_facts.push(revocation);
        self.revocations
            .record(revocation)
            .map_err(|_| NodeStateError::RevocationConflict)
    }
}

fn read_state_file(dir: &Path, name: &'static str) -> Result<Option<String>, NodeStateError> {
    let path = dir.join(name);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() > MAX_STATE_FILE_BYTES {
        return Err(NodeStateError::InvalidFile(name));
    }
    let file = File::open(&path)?;
    let mut bytes = Vec::new();
    file.take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > usize::try_from(MAX_STATE_FILE_BYTES).unwrap_or(usize::MAX) {
        return Err(NodeStateError::InvalidFile(name));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| NodeStateError::InvalidFile(name))
}

fn write_json(dir: &Path, name: &str, value: &impl Serialize) -> Result<(), NodeStateError> {
    let bytes = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    write_atomic(dir, name, &bytes)
}

fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), NodeStateError> {
    let temporary = dir.join(format!(".{name}.tmp"));
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, dir.join(name))?;
        File::open(dir)?.sync_all()
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.map_err(NodeStateError::from)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionsFile {
    format: u32,
    versions: BTreeMap<TaskId, AdmissionVersion>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationsFile {
    format: u32,
    revocations: Vec<RevocationRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationRecord {
    lease: LeaseId,
    revoked_at_unix_ms: u64,
    reason: ReasonRecord,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReasonRecord {
    Operator,
    Policy,
    DelegationRevoked,
    Security,
}

impl From<RevocationReason> for ReasonRecord {
    fn from(reason: RevocationReason) -> Self {
        match reason {
            RevocationReason::Operator => Self::Operator,
            RevocationReason::Policy => Self::Policy,
            RevocationReason::DelegationRevoked => Self::DelegationRevoked,
            RevocationReason::Security => Self::Security,
        }
    }
}

impl From<ReasonRecord> for RevocationReason {
    fn from(reason: ReasonRecord) -> Self {
        match reason {
            ReasonRecord::Operator => Self::Operator,
            ReasonRecord::Policy => Self::Policy,
            ReasonRecord::DelegationRevoked => Self::DelegationRevoked,
            ReasonRecord::Security => Self::Security,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_authority::AuthorityLease;
    use ward_authority::revocation::LeaseLineage;

    use super::*;
    use crate::test_support::trusted_root_lease;

    fn node() -> NodeId {
        NodeId::from_u128(4)
    }

    fn version(value: u64) -> AdmissionVersion {
        AdmissionVersion::new(value).unwrap()
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn usable(state: &NodeState, lease: &AuthorityLease, now: u64) -> bool {
        let lineage = LeaseLineage::for_lease(lease, []).unwrap();
        state
            .revocations()
            .is_usable_with_lineage(lease, &lineage, now)
    }

    #[test]
    fn state_directory_is_created_private_and_pins_the_node_identity() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("state");

        let state = NodeState::open(&dir, node()).unwrap();
        assert_eq!(state.node(), node());
        assert_eq!(state.dir(), dir);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(
            std::fs::read_to_string(dir.join(NODE_ID_FILE)).unwrap(),
            format!("{}\n", node())
        );
        assert_eq!(mode(&dir.join(NODE_ID_FILE)), 0o600);
        drop(state);

        assert_eq!(NodeState::open(&dir, node()).unwrap().node(), node());
        assert!(matches!(
            NodeState::open(&dir, NodeId::from_u128(99)),
            Err(NodeStateError::NodeIdMismatch { recorded }) if recorded == node()
        ));
    }

    #[test]
    fn a_shared_or_non_directory_state_path_is_refused() {
        let parent = tempfile::tempdir().unwrap();
        let shared = parent.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        for loose in [0o755, 0o750, 0o707] {
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(loose)).unwrap();
            assert!(
                matches!(
                    NodeState::open(&shared, node()),
                    Err(NodeStateError::InsecureDirectory)
                ),
                "mode {loose:o}"
            );
        }

        let file = parent.path().join("file");
        std::fs::write(&file, "").unwrap();
        assert!(matches!(
            NodeState::open(&file, node()),
            Err(NodeStateError::NotADirectory)
        ));
    }

    #[test]
    fn admission_versions_are_strictly_increasing_and_survive_restart() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("state");
        let task = TaskId::from_u128(7);
        let other = TaskId::from_u128(8);

        let mut state = NodeState::open(&dir, node()).unwrap();
        assert_eq!(state.last_admitted_version(task), None);
        state.record_admitted_version(task, version(2)).unwrap();
        for stale in [1, 2] {
            assert!(matches!(
                state.record_admitted_version(task, version(stale)),
                Err(NodeStateError::NonIncreasingVersion)
            ));
        }
        state.record_admitted_version(other, version(1)).unwrap();
        assert_eq!(state.last_admitted_version(task), Some(version(2)));
        assert_eq!(mode(&dir.join(ADMISSION_VERSIONS_FILE)), 0o600);
        drop(state);

        let mut state = NodeState::open(&dir, node()).unwrap();
        assert_eq!(state.last_admitted_version(task), Some(version(2)));
        assert_eq!(state.last_admitted_version(other), Some(version(1)));
        assert!(matches!(
            state.record_admitted_version(task, version(2)),
            Err(NodeStateError::NonIncreasingVersion)
        ));
        state.record_admitted_version(task, version(3)).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_failed_version_write_changes_nothing() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("state");
        let task = TaskId::from_u128(7);
        let mut state = NodeState::open(&dir, node()).unwrap();
        std::fs::create_dir_all(dir.join(ADMISSION_VERSIONS_FILE).join("blocker")).unwrap();

        assert!(matches!(
            state.record_admitted_version(task, version(1)),
            Err(NodeStateError::Io(_))
        ));
        assert_eq!(state.last_admitted_version(task), None);
    }

    #[test]
    fn revocations_are_durable_and_conflicts_survive_restart() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("state");
        let lease = trusted_root_lease();
        let fact = AuthorityRevocation::new(lease.id(), 3_000, RevocationReason::Operator);

        let mut state = NodeState::open(&dir, node()).unwrap();
        assert!(usable(&state, &lease, 5_000));
        state.record_revocation(fact).unwrap();
        state.record_revocation(fact).unwrap();
        assert!(!usable(&state, &lease, 5_000));
        assert!(usable(&state, &lease, 2_999));
        assert_eq!(mode(&dir.join(REVOCATIONS_FILE)), 0o600);
        drop(state);

        let mut state = NodeState::open(&dir, node()).unwrap();
        assert!(!usable(&state, &lease, 5_000));
        assert!(usable(&state, &lease, 2_999));
        assert!(matches!(
            state.record_revocation(AuthorityRevocation::new(
                lease.id(),
                4_000,
                RevocationReason::Security
            )),
            Err(NodeStateError::RevocationConflict)
        ));
        assert!(!usable(&state, &lease, 2_999));
        drop(state);

        let state = NodeState::open(&dir, node()).unwrap();
        assert!(state.revocations().is_conflicted(lease.id()));
        assert!(!usable(&state, &lease, 2_999));
    }

    #[test]
    fn malformed_or_oversized_state_files_fail_closed() {
        for (file, content) in [
            (ADMISSION_VERSIONS_FILE, "{not json".to_owned()),
            (
                ADMISSION_VERSIONS_FILE,
                r#"{"format":1,"versions":{"task_00000000000000000000000007":0}}"#.to_owned(),
            ),
            (
                ADMISSION_VERSIONS_FILE,
                r#"{"format":2,"versions":{}}"#.to_owned(),
            ),
            (
                ADMISSION_VERSIONS_FILE,
                r#"{"format":1,"versions":{},"extra":1}"#.to_owned(),
            ),
            (
                REVOCATIONS_FILE,
                r#"{"format":1,"revocations":[{"lease":"lease_00000000000000000000000009","revoked_at_unix_ms":1,"reason":"whim"}]}"#
                    .to_owned(),
            ),
            (NODE_ID_FILE, "not-a-node-id\n".to_owned()),
            (
                ADMISSION_VERSIONS_FILE,
                " ".repeat(usize::try_from(MAX_STATE_FILE_BYTES).unwrap() + 1),
            ),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let dir = parent.path().join("state");
            drop(NodeState::open(&dir, node()).unwrap());
            std::fs::write(dir.join(file), &content).unwrap();
            assert!(
                matches!(
                    NodeState::open(&dir, node()),
                    Err(NodeStateError::InvalidFile(name)) if name == file
                ),
                "{file}: {}",
                content.chars().take(80).collect::<String>()
            );
        }
    }
}
