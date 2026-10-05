//! Node-allocated task workspaces and the node-owned snapshot store (ADR-0030 §1).
//!
//! The node keeps its project content in a content-addressed snapshot store under its
//! state directory (`<state-dir>/cas`, [`SNAPSHOT_STORE_DIR`]); `ward-node snapshot import`
//! captures a local directory into it. On `start` the node allocates
//! `<task-root>/<task>/<attempt>/` itself, mode 0700, and materialises the admitted
//! envelope's snapshot id into it. No path ever comes from a request, and an attempt's
//! workspace is created exactly once: an existing one refuses the start, so an attempt is
//! never re-run over leftovers of an earlier run.

use std::fs::DirBuilder;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;
use ward_node_protocol::TaskBinding;
use ward_snapshot::{CaptureOptions, Digest, SnapshotRole, SnapshotStore};

/// Directory, inside the node state directory, holding the node's snapshot store.
pub const SNAPSHOT_STORE_DIR: &str = "cas";

/// Why the task root could not be opened.
#[derive(Debug, Error)]
pub enum TaskRootError {
    /// Task root I/O failed.
    #[error("task root I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The task root exists but is not a directory (or is a symlink).
    #[error("task root is not a directory")]
    NotADirectory,
    /// The task root is accessible to group or others.
    #[error("task root must be private (mode 0700 or stricter)")]
    InsecureDirectory,
}

/// Why an attempt's workspace could not be prepared. Nothing is left behind.
#[derive(Debug, Error)]
pub enum WorkspaceError {
    /// The snapshot is not in the node's store, or cannot be read from it intact.
    #[error("snapshot is not available in the node store")]
    SnapshotUnavailable,
    /// The attempt already has a workspace; an attempt never runs twice.
    #[error("the attempt already has a workspace")]
    AttemptExists,
    /// Creating or materialising the workspace failed.
    #[error("workspace preparation failed: {0}")]
    Io(String),
}

/// The private directory under which the node allocates task workspaces.
#[derive(Clone, Debug)]
pub struct TaskRoot {
    dir: PathBuf,
}

impl TaskRoot {
    /// Open (creating mode 0700 if absent) the task root at `dir`.
    ///
    /// # Errors
    ///
    /// Returns [`TaskRootError`] if `dir` is not a real directory or is accessible to group
    /// or others.
    pub fn open(dir: &Path) -> Result<Self, TaskRootError> {
        match std::fs::symlink_metadata(dir) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            }
            Err(error) => return Err(error.into()),
        }
        let metadata = std::fs::symlink_metadata(dir)?;
        if !metadata.is_dir() {
            return Err(TaskRootError::NotADirectory);
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(TaskRootError::InsecureDirectory);
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// The task root directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The workspace path of the attempt `binding` names: `<task-root>/<task>/<attempt>`.
    #[must_use]
    pub fn workspace(&self, binding: TaskBinding) -> PathBuf {
        self.dir
            .join(binding.task().to_string())
            .join(binding.attempt().to_string())
    }

    /// Allocate the attempt's workspace and materialise `snapshot` into it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError`]; on error no workspace exists for the attempt.
    pub fn materialise(
        &self,
        binding: TaskBinding,
        snapshots: &SnapshotStore,
        snapshot: ward_events::SnapshotId,
    ) -> Result<PathBuf, WorkspaceError> {
        let id = store_id(snapshot);
        snapshots
            .manifest(id)
            .map_err(|_| WorkspaceError::SnapshotUnavailable)?;

        let task_dir = self.dir.join(binding.task().to_string());
        match DirBuilder::new().mode(0o700).create(&task_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(WorkspaceError::Io(error.to_string())),
        }
        let metadata = std::fs::symlink_metadata(&task_dir)
            .map_err(|error| WorkspaceError::Io(error.to_string()))?;
        if !metadata.is_dir() {
            return Err(WorkspaceError::Io(
                "task directory is not a directory".into(),
            ));
        }

        let workspace = self.workspace(binding);
        match DirBuilder::new().mode(0o700).create(&workspace) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(WorkspaceError::AttemptExists);
            }
            Err(error) => return Err(WorkspaceError::Io(error.to_string())),
        }
        if let Err(error) = snapshots.materialize(id, &workspace) {
            discard(&workspace);
            return Err(WorkspaceError::Io(error.to_string()));
        }
        Ok(workspace)
    }
}

/// Remove a workspace the node allocated for an attempt that never ran.
pub(crate) fn discard(workspace: &Path) {
    let _ = std::fs::remove_dir_all(workspace);
}

/// Open the node's snapshot store under its private state directory.
///
/// # Errors
///
/// Returns the store's error if it cannot be opened or created.
pub fn open_snapshot_store(state_dir: &Path) -> ward_snapshot::Result<SnapshotStore> {
    SnapshotStore::open(state_dir.join(SNAPSHOT_STORE_DIR))
}

/// Capture `project_dir` into the node's snapshot store and return its id, the id an
/// admission envelope names for the workload's project snapshot.
///
/// # Errors
///
/// Returns the store's error if the directory cannot be captured or stored.
pub fn import_snapshot(
    snapshots: &SnapshotStore,
    project_dir: &Path,
) -> ward_snapshot::Result<ward_events::SnapshotId> {
    let id =
        snapshots.store_snapshot(project_dir, SnapshotRole::Entry, CaptureOptions::default())?;
    Ok(ward_events::SnapshotId::new(
        ward_events::Blake3Hash::from_bytes(*id.digest().as_bytes()),
    ))
}

fn store_id(snapshot: ward_events::SnapshotId) -> ward_snapshot::SnapshotId {
    ward_snapshot::SnapshotId(Digest::from_bytes(*snapshot.hash().as_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_events::{Blake3Hash, ExecutionAttemptId, LeaseId, SnapshotId, TaskId};

    use super::*;

    fn binding() -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        )
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn task_root_is_created_private_and_an_exposed_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tasks");
        TaskRoot::open(&root).unwrap();
        assert_eq!(mode(&root), 0o700);

        for exposed in [0o750, 0o705, 0o755, 0o777] {
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(exposed)).unwrap();
            assert!(
                matches!(TaskRoot::open(&root), Err(TaskRootError::InsecureDirectory)),
                "{exposed:o}"
            );
        }
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            TaskRoot::open(&file),
            Err(TaskRootError::NotADirectory)
        ));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        assert!(matches!(
            TaskRoot::open(&link),
            Err(TaskRootError::NotADirectory)
        ));
    }

    #[test]
    fn import_then_materialise_allocates_a_private_workspace_once() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::write(project.join("src/main.txt"), b"hello").unwrap();
        let store = open_snapshot_store(&dir.path().join("state")).unwrap();
        let id = import_snapshot(&store, &project).unwrap();
        assert_eq!(
            id.to_string(),
            store
                .store_snapshot(&project, SnapshotRole::Entry, CaptureOptions::default())
                .unwrap()
                .to_string()
        );

        let root = TaskRoot::open(&dir.path().join("tasks")).unwrap();
        let workspace = root.materialise(binding(), &store, id).unwrap();
        assert_eq!(
            workspace,
            dir.path()
                .join("tasks")
                .join(binding().task().to_string())
                .join(binding().attempt().to_string())
        );
        assert_eq!(
            std::fs::read(workspace.join("src/main.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(mode(workspace.parent().unwrap()), 0o700);
        assert_eq!(mode(&workspace), 0o700);

        assert!(matches!(
            root.materialise(binding(), &store, id),
            Err(WorkspaceError::AttemptExists)
        ));
    }

    #[test]
    fn a_snapshot_missing_from_the_store_allocates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_snapshot_store(&dir.path().join("state")).unwrap();
        let root = TaskRoot::open(&dir.path().join("tasks")).unwrap();
        let missing = SnapshotId::new(Blake3Hash::from_bytes([0x11; 32]));
        assert!(matches!(
            root.materialise(binding(), &store, missing),
            Err(WorkspaceError::SnapshotUnavailable)
        ));
        assert_eq!(std::fs::read_dir(root.dir()).unwrap().count(), 0);
    }
}
