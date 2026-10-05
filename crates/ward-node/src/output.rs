//! Bounded result return for admitted attempts (#332 stage 2, the result half).
//!
//! A node started with `--output-return`
//! ([`crate::execution::NodeExecution::with_output_return`]) honours a manifest's `output`
//! grant ([`OutputGrant`]): while the workload runs the launcher keeps exactly the first
//! `stdio_bytes` of its stdout and of its stderr (a head; the rest is drained and
//! counted), and once the workload has ended and been reaped the attempt's reaper
//! collects the declared files from the workspace ([`collect`]). Nothing of the
//! workspace is read while the attempt executes.
//!
//! Collection is bounded and never leaves the workspace: a declared path is relative and
//! in the grammar of [`ward_node_protocol::OutputPath`] (no `..`, no absolute path), each
//! component is looked at without following symlinks, and a symlink, directory or other
//! non-regular file anywhere on the path is reported `not_a_regular_file` with nothing
//! followed or read. A regular file is returned whole while it fits the remaining
//! `files_bytes` budget, digest-only past it, and reported `too_large` without being read
//! or hashed above [`MAX_OUTPUT_FILE_BYTES`]. Every size is the size read, every digest
//! `BLAKE3-256` of exactly the bytes a control plane can compare against.
//!
//! The result is durable: [`AttemptOutputStore`] writes it as `result.json` (mode 0600)
//! in `<task-root>/<task>/<attempt>.output/` (mode 0700), beside the workspace and the
//! evidence directory and never inside the workspace, with the same temporary-file,
//! fsync and rename discipline as every node state file, so it survives a node restart
//! and `seal`. The evidence log records what was collected ([`collected_event`]), with
//! every digest, before the attempt's end record; a result whose record cannot be
//! appended is removed again rather than served unbound. Retention is the operator's,
//! as for workspaces and evidence logs.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;
use ward_events::{
    Blake3Hash, NodeOutputFile, NodeOutputFileStatus, NodeOutputStream, SandboxPath, SandboxRoot,
    WardEvent,
};
use ward_node_protocol::{
    AttemptOutput, MAX_OUTPUT_FILE_BYTES, MAX_OUTPUT_FILES_BYTES, MAX_OUTPUT_STDIO_BYTES,
    MAX_RESULT_RESPONSE_BYTES, OutputFile, OutputFileSkip, OutputFileStatus, OutputGrant,
    OutputStream, TaskBinding,
};

use crate::evidence::private_dir;
use crate::state::write_atomic;

/// Suffix of an attempt's output directory, beside its workspace.
pub const OUTPUT_SUFFIX: &str = ".output";

/// File name of the stored result inside an attempt's output directory.
pub const RESULT_FILE: &str = "result.json";

/// Bytes read at a time while digesting a file that is not returned inline.
const DIGEST_CHUNK: usize = 64 * 1024;

/// One captured stream as the launcher hands it over: the head it kept and the total the
/// workload wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapturedStream {
    /// Exactly the first bytes of the stream, up to the granted budget.
    pub head: Vec<u8>,
    /// Every byte the workload wrote, the head included.
    pub total: u64,
}

/// Both captured streams of a workload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapturedStdio {
    /// The workload's stdout.
    pub stdout: CapturedStream,
    /// The workload's stderr.
    pub stderr: CapturedStream,
}

/// The output directory of `binding` under the task root `root`:
/// `<root>/<task>/<attempt>.output`.
#[must_use]
pub fn output_dir(root: &Path, binding: TaskBinding) -> PathBuf {
    root.join(binding.task().to_string())
        .join(format!("{}{OUTPUT_SUFFIX}", binding.attempt()))
}

/// The output directory beside the attempt workspace `workspace`.
#[must_use]
pub fn output_dir_beside(workspace: &Path) -> Option<PathBuf> {
    let attempt = workspace.file_name()?.to_str()?;
    Some(workspace.with_file_name(format!("{attempt}{OUTPUT_SUFFIX}")))
}

/// Collect what `grant` asks for from the ended attempt's `workspace` and its captured
/// `stdio`. Infallible: whatever cannot be returned is reported as such.
#[must_use]
pub fn collect(workspace: &Path, grant: &OutputGrant, stdio: CapturedStdio) -> AttemptOutput {
    let stdio_budget = grant.stdio_bytes().min(MAX_OUTPUT_STDIO_BYTES);
    let stream = |captured: CapturedStream| {
        let mut head = captured.head;
        head.truncate(usize::try_from(stdio_budget).unwrap_or(usize::MAX));
        let dropped = captured.total.saturating_sub(head.len() as u64);
        OutputStream::new(head, dropped).unwrap_or_default()
    };
    let stdout = stream(stdio.stdout);
    let stderr = stream(stdio.stderr);
    let mut budget = grant.files_bytes().min(MAX_OUTPUT_FILES_BYTES);
    let files = grant
        .files()
        .iter()
        .map(|path| OutputFile {
            path: path.clone(),
            status: collect_file(workspace, path.as_str(), &mut budget),
        })
        .collect();
    AttemptOutput::new(stdout, stderr, files).unwrap_or_default()
}

/// Look at `relative` under `workspace` without following a symlink anywhere on the way,
/// and return the regular file there within `budget`, its digest past it.
fn collect_file(workspace: &Path, relative: &str, budget: &mut u64) -> OutputFileStatus {
    let skipped = OutputFileStatus::Skipped;
    let path = Path::new(relative);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return skipped(OutputFileSkip::NotARegularFile);
    }
    let mut current = workspace.to_path_buf();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        current.push(component);
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return skipped(OutputFileSkip::Missing);
            }
            Err(_) => return skipped(OutputFileSkip::NotARegularFile),
        };
        let last = components.peek().is_none();
        if metadata.file_type().is_symlink() || (!last && !metadata.is_dir()) {
            return skipped(OutputFileSkip::NotARegularFile);
        }
        if last {
            if !metadata.is_file() {
                return skipped(OutputFileSkip::NotARegularFile);
            }
            if metadata.len() > MAX_OUTPUT_FILE_BYTES {
                return skipped(OutputFileSkip::TooLarge);
            }
            return read_regular_file(&current, metadata.dev(), metadata.ino(), budget);
        }
    }
    skipped(OutputFileSkip::Missing)
}

/// Open the regular file `path` that was just inspected as (`dev`, `ino`) and return or
/// digest it. A file that is no longer that inode (something replaced it between the
/// look and the open) is not read.
fn read_regular_file(path: &Path, dev: u64, ino: u64, budget: &mut u64) -> OutputFileStatus {
    let skipped = OutputFileStatus::Skipped;
    let Ok(mut file) = std::fs::File::open(path) else {
        return skipped(OutputFileSkip::NotARegularFile);
    };
    let Ok(opened) = file.metadata() else {
        return skipped(OutputFileSkip::NotARegularFile);
    };
    if !opened.is_file() || opened.dev() != dev || opened.ino() != ino {
        return skipped(OutputFileSkip::NotARegularFile);
    }
    let size = opened.len();
    if size > MAX_OUTPUT_FILE_BYTES {
        return skipped(OutputFileSkip::TooLarge);
    }
    if size <= *budget {
        let mut content = Vec::new();
        if file
            .by_ref()
            .take(MAX_OUTPUT_FILE_BYTES + 1)
            .read_to_end(&mut content)
            .is_err()
        {
            return skipped(OutputFileSkip::NotARegularFile);
        }
        let read = content.len() as u64;
        if read <= *budget {
            *budget -= read;
            return OutputFileStatus::Returned {
                size: read,
                digest: Blake3Hash::hash(&content),
                content,
            };
        }
        return match digest_bytes(&content) {
            Some((size, digest)) => OutputFileStatus::DigestOnly { size, digest },
            None => skipped(OutputFileSkip::TooLarge),
        };
    }
    match digest_reader(&mut file) {
        Some((size, digest)) => OutputFileStatus::DigestOnly { size, digest },
        None => skipped(OutputFileSkip::TooLarge),
    }
}

fn digest_bytes(content: &[u8]) -> Option<(u64, Blake3Hash)> {
    let size = content.len() as u64;
    (size <= MAX_OUTPUT_FILE_BYTES).then(|| (size, Blake3Hash::hash(content)))
}

/// Digest `reader` up to [`MAX_OUTPUT_FILE_BYTES`]; `None` past that or on an I/O error.
fn digest_reader(reader: &mut impl Read) -> Option<(u64, Blake3Hash)> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; DIGEST_CHUNK];
    let mut size: u64 = 0;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        size = size.checked_add(read as u64)?;
        if size > MAX_OUTPUT_FILE_BYTES {
            return None;
        }
        hasher.update(&buffer[..read]);
    }
    Some((size, Blake3Hash::from_bytes(*hasher.finalize().as_bytes())))
}

/// The evidence record of a collected `output`: every count, size, digest and status,
/// never the bytes. `None` only if a declared path cannot be spelled as a workspace path,
/// which the manifest grammar rules out.
#[must_use]
pub fn collected_event(output: &AttemptOutput) -> Option<WardEvent> {
    let stream = |stream: &OutputStream| NodeOutputStream {
        returned: stream.content().len() as u64,
        dropped: stream.dropped(),
    };
    let files = output
        .files()
        .iter()
        .map(|file| {
            let path = SandboxPath::new(SandboxRoot::Work, file.path.as_str()).ok()?;
            let (size, digest, status) = match &file.status {
                OutputFileStatus::Returned { size, digest, .. } => {
                    (*size, Some(*digest), NodeOutputFileStatus::Returned)
                }
                OutputFileStatus::DigestOnly { size, digest } => {
                    (*size, Some(*digest), NodeOutputFileStatus::DigestOnly)
                }
                OutputFileStatus::Skipped(OutputFileSkip::Missing) => {
                    (0, None, NodeOutputFileStatus::Missing)
                }
                OutputFileStatus::Skipped(OutputFileSkip::NotARegularFile) => {
                    (0, None, NodeOutputFileStatus::NotARegularFile)
                }
                OutputFileStatus::Skipped(OutputFileSkip::TooLarge) => {
                    (0, None, NodeOutputFileStatus::TooLarge)
                }
            };
            Some(NodeOutputFile {
                path,
                size,
                digest,
                status,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(WardEvent::NodeAttemptOutputCollected {
        stdout: stream(output.stdout()),
        stderr: stream(output.stderr()),
        files,
    })
}

/// Why a stored result could not be written or read.
#[derive(Debug, Error)]
pub enum OutputStoreError {
    /// Output directory or result I/O failed.
    #[error("output store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A directory on the output path is not a private directory.
    #[error("output path is not a private directory")]
    InsecurePath,
    /// The stored result is not a regular file, is over the bound, or does not decode as
    /// one result document.
    #[error("stored result is invalid")]
    Malformed,
}

/// The durable result of one attempt. The registry's reaper is its only writer.
#[derive(Clone, Debug)]
pub struct AttemptOutputStore {
    dir: PathBuf,
}

impl AttemptOutputStore {
    /// The store of `binding` under the task root `root`.
    #[must_use]
    pub fn new(root: &Path, binding: TaskBinding) -> Self {
        Self {
            dir: output_dir(root, binding),
        }
    }

    /// The store beside the attempt workspace `workspace`.
    #[must_use]
    pub fn beside(workspace: &Path) -> Option<Self> {
        output_dir_beside(workspace).map(|dir| Self { dir })
    }

    /// The output directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Durably write `output` as the attempt's result, replacing any earlier one.
    ///
    /// # Errors
    ///
    /// Returns [`OutputStoreError`] when a directory on the path is not private or the
    /// write fails; nothing is then served.
    pub fn write(&self, output: &AttemptOutput) -> Result<(), OutputStoreError> {
        self.open()?;
        let json = serde_json::to_vec(output).map_err(|_| OutputStoreError::Malformed)?;
        if json.len() > MAX_RESULT_RESPONSE_BYTES {
            return Err(OutputStoreError::Malformed);
        }
        write_atomic(&self.dir, RESULT_FILE, &json)?;
        Ok(())
    }

    /// Read the stored result; `None` when none was written.
    ///
    /// # Errors
    ///
    /// Returns [`OutputStoreError`] when a directory on the path is not private, the
    /// result is not a regular file, exceeds the response bound or does not decode.
    pub fn read(&self) -> Result<Option<AttemptOutput>, OutputStoreError> {
        let path = self.dir.join(RESULT_FILE);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        self.open()?;
        if !metadata.is_file()
            || usize::try_from(metadata.len()).is_ok_and(|len| len > MAX_RESULT_RESPONSE_BYTES)
        {
            return Err(OutputStoreError::Malformed);
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&path)?
            .take(MAX_RESULT_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_RESULT_RESPONSE_BYTES {
            return Err(OutputStoreError::Malformed);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| OutputStoreError::Malformed)
    }

    /// Remove the stored result, if any, so nothing is served.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of a removal that failed for a reason other than absence.
    pub fn remove(&self) -> Result<(), OutputStoreError> {
        match std::fs::remove_file(self.dir.join(RESULT_FILE)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn open(&self) -> Result<(), OutputStoreError> {
        let private = |dir: &Path| {
            private_dir(dir).map_err(|error| match error {
                crate::evidence::EvidenceError::Io(error) => OutputStoreError::Io(error),
                _ => OutputStoreError::InsecurePath,
            })
        };
        if let Some(task_dir) = self.dir.parent() {
            private(task_dir)?;
        }
        private(&self.dir)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;

    use ward_events::{ExecutionAttemptId, LeaseId, TaskId};
    use ward_node_protocol::OutputPath;

    use super::*;

    fn binding() -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(7),
            ExecutionAttemptId::from_u128(8),
            LeaseId::from_u128(9),
        )
    }

    fn grant(stdio: u64, files: &[&str], budget: u64) -> OutputGrant {
        OutputGrant::new(
            stdio,
            files
                .iter()
                .map(|path| OutputPath::new(*path).unwrap())
                .collect(),
            budget,
        )
        .unwrap()
    }

    fn captured(
        stdout: &[u8],
        stdout_total: u64,
        stderr: &[u8],
        stderr_total: u64,
    ) -> CapturedStdio {
        CapturedStdio {
            stdout: CapturedStream {
                head: stdout.to_vec(),
                total: stdout_total,
            },
            stderr: CapturedStream {
                head: stderr.to_vec(),
                total: stderr_total,
            },
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn stdio_is_returned_head_first_within_the_granted_budget_and_the_rest_is_counted() {
        let workspace = tempfile::tempdir().unwrap();
        let output = collect(
            workspace.path(),
            &grant(4, &[], 0),
            captured(b"abcdefgh", 100, b"xy", 2),
        );
        assert_eq!(output.stdout().content(), b"abcd");
        assert_eq!(output.stdout().dropped(), 96);
        assert!(output.stdout().truncated());
        assert_eq!(output.stderr().content(), b"xy");
        assert_eq!(output.stderr().dropped(), 0);
        assert!(!output.stderr().truncated());
        assert!(output.files().is_empty());

        let ceiling = collect(
            workspace.path(),
            &grant(u64::MAX, &[], 0),
            captured(
                &vec![0u8; usize::try_from(MAX_OUTPUT_STDIO_BYTES).unwrap() + 10],
                MAX_OUTPUT_STDIO_BYTES + 10,
                b"",
                0,
            ),
        );
        assert_eq!(
            ceiling.stdout().content().len() as u64,
            MAX_OUTPUT_STDIO_BYTES,
            "the node's ceiling bounds a head the launcher kept past it"
        );
        assert_eq!(ceiling.stdout().dropped(), 10);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn files_are_returned_within_the_budget_digested_past_it_and_never_followed_outside() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("work");
        std::fs::create_dir_all(workspace.join("out")).unwrap();
        std::fs::write(workspace.join("out/report.json"), b"{\"ok\":true}").unwrap();
        std::fs::write(workspace.join("big.bin"), vec![b'b'; 3000]).unwrap();
        std::fs::write(workspace.join("second.txt"), b"second").unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"host secret").unwrap();
        std::os::unix::fs::symlink(&secret, workspace.join("link")).unwrap();
        std::os::unix::fs::symlink("out/report.json", workspace.join("inner-link")).unwrap();
        std::os::unix::fs::symlink(dir.path(), workspace.join("escape")).unwrap();
        std::os::unix::fs::symlink("out", workspace.join("out-link")).unwrap();
        let huge = std::fs::File::create(workspace.join("huge")).unwrap();
        huge.set_len(MAX_OUTPUT_FILE_BYTES + 1).unwrap();

        let output = collect(
            &workspace,
            &grant(
                16,
                &[
                    "out/report.json",
                    "big.bin",
                    "second.txt",
                    "missing.txt",
                    "out",
                    "link",
                    "inner-link",
                    "escape/secret",
                    "out-link/report.json",
                    "huge",
                ],
                100,
            ),
            CapturedStdio::default(),
        );
        let statuses: Vec<(&str, &OutputFileStatus)> = output
            .files()
            .iter()
            .map(|file| (file.path.as_str(), &file.status))
            .collect();
        assert_eq!(
            statuses[0],
            (
                "out/report.json",
                &OutputFileStatus::Returned {
                    size: 11,
                    digest: Blake3Hash::hash(b"{\"ok\":true}"),
                    content: b"{\"ok\":true}".to_vec(),
                }
            )
        );
        assert_eq!(
            statuses[1],
            (
                "big.bin",
                &OutputFileStatus::DigestOnly {
                    size: 3000,
                    digest: Blake3Hash::hash(&vec![b'b'; 3000]),
                }
            ),
            "past the budget: digest only, budget untouched"
        );
        assert_eq!(
            statuses[2],
            (
                "second.txt",
                &OutputFileStatus::Returned {
                    size: 6,
                    digest: Blake3Hash::hash(b"second"),
                    content: b"second".to_vec(),
                }
            ),
            "a later small file still fits what the budget has left"
        );
        assert_eq!(
            statuses[3],
            (
                "missing.txt",
                &OutputFileStatus::Skipped(OutputFileSkip::Missing)
            )
        );
        for (index, name) in [
            (4, "out"),
            (5, "link"),
            (6, "inner-link"),
            (7, "escape/secret"),
            (8, "out-link/report.json"),
        ] {
            assert_eq!(
                statuses[index],
                (
                    name,
                    &OutputFileStatus::Skipped(OutputFileSkip::NotARegularFile)
                ),
                "{name}"
            );
        }
        assert_eq!(
            statuses[9],
            ("huge", &OutputFileStatus::Skipped(OutputFileSkip::TooLarge))
        );
        let json = serde_json::to_string(&output).unwrap();
        assert!(!json.contains("host secret"), "{json}");
        assert!(output.truncated());
    }

    #[test]
    fn the_evidence_record_carries_every_digest_and_status_and_no_bytes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        let output = collect(
            dir.path(),
            &grant(8, &["a.txt", "b.txt"], 1024),
            captured(b"12345678", 20, b"", 0),
        );
        let event = collected_event(&output).unwrap();
        assert_eq!(
            event,
            WardEvent::NodeAttemptOutputCollected {
                stdout: NodeOutputStream {
                    returned: 8,
                    dropped: 12,
                },
                stderr: NodeOutputStream {
                    returned: 0,
                    dropped: 0,
                },
                files: vec![
                    NodeOutputFile {
                        path: SandboxPath::new(SandboxRoot::Work, "a.txt").unwrap(),
                        size: 5,
                        digest: Some(Blake3Hash::hash(b"alpha")),
                        status: NodeOutputFileStatus::Returned,
                    },
                    NodeOutputFile {
                        path: SandboxPath::new(SandboxRoot::Work, "b.txt").unwrap(),
                        size: 0,
                        digest: None,
                        status: NodeOutputFileStatus::Missing,
                    },
                ],
            }
        );
        let encoded = postcard::to_allocvec(&event).unwrap();
        assert!(!encoded.windows(5).any(|window| window == b"alpha"));
    }

    #[test]
    fn the_store_writes_a_private_result_that_reads_back_and_refuses_damage() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = AttemptOutputStore::new(root.path(), binding());
        assert_eq!(
            store.dir(),
            root.path()
                .join(binding().task().to_string())
                .join(format!("{}.output", binding().attempt()))
        );
        assert_eq!(
            AttemptOutputStore::beside(&root.path().join("t").join("exec_x"))
                .unwrap()
                .dir(),
            root.path().join("t").join("exec_x.output")
        );
        assert!(store.read().unwrap().is_none());

        let output = collect(
            root.path(),
            &grant(4, &[], 0),
            captured(b"abcdefgh", 8, b"", 0),
        );
        store.write(&output).unwrap();
        assert_eq!(mode(store.dir().parent().unwrap()), 0o700);
        assert_eq!(mode(store.dir()), 0o700);
        assert_eq!(mode(&store.dir().join(RESULT_FILE)), 0o600);
        assert_eq!(store.read().unwrap(), Some(output.clone()));
        assert!(!store.dir().join(format!(".{RESULT_FILE}.tmp")).exists());

        std::fs::write(store.dir().join(RESULT_FILE), b"{\"stdout\":").unwrap();
        assert!(matches!(store.read(), Err(OutputStoreError::Malformed)));
        store.remove().unwrap();
        assert!(store.read().unwrap().is_none());
        store.remove().unwrap();

        std::fs::set_permissions(store.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            store.write(&output),
            Err(OutputStoreError::InsecurePath)
        ));
        std::fs::set_permissions(store.dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
        store.write(&output).unwrap();
        std::fs::remove_file(store.dir().join(RESULT_FILE)).unwrap();
        std::fs::create_dir(store.dir().join(RESULT_FILE)).unwrap();
        assert!(matches!(store.read(), Err(OutputStoreError::Malformed)));
    }
}
