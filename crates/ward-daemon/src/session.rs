//! Session lifecycle: policy → manifest → entry snapshot → sandboxed execution,
//! all recorded to the append-only event log.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ward_events::{
    AgentIdentity, AgentKind, AgentState, BoundedArgv, BoundedText, Chain, EndReason, EventRecord,
    ExitStatus, FileChangeKind, FsyncPolicy, LogWriter, NameText, Origin, Pid, ProcessRef,
    SandboxPath, SandboxRoot, Timestamp, WardEvent,
};
use ward_policy::{CapabilityManifest, Policy, merge};
use ward_snapshot::{CaptureOptions, SnapshotRole, SnapshotStore};

use crate::error::{Error, Result};
use crate::ids::{ev_hash, ev_snapshot, new_session_id, project_id_for};
use crate::sandbox;

/// A live WardOS session over one project.
pub struct Session {
    manifest: CapabilityManifest,
    worktree: PathBuf,
    entry_snapshot: String,
    chain: Chain,
    log: LogWriter,
    started: SystemTime,
    next_pid: u32,
    root_pid: Pid,
    session_str: String,
    log_path: PathBuf,
}

/// A single command run and the events it produced, for immediate rendering.
pub struct RunReport {
    /// The command that ran.
    pub argv: Vec<String>,
    /// Exit code, or `None` if signalled.
    pub code: Option<i32>,
    /// Files changed under the worktree.
    pub files_changed: usize,
    /// Wall-clock duration.
    pub duration: Duration,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
}

impl Session {
    /// Open a session using the default state root (`$WARD_STATE_DIR` or
    /// `~/.local/state/ward`).
    pub fn start(project_dir: &Path) -> Result<Self> {
        Self::start_in(project_dir, &state_root())
    }

    /// Open a session, storing the snapshot CAS and event log under `state`.
    ///
    /// Resolves the project, merges policy into a manifest, freezes an entry
    /// snapshot, and opens the event log.
    pub fn start_in(project_dir: &Path, state: &Path) -> Result<Self> {
        let worktree = project_dir
            .canonicalize()
            .map_err(|e| Error::io(project_dir, e))?;
        let project_id = project_id_for(&worktree);
        let session = new_session_id();
        let session_str = session.to_string();

        let project_policy = load_project_policy(&worktree)?;
        // `ward-policy` and `ward-events` keep independent id newtypes so each crate
        // builds alone; bridge the same identity into the policy-crate types here.
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &project_policy,
            ward_policy::SessionId(session_str.clone()),
            ward_policy::ProjectId(project_id.to_string()),
        );

        let store =
            SnapshotStore::open(state.join("cas")).map_err(|e| Error::Snapshot(e.to_string()))?;
        let entry = store
            .store_snapshot(&worktree, SnapshotRole::Entry, CaptureOptions::default())
            .map_err(|e| Error::Snapshot(e.to_string()))?;

        let session_dir = state.join("sessions").join(&session_str);
        std::fs::create_dir_all(&session_dir).map_err(|e| Error::io(&session_dir, e))?;
        let log_path = session_dir.join("events.log");
        let manifest_hash = ev_hash(manifest.policy_hash.0);
        let chain = Chain::genesis(session, manifest_hash);
        let log = LogWriter::create(&log_path, chain.head(), FsyncPolicy::DEFAULT)
            .map_err(|e| Error::Events(e.to_string()))?;

        let mut s = Self {
            manifest,
            worktree,
            entry_snapshot: entry.to_string(),
            chain,
            log,
            started: SystemTime::now(),
            next_pid: 1,
            root_pid: Pid::new(1).map_err(|e| Error::Events(e.to_string()))?,
            session_str,
            log_path,
        };
        let agent = AgentIdentity {
            kind: AgentKind::Other,
            name: NameText::new("shell"),
            version: NameText::new(env!("CARGO_PKG_VERSION")),
            image: None,
        };
        s.emit(
            Origin::Wardd,
            WardEvent::SessionStarted {
                project: project_id,
                agent,
                manifest_hash,
                entry_snapshot: ev_snapshot(entry),
                policy_hash: manifest_hash,
                tool_images: Vec::new(),
            },
        )?;
        Ok(s)
    }

    /// The effective capability manifest.
    pub fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    /// The entry snapshot id (`blake3:…`).
    pub fn entry_snapshot(&self) -> &str {
        &self.entry_snapshot
    }

    /// The session id string.
    pub fn id(&self) -> &str {
        &self.session_str
    }

    /// The event log path for this session.
    #[must_use]
    pub fn log_path(&self) -> PathBuf {
        self.log_path.clone()
    }

    /// Run one command inside the sandbox, recording its events.
    pub fn run(&mut self, argv: &[String]) -> Result<RunReport> {
        self.emit(
            Origin::Wardd,
            WardEvent::AgentStateChanged {
                state: AgentState::Working,
            },
        )?;
        let pid = self.alloc_pid();
        let cwd =
            SandboxPath::new(SandboxRoot::Work, ".").map_err(|e| Error::Events(e.to_string()))?;
        self.emit(
            Origin::Kernel,
            WardEvent::CommandStarted {
                pid,
                parent: self.root_pid,
                argv: BoundedArgv::from_bytes(argv.iter().map(String::as_bytes)),
                cwd,
                exe_digest: None,
            },
        )?;

        let before = scan(&self.worktree);
        let outcome = sandbox::run(&self.worktree, &self.manifest.network, argv)?;
        let after = scan(&self.worktree);
        let changed = diff_paths(&before, &after);

        for rel in &changed {
            if let Ok(path) = SandboxPath::new(SandboxRoot::Work, rel) {
                self.emit(
                    Origin::Kernel,
                    WardEvent::FileModified {
                        path,
                        by: ProcessRef {
                            pid,
                            comm: comm(argv),
                        },
                        kind: FileChangeKind::Write,
                    },
                )?;
            }
        }
        self.emit(
            Origin::Kernel,
            WardEvent::CommandFinished {
                pid,
                exit: exit_status(outcome.code),
                duration: outcome.duration,
            },
        )?;
        self.emit(
            Origin::Wardd,
            WardEvent::AgentStateChanged {
                state: AgentState::Idle,
            },
        )?;

        Ok(RunReport {
            argv: argv.to_vec(),
            code: outcome.code,
            files_changed: changed.len(),
            duration: outcome.duration,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
        })
    }

    /// End the session and seal the log.
    pub fn stop(mut self, reason: EndReason) -> Result<()> {
        self.emit(
            Origin::Wardd,
            WardEvent::AgentStateChanged {
                state: AgentState::Finished,
            },
        )?;
        self.emit(
            Origin::Wardd,
            WardEvent::SessionEnded {
                reason,
                final_snapshot: None,
            },
        )?;
        self.log.seal().map_err(|e| Error::Events(e.to_string()))?;
        Ok(())
    }

    fn alloc_pid(&mut self) -> Pid {
        self.next_pid = self.next_pid.wrapping_add(1).max(2);
        Pid::new(self.next_pid).unwrap_or(self.root_pid)
    }

    fn emit(&mut self, origin: Origin, event: WardEvent) -> Result<()> {
        let record: EventRecord = self
            .chain
            .append(origin, event, now_ts(self.started))
            .map_err(|e| Error::Events(e.to_string()))?;
        self.log
            .append(&record)
            .map_err(|e| Error::Events(e.to_string()))?;
        Ok(())
    }
}

fn comm(argv: &[String]) -> Option<BoundedText<32>> {
    argv.first().map(|a| {
        let base = Path::new(a)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(a);
        BoundedText::new(base)
    })
}

fn exit_status(code: Option<i32>) -> ExitStatus {
    match code {
        Some(code) => ExitStatus::Exited { code },
        None => ExitStatus::Signaled {
            signal: 9,
            core_dumped: false,
        },
    }
}

fn now_ts(started: SystemTime) -> Timestamp {
    let mono = SystemTime::now()
        .duration_since(started)
        .unwrap_or_default();
    Timestamp::mono(mono)
}

fn load_project_policy(worktree: &Path) -> Result<Policy> {
    let path = worktree.join(".ward").join("policy.yaml");
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            Policy::from_yaml(&text).map_err(|e| Error::Policy(format!("{}: {e}", path.display())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Policy::default()),
        Err(e) => Err(Error::io(&path, e)),
    }
}

fn state_root() -> PathBuf {
    if let Ok(dir) = std::env::var("WARD_STATE_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".local/state/ward")
}

/// Map relative worktree paths to (mtime, size), skipping `.git` and `target`.
fn scan(worktree: &Path) -> BTreeMap<String, (u128, u64)> {
    let mut out = BTreeMap::new();
    walk(worktree, worktree, &mut out);
    out
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (u128, u64)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" || name == "target" || name == "node_modules" {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            walk(root, &path, out);
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            out.insert(rel, (mtime, meta.len()));
        }
    }
}

fn diff_paths(
    before: &BTreeMap<String, (u128, u64)>,
    after: &BTreeMap<String, (u128, u64)>,
) -> Vec<String> {
    let mut changed = Vec::new();
    for (path, meta) in after {
        if before.get(path) != Some(meta) {
            changed.push(path.clone());
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn exit_status_maps_code_and_signal() {
        assert_eq!(exit_status(Some(0)), ExitStatus::Exited { code: 0 });
        assert_eq!(exit_status(Some(7)), ExitStatus::Exited { code: 7 });
        assert!(matches!(exit_status(None), ExitStatus::Signaled { .. }));
    }

    #[test]
    fn comm_is_the_executable_basename() {
        let argv = vec!["/usr/bin/cargo".to_string(), "test".to_string()];
        assert_eq!(comm(&argv).unwrap().as_str(), "cargo");
        assert!(comm(&[]).is_none());
    }

    #[test]
    fn diff_reports_only_changed_paths() {
        let mut before = BTreeMap::new();
        before.insert("a".to_string(), (1u128, 10u64));
        before.insert("b".to_string(), (1, 10));
        let mut after = before.clone();
        after.insert("b".to_string(), (2, 12)); // modified
        after.insert("c".to_string(), (1, 1)); // created
        let mut changed = diff_paths(&before, &after);
        changed.sort();
        assert_eq!(changed, vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn missing_policy_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let policy = load_project_policy(dir.path()).unwrap();
        assert_eq!(policy, Policy::default());
    }
}
