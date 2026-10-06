//! `ward node migrate`: one installation's per-session state carried into a local node, as
//! one transaction (ADR-0040 §2).
//!
//! [`plan`] reads the session tree and writes nothing: every session log must be sealed
//! and verify, every snapshot the per-session runtime retains ([`retention::roots`]) is
//! listed, and every policy layer a session read is named. [`migrate`] then builds the
//! whole node home in a staging directory beside the session tree (`node.staging`): the
//! local issuer key and the trust store naming it, the retained snapshots copied into the
//! node's store and verified by digest, and the record. Only then does one rename make it
//! `node/`, which is the commit: before it the installation is in per-session mode with
//! its session tree unchanged, after it in local node mode. A failure before the rename
//! removes the staging directory; one that kills the process leaves it, inert, and the
//! next run removes it first. [`rollback`] undoes the rename the same way.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ward_daemon::retention;
use ward_daemon::session::{SessionMeta, session_dir};
use ward_events::{NodeId, PrincipalId};
use ward_node_client::{IssuerKey, SEED_LEN};
use ward_snapshot::{Digest, SnapshotId, SnapshotStore};

use super::{CarriedLog, MigrationRecord, NodeHome, RECORD_FORMAT, ReferencedPolicy, digest};
use crate::replay;

/// Where a migration builds the node home before the rename that commits it.
const STAGING_DIR: &str = "node.staging";
/// Where a rollback moves a node home aside, followed by the time in Unix milliseconds.
const ROLLED_BACK_PREFIX: &str = "node.rolled-back-";

/// Why a migration or a rollback did not happen. Every case leaves the installation in the
/// mode it was in.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MigrationError {
    /// The installation is already in local node mode.
    #[error(
        "already in local node mode ({}); `ward node migrate --rollback` returns to \
         per-session mode first",
        .0.display()
    )]
    AlreadyMigrated(PathBuf),
    /// There is no migration to roll back.
    #[error("not in local node mode; there is nothing to roll back")]
    NotMigrated,
    /// The local node is still serving its socket.
    #[error("the local node is serving on {}; stop it before rolling back", .0.display())]
    NodeServing(PathBuf),
    /// A session's log is not sealed.
    #[error(
        "session {0} is not sealed; `ward stop --session {0}` seals it, and a migration \
         carries only sealed evidence"
    )]
    Unsealed(String),
    /// A session's log does not verify.
    #[error("{} does not verify ({reason}); a migration carries only evidence that verifies", path.display())]
    Unverified {
        /// The log.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// A retained snapshot could not be imported whole.
    #[error("snapshot {id}: {reason}")]
    Snapshot {
        /// The snapshot, as 64 lowercase hex digits.
        id: String,
        /// Why.
        reason: String,
    },
    /// The local issuer key could not be created.
    #[error("local issuer key: {0}")]
    Issuer(String),
    /// Reading the session tree failed.
    #[error(transparent)]
    Session(#[from] ward_daemon::Error),
    /// A filesystem operation failed.
    #[error("io error at {}: {source}", path.display())]
    Io {
        /// The path.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> MigrationError + '_ {
    move |source| MigrationError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// What a migration of one session tree would carry, read without writing anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    state: PathBuf,
    /// The snapshots the per-session runtime retains, imported into the node's store.
    pub snapshots: Vec<SnapshotId>,
    /// Every sealed session log, left in place and recorded.
    pub evidence: Vec<CarriedLog>,
    /// Every policy layer a session read, referenced and never rewritten.
    pub policy: Vec<ReferencedPolicy>,
}

/// The points a migration passes, in order; [`migrate`] calls its checkpoint after each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The staging directory exists.
    Staged,
    /// The local issuer key is written.
    IssuerKey,
    /// The trust store is written.
    TrustStore,
    /// The snapshot at this index of [`Plan::snapshots`] is imported.
    Snapshot(usize),
    /// The record is written; the rename is next.
    Record,
}

/// Read the session tree at `state` into a [`Plan`], writing nothing.
pub(crate) fn plan(state: &Path) -> Result<Plan, MigrationError> {
    let home = NodeHome::under(state);
    if fs::symlink_metadata(home.dir()).is_ok() {
        return Err(MigrationError::AlreadyMigrated(home.dir().to_path_buf()));
    }
    let mut evidence = Vec::new();
    let mut projects = BTreeSet::new();
    for id in session_ids(state)? {
        let log = session_dir(state, &id).join("events.log");
        if fs::symlink_metadata(&log).is_err() {
            continue;
        }
        evidence.push(sealed(state, &id, &log)?);
        if let Ok(meta) = SessionMeta::load(state, &id) {
            projects.insert(meta.project);
        }
    }
    let mut policy = projects
        .iter()
        .map(|project| referenced(project.join(".ward").join("policy.yaml")))
        .collect::<Result<Vec<_>, _>>()?;
    policy.push(referenced(ward_daemon::credentials::config::path(state))?);
    let mut snapshots: Vec<SnapshotId> = retention::roots(state)?.iter().copied().collect();
    snapshots.sort();
    Ok(Plan {
        state: state.to_path_buf(),
        snapshots,
        evidence,
        policy,
    })
}

/// Every session id with a directory under `<state>/sessions/`, in order.
fn session_ids(state: &Path) -> Result<Vec<String>, MigrationError> {
    let dir = state.join("sessions");
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(&dir)(e)),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io(&dir))?;
        if entry.file_type().map_err(io(&dir))?.is_dir() {
            ids.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    ids.sort();
    Ok(ids)
}

/// Session `id`'s log at `log`, verified as `ward replay --verify` verifies it and
/// sealed, as a [`CarriedLog`].
fn sealed(state: &Path, id: &str, log: &Path) -> Result<CarriedLog, MigrationError> {
    let unverified = |reason: String| MigrationError::Unverified {
        path: log.to_path_buf(),
        reason,
    };
    let report = replay::replay(
        log,
        replay::Options {
            verify: true,
            json: false,
        },
    )
    .map_err(|e| unverified(e.to_string()))?;
    if report.sealed == replay::Sealed::Absent {
        return Err(MigrationError::Unsealed(id.to_owned()));
    }
    if let Some(failure) = &report.failure {
        return Err(unverified(replay::failure_text(failure)));
    }
    let head = report
        .head
        .ok_or_else(|| unverified("no records".to_owned()))?;
    let bytes = fs::read(log).map_err(io(log))?;
    Ok(CarriedLog {
        path: log.strip_prefix(state).unwrap_or(log).to_path_buf(),
        bytes: bytes.len() as u64,
        blake3: digest(&bytes),
        head: head.hash.to_hex(),
        records: report.records,
    })
}

fn referenced(path: PathBuf) -> Result<ReferencedPolicy, MigrationError> {
    let blake3 = match fs::read(&path) {
        Ok(bytes) => Some(digest(&bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(io(&path)(e)),
    };
    Ok(ReferencedPolicy { path, blake3 })
}

/// The plan as `ward node migrate --dry-run` prints it.
pub(crate) fn describe(plan: &Plan) -> String {
    let home = NodeHome::under(&plan.state);
    let mut out = String::new();
    let _ = writeln!(out, "ward node migrate --dry-run: nothing was written");
    let _ = writeln!(
        out,
        "  node home   {} (mode 0700), committed by one rename",
        home.dir().display()
    );
    let _ = writeln!(
        out,
        "  issuer      a new local Ed25519 key, mode 0600, trusted for a new local principal"
    );
    let _ = writeln!(
        out,
        "  snapshots   {} retained, imported into {} and verified by digest",
        plan.snapshots.len(),
        home.snapshots().display()
    );
    for id in &plan.snapshots {
        let _ = writeln!(out, "    {}", id.digest().to_hex());
    }
    let _ = writeln!(
        out,
        "  evidence    {} sealed session logs, left in place and recorded by BLAKE3",
        plan.evidence.len()
    );
    for log in &plan.evidence {
        let _ = writeln!(
            out,
            "    {}  {} records  blake3 {}",
            log.path.display(),
            log.records,
            log.blake3
        );
    }
    let _ = writeln!(
        out,
        "  policy      {} files, referenced and never rewritten",
        plan.policy.len()
    );
    for layer in &plan.policy {
        let _ = writeln!(
            out,
            "    {}  {}",
            layer.path.display(),
            layer
                .blake3
                .as_deref()
                .map_or_else(|| "absent".to_owned(), |hash| format!("blake3 {hash}"))
        );
    }
    out
}

/// Carry the session tree into a new node home for node `node`, calling `checkpoint` after
/// each [`Step`]; an error from it stops the migration there, as any other failure does.
pub(crate) fn migrate(
    plan: &Plan,
    node: NodeId,
    checkpoint: &mut dyn FnMut(Step) -> Result<(), MigrationError>,
) -> Result<MigrationRecord, MigrationError> {
    let home = NodeHome::under(&plan.state);
    if fs::symlink_metadata(home.dir()).is_ok() {
        return Err(MigrationError::AlreadyMigrated(home.dir().to_path_buf()));
    }
    let staging = plan.state.join(STAGING_DIR);
    remove_leftover(&staging)?;
    let committed = stage(plan, node, &staging, checkpoint).and_then(|record| {
        rename_noreplace(&staging, home.dir())?;
        Ok(record)
    });
    if committed.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    committed
}

fn stage(
    plan: &Plan,
    node: NodeId,
    staging: &Path,
    checkpoint: &mut dyn FnMut(Step) -> Result<(), MigrationError>,
) -> Result<MigrationRecord, MigrationError> {
    private_dir(staging)?;
    checkpoint(Step::Staged)?;
    let home = NodeHome::at(staging.to_path_buf());
    private_dir(&home.state_dir())?;
    private_dir(&home.task_root())?;
    let key = issuer_key(&home.seed())?;
    checkpoint(Step::IssuerKey)?;
    let issuer = PrincipalId::from_u128(ward_daemon::ids::new_ulid()?);
    write_private(
        &home.trust_store(),
        format!(
            "# The local issuer `ward node migrate` created for this installation.\n{}\n",
            key.trust_store_line(issuer)
        )
        .as_bytes(),
    )?;
    checkpoint(Step::TrustStore)?;
    if !plan.snapshots.is_empty() {
        let store = |path: PathBuf, opened: ward_snapshot::Result<SnapshotStore>| {
            opened.map_err(|e| io(&path)(std::io::Error::other(e)))
        };
        let source_root = plan.state.join("cas");
        let source = store(
            source_root.clone(),
            SnapshotStore::open_existing(&source_root),
        )?;
        let target = store(home.snapshots(), SnapshotStore::open(home.snapshots()))?;
        for (index, id) in plan.snapshots.iter().enumerate() {
            target
                .copy_from(&source, *id)
                .and_then(|copied| target.verify(copied))
                .map_err(|e| MigrationError::Snapshot {
                    id: id.digest().to_hex(),
                    reason: e.to_string(),
                })?;
            checkpoint(Step::Snapshot(index))?;
        }
    }
    let record = MigrationRecord {
        format: RECORD_FORMAT,
        node,
        issuer,
        issuer_key_id: key.key_id().to_hex(),
        migrated_at_unix_ms: now_ms(),
        source: plan.state.clone(),
        snapshots: plan
            .snapshots
            .iter()
            .map(|id| id.digest().to_hex())
            .collect(),
        evidence: plan.evidence.clone(),
        policy: plan.policy.clone(),
    };
    let json = serde_json::to_vec_pretty(&record)
        .map_err(|e| io(&home.record())(std::io::Error::other(e)))?;
    write_private(&home.record(), &json)?;
    checkpoint(Step::Record)?;
    sync_tree(staging)?;
    Ok(record)
}

/// A new local issuer key, its seed written to `path` with mode 0600 and read back
/// through the same check every signer applies.
fn issuer_key(path: &Path) -> Result<IssuerKey, MigrationError> {
    let mut seed = [0_u8; SEED_LEN];
    getrandom::fill(&mut seed).map_err(|e| MigrationError::Issuer(e.to_string()))?;
    write_private(path, &seed)?;
    IssuerKey::from_seed_file(path).map_err(|e| MigrationError::Issuer(e.to_string()))
}

fn private_dir(path: &Path) -> Result<(), MigrationError> {
    DirBuilder::new().mode(0o700).create(path).map_err(io(path))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), MigrationError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io(path))?;
    file.write_all(bytes).map_err(io(path))?;
    file.sync_all().map_err(io(path))
}

/// Flush every directory under `root`, `root` included, so the renamed home is durable
/// as a whole.
fn sync_tree(root: &Path) -> Result<(), MigrationError> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(io(&dir))? {
            let entry = entry.map_err(io(&dir))?;
            if entry.file_type().map_err(io(&dir))?.is_dir() {
                stack.push(entry.path());
            }
        }
        fs::File::open(&dir)
            .and_then(|handle| handle.sync_all())
            .map_err(io(&dir))?;
    }
    Ok(())
}

fn remove_leftover(path: &Path) -> Result<(), MigrationError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(path)(e)),
    }
}

/// Rename `from` to `to` only if `to` does not exist, as one step; then flush the
/// parent, best effort: a rename lost to a crash before that leaves the prior mode.
fn rename_noreplace(from: &Path, to: &Path) -> Result<(), MigrationError> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    use rustix::io::Errno;
    match renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
        Ok(()) => {}
        Err(Errno::EXIST | Errno::NOTEMPTY) => {
            return Err(MigrationError::AlreadyMigrated(to.to_path_buf()));
        }
        Err(Errno::INVAL | Errno::NOSYS) if fs::symlink_metadata(to).is_err() => {
            fs::rename(from, to).map_err(io(to))?;
        }
        Err(e) => return Err(io(to)(e.into())),
    }
    if let Some(parent) = to.parent() {
        let _ = fs::File::open(parent).and_then(|handle| handle.sync_all());
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// What a rollback did with the node home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RolledBack {
    /// No attempt ever ran; the node home is gone.
    Removed,
    /// Attempts ran; the node home, with their evidence, was moved here.
    Kept(PathBuf),
}

/// Return the installation at `state` to per-session mode.
pub(crate) fn rollback(state: &Path) -> Result<RolledBack, MigrationError> {
    let home = NodeHome::under(state);
    if fs::symlink_metadata(home.dir()).is_err() {
        return Err(MigrationError::NotMigrated);
    }
    if UnixStream::connect(home.socket()).is_ok() {
        return Err(MigrationError::NodeServing(home.socket()));
    }
    remove_leftover(&state.join(STAGING_DIR))?;
    let aside = state.join(format!("{ROLLED_BACK_PREFIX}{}", now_ms()));
    rename_noreplace(home.dir(), &aside)?;
    let attempts = fs::read_dir(NodeHome::at(aside.clone()).task_root())
        .map_or(true, |mut entries| entries.next().is_some());
    if attempts {
        return Ok(RolledBack::Kept(aside));
    }
    fs::remove_dir_all(&aside).map_err(io(&aside))?;
    Ok(RolledBack::Removed)
}

/// One line of `ward node status`: a carried object and whether it is as it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Finding {
    /// Whether the object is as the migration recorded it.
    pub ok: bool,
    /// What was found.
    pub line: String,
}

/// Re-check what `record` says the migration of `state` carried.
pub(crate) fn check(state: &Path, record: &MigrationRecord) -> Vec<Finding> {
    let mut findings = Vec::new();
    for log in &record.evidence {
        let path = state.join(&log.path);
        let id = log
            .path
            .parent()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ok = match sealed(state, &id, &path) {
            Ok(now) if now == *log => Ok(()),
            Ok(_) => Err("changed since the migration".to_owned()),
            Err(e) => Err(e.to_string()),
        };
        findings.push(match ok {
            Ok(()) => Finding {
                ok: true,
                line: format!(
                    "evidence {}: unchanged, verifies ({} records)",
                    log.path.display(),
                    log.records
                ),
            },
            Err(reason) => Finding {
                ok: false,
                line: format!("evidence {}: {reason}", log.path.display()),
            },
        });
    }
    let store = SnapshotStore::open_existing(NodeHome::under(state).snapshots());
    for hex in &record.snapshots {
        let whole = Digest::from_hex(hex)
            .map_err(|e| e.to_string())
            .and_then(|digest| {
                store
                    .as_ref()
                    .map_err(ToString::to_string)?
                    .verify(SnapshotId(digest))
                    .map_err(|e| e.to_string())
            });
        findings.push(match whole {
            Ok(()) => Finding {
                ok: true,
                line: format!("snapshot {hex}: present and whole in the node's store"),
            },
            Err(reason) => Finding {
                ok: false,
                line: format!("snapshot {hex}: {reason}"),
            },
        });
    }
    for layer in &record.policy {
        let now = referenced(layer.path.clone()).map(|now| now.blake3);
        let state_word = match (&now, &layer.blake3) {
            (Ok(None), None) => "absent, as at the migration",
            (Ok(now), was) if now == was => "unchanged",
            (Ok(_), _) => "changed since the migration; policy stays yours to edit",
            (Err(_), _) => "unreadable",
        };
        findings.push(Finding {
            ok: true,
            line: format!("policy {}: {state_word}", layer.path.display()),
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;

    use ward_daemon::Session;
    use ward_events::EndReason;

    use super::*;
    use crate::node_mode::{Mode, mode};

    const NODE: NodeId = NodeId::from_u128(4);

    struct Installation {
        _dir: tempfile::TempDir,
        state: PathBuf,
        project: PathBuf,
        pinned: SnapshotId,
        log: PathBuf,
    }

    fn installation() -> Installation {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let project = dir.path().join("project");
        fs::create_dir_all(project.join(".ward")).unwrap();
        fs::write(project.join(".ward/policy.yaml"), "network: offline\n").unwrap();
        fs::write(project.join("input.txt"), "carried\n").unwrap();
        let session = Session::start_in(&project, &state).unwrap();
        session.persist_current().unwrap();
        let pinned: SnapshotId = session.entry_snapshot().parse().unwrap();
        let log = session.log_path();
        session.stop(EndReason::UserStop).unwrap();
        retention::mark_kept(&state, pinned).unwrap();
        Installation {
            project: project.canonicalize().unwrap(),
            _dir: dir,
            state,
            pinned,
            log,
        }
    }

    fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                let meta = fs::symlink_metadata(&path).unwrap();
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                if meta.is_dir() {
                    out.insert(rel, b"dir".to_vec());
                    stack.push(path);
                } else {
                    out.insert(rel, fs::read(&path).unwrap());
                }
            }
        }
        out
    }

    fn mode_bits(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[allow(clippy::unnecessary_wraps)]
    fn proceed(_: Step) -> Result<(), MigrationError> {
        Ok(())
    }

    #[test]
    fn a_plan_names_every_sealed_log_retained_snapshot_and_policy_layer_and_writes_nothing() {
        let home = installation();
        let before = tree(&home.state);
        let plan = plan(&home.state).unwrap();
        assert_eq!(
            tree(&home.state),
            before,
            "planning wrote to the session tree"
        );

        assert_eq!(plan.snapshots, [home.pinned]);
        assert_eq!(plan.evidence.len(), 1);
        let carried = &plan.evidence[0];
        assert_eq!(home.state.join(&carried.path), home.log);
        let bytes = fs::read(&home.log).unwrap();
        assert_eq!(carried.bytes, bytes.len() as u64);
        assert_eq!(carried.blake3, digest(&bytes));
        assert!(carried.records >= 2, "{carried:?}");
        assert_eq!(
            plan.policy,
            [
                ReferencedPolicy {
                    path: home.project.join(".ward/policy.yaml"),
                    blake3: Some(digest(b"network: offline\n")),
                },
                ReferencedPolicy {
                    path: home.state.join("credentials.toml"),
                    blake3: None,
                },
            ]
        );
        let text = describe(&plan);
        assert!(text.contains(&home.pinned.digest().to_hex()), "{text}");
        assert!(text.contains(&carried.path.display().to_string()), "{text}");
        assert!(text.contains("policy.yaml"), "{text}");
    }

    #[test]
    fn an_unsealed_session_refuses_the_plan_by_name() {
        let home = installation();
        let open = Session::start_in(&home.project, &home.state).unwrap();
        let id = open.id().to_owned();
        drop(open);
        match plan(&home.state) {
            Err(MigrationError::Unsealed(session)) => assert_eq!(session, id),
            other => panic!("an unsealed session must refuse the plan: {other:?}"),
        }
    }

    #[test]
    fn a_log_that_does_not_verify_refuses_the_plan() {
        let home = installation();
        let mut bytes = fs::read(&home.log).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::set_permissions(&home.log, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&home.log, bytes).unwrap();
        assert!(matches!(
            plan(&home.state),
            Err(MigrationError::Unverified { path, .. }) if path == home.log
        ));
    }

    #[test]
    fn an_empty_installation_plans_an_empty_migration() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan(dir.path()).unwrap();
        assert!(plan.snapshots.is_empty() && plan.evidence.is_empty());
        assert_eq!(plan.policy.len(), 1, "the system layer is always named");
        let record = migrate(&plan, NODE, &mut proceed).unwrap();
        assert!(record.snapshots.is_empty());
        assert!(matches!(mode(dir.path()).unwrap(), Mode::LocalNode(_)));
    }

    #[test]
    fn a_migration_commits_a_node_home_carrying_everything_and_leaves_the_session_tree_alone() {
        let home = installation();
        let before = tree(&home.state);
        let plan = plan(&home.state).unwrap();
        let record = migrate(&plan, NODE, &mut proceed).unwrap();

        let node = NodeHome::under(&home.state);
        let mut after = tree(&home.state);
        after.retain(|path, _| !path.starts_with("node"));
        assert_eq!(after, before, "the session tree changed");
        assert!(!home.state.join(STAGING_DIR).exists());

        assert_eq!(
            mode(&home.state).unwrap(),
            Mode::LocalNode(Box::new(record.clone()))
        );
        assert_eq!(record.node, NODE);
        assert_eq!(record.source, home.state);
        assert_eq!(record.snapshots, [home.pinned.digest().to_hex()]);
        assert_eq!(record.evidence, plan.evidence);
        assert_eq!(record.policy, plan.policy);

        for dir in [node.dir(), &node.state_dir(), &node.task_root()] {
            assert_eq!(mode_bits(dir), 0o700, "{}", dir.display());
        }
        assert_eq!(mode_bits(&node.seed()), 0o600);
        assert_eq!(mode_bits(&node.trust_store()), 0o600);
        let key = IssuerKey::from_seed_file(&node.seed()).unwrap();
        assert_eq!(record.issuer_key_id, key.key_id().to_hex());
        let trust = fs::read_to_string(node.trust_store()).unwrap();
        assert!(
            trust.contains(&key.trust_store_line(record.issuer)),
            "{trust}"
        );

        let imported = SnapshotStore::open_existing(node.snapshots()).unwrap();
        imported.verify(home.pinned).unwrap();
        let source = SnapshotStore::open_existing(home.state.join("cas")).unwrap();
        assert_eq!(
            imported.manifest(home.pinned).unwrap(),
            source.manifest(home.pinned).unwrap()
        );
        assert!(check(&home.state, &record).iter().all(|finding| finding.ok));
    }

    #[test]
    fn a_failure_at_any_step_leaves_the_prior_state_byte_identical_and_a_rerun_succeeds() {
        let home = installation();
        let before = tree(&home.state);
        let plan = plan(&home.state).unwrap();
        let steps = [
            Step::Staged,
            Step::IssuerKey,
            Step::TrustStore,
            Step::Snapshot(0),
            Step::Record,
        ];
        for failing in steps {
            let mut fail = |step: Step| {
                if step == failing {
                    Err(MigrationError::Issuer(format!("injected at {step:?}")))
                } else {
                    Ok(())
                }
            };
            let error = migrate(&plan, NODE, &mut fail).unwrap_err();
            assert!(error.to_string().contains("injected"), "{error}");
            assert_eq!(
                tree(&home.state),
                before,
                "failing at {failing:?} changed the state"
            );
            assert_eq!(mode(&home.state).unwrap(), Mode::PerSession);
        }
        migrate(&plan, NODE, &mut proceed).unwrap();
        assert!(matches!(mode(&home.state).unwrap(), Mode::LocalNode(_)));
    }

    #[test]
    fn a_corrupt_retained_snapshot_fails_the_migration_and_changes_nothing() {
        let home = installation();
        let digest_hex = Digest::of(b"carried\n").to_hex();
        let blob = home
            .state
            .join("cas/blobs")
            .join(&digest_hex[..2])
            .join(&digest_hex);
        fs::set_permissions(&blob, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&blob, b"tampered\n").unwrap();
        let before = tree(&home.state);
        let plan = plan(&home.state).unwrap();
        assert!(matches!(
            migrate(&plan, NODE, &mut proceed),
            Err(MigrationError::Snapshot { id, .. }) if id == home.pinned.digest().to_hex()
        ));
        assert_eq!(tree(&home.state), before);
    }

    #[test]
    fn a_leftover_staging_directory_is_removed_and_never_committed() {
        let home = installation();
        let staging = home.state.join(STAGING_DIR);
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("migration.json"), b"{}").unwrap();
        assert_eq!(mode(&home.state).unwrap(), Mode::PerSession);
        let plan = plan(&home.state).unwrap();
        migrate(&plan, NODE, &mut proceed).unwrap();
        assert!(!staging.exists());
        assert!(matches!(mode(&home.state).unwrap(), Mode::LocalNode(_)));
    }

    #[test]
    fn a_second_migration_is_refused_and_changes_nothing() {
        let home = installation();
        let plan_before = plan(&home.state).unwrap();
        migrate(&plan_before, NODE, &mut proceed).unwrap();
        let before = tree(&home.state);
        assert!(matches!(
            plan(&home.state),
            Err(MigrationError::AlreadyMigrated(_))
        ));
        assert!(matches!(
            migrate(&plan_before, NODE, &mut proceed),
            Err(MigrationError::AlreadyMigrated(_))
        ));
        assert_eq!(tree(&home.state), before);
    }

    #[test]
    fn a_rollback_with_no_attempt_restores_the_prior_state_exactly() {
        let home = installation();
        let before = tree(&home.state);
        assert!(matches!(
            rollback(&home.state),
            Err(MigrationError::NotMigrated)
        ));
        let plan = plan(&home.state).unwrap();
        migrate(&plan, NODE, &mut proceed).unwrap();
        assert_eq!(rollback(&home.state).unwrap(), RolledBack::Removed);
        assert_eq!(tree(&home.state), before);
        assert_eq!(mode(&home.state).unwrap(), Mode::PerSession);
    }

    #[test]
    fn a_rollback_after_attempts_ran_keeps_their_evidence_aside() {
        let home = installation();
        let plan = plan(&home.state).unwrap();
        migrate(&plan, NODE, &mut proceed).unwrap();
        let node = NodeHome::under(&home.state);
        let attempt = node.task_root().join("task_x/exec_y.evidence");
        fs::create_dir_all(&attempt).unwrap();
        fs::write(attempt.join("events.log"), b"evidence").unwrap();

        let RolledBack::Kept(aside) = rollback(&home.state).unwrap() else {
            panic!("a node home with attempts must be kept");
        };
        assert!(
            aside
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(ROLLED_BACK_PREFIX)
        );
        assert_eq!(
            fs::read(aside.join("tasks/task_x/exec_y.evidence/events.log")).unwrap(),
            b"evidence"
        );
        assert_eq!(mode(&home.state).unwrap(), Mode::PerSession);
        migrate(&plan, NODE, &mut proceed).unwrap();
        assert!(matches!(mode(&home.state).unwrap(), Mode::LocalNode(_)));
    }

    #[test]
    fn a_rollback_is_refused_while_the_node_serves() {
        let home = installation();
        let plan = plan(&home.state).unwrap();
        migrate(&plan, NODE, &mut proceed).unwrap();
        let node = NodeHome::under(&home.state);
        let _listener = std::os::unix::net::UnixListener::bind(node.socket()).unwrap();
        assert!(matches!(
            rollback(&home.state),
            Err(MigrationError::NodeServing(socket)) if socket == node.socket()
        ));
        assert!(matches!(mode(&home.state).unwrap(), Mode::LocalNode(_)));
    }

    #[test]
    fn the_status_check_names_a_changed_log_a_missing_snapshot_and_an_edited_policy() {
        let home = installation();
        let plan = plan(&home.state).unwrap();
        let record = migrate(&plan, NODE, &mut proceed).unwrap();
        assert_eq!(check(&home.state, &record).len(), 4);

        fs::write(
            home.project.join(".ward/policy.yaml"),
            "network: offline\n# edited\n",
        )
        .unwrap();
        let findings = check(&home.state, &record);
        let policy = findings
            .iter()
            .find(|f| f.line.contains("policy.yaml"))
            .unwrap();
        assert!(policy.ok, "editing policy stays the user's: {policy:?}");
        assert!(policy.line.contains("changed"), "{policy:?}");

        let mut bytes = fs::read(&home.log).unwrap();
        bytes.push(0);
        fs::set_permissions(&home.log, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&home.log, bytes).unwrap();
        let manifest = NodeHome::under(&home.state)
            .snapshots()
            .join("manifests")
            .join(home.pinned.digest().to_hex());
        fs::remove_file(manifest).unwrap();
        let failed: Vec<Finding> = check(&home.state, &record)
            .into_iter()
            .filter(|f| !f.ok)
            .collect();
        assert_eq!(failed.len(), 2, "{failed:?}");
        assert!(failed.iter().any(|f| f.line.contains("events.log")));
        assert!(
            failed
                .iter()
                .any(|f| f.line.contains(&home.pinned.digest().to_hex()))
        );
    }
}
