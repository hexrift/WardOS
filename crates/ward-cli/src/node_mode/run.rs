//! `ward run --via-node` and `ward node serve`: the CLI path through the local node
//! (ADR-0040 §3).
//!
//! A run is one node attempt: the project's effective policy compiled into the envelope's
//! manifest ([`super::compile`]), a fresh snapshot of the project (or a snapshot the node
//! already holds) as its workspace, a root lease the local issuer signs for exactly that
//! attempt, and the fail-closed driver of `ward-node-client` taking it from `create` to
//! `seal`. Nothing here runs anything in-process: a node that is not serving, refuses, or
//! answers `unknown` ends the command with that, and nothing else is tried.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{AgentId, DelegationId, ExecutionAttemptId, LeaseId, SessionId, TaskId};
use ward_node_client::{
    AttemptOutcome, AttemptReport, AttemptRequest, CancelToken, Client, Driver, EnvelopeInput,
    IssuerKey, OperationIds, RunConfig, Timeouts, UnixTransport, WorkloadInput,
};
use ward_node_protocol::{
    CapabilityManifest, CapabilityManifestBytes, NetworkGrant, OutputGrant, TaskAdmissionAuthority,
    TaskBinding,
};
use ward_snapshot::{CaptureOptions, SnapshotRole, SnapshotStore};

use super::compile::compile;
use super::{MigrationRecord, Mode, NodeHome, mode};

/// The head of each output stream a run asks the node to return.
const STDIO_BYTES: u64 = 256 * 1024;
/// How long past its budget an attempt's authority stays valid, for the node to end it.
const AUTHORITY_GRACE: Duration = Duration::from_secs(120);
/// The capability the local issuer grants a run, on the project it runs over.
const RUN_CAPABILITY: &str = "project.run";

/// One `ward run --via-node`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NodeRun {
    /// The project directory.
    pub dir: PathBuf,
    /// The program and its arguments.
    pub argv: Vec<String>,
    /// A snapshot already in the node's store to run over, as 64 lowercase hex digits,
    /// instead of a fresh capture of the project.
    pub snapshot: Option<String>,
    /// The attempt's wall-clock budget.
    pub budget: Duration,
}

fn refused(message: impl Into<String>) -> ward_daemon::Error {
    ward_daemon::Error::Project(message.into())
}

/// The record of the installation at `state`, or why it is not in local node mode.
fn local_node(state: &Path) -> ward_daemon::Result<MigrationRecord> {
    match mode(state)? {
        Mode::LocalNode(record) => Ok(*record),
        Mode::PerSession => Err(refused(
            "not in local node mode: `ward node migrate` moves this installation to a local \
             node; nothing ran",
        )),
    }
}

/// Run `request` as one attempt on the local node of the installation at `state`.
pub(crate) fn run_via_node(state: &Path, request: &NodeRun) -> ward_daemon::Result<ExitCode> {
    let record = local_node(state)?;
    let home = NodeHome::under(state);
    let worktree = request
        .dir
        .canonicalize()
        .map_err(|source| ward_daemon::Error::Io {
            path: request.dir.clone(),
            source,
        })?;
    let session = SessionId::from_u128(ward_daemon::ids::new_ulid()?);
    let policy = ward_daemon::session::effective_manifest(&worktree, state, &session.to_string())?;
    let network = compile(&policy).map_err(|reasons| {
        refused(format!(
            "the local node cannot enforce this project's policy as a session would, so \
             nothing ran:\n  {}",
            reasons.join("\n  ")
        ))
    })?;

    let client =
        Client::connect(UnixTransport::new(home.socket(), Timeouts::default())).map_err(|e| {
            refused(format!(
                "the local node is not serving at {} ({e}); `ward node serve` starts it, and \
                 nothing runs in-process instead",
                home.socket().display()
            ))
        })?;
    let capabilities = client
        .capabilities()
        .map_err(|e| refused(format!("the local node's capabilities: {e}")))?;
    if matches!(network, NetworkGrant::Custom(_)) && !capabilities.network().proxy_allowlist {
        return Err(refused(
            "network: the project's policy grants hosts and the local node runs no egress \
             proxy (`--network-allowlist`); nothing ran",
        ));
    }
    let mut manifest = CapabilityManifest::new(network);
    if capabilities.output().stdio {
        manifest = manifest.with_output(
            OutputGrant::new(STDIO_BYTES, Vec::new(), 0)
                .map_err(|e| refused(format!("output grant: {e}")))?,
        );
    }

    let snapshot = snapshot(&home, &worktree, request.snapshot.as_deref())?;
    let envelope = envelope(
        &record,
        session,
        &policy.project.0,
        request,
        &manifest,
        snapshot,
    )?;
    let issuer = IssuerKey::from_seed_file(&home.seed())
        .map_err(|e| refused(format!("local issuer {}: {e}", home.seed().display())))?;
    let attempt = AttemptRequest::sign(&envelope, &issuer, Some(home.task_root()))
        .map_err(|e| refused(format!("signing the envelope: {e}")))?;
    let report = Driver::new(&client, RunConfig::default()).run_attempt(
        &attempt,
        &OperationIds::default(),
        &CancelToken::default(),
        &mut |_| {},
    );
    Ok(print_report(&report))
}

/// The id of the snapshot a run materialises: `named`, which the node's store must hold
/// whole, or a fresh capture of `worktree` into that store.
fn snapshot(
    home: &NodeHome,
    worktree: &Path,
    named: Option<&str>,
) -> ward_daemon::Result<ward_events::SnapshotId> {
    let store = SnapshotStore::open(home.snapshots())
        .map_err(|e| ward_daemon::Error::Snapshot(e.to_string()))?;
    let id = match named {
        Some(hex) => {
            let id = ward_snapshot::SnapshotId(
                ward_snapshot::Digest::from_hex(hex)
                    .map_err(|e| ward_daemon::Error::Snapshot(e.to_string()))?,
            );
            store.verify(id).map_err(|e| {
                ward_daemon::Error::Snapshot(format!("{hex} is not whole in the node's store: {e}"))
            })?;
            id
        }
        None => store
            .store_snapshot(worktree, SnapshotRole::Entry, CaptureOptions::default())
            .map_err(|e| ward_daemon::Error::Snapshot(e.to_string()))?,
    };
    Ok(ward_events::SnapshotId::new(
        ward_events::Blake3Hash::from_bytes(*id.digest().as_bytes()),
    ))
}

fn envelope(
    record: &MigrationRecord,
    session: SessionId,
    project: &str,
    request: &NodeRun,
    manifest: &CapabilityManifest,
    snapshot: ward_events::SnapshotId,
) -> ward_daemon::Result<ward_node_protocol::TaskAdmissionEnvelope> {
    let fresh = || ward_daemon::ids::new_ulid();
    let binding = TaskBinding::new(
        TaskId::from_u128(fresh()?),
        ExecutionAttemptId::from_u128(fresh()?),
        LeaseId::from_u128(fresh()?),
    );
    let agent = AgentId::from_u128(fresh()?);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    let budget_ms = u64::try_from(request.budget.as_millis()).unwrap_or(u64::MAX);
    let expires = now
        .saturating_add(budget_ms)
        .saturating_add(u64::try_from(AUTHORITY_GRACE.as_millis()).unwrap_or(0));
    let grant = CapabilityName::new(RUN_CAPABILITY)
        .and_then(|name| ResourceRef::new(project).map(|resource| (name, resource)))
        .map_err(|_| refused(format!("project id {project} is not a resource reference")))?;
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(fresh()?),
            issuer: record.issuer,
            subject: agent,
            task: binding.task(),
            grants: GrantSet::new([CapabilityGrant::new(grant.0, grant.1, false)])
                .map_err(|e| refused(format!("lease grants: {e}")))?,
            issued_at_unix_ms: now,
            expires_at_unix_ms: expires,
            version: LeaseVersion::new(1).map_err(|e| refused(format!("lease version: {e}")))?,
        },
        now,
        EmptyAuthorityPolicy::Reject,
    )
    .map_err(|e| refused(format!("lease: {e}")))?;
    let authority = TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
        .map_err(|e| refused(format!("authority: {e}")))?;
    EnvelopeInput {
        binding,
        agent,
        node: record.node,
        session,
        authority,
        workload: WorkloadInput {
            argv: request.argv.clone(),
            capability_manifest: Some(
                CapabilityManifestBytes::encode(manifest)
                    .map_err(|e| refused(format!("manifest: {e}")))?,
            ),
            snapshot,
            wall_clock_budget_ms: budget_ms,
        },
        issued_at_unix_ms: now,
        expires_at_unix_ms: expires,
        version: 1,
    }
    .build()
    .map_err(|e| refused(format!("envelope: {e}")))
}

/// Print what the node returned and how the attempt ended; the exit code is success only
/// for a `completed` receipt.
fn print_report(report: &AttemptReport) -> ExitCode {
    if let Some(output) = &report.output {
        let _ = std::io::stdout().write_all(output.stdout().content());
        let _ = std::io::stderr().write_all(output.stderr().content());
        if output.truncated() {
            eprintln!("ward: the node returned the first {STDIO_BYTES} bytes of each stream");
        }
    }
    let attempt = format!("{}/{}", report.binding.task(), report.binding.attempt());
    let outcome = match report.outcome {
        AttemptOutcome::Completed => "completed".to_owned(),
        AttemptOutcome::Failed => "failed".to_owned(),
        AttemptOutcome::Unknown => format!(
            "unknown ({}); treat it as failed",
            report
                .transport_error
                .as_deref()
                .unwrap_or("the node reported no trustworthy receipt")
        ),
        AttemptOutcome::Refused { verb, reason } => format!(
            "refused at {} ({}); nothing ran",
            verb.as_str(),
            serde_json::to_value(reason)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| format!("{reason:?}"))
        ),
    };
    eprintln!("ward: node attempt {attempt} {outcome}");
    if let Some(log) = &report.evidence_log {
        let sealed = report.evidence_head.map_or_else(
            || "not sealed".to_owned(),
            |head| format!("sealed {}", head.to_hex()),
        );
        eprintln!("ward: evidence {} ({sealed})", log.display());
    }
    if report.outcome == AttemptOutcome::Completed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `ward node serve`: replace this process with the local node of the installation at
/// `state`, serving its home's socket under its own paths, with `extra` flags after.
pub(crate) fn serve(state: &Path, extra: &[OsString]) -> ward_daemon::Result<ExitCode> {
    let record = local_node(state)?;
    let home = NodeHome::under(state);
    let binary = find("ward-node").ok_or_else(|| {
        refused("ward-node not found beside `ward` or on PATH; install the node tarball")
    })?;
    if std::os::unix::net::UnixStream::connect(home.socket()).is_ok() {
        return Err(refused(format!(
            "the local node is already serving on {}",
            home.socket().display()
        )));
    }
    let _ = std::fs::remove_file(home.socket());
    let error = std::process::Command::new(&binary)
        .args(serve_args(&home, &record))
        .args(extra)
        .exec();
    Err(ward_daemon::Error::Io {
        path: binary,
        source: error,
    })
}

/// The flags `ward node serve` starts `ward-node` with.
pub(crate) fn serve_args(home: &NodeHome, record: &MigrationRecord) -> Vec<OsString> {
    vec![
        "--socket".into(),
        home.socket().into(),
        "--state-dir".into(),
        home.state_dir().into(),
        "--node-id".into(),
        record.node.to_string().into(),
        "--trusted-issuers".into(),
        home.trust_store().into(),
        "--task-root".into(),
        home.task_root().into(),
        "--network-allowlist".into(),
        "--output-return".into(),
    ]
}

/// `name` beside the running `ward`, else on `PATH`.
fn find(name: &str) -> Option<PathBuf> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        .filter(|path| path.is_file());
    beside.or_else(|| {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(name))
                .find(|candidate| candidate.is_file())
        })
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::BTreeMap;

    use ward_events::{NodeId, PrincipalId};

    use super::*;
    use crate::node_mode::RECORD_FORMAT;

    fn record() -> MigrationRecord {
        MigrationRecord {
            format: RECORD_FORMAT,
            node: NodeId::from_u128(4),
            issuer: PrincipalId::from_u128(2),
            issuer_key_id: String::new(),
            migrated_at_unix_ms: 0,
            source: PathBuf::from("/state"),
            snapshots: Vec::new(),
            evidence: Vec::new(),
            policy: Vec::new(),
        }
    }

    fn run(dir: &Path) -> NodeRun {
        NodeRun {
            dir: dir.to_path_buf(),
            argv: vec!["true".to_owned()],
            snapshot: None,
            budget: Duration::from_secs(60),
        }
    }

    #[test]
    fn a_run_outside_local_node_mode_is_refused_and_nothing_runs() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let error = run_via_node(state.path(), &run(project.path())).unwrap_err();
        assert!(error.to_string().contains("ward node migrate"), "{error}");
        assert!(!NodeHome::under(state.path()).dir().exists());
        let error = serve(state.path(), &[]).unwrap_err();
        assert!(error.to_string().contains("ward node migrate"), "{error}");
    }

    fn migrated(state: &Path) {
        let plan = super::super::migrate::plan(state).unwrap();
        super::super::migrate::migrate(&plan, NodeId::from_u128(4), &mut |_| Ok(())).unwrap();
    }

    #[test]
    fn a_policy_the_node_cannot_enforce_is_refused_by_name_before_the_node_is_asked() {
        let state = tempfile::tempdir().unwrap();
        migrated(state.path());
        let project = tempfile::tempdir().unwrap();
        let error = run_via_node(state.path(), &run(project.path()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("credentials.github: ask"), "{error}");
        assert!(error.contains("nothing ran"), "{error}");
        assert!(
            !NodeHome::under(state.path())
                .snapshots()
                .join("manifests")
                .exists(),
            "a refused run must capture nothing"
        );
    }

    #[test]
    fn a_runnable_policy_with_no_node_serving_fails_closed_naming_the_socket() {
        let state = tempfile::tempdir().unwrap();
        migrated(state.path());
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".ward")).unwrap();
        std::fs::write(
            project.path().join(".ward/policy.yaml"),
            "network: offline\ncredentials:\n  github: deny\n  ssh-signing: deny\n",
        )
        .unwrap();
        let error = run_via_node(state.path(), &run(project.path()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not serving"), "{error}");
        assert!(error.contains("nothing runs in-process"), "{error}");
        assert!(error.contains(&NodeHome::under(state.path()).socket().display().to_string()));
    }

    #[test]
    fn the_envelope_binds_a_fresh_attempt_to_the_local_issuer_and_the_compiled_manifest() {
        let request = run(Path::new("/p"));
        let snapshot = ward_events::SnapshotId::new(ward_events::Blake3Hash::from_bytes([1; 32]));
        let manifest = CapabilityManifest::new(NetworkGrant::Offline);
        let envelope = envelope(
            &record(),
            SessionId::from_u128(5),
            "proj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            &request,
            &manifest,
            snapshot,
        )
        .unwrap();
        assert_eq!(envelope.node(), NodeId::from_u128(4));
        assert_eq!(envelope.session(), SessionId::from_u128(5));
        let lease = envelope.authority().lease();
        assert_eq!(lease.issuer(), PrincipalId::from_u128(2));
        assert_eq!(lease.subject(), envelope.agent());
        assert_eq!(lease.task(), envelope.binding().task());
        assert_eq!(envelope.workload().argv().args(), ["true"]);
        assert_eq!(envelope.workload().snapshot(), snapshot);
        assert_eq!(envelope.workload().wall_clock_budget_ms(), 60_000);
        assert_eq!(
            envelope.workload().capability_manifest(),
            &CapabilityManifestBytes::encode(&manifest).unwrap()
        );
        let other = envelope_binding(&request);
        assert_ne!(other, envelope.binding(), "every run is a fresh attempt");
    }

    fn envelope_binding(request: &NodeRun) -> TaskBinding {
        envelope(
            &record(),
            SessionId::from_u128(5),
            "proj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            request,
            &CapabilityManifest::new(NetworkGrant::Offline),
            ward_events::SnapshotId::new(ward_events::Blake3Hash::from_bytes([1; 32])),
        )
        .unwrap()
        .binding()
    }

    #[test]
    fn serve_starts_the_node_on_the_home_s_own_paths() {
        let home = NodeHome::under(Path::new("/s"));
        let args: Vec<String> = serve_args(&home, &record())
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let flags: BTreeMap<&str, &str> = args
            .chunks(2)
            .take(5)
            .map(|pair| (pair[0].as_str(), pair[1].as_str()))
            .collect();
        assert_eq!(flags["--socket"], "/s/node/node.sock");
        assert_eq!(flags["--state-dir"], "/s/node/state");
        assert_eq!(flags["--node-id"], NodeId::from_u128(4).to_string());
        assert_eq!(flags["--trusted-issuers"], "/s/node/trusted-issuers");
        assert_eq!(flags["--task-root"], "/s/node/tasks");
        assert_eq!(&args[10..], ["--network-allowlist", "--output-return"]);
    }
}
