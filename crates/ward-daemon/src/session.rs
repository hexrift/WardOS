//! Session lifecycle: policy → manifest → entry snapshot → sandboxed execution,
//! all recorded to the append-only event log.
//!
//! Phase 1 keeps session state on disk so it survives across `ward` invocations:
//! `ward up` records a [`SessionMeta`] under `<state>/sessions/<id>/session.json`
//! and points `<state>/projects/<project-id>/current` at it; `ward run` reopens
//! that session's log and resumes its hash chain; `ward stop` seals the log and
//! clears the pointer. The daemon/socket split (ADR-0009) replaces the on-disk
//! pointer with a live supervisor in Phase 2.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use ward_events::{
    AgentIdentity, AgentKind, AgentState, AttemptId, BoundedArgv, BoundedText, DenyReason,
    EndReason, ExitStatus, FileChangeKind, ImageDigest, NameText, Origin, Pid, ProcessRef, RuleRef,
    SandboxPath, SandboxRoot, Scope, ServiceId, ShortText, StepStatus, VerifyRequester,
    VerifySummary, WardEvent,
};
use ward_policy::{CapabilityManifest, NetworkCapability, ObserverMode, Policy, merge};
use ward_snapshot::{CaptureOptions, SnapshotMeta, SnapshotRole, SnapshotStore};

use crate::attempt::{
    AttemptGuard, CancelToken, finalize_interrupted, lock_session_verification, next_attempt_id,
};
use crate::control::{LocalLog, RemoteSink, SOCKET_NAME, Sink, unix_ms};
use crate::describe::SessionDescription;
use crate::egress::Egress;
use crate::error::{Error, Result};
use crate::gateway::Gateway;
use crate::github;
use crate::hooks::{DaemonHolder, Holder, Hooks};
use crate::ids::{ev_capture, ev_hash, ev_role, ev_snapshot, new_session_id, project_id_for};
use crate::observe::{DrainClock, Observation, Observers, file_batch};
use crate::pause;
use crate::sandbox::{Launch, RELAY_ADDR, StdioMode, find_shim};
use crate::verify;
use crate::watch::{CaptureMode, Captured, WatchOutcome};

/// A live WardOS session over one project.
pub struct Session {
    manifest: CapabilityManifest,
    worktree: PathBuf,
    entry_snapshot: String,
    origin_repo: Option<String>,
    sink: Box<dyn Sink>,
    started: SystemTime,
    agent: AgentIdentity,
    next_pid: u32,
    root_pid: Pid,
    session_str: String,
    project_id: String,
    state: PathBuf,
    log_path: PathBuf,
    /// The next verification attempt id this session will allocate (#139):
    /// recomputed from the log at open time ([`crate::attempt::next_attempt_id`]),
    /// so it stays correct across process restarts without its own counter file.
    next_attempt: AttemptId,
    /// Cancellation handle for the next/current `verify()` call (#139). A fresh,
    /// never-cancelled token by default; [`Session::begin_verify_cancel`] replaces
    /// it with one the caller can hold onto and cancel from elsewhere.
    cancel: CancelToken,
    /// The low-space preflight's configured minimum (#151 item 6), read once
    /// at open time from [`crate::space::min_free_bytes`]. Kept on `Session`
    /// (rather than re-read from the environment at every call) so a test can
    /// set it directly to force the guard to trip or clear without needing to
    /// mutate process-global environment state — see `crate::space`'s own
    /// tests for why that would be undesirable even just for tests.
    min_free_bytes: u64,
}

/// The on-disk record of a session, written to `sessions/<id>/session.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMeta {
    /// Session id (`sess_…`).
    pub id: String,
    /// Canonical project worktree path.
    pub project: PathBuf,
    /// Stable project id (`proj_…`).
    pub project_id: String,
    /// Entry snapshot id (`blake3:…`).
    pub entry_snapshot: String,
    /// `owner/repo` of the worktree's `origin` remote, resolved once when
    /// the session started (see [`github::resolve_origin_repo`]) and never
    /// re-read afterward — the value `RepoSelector::CurrentRepository`
    /// grants use for the rest of the session (issue #196). `None` when
    /// there was no resolvable origin at session start. Absent (defaults to
    /// `None`) in records written before this field was persisted.
    #[serde(default)]
    pub origin_repo: Option<String>,
    /// The effective capability manifest.
    pub manifest: CapabilityManifest,
    /// Session start time, milliseconds since the Unix epoch.
    pub started_unix_ms: u64,
    /// The agent identity recorded at start (absent in records written before it
    /// was persisted).
    #[serde(default)]
    pub agent: Option<AgentIdentity>,
}

impl SessionMeta {
    /// How long ago the session started (saturating at zero).
    #[must_use]
    pub fn started_ago(&self) -> Duration {
        let start = UNIX_EPOCH + Duration::from_millis(self.started_unix_ms);
        SystemTime::now().duration_since(start).unwrap_or_default()
    }

    /// Load the current session's metadata for `project_dir`, if one is active.
    ///
    /// Does not start a session or touch the event log.
    pub fn current(project_dir: &Path, state: &Path) -> Result<Option<Self>> {
        let worktree = project_dir
            .canonicalize()
            .map_err(|e| Error::io(project_dir, e))?;
        let project_id = project_id_for(&worktree).to_string();
        let Some(id) = read_current(state, &project_id)? else {
            return Ok(None);
        };
        match Self::load(state, &id) {
            Ok(meta) => Ok(Some(meta)),
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Load the record of session `id` from `sessions/<id>/session.json`.
    pub fn load(state: &Path, id: &str) -> Result<Self> {
        let path = meta_path(state, id);
        let bytes = std::fs::read(&path).map_err(|e| Error::io(&path, e))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Project(format!("{}: {e}", path.display())))
    }

    /// The immutable facts of the session, as [`Session::describe`] reports them
    /// for a reopened session.
    #[must_use]
    pub fn describe(&self) -> SessionDescription {
        let agent = self.agent.clone().unwrap_or_else(unknown_agent);
        SessionDescription {
            session: self.id.clone(),
            project: self.project_id.clone(),
            worktree: self.project.clone(),
            started_unix_ms: self.started_unix_ms,
            agent: Some((&agent).into()),
            entry_snapshot: self.entry_snapshot.clone(),
            policy_hash: self.manifest.policy_hash.to_hex(),
            manifest: self.manifest.clone(),
        }
    }
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
    /// Which capture source produced the file events.
    pub capture: CaptureMode,
    /// Whether the inotify watch lost coverage of some part of the worktree
    /// during this run (a nested directory could not be, or could not be
    /// re-, registered). Always `false` for [`CaptureMode::Scan`], which has
    /// no notion of partial coverage. See #144.
    pub observer_degraded: bool,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
}

/// What `ward stop --restore-entry` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    /// The entry snapshot written over the worktree.
    pub snapshot: String,
    /// Paths written, removed or moved aside to match it.
    pub files: usize,
    /// Worktree-relative directory holding what the restore replaced, when
    /// anything differed.
    pub backup: Option<String>,
}

/// What `ward verify` reports.
#[derive(Clone, Debug)]
pub struct VerifyReport {
    /// Candidate snapshot id.
    pub candidate: String,
    /// Whether the trusted verifier passed.
    pub passed: bool,
    /// The budget, in seconds, when the verifier was killed for exceeding it instead
    /// of exiting on its own (`VerificationTimedOut`, #139). `None` when it exited.
    pub timed_out: Option<u64>,
    /// Parsed counts.
    pub summary: VerifySummary,
    /// Protected paths the verifier took from the entry snapshot instead of the worktree.
    pub restored: Vec<String>,
    /// The verifier's combined output.
    pub output: String,
}

/// What a session reopened from a record written before the identity was persisted
/// reports as its agent.
fn unknown_agent() -> AgentIdentity {
    AgentIdentity {
        kind: AgentKind::Other,
        name: NameText::new("unknown"),
        version: NameText::new("0"),
        image: None,
    }
}

/// Paths `TamperWard` protects (`protected.tests` in `.tamperward/config.yml`),
/// read from the *entry* snapshot `entry_snapshot` under `state` so a worktree
/// edit cannot lift them; empty when the file or key is absent.
#[must_use]
pub fn protected_paths(state: &Path, entry_snapshot: &str) -> Vec<String> {
    let yaml = SnapshotStore::open(state.join("cas"))
        .ok()
        .zip(entry_snapshot.parse::<ward_snapshot::SnapshotId>().ok())
        .and_then(|(store, entry)| store.cat(entry, Path::new(verify::CONFIG_PATH)).ok());
    yaml.and_then(|bytes| {
        serde_yaml::from_str::<verify::Config>(&String::from_utf8_lossy(&bytes)).ok()
    })
    .map(|c| c.protected.tests)
    .unwrap_or_default()
}

/// A refused GitHub grant, as recorded before the command starts.
fn github_refusal(reason: DenyReason) -> WardEvent {
    WardEvent::CredentialDenied {
        service: ServiceId::new(github::SERVICE).unwrap_or_else(|_| unreachable!("static id")),
        scope: Scope::default(),
        reason,
    }
}

/// Identity of the 0.1 verifier: a namespace sandbox on this host, not an image.
fn verifier_image() -> ImageDigest {
    ImageDigest::from_bytes(*blake3::hash(b"ward-verifier/namespace/0.1").as_bytes())
}

/// Options for [`Session::launch`].
#[derive(Clone, Debug, Default)]
pub struct LaunchOpts {
    /// Extra environment inside the sandbox.
    pub env: Vec<(String, String)>,
    /// Inherit the terminal instead of capturing output.
    pub interactive: bool,
    /// Credentials the proxy injects for this launch (`gateway.rs`).
    pub gateways: Vec<Gateway>,
    /// Files seeded read-only into the sandbox: `(path, content)`.
    pub seeds: Vec<(String, String)>,
    /// Credential refusals to record before the command starts.
    pub refusals: Vec<WardEvent>,
    /// Lines for the user about credential decisions.
    pub notes: Vec<String>,
}

/// Nominal validity of a gateway grant. The route itself lives exactly as long
/// as the launch; this is the bound recorded in the log.
const GATEWAY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

impl Session {
    /// Open a session using the default state root (`$WARD_STATE_DIR` or
    /// `~/.local/state/ward`).
    pub fn start(project_dir: &Path) -> Result<Self> {
        Self::start_in(project_dir, &state_root())
    }

    /// Open a session, storing the snapshot CAS and event log under `state`.
    ///
    /// Resolves the project, merges policy into a manifest, freezes an entry
    /// snapshot, and opens a fresh event log. Does not itself become the project's
    /// current session; call [`persist_current`](Self::persist_current) for that.
    pub fn start_in(project_dir: &Path, state: &Path) -> Result<Self> {
        let worktree = project_dir
            .canonicalize()
            .map_err(|e| Error::io(project_dir, e))?;
        let project_id = project_id_for(&worktree);
        let project_id_str = project_id.to_string();
        let session = new_session_id()?;
        let session_str = session.to_string();

        let project_policy = load_project_policy(&worktree)?;
        // `ward-policy` and `ward-events` keep independent id newtypes so each crate
        // builds alone; bridge the same identity into the policy-crate types here.
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &project_policy,
            ward_policy::SessionId(session_str.clone()),
            ward_policy::ProjectId(project_id_str.clone()),
        );

        let store =
            SnapshotStore::open(state.join("cas")).map_err(|e| Error::Snapshot(e.to_string()))?;
        let entry = store
            .store_snapshot(&worktree, SnapshotRole::Entry, CaptureOptions::default())
            .map_err(|e| Error::Snapshot(e.to_string()))?;
        // Resolved once, here, against the live worktree — before the sandbox
        // exists, the same trust window the entry snapshot capture above
        // relies on — and never again for the rest of the session (issue #196).
        let origin_repo = github::resolve_origin_repo(&worktree);

        let session_dir = session_dir(state, &session_str);
        std::fs::create_dir_all(&session_dir).map_err(|e| Error::io(&session_dir, e))?;
        let log_path = session_dir.join("events.log");
        let manifest_hash = ev_hash(manifest.policy_hash.0);
        let started = SystemTime::now();
        let sink = Box::new(LocalLog::create(
            &log_path,
            session,
            manifest_hash,
            started,
        )?);

        let agent = AgentIdentity {
            kind: AgentKind::Other,
            name: NameText::new("shell"),
            version: NameText::new(env!("CARGO_PKG_VERSION")),
            image: None,
        };
        let mut s = Self {
            manifest,
            worktree,
            entry_snapshot: entry.to_string(),
            origin_repo,
            sink,
            started,
            agent: agent.clone(),
            next_pid: 1,
            root_pid: Pid::new(1).map_err(|e| Error::Events(e.to_string()))?,
            session_str,
            project_id: project_id_str,
            state: state.to_path_buf(),
            log_path,
            // A brand-new log has no attempts to have left dangling.
            next_attempt: AttemptId::new(1),
            cancel: CancelToken::new(),
            min_free_bytes: crate::space::min_free_bytes(),
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

    /// Reopen the project's current session (set by [`persist_current`]) for more
    /// commands, resuming its hash chain from the log head. Returns `None` when the
    /// project has no active session.
    ///
    /// [`persist_current`]: Self::persist_current
    pub fn open_current(project_dir: &Path, state: &Path) -> Result<Option<Self>> {
        let Some(meta) = SessionMeta::current(project_dir, state)? else {
            return Ok(None);
        };
        let worktree = meta.project.clone();
        let dir = session_dir(state, &meta.id);
        let log_path = dir.join("events.log");
        let started = UNIX_EPOCH + Duration::from_millis(meta.started_unix_ms);
        // A running daemon (ADR-0015) is the writer; otherwise this process is. Either
        // way, this is a process (re)taking ownership of the log — exactly when #139
        // says a dangling verification attempt (one whose own process died before it
        // reached a terminal record) should be reconciled, so it is closed out here
        // before anything else reads or writes through `sink`. Idempotent: a daemon
        // that had already reconciled at its own `serve` startup just finds nothing
        // left to do.
        let mut sink: Box<dyn Sink> = match RemoteSink::connect(&dir.join(SOCKET_NAME)) {
            Some(remote) => Box::new(remote),
            None => Box::new(LocalLog::open(&log_path, started)?),
        };
        // Fail closed (review of #208, finding 3): a reconciliation failure here
        // means this process cannot say whether a dangling attempt was actually
        // closed out, so it must not hand back a `Session` that looks fully caught
        // up when it might not be. Safe to call unconditionally, including through
        // a `RemoteSink` onto a daemon that may be mid-verification (finding 1):
        // `reconcile_dangling_attempts` never interrupts a marker whose owning
        // process is still verifiably alive, so a second `ward` command merely
        // opening this session can no longer ever cut a live attempt short.
        crate::attempt::reconcile_dangling_attempts(&mut *sink, &dir)?;
        Ok(Some(Self {
            manifest: meta.manifest,
            worktree,
            entry_snapshot: meta.entry_snapshot,
            next_attempt: next_attempt_id(&log_path),
            cancel: CancelToken::new(),
            // Carried over from the record written at session start, never
            // recomputed from the (possibly since-reopened) live worktree.
            origin_repo: meta.origin_repo,
            sink,
            started,
            agent: meta.agent.unwrap_or_else(unknown_agent),
            next_pid: 1,
            root_pid: Pid::new(1).map_err(|e| Error::Events(e.to_string()))?,
            session_str: meta.id,
            project_id: meta.project_id,
            state: state.to_path_buf(),
            log_path,
            min_free_bytes: crate::space::min_free_bytes(),
        }))
    }

    /// Record this session as the project's current session: write its
    /// `session.json` and point `projects/<project-id>/current` at it.
    pub fn persist_current(&self) -> Result<()> {
        let meta = SessionMeta {
            id: self.session_str.clone(),
            project: self.worktree.clone(),
            project_id: self.project_id.clone(),
            entry_snapshot: self.entry_snapshot.clone(),
            origin_repo: self.origin_repo.clone(),
            manifest: self.manifest.clone(),
            started_unix_ms: unix_ms(self.started),
            agent: Some(self.agent.clone()),
        };
        let path = meta_path(&self.state, &self.session_str);
        let bytes = serde_json::to_vec_pretty(&meta)
            .map_err(|e| Error::Project(format!("serialize session.json: {e}")))?;
        std::fs::write(&path, bytes).map_err(|e| Error::io(&path, e))?;
        write_current(&self.state, &self.project_id, &self.session_str)
    }

    /// The effective capability manifest.
    pub fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    /// The immutable facts of this session (`ward session describe`).
    #[must_use]
    pub fn describe(&self) -> SessionDescription {
        SessionDescription {
            session: self.session_str.clone(),
            project: self.project_id.clone(),
            worktree: self.worktree.clone(),
            started_unix_ms: unix_ms(self.started),
            agent: Some((&self.agent).into()),
            entry_snapshot: self.entry_snapshot.clone(),
            policy_hash: self.manifest.policy_hash.to_hex(),
            manifest: self.manifest.clone(),
        }
    }

    /// Capture the worktree into the session CAS under `role` and record it
    /// (`ward snapshot create`). The sandbox is frozen for the length of the
    /// walk ([`freeze_for_capture`](Self::freeze_for_capture), ST-018) so no
    /// agent write can interleave with it; the recorded stall is how long the
    /// capture held the tree still.
    pub fn snapshot(&mut self, role: SnapshotRole) -> Result<SnapshotMeta> {
        // Low-space preflight (#151 item 6): refuse before the walk starts,
        // not partway through it. Never deletes anything on a trip — see
        // `crate::space`'s own doc comment.
        crate::space::check(&self.state, self.min_free_bytes)?;
        let store = crate::snapshot::open_store(&self.state)?;
        let guard = self.freeze_for_capture();
        let started = Instant::now();
        let meta = store
            .capture(&self.worktree, role, CaptureOptions::default())
            .map_err(|e| Error::Snapshot(e.to_string()))?;
        let stall = started.elapsed();
        drop(guard);
        self.emit(
            Origin::Wardd,
            WardEvent::SnapshotCreated {
                role: ev_role(role),
                id: ev_snapshot(meta.id),
                entries: meta.entries,
                bytes: meta.bytes,
                capture: ev_capture(meta.capture_mode),
                stall,
            },
        )?;
        Ok(meta)
    }

    /// Freeze the session's sandbox for the length of a capture so no agent
    /// write interleaves with the walk (ST-018, `docs/security-model.md` G5/G9):
    /// the returned guard holds the freeze and thaws when it drops. A no-op when
    /// no sandbox of the session is running, and it leaves a user pause in place.
    fn freeze_for_capture(&self) -> pause::CaptureFreeze {
        pause::CaptureFreeze::acquire(&self.state, &self.session_str)
    }

    /// Paths `TamperWard` protects (`protected.tests` in `.tamperward/config.yml`),
    /// read from the *entry* snapshot so a worktree edit cannot lift them; empty
    /// when the file or key is absent.
    #[must_use]
    pub fn protected_paths(&self) -> Vec<String> {
        protected_paths(&self.state, &self.entry_snapshot)
    }

    /// The state root holding this session's CAS and log.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state
    }

    /// Where an `ask` waits for the user (ADR-0016): the session daemon, when
    /// one serves this session; otherwise nothing, and the ask passes through
    /// to the agent's own prompt as before.
    fn holder(&self) -> Option<std::sync::Arc<dyn Holder>> {
        let socket = session_dir(&self.state, &self.session_str).join(SOCKET_NAME);
        RemoteSink::connect(&socket)?;
        Some(std::sync::Arc::new(DaemonHolder::new(
            socket,
            approval_timeout(),
        )))
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

    /// Force any buffered log records to disk. Call after [`run`](Self::run) on a
    /// session that stays active so nothing is lost if the process exits.
    pub fn sync(&mut self) -> Result<()> {
        self.sink.sync()
    }

    /// Run one command inside the sandbox, recording its events.
    ///
    /// File changes are captured live over the worktree with inotify for the
    /// duration of the command; if inotify cannot be initialised the run falls back
    /// to a before/after directory scan. Reads are captured only when the observer
    /// is Live or StepThrough.
    pub fn run(&mut self, argv: &[String]) -> Result<RunReport> {
        self.launch(argv, &LaunchOpts::default())
    }

    /// Launch a known agent interactively (`docs/agent-integration.md`).
    pub fn run_agent(
        &mut self,
        name: &str,
        args: &[String],
        pass_env: &[String],
    ) -> Result<RunReport> {
        let (command, opts) = self.agent_launch(name, args, pass_env, &[])?;
        self.launch(&command, &opts)
    }

    /// What [`run_agent`](Self::run_agent) would launch: the profile's command and
    /// env, explicitly passed-through host variables, and the model-API gateway
    /// when the host holds the key. Passing the key variable through with
    /// `pass_env` hands the agent the real key instead, and no gateway is set up.
    /// Nothing is granted when the session is offline.
    pub fn agent_launch(
        &self,
        name: &str,
        args: &[String],
        pass_env: &[String],
        grants: &[String],
    ) -> Result<(Vec<String>, LaunchOpts)> {
        let profile = crate::agents::profile(name)
            .ok_or_else(|| Error::Project(format!("unknown agent `{name}`")))?;
        let mut env: Vec<(String, String)> = profile
            .env
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        for key in pass_env {
            if let Ok(v) = std::env::var(key) {
                env.push((key.clone(), v));
            }
        }
        let online = !matches!(self.manifest.network, NetworkCapability::Offline);
        let mut gateways = profile
            .gateway
            .filter(|g| online && !pass_env.iter().any(|k| k == g.key_env))
            .map(|spec| Gateway::resolve(&spec, &self.state))
            .transpose()?
            .flatten()
            .into_iter()
            .collect::<Vec<_>>();
        let mut seeds: Vec<(String, String)> = profile
            .settings
            .map(|s| (s.path.to_owned(), (s.content)()))
            .into_iter()
            .collect();
        let mut refusals = Vec::new();
        let mut notes = Vec::new();
        let requested = grants.iter().any(|g| g == github::SERVICE);
        // Fixed once, at session start (`self.origin_repo`), never re-read from
        // the live worktree at grant time (issue #196): a `.git/config` edit
        // the agent makes mid-session cannot redirect where a
        // `RepoSelector::CurrentRepository` credential grant points.
        match github::grant(
            &self.manifest,
            self.origin_repo.as_deref(),
            &self.state,
            requested,
        )? {
            github::Grant::Granted {
                gateways: routes,
                repos,
                write,
            } => {
                notes.push(format!(
                    "github: token stays on the host; the proxy injects it for {} ({})",
                    repos.join(", "),
                    if write { "read & write" } else { "read-only" }
                ));
                gateways.extend(routes);
                seeds.push((github::GITCONFIG_PATH.to_owned(), github::gitconfig()));
            }
            github::Grant::Ask => notes.push(
                "github: policy says ask; pass --grant github to route git and API calls through the proxy"
                    .to_owned(),
            ),
            github::Grant::Denied if requested => {
                refusals.push(github_refusal(DenyReason::PolicyDeny {
                    rule: RuleRef::new("credentials.github").map_err(|e| Error::Events(e.to_string()))?,
                }));
                notes.push("github: denied by policy".to_owned());
            }
            github::Grant::NoKey if requested => {
                notes.push(format!("github: no {} on the host or in the vault", github::KEY_ENV));
            }
            github::Grant::NoRemote if requested => {
                notes.push("github: the worktree has no GitHub origin remote to scope the grant to".to_owned());
            }
            github::Grant::Offline if requested => notes.push("github: session is offline".to_owned()),
            _ => {}
        }
        for g in &gateways {
            env.extend(g.env.iter().cloned());
        }
        let mut command = vec![profile.binary.to_string()];
        command.extend(args.iter().cloned());
        Ok((
            command,
            LaunchOpts {
                env,
                interactive: true,
                gateways,
                seeds,
                refusals,
                notes,
            },
        ))
    }

    /// Whether the session is paused by the host (ADR-0019 §3): its daemon has
    /// written the marker the proxies refuse on.
    #[must_use]
    pub fn paused(&self) -> bool {
        pause::marker_path(&self.state, &self.session_str).exists()
    }

    /// Run a command with explicit options; every run gets the session egress proxy.
    /// Refused while the session is paused: a sandbox started then would run
    /// unfrozen behind a closed proxy, which is neither state the user chose.
    ///
    /// Once `CommandStarted` (and any credential grant `opts.gateways` makes) is on
    /// the log, every exit path leaves exactly one terminal record behind it —
    /// `CommandFinished`, or, when the launch could not be carried that far (the
    /// sandbox or hook socket failed to bind, the child failed to spawn, …),
    /// `LaunchAborted` (#140, PR #197 review). Without this, a credential granted
    /// above could outlive a launch that never even started: the daemon's
    /// `open_launches` would keep the pid open forever, exactly the staleness #140
    /// exists to prevent, just reached through a different exit path than an
    /// ordinary `CommandFinished`. The real error is still returned to the caller
    /// unchanged either way — the terminal record is additive, never a substitute
    /// (the same discipline `VerificationErrored` (#139) uses for `Session::verify`).
    /// If the terminal record's own append also fails (sink gone, disk full, …),
    /// that failure is folded into the returned error rather than discarded, so the
    /// caller learns the log may still end at `CommandStarted`.
    pub fn launch(&mut self, argv: &[String], opts: &LaunchOpts) -> Result<RunReport> {
        self.refuse_while_paused()?;
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

        for refusal in &opts.refusals {
            self.emit(Origin::Wardd, refusal.clone())?;
        }
        for g in &opts.gateways {
            self.emit(Origin::Wardd, g.granted(GATEWAY_TTL)?)?;
        }

        // From here on `CommandStarted` (and any grant just above) is already on the
        // log, so the `match` below never lets an error skip past leaving a terminal
        // record for it.
        let result = self.run_launch(pid, argv, opts);
        let outcome = match result {
            Ok(report) => Ok(report),
            Err(e) => {
                let reason = ShortText::new(&e.to_string());
                Err(
                    match self.emit(Origin::Kernel, WardEvent::LaunchAborted { pid, reason }) {
                        Ok(()) => e,
                        // The fallback terminal record's own append failed too: never
                        // silently discard that (the exact gap #140/#139 both exist to
                        // close). Fold both failures into what the caller sees, so this
                        // is distinguishable from an ordinary abort whose record landed.
                        Err(emit_err) => Error::Events(format!(
                            "launch failed ({e}), and the terminal record for it could \
                             not be written ({emit_err}); the log may still end at \
                             CommandStarted"
                        )),
                    },
                )
            }
        };
        // The agent is idle either way: the launch finished, or it never got off the
        // ground. Best-effort — a failure here is secondary to `outcome` above, and
        // before this fix a failed launch left the agent reporting `Working` forever,
        // since the function returned early without ever reaching this point.
        let _ = self.emit(
            Origin::Wardd,
            WardEvent::AgentStateChanged {
                state: AgentState::Idle,
            },
        );
        outcome
    }

    /// The launch's fallible span, from starting the observers and the sandbox/hook
    /// setup through the child's own exit and its `CommandFinished`: everything that
    /// can fail with `CommandStarted` (and any credential grant above it) already on
    /// the log. An `Err` here means the launch never reached `CommandFinished`;
    /// [`launch`](Self::launch) turns that into a `LaunchAborted` terminal record
    /// instead (#140, PR #197 review).
    ///
    /// Split out of [`launch`](Self::launch) so the observers also live in one scope
    /// that owns their shutdown: [`Observers`] stops every producer it holds when it
    /// drops, whichever way this function is left, and the final flush below runs on
    /// the failure paths too — a sandbox that could not be prepared, a child that
    /// could not be spawned — so what the producers had already recorded still
    /// reaches the log instead of dying with the thread that held it. File and
    /// network observations reach the log *while the command is still running*
    /// (#137), not in one batch after it exits: the watch, the proxy's recorder and
    /// the hook broker each hand what they see to a bounded queue, and this thread —
    /// the session's single log writer — drains those queues between waits on the
    /// child and appends what it takes through the same [`Sink`](crate::control::Sink)
    /// every other record goes through. The producers never touch the log, so there
    /// is still exactly one writer.
    fn run_launch(&mut self, pid: Pid, argv: &[String], opts: &LaunchOpts) -> Result<RunReport> {
        let watch_reads = matches!(
            self.manifest.observer,
            ObserverMode::Live | ObserverMode::StepThrough(_)
        );
        let run_dir = run_dir(&self.session_str)?;
        let mut observers = Observers::new(run_dir.clone());
        let live_watch = observers.start_watch(&self.worktree, watch_reads);
        // Without a live watch there is nothing to stream: the fallback can only
        // diff the tree before against the tree after.
        let before = (!live_watch).then(|| scan(&self.worktree));

        let mut egress = Egress::start(
            &run_dir,
            &self.manifest.network,
            opts.gateways.iter().map(|g| g.route.clone()).collect(),
        )?;
        egress.watch_marker(pause::marker_path(&self.state, &self.session_str));
        observers.set_egress(egress);
        observers.set_hooks(Hooks::start_with(
            &run_dir,
            self.manifest.observer,
            self.protected_paths(),
            self.holder(),
        )?);

        let comm = comm(argv);
        let by = ProcessRef {
            pid,
            comm: comm.clone(),
        };
        let mut changed_paths = BTreeSet::new();
        // A sink failure during a live drain stops further live drains but never
        // the child: the agent's command is not the log's problem to abort.
        let mut live_error: Option<Error> = None;

        let run = match self.prepare(argv, opts, &run_dir, &observers) {
            Ok(launch) => {
                let mut clock = DrainClock::new();
                launch.run_observed(&mut || {
                    if live_error.is_some() || !clock.due(observers.queued()) {
                        return;
                    }
                    let batch = observers.drain(&by);
                    if let Err(e) = self.ingest(batch, &mut changed_paths) {
                        live_error = Some(e);
                    }
                })
            }
            Err(e) => Err(e),
        };

        // The one and only tail flush: the producers are stopped and handed over
        // here, so nothing this command observed can be appended twice, and it
        // happens before the terminal `CommandFinished` record below.
        let finished = observers.finish(&by);
        let watch_dropped = finished.watch.as_ref().map_or(0, |w| w.dropped);
        let (captured, capture, observer_degraded) =
            collect_captured(finished.watch, before, &self.worktree);
        let mut tail = file_batch(&captured, &by, watch_dropped, finished.capacity);
        tail.extend(finished.tail);
        let flushed = self.ingest(tail, &mut changed_paths);

        // A failed run still flushed what was observed before it failed; only now
        // does the failure win.
        let outcome = run?;
        flushed?;
        if let Some(e) = live_error {
            return Err(e);
        }

        self.emit(
            Origin::Kernel,
            WardEvent::CommandFinished {
                pid,
                exit: exit_status(outcome.code),
                duration: outcome.duration,
            },
        )?;

        Ok(RunReport {
            argv: argv.to_vec(),
            code: outcome.code,
            files_changed: changed_paths.len(),
            duration: outcome.duration,
            capture,
            observer_degraded,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
        })
    }

    /// The sandboxed launch: egress and hook sockets bound, settings seeded, the
    /// shim when it can relay, proxy env, and the caller's env and stdio.
    ///
    /// Unix socket paths are capped at 108 bytes, so both sockets live in the short,
    /// private per-session `run_dir` rather than under the (possibly deep) state root.
    fn prepare(
        &self,
        argv: &[String],
        opts: &LaunchOpts,
        run_dir: &Path,
        observers: &Observers,
    ) -> Result<Launch> {
        let mut launch = Launch::new(&self.worktree, argv.to_vec());
        if let Some(socket) = observers.egress_socket() {
            launch = launch.egress(socket);
        }
        if let Some(socket) = observers.hook_socket() {
            launch = launch.hooks(socket);
        }
        for (n, (path, content)) in opts.seeds.iter().enumerate() {
            let file = run_dir.join(format!("seed-{n}"));
            std::fs::write(&file, content).map_err(|e| Error::io(&file, e))?;
            launch = launch.seed(file, path.clone());
        }
        // The shim is used only when it can relay to the egress socket; an older build
        // without `--relay` would reject the flag, so fall back to a direct exec (still
        // isolated by bwrap; the socket is bound for socket-aware tools).
        if let Some(shim) = find_shim().filter(|s| s.relay) {
            // Both cases: curl and friends honour only lowercase `http_proxy`.
            launch = launch.shim_flags(shim.flags()).shim(shim.path);
            for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                launch = launch.env(key, format!("http://{RELAY_ADDR}"));
            }
            for key in ["NO_PROXY", "no_proxy"] {
                launch = launch.env(key, "localhost,127.0.0.1");
            }
        }
        for (k, v) in &opts.env {
            launch = launch.env(k.clone(), v.clone());
        }
        if opts.interactive {
            launch = launch.stdio(StdioMode::Inherit);
        }
        Ok(launch)
    }

    /// Verify the worktree in a disposable verifier (`verify.rs`) and record the run:
    /// an attempt id allocated before anything expensive starts, the candidate
    /// snapshot, the start with the pristine id and config hash, one progress step
    /// per restored protected path and one for the command, then the pass or fail
    /// with the parsed summary and the output hash.
    ///
    /// #139: every exit path from here leaves exactly one terminal record behind
    /// the attempt it concerns — `VerificationPassed`, `VerificationFailed`,
    /// `VerificationTimedOut` (the command was killed at `verify.budget_secs`),
    /// `VerificationErrored` (the run could not be carried to either of those:
    /// the sandbox runtime failed to launch, a step in between errored, …),
    /// `VerificationCancelled` (a cooperative cancel, see
    /// [`begin_verify_cancel`](Self::begin_verify_cancel), took effect between
    /// steps), or `VerificationInterrupted` (this attempt, or an earlier one this
    /// session left dangling, is reconciled because the process that had been
    /// running it is gone — this call's own opening reconciliation, or the next
    /// one, since a preparation failure with no candidate yet leaves this shape
    /// too). A subscriber watching the log therefore never *silently* sees a
    /// non-terminal verification record with nothing after it. The real error is
    /// still returned to the caller either way — a terminal record on the log does
    /// not replace it. If appending that terminal record itself also fails (the
    /// sink is gone, disk full, …), the caller's error says so explicitly instead
    /// of quietly discarding it.
    ///
    /// One attempt at a time, across every handle (review 5284360930 of #208,
    /// finding 1): two `Session` handles for this same session — two threads in one
    /// process, or two entirely separate `ward`/`wardd` processes — can each call this
    /// concurrently, so the whole body below runs under
    /// [`lock_session_verification`], acquired before attempt-id allocation and held
    /// until this call returns on every exit path. See that function's own doc
    /// comment for the full reasoning, including why it is a lock distinct from
    /// reconciliation's own.
    pub fn verify(&mut self) -> Result<VerifyReport> {
        let dir = session_dir(&self.state, &self.session_str);
        // Exclusive and session-scoped for this call's entire lifetime — see the doc
        // comment above and `lock_session_verification`'s own. An ordinary local
        // binding, so it releases on every exit path below (an early `?` return, a
        // panic, or falling off the end) exactly as reliably as it would on success.
        let _verify_lock = lock_session_verification(&dir)?;

        // Close out anything a previous attempt in this session left dangling
        // before allocating a new one. The daemon's own startup and
        // `Session::open_current` already reconcile whenever they (re)take
        // ownership of the log; this additionally covers a same-process leftover —
        // a prior `verify()` call whose `AttemptGuard` dropped without
        // finishing — without needing a process restart to notice it. Fail closed
        // (review of #208, finding 3): starting a fresh attempt on top of one this
        // process could not confirm was reconciled would risk exactly the
        // contradictory-history problem #139 exists to prevent. Also refreshes
        // `self.sink`'s own cached view of the log via `Sink::resync` (review
        // 5283028228 of #208, finding 4) — now done under `_verify_lock`, so nothing
        // else can append between that refresh and this attempt's own first append.
        crate::attempt::reconcile_dangling_attempts(&mut *self.sink, &dir)?;

        // Allocated fresh from the log, under the lock, rather than from this
        // `Session`'s own cached `next_attempt` field (review 5284360930 of #208,
        // finding 1): two `Session` handles opened before either had started
        // verifying would otherwise both cache the very same result from
        // `open_current`/`start_in` and collide. Safe now that `_verify_lock` above
        // rules out a second, concurrent allocator for this session — the log
        // already reflects every attempt any earlier lock holder finished. Still
        // kept in sync on `self.next_attempt` afterward so `alloc_attempt` (used
        // directly by tests exercising `verify_prepared` in isolation, and as a
        // plain in-memory counter with no locking of its own) stays consistent with
        // what a fresh `verify()` call on this same `Session` would allocate next.
        let attempt = next_attempt_id(&self.log_path);
        self.next_attempt = AttemptId::new(attempt.get().saturating_add(1));
        // Allocated, and recorded, before any expensive preparation begins (#139
        // item 2): a subscriber sees this attempt exists, and a reconciliation pass
        // can find and close it out if this process disappears, before candidate
        // capture — which can itself take real time over a large worktree.
        let guard = AttemptGuard::start(&dir, attempt, VerifyRequester::User)?;
        self.emit(
            Origin::Wardd,
            WardEvent::VerificationAttemptStarted {
                attempt,
                requested_by: VerifyRequester::User,
            },
        )?;
        if self.cancel.is_cancelled() {
            return self.finalize_cancelled(guard, attempt, None);
        }

        // #139 item 4 (review of #208, finding 4): every fallible step between
        // `VerificationAttemptStarted` and a bound candidate — opening the CAS,
        // parsing the entry snapshot id, allocating the scratch `run_dir`, and
        // `verify::prepare` itself — shares one finalizer below. Before this fix
        // only `verify::prepare`'s own failure went through it; a `SnapshotStore`,
        // parse, or `run_dir` failure returned bare, leaving the log stuck at
        // `VerificationAttemptStarted` until some future reopen's reconciliation
        // pass happened to notice. The closure returns the entry id and scratch
        // root alongside the prepared verification so nothing after it has to
        // recompute them (and, for `run_dir`, risk a second, needless directory
        // allocation).
        let prep = (|| -> Result<(ward_snapshot::SnapshotId, PathBuf, verify::Verification)> {
            // Low-space preflight (#151 item 6): refuse before `verify::prepare`'s
            // own candidate capture (the worktree-walk-and-hash step) starts, not
            // partway through it. A trip here is folded into the same
            // `VerificationInterrupted { candidate: None, .. }` handling as any
            // other prep failure below — it never deletes anything, and the
            // pristine entry snapshot and its evidence are untouched either way.
            crate::space::check(&self.state, self.min_free_bytes)?;
            let store = SnapshotStore::open(self.state.join("cas"))
                .map_err(|e| Error::Snapshot(e.to_string()))?;
            let entry: ward_snapshot::SnapshotId = self
                .entry_snapshot
                .parse()
                .map_err(|e: ward_snapshot::SnapshotError| Error::Snapshot(e.to_string()))?;
            let scratch_root = run_dir(&self.session_str)?;
            // Freeze the agent only for the candidate capture inside `prepare`; the
            // verifier itself runs from the CAS, not the worktree (ST-018, G5/G9).
            let prepared = {
                let _freeze = self.freeze_for_capture();
                verify::prepare(&store, &self.worktree, entry, &scratch_root)?
            };
            Ok((entry, scratch_root, prepared))
        })();
        let (entry, scratch_root, prepared) = match prep {
            Ok(prep) => prep,
            Err(e) => {
                // Unlike a `verify::execute` failure, there is no candidate yet for
                // a `VerificationErrored` record to name — that field is mandatory,
                // and #139 item 3 never invents one for a failed capture. The
                // attempt itself already exists on the log
                // (`VerificationAttemptStarted` above), so it still gets its own
                // terminal record: `VerificationInterrupted { candidate: None, .. }`.
                let reason = ShortText::new(&e.to_string());
                return match finalize_interrupted(&mut *self.sink, guard, attempt, None, reason) {
                    Ok(()) => Err(e),
                    Err(finalize_err) => Err(Error::Events(format!(
                        "verification could not be prepared ({e}), and the terminal \
                         record for it could not be written ({finalize_err}); the log \
                         may still end at VerificationAttemptStarted"
                    ))),
                };
            }
        };
        // Capture succeeded: bind the candidate to the attempt now, never earlier
        // (#139 item 3).
        guard.bind_candidate(ev_snapshot(prepared.candidate));
        if self.cancel.is_cancelled() {
            let _ = std::fs::remove_dir_all(&prepared.scratch);
            let _ = std::fs::remove_dir(&scratch_root);
            return self.finalize_cancelled(guard, attempt, Some(ev_snapshot(prepared.candidate)));
        }
        self.verify_prepared(&prepared, entry, &scratch_root, attempt, guard)
    }

    /// Finalize `attempt` as cancelled (#139 item 6): append `VerificationCancelled`,
    /// finish `guard`, and return the distinguishable [`Error::Cancelled`] instead of
    /// a generic failure. Shared by every checkpoint in [`verify`](Self::verify) and
    /// [`verify_prepared`](Self::verify_prepared) that finds
    /// [`Session::cancel`](Self) already set.
    fn finalize_cancelled(
        &mut self,
        guard: AttemptGuard,
        attempt: AttemptId,
        candidate: Option<ward_events::SnapshotId>,
    ) -> Result<VerifyReport> {
        match self.emit(
            Origin::User,
            WardEvent::VerificationCancelled { attempt, candidate },
        ) {
            Ok(()) => {
                guard.finish();
                Err(Error::Cancelled(
                    "verification was cancelled before it reached a pass/fail result".to_owned(),
                ))
            }
            Err(emit_err) => Err(Error::Events(format!(
                "verification was cancelled, and the terminal record for it could not \
                 be written ({emit_err}); the log may still end at a non-terminal \
                 verification record"
            ))),
        }
    }

    /// Records and runs a verification that has already been prepared: the request
    /// and start, then a terminal record (#139), then cleanup. Split out of
    /// [`verify`](Self::verify) so it can be exercised directly with a hand-built
    /// [`verify::Verification`], without needing a real `.tamperward/config.yml` or a
    /// working sandbox runtime, to prove that a `verify::execute` failure still ends
    /// the log in `VerificationErrored` rather than a bare `VerificationStarted`.
    fn verify_prepared(
        &mut self,
        prepared: &verify::Verification,
        entry: ward_snapshot::SnapshotId,
        scratch_root: &Path,
        attempt: AttemptId,
        guard: AttemptGuard,
    ) -> Result<VerifyReport> {
        let candidate = ev_snapshot(prepared.candidate);
        self.emit(
            Origin::User,
            WardEvent::VerificationRequested {
                candidate,
                requested_by: VerifyRequester::User,
            },
        )?;
        self.emit(
            Origin::Verifier,
            WardEvent::VerificationStarted {
                candidate,
                pristine: ev_snapshot(entry),
                verifier_image: verifier_image(),
                manifest_hash: ev_hash(prepared.manifest_hash),
            },
        )?;

        // From here on `VerificationStarted` is already on the log, so every path out
        // of this function attempts to leave a terminal verification record behind
        // it. If that append itself fails too, the log may still end at
        // `VerificationStarted` — the `match` below never hides that from the caller.
        let result = self.run_prepared_verification(prepared, attempt, candidate);
        let _ = std::fs::remove_dir_all(&prepared.scratch);
        let _ = std::fs::remove_dir(scratch_root);
        match result {
            Ok(report) => {
                guard.finish();
                Ok(report)
            }
            // Cancelled between steps (checked inside `run_prepared_verification`),
            // not merely errored: a distinct terminal outcome (#139 item 6), never
            // `VerificationErrored`.
            Err(Error::Cancelled(_)) => self.finalize_cancelled(guard, attempt, Some(candidate)),
            Err(e) => {
                let reason = ShortText::new(&e.to_string());
                match self.emit(
                    Origin::Verifier,
                    WardEvent::VerificationErrored { candidate, reason },
                ) {
                    // The terminal record is on the log; the caller still sees the
                    // real failure that produced it.
                    Ok(()) => {
                        guard.finish();
                        Err(e)
                    }
                    // The append itself failed too, so the log may still end at
                    // `VerificationStarted` — exactly the silent gap this function
                    // exists to close. Never discard that: fold both failures into
                    // what the caller sees, so this case is distinguishable from an
                    // ordinary verification error whose terminal record was written
                    // successfully. The guard is deliberately left unfinished: its
                    // marker survives so the next reconciliation pass still catches
                    // this attempt even though a live terminal record could not be
                    // written just now.
                    Err(emit_err) => Err(Error::Events(format!(
                        "verification failed ({e}), and the terminal record for it \
                         could not be written ({emit_err}); the log may still end at \
                         VerificationStarted"
                    ))),
                }
            }
        }
    }

    /// The steps of a prepared verification once `VerificationStarted` is recorded:
    /// the restore progress, a cancellation checkpoint, the command's progress step,
    /// then its verdict. An `Err` here means none of those reached a terminal
    /// verification record; the caller ([`verify_prepared`](Self::verify_prepared))
    /// turns a plain error into `VerificationErrored` and an
    /// [`Error::Cancelled`] into `VerificationCancelled` (#139).
    fn run_prepared_verification(
        &mut self,
        prepared: &verify::Verification,
        attempt: AttemptId,
        candidate: ward_events::SnapshotId,
    ) -> Result<VerifyReport> {
        for rel in &prepared.restored {
            self.emit(
                Origin::Verifier,
                WardEvent::VerificationProgress {
                    step: ShortText::new(&format!("restore {rel}")),
                    status: StepStatus::Pass,
                },
            )?;
        }
        // The last checkpoint before the verifier subprocess itself runs: a cancel
        // requested any time up to here takes effect. One requested once `execute`
        // has actually started is honoured only at the *next* attempt's checkpoints
        // — the running subprocess is bounded by its own `verify.budget_secs`
        // timeout as before this change, not pre-emptively killed (#139: cooperative
        // cancellation, not full preemption; see the pull request description).
        if self.cancel.is_cancelled() {
            return Err(Error::Cancelled(
                "verification was cancelled before the verifier command started".to_owned(),
            ));
        }
        let outcome = verify::execute(prepared)?;
        let status = if outcome.passed {
            StepStatus::Pass
        } else {
            StepStatus::Fail
        };
        self.emit(
            Origin::Verifier,
            WardEvent::VerificationProgress {
                step: ShortText::new(&prepared.config.verify.command),
                status,
            },
        )?;
        let result_hash = ev_hash(outcome.result_hash);
        let budget_secs = prepared.config.verify.budget_secs;
        let event = if outcome.passed {
            WardEvent::VerificationPassed {
                candidate,
                summary: outcome.summary,
                result_hash,
            }
        } else if outcome.timed_out {
            // Killed at the budget, not a verdict on the tests: its own terminal
            // outcome, never `VerificationFailed` (#139 item 1).
            WardEvent::VerificationTimedOut {
                attempt,
                candidate,
                summary: outcome.summary,
                result_hash,
                budget_secs,
            }
        } else {
            WardEvent::VerificationFailed {
                candidate,
                summary: outcome.summary,
                result_hash,
            }
        };
        self.emit(Origin::Verifier, event)?;
        Ok(VerifyReport {
            candidate: candidate.to_string(),
            passed: outcome.passed,
            timed_out: outcome.timed_out.then_some(budget_secs),
            summary: outcome.summary,
            restored: prepared.restored.clone(),
            output: outcome.output,
        })
    }

    fn refuse_while_paused(&self) -> Result<()> {
        if self.paused() {
            return Err(Error::Sandbox(
                "session is paused by ward; `ward resume` before running anything".into(),
            ));
        }
        Ok(())
    }

    /// Materialise the entry snapshot over the worktree (`ward stop
    /// --restore-entry`, ADR-0019 §3): every path that differs from the entry
    /// is moved to `.ward/restore-<unix seconds>/` first, then the entry's
    /// files, directories and symlinks are written and paths the entry does
    /// not hold are gone. Paths the capture ignores (`.gitignore`) are not
    /// looked at. Records `EntryRestored`.
    pub fn restore_entry(&mut self) -> Result<RestoreReport> {
        let store = SnapshotStore::open(self.state.join("cas"))
            .map_err(|e| Error::Snapshot(e.to_string()))?;
        let entry: ward_snapshot::SnapshotId = self
            .entry_snapshot
            .parse()
            .map_err(|e: ward_snapshot::SnapshotError| Error::Snapshot(e.to_string()))?;
        // Freeze the agent across the whole restore: the candidate capture must
        // be atomic (ST-018, G5/G9) and the worktree must not change under the
        // rewrite that follows it.
        let _freeze = self.freeze_for_capture();
        let now = store
            .store_snapshot(
                &self.worktree,
                SnapshotRole::Candidate,
                CaptureOptions::default(),
            )
            .map_err(|e| Error::Snapshot(e.to_string()))?;
        let mut diff = store
            .diff(entry, now)
            .map_err(|e| Error::Snapshot(e.to_string()))?;
        let manifest = store
            .manifest(entry)
            .map_err(|e| Error::Snapshot(e.to_string()))?;
        // An earlier restore's backup is not the agent's work: leave it where
        // it is rather than nesting it in this one.
        diff.added
            .retain(|rel| !rel.starts_with(b".ward/restore-") && rel != b".ward");
        let files = diff.added.len() + diff.removed.len() + diff.changed.len();
        let backup_rel = format!(".ward/restore-{}", unix_ms(SystemTime::now()) / 1000);
        let backup = self.worktree.join(&backup_rel);
        // Move aside what the restore replaces (a moved parent takes its
        // children with it; those then are simply not found).
        for rel in diff.changed.iter().chain(&diff.added) {
            let rel = restore_path(rel)?;
            let from = self.worktree.join(&rel);
            let to = backup.join(&rel);
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
            }
            match std::fs::rename(&from, &to) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::io(&from, e)),
            }
        }
        // Write the entry's own bytes for what changed or is missing.
        for rel in diff.changed.iter().chain(&diff.removed) {
            if let Some(item) = manifest.get(rel) {
                let path = self.worktree.join(restore_path(rel)?);
                write_entry_item(&store, entry, item, &path)?;
            }
        }
        let backup_text = if files == 0 {
            String::new()
        } else {
            backup_rel.clone()
        };
        self.emit(
            Origin::Wardd,
            WardEvent::EntryRestored {
                snapshot: ev_snapshot(entry),
                files: files as u64,
                backup: ShortText::new(&backup_text),
            },
        )?;
        Ok(RestoreReport {
            snapshot: entry.to_string(),
            files,
            backup: (files > 0).then_some(backup_rel),
        })
    }

    /// End the session, seal the log, and clear the project's current pointer.
    ///
    /// Stop is termination of the session's workloads followed by evidence
    /// sealing (#145 item 5): every sandboxed process of the session is ended and
    /// confirmed gone ([`pause::terminate`]) before the log is sealed. A running
    /// daemon (ADR-0015) does both on a
    /// [`Request::Stop`](crate::control::Request::Stop) and exits; without one this
    /// process terminates the workloads itself, then seals. Either way the call
    /// fails — with the log left unsealed and the project's current pointer kept,
    /// so `ward stop` can simply be run again — when termination could not be
    /// confirmed. Returns how many sandboxed processes were ended.
    pub fn stop(mut self, reason: EndReason) -> Result<u32> {
        let here = if self.sink.ends_workloads() {
            0
        } else {
            self.end_workloads_here()?
        };
        self.emit(
            Origin::Wardd,
            WardEvent::AgentStateChanged {
                state: AgentState::Finished,
            },
        )?;
        let there = self.sink.stop(reason)?;
        clear_current(&self.state, &self.project_id, &self.session_str)?;
        Ok(here + there)
    }

    /// `ward stop --restore-entry`: restore the entry snapshot over the worktree,
    /// then [`stop`](Self::stop) — with the session's workloads already quiescent
    /// before the restore begins, and still quiescent until they are terminated
    /// (#145 acceptance: "stop/restoration must wait for quiescence"). A restore
    /// holds its own capture freeze only for its own length, so without this a
    /// still-running agent would resume in the gap between the restore and the
    /// stop and could write over the restored worktree.
    ///
    /// With a daemon serving, the session is paused first (`Request::Pause`,
    /// recorded as usual) unless it already is, so the pause's freeze covers the
    /// restore and the stop then kills that frozen tree. Without one, the
    /// workloads are terminated first, in this process. Returns the restore and
    /// how many sandboxed processes the stop ended.
    pub fn stop_restoring_entry(mut self, reason: EndReason) -> Result<(RestoreReport, u32)> {
        let mut ended = 0;
        if self.sink.ends_workloads() {
            if !self.paused() {
                let socket = session_dir(&self.state, &self.session_str).join(SOCKET_NAME);
                let mut control = RemoteSink::connect(&socket).ok_or_else(|| {
                    Error::Daemon(format!(
                        "{}: the session daemon did not answer; nothing was restored",
                        socket.display()
                    ))
                })?;
                match control.call(&crate::control::Request::Pause {
                    reason: "ward stop --restore-entry".into(),
                })? {
                    // An unsettled freeze still has the marker and the held
                    // approvals in place; the stop that follows kills the tree
                    // whether or not every process confirmed stopped.
                    crate::control::Response::Paused { .. } => {}
                    // Paused by someone else in between: just as quiescent.
                    crate::control::Response::Error(e) if e == "already paused" => {}
                    crate::control::Response::Error(e) => {
                        return Err(Error::Daemon(format!(
                            "could not pause the session before restoring: {e}; nothing \
                             was restored"
                        )));
                    }
                    other => {
                        return Err(Error::Daemon(format!("unexpected response {other:?}")));
                    }
                }
            }
        } else {
            ended = self.end_workloads_here()?;
        }
        let report = self.restore_entry()?;
        ended += self.stop(reason)?;
        Ok((report, ended))
    }

    /// The daemonless half of [`Self::stop`]: what `Served::stop` does for a
    /// served session, in this process. With no daemon there is no pause state
    /// to hold, so an unconfirmed termination writes the marker (every proxy of
    /// the session refuses) and records `WorkloadsTerminated { pending }`, then
    /// refuses the stop.
    fn end_workloads_here(&mut self) -> Result<u32> {
        let outcome = pause::terminate(&self.session_str, None);
        self.record_termination(&outcome)
    }

    /// Record `outcome` and decide the stop: `Ok(ended)` once everything is
    /// gone, the refusal otherwise. Split from [`Self::end_workloads_here`] so
    /// the refused path is testable without a process that survives `SIGKILL`.
    fn record_termination(&mut self, outcome: &pause::Termination) -> Result<u32> {
        let (ended, pending) = (outcome.ended, outcome.pending());
        if pending == 0 {
            // Nothing is left for a marker to hold back — including one an
            // earlier refused stop of this session left behind.
            let _ = pause::clear_marker(&self.state, &self.session_str);
            if !outcome.touched_anything() {
                return Ok(0);
            }
            self.emit(
                Origin::Wardd,
                WardEvent::WorkloadsTerminated { ended, pending },
            )?;
            return Ok(ended);
        }
        let marker = pause::write_marker(
            &self.state,
            &self.session_str,
            &pause::stop_hold_reason(pending),
        )
        .err();
        let logged = self
            .emit(
                Origin::Wardd,
                WardEvent::WorkloadsTerminated { ended, pending },
            )
            .err();
        Err(Error::Daemon(pause::stop_refusal(
            &self.session_str,
            ended,
            pending,
            "the proxy is closed. Run `ward stop` again to retry",
            marker.as_ref(),
            logged.as_ref(),
        )))
    }

    /// Append one batch of drained observations, in the order the batch holds them,
    /// noting every modified path in `changed_paths`.
    ///
    /// Each record keeps the time its source observed it, not the time it reached
    /// the log, so a live-drained timeline reads exactly as the batched one did.
    fn ingest(
        &mut self,
        batch: Vec<Observation>,
        changed_paths: &mut BTreeSet<String>,
    ) -> Result<()> {
        for item in batch {
            if let WardEvent::FileModified { path, .. } = &item.event {
                changed_paths.insert(path.to_string());
            }
            self.emit_at(item.at, item.origin, item.event)?;
        }
        Ok(())
    }

    fn alloc_pid(&mut self) -> Pid {
        self.next_pid = self.next_pid.wrapping_add(1).max(2);
        Pid::new(self.next_pid).unwrap_or(self.root_pid)
    }

    /// Allocate the next verification attempt id (#139): monotonic for the life of
    /// this `Session`, and never repeats one [`next_attempt_id`] would also hand out
    /// to a fresh `Session` reopened on the same log.
    ///
    /// [`Self::verify`] no longer calls this directly (review 5284360930 of #208,
    /// finding 1): it allocates under [`lock_session_verification`] straight from a
    /// fresh [`next_attempt_id`] read instead, since this method's cached
    /// `self.next_attempt` field is exactly what let two separately-opened `Session`
    /// handles collide on the same id before that fix. Kept as a plain, unlocked
    /// counter for the tests below that exercise [`Self::verify_prepared`] directly,
    /// without needing a real `.tamperward/config.yml` for `verify()`'s own
    /// preparation step to succeed.
    #[cfg(test)]
    fn alloc_attempt(&mut self) -> AttemptId {
        let attempt = self.next_attempt;
        self.next_attempt = AttemptId::new(attempt.get().saturating_add(1));
        attempt
    }

    /// A fresh cancellation handle for the next `verify()` call (#139): replaces
    /// whatever token is current, so an old cancel from an earlier attempt cannot
    /// leak into a new one, and returns a clone the caller keeps to cancel it from
    /// elsewhere — typically another thread, since `verify()` blocks the one that
    /// calls it. `verify()` checks whatever token is current at points between its
    /// steps (never while the verifier subprocess itself is running); a caller who
    /// never calls this leaves verification uncancellable, exactly as before #139.
    pub fn begin_verify_cancel(&mut self) -> CancelToken {
        self.cancel = CancelToken::new();
        self.cancel.clone()
    }

    fn emit(&mut self, origin: Origin, event: WardEvent) -> Result<()> {
        self.emit_at(SystemTime::now(), origin, event)
    }

    /// Append an event that happened at `at`: captured facts (proxy decisions, hook
    /// claims, file events) are drained after the command exits but keep their
    /// own time, so the observer timeline is truthful.
    fn emit_at(&mut self, at: SystemTime, origin: Origin, event: WardEvent) -> Result<()> {
        self.sink.append(origin, event, at).map(drop)
    }
}

/// A snapshot path as a worktree-relative path, refusing anything that could
/// leave the worktree (the CAS is trusted, the check costs nothing).
fn restore_path(rel: &[u8]) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    let rel = Path::new(std::ffi::OsStr::from_bytes(rel));
    if rel.is_absolute()
        || rel
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(Error::Snapshot(format!(
            "refusing snapshot path {}",
            rel.display()
        )));
    }
    Ok(rel.to_path_buf())
}

/// Write one entry of snapshot `id` at `path`: a directory, a file with its
/// mode, or a symlink with the stored target; nodes the capture does not carry
/// (devices, sockets) are skipped.
fn write_entry_item(
    store: &SnapshotStore,
    id: ward_snapshot::SnapshotId,
    item: &ward_snapshot::Entry,
    path: &Path,
) -> Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use ward_snapshot::EntryType;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let content = || {
        store
            .cat(id, Path::new(std::ffi::OsStr::from_bytes(&item.path)))
            .map_err(|e| Error::Snapshot(e.to_string()))
    };
    match item.kind {
        EntryType::Dir | EntryType::SubmoduleWorktree => {
            std::fs::create_dir_all(path).map_err(|e| Error::io(path, e))?;
        }
        EntryType::File => {
            std::fs::write(path, content()?).map_err(|e| Error::io(path, e))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(item.mode))
                .map_err(|e| Error::io(path, e))?;
        }
        EntryType::Symlink => {
            std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&content()?), path)
                .map_err(|e| Error::io(path, e))?;
        }
        EntryType::Unsupported => {}
    }
    Ok(())
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

/// How long the daemon holds an unanswered approval before denying it
/// (`approval.timeout_secs`): `$WARD_APPROVAL_TIMEOUT_SECS`, else
/// [`crate::approvals::DEFAULT_TIMEOUT_SECS`]. The policy schema has no
/// `approval` key yet, so the session's environment is where the knob lives.
#[must_use]
pub fn approval_timeout() -> Duration {
    let secs = std::env::var("WARD_APPROVAL_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(crate::approvals::DEFAULT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// The default state root: `$WARD_STATE_DIR`, else `~/.local/state/ward`.
#[must_use]
pub fn state_root() -> PathBuf {
    if let Ok(dir) = std::env::var("WARD_STATE_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".local/state/ward")
}

/// A short, 0700 per-session directory for the egress socket (see `launch`).
/// Where a launch of `session_id` keeps its sockets on the host (never bound into
/// the sandbox).
#[must_use]
pub fn run_dir_path(session_id: &str) -> PathBuf {
    let tail: String = session_id
        .chars()
        .rev()
        .take(10)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    std::env::temp_dir().join(format!("ward-{tail}"))
}

/// The `run_dir` reuses a fixed, predictable name in shared, world-writable
/// `/tmp` (see [`run_dir_path`]), so an `AlreadyExists` on create must never be
/// trusted blindly: another local user can pre-plant (or race-recreate, right
/// after this session's own `remove_dir_all`) that path as a symlink to a
/// directory they control, and have the egress/hook sockets and seed files
/// this function's caller writes into `dir` land there instead (ST-023, T7,
/// CWE-377). `mkdir` fails on an existing symlink without following it, so on
/// `AlreadyExists` we `lstat` the node ourselves and refuse to reuse anything
/// that isn't a real, non-symlink directory we own at exactly mode 0700.
/// Name of the marker [`run_dir`] writes recording which session owns it: the
/// "recorded operation ownership" a storage-usage scan
/// ([`crate::usage::scan_scratch`]) reads to tell a leftover run dir's owning
/// session apart, so it can classify abandoned scratch without inferring
/// liveness from a PID or an mtime (#151, issue's own explicit constraint).
/// Never trusted for anything security-relevant — `run_dir`'s own reuse check
/// above is what actually gates a symlink or foreign-owned directory; this is
/// purely an accounting breadcrumb, always written last, after that check
/// passes.
pub(crate) const OWNER_MARKER: &str = ".ward-owner";

fn run_dir(session_id: &str) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let dir = run_dir_path(session_id);
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {
            write_owner_marker(&dir, session_id)?;
            Ok(dir)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(&dir).map_err(|e| Error::io(&dir, e))?;
            let owned_private_dir = !meta.is_symlink()
                && meta.is_dir()
                && meta.uid() == nix::unistd::getuid().as_raw()
                && meta.permissions().mode() & 0o777 == 0o700;
            if owned_private_dir {
                write_owner_marker(&dir, session_id)?;
                Ok(dir)
            } else {
                Err(Error::io(
                    &dir,
                    std::io::Error::other(
                        "refusing to reuse an existing run dir that is not a private directory we own",
                    ),
                ))
            }
        }
        Err(e) => Err(Error::io(&dir, e)),
    }
}

/// Record `session_id` as the owner of `dir` (see [`OWNER_MARKER`]). Best-effort
/// in the sense that any write failure is a real error for the caller — a run
/// dir a usage scan cannot attribute is left as `Unknown`, never reported as
/// reclaimable, so a marker write that somehow failed silently would only ever
/// make accounting more conservative, not less — but there is no legitimate way
/// for this write to fail against a directory we just created or verified we
/// own, so it is propagated rather than swallowed.
fn write_owner_marker(dir: &Path, session_id: &str) -> Result<()> {
    let path = dir.join(OWNER_MARKER);
    std::fs::write(&path, session_id).map_err(|e| Error::io(&path, e))
}

/// `<state>/sessions/<id>`: where a session keeps its log, metadata and control
/// socket.
#[must_use]
pub fn session_dir(state: &Path, id: &str) -> PathBuf {
    state.join("sessions").join(id)
}

fn meta_path(state: &Path, id: &str) -> PathBuf {
    session_dir(state, id).join("session.json")
}

fn current_pointer(state: &Path, project_id: &str) -> PathBuf {
    state.join("projects").join(project_id).join("current")
}

fn read_current(state: &Path, project_id: &str) -> Result<Option<String>> {
    let path = current_pointer(state, project_id);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let id = s.trim().to_owned();
            Ok(if id.is_empty() { None } else { Some(id) })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(&path, e)),
    }
}

fn write_current(state: &Path, project_id: &str, id: &str) -> Result<()> {
    let path = current_pointer(state, project_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    std::fs::write(&path, id).map_err(|e| Error::io(&path, e))
}

/// Clear the current pointer, but only if it still names `id` (do not clobber a
/// newer session that replaced this one).
fn clear_current(state: &Path, project_id: &str, id: &str) -> Result<()> {
    if read_current(state, project_id)?.as_deref() == Some(id) {
        let path = current_pointer(state, project_id);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(&path, e)),
        }
    }
    Ok(())
}

/// Resolve which file events a run produced: the live inotify watch's finished
/// outcome when one started, or a before/after scan otherwise. Returns the
/// events, which source produced them, and whether the watch lost coverage of
/// part of the worktree (always `false` for a scan, which has no notion of
/// partial coverage). Takes an already-finished [`WatchOutcome`] rather than a
/// [`Watcher`] so this mapping can be tested with a synthetic outcome instead
/// of a live watcher thread.
fn collect_captured(
    watch: Option<WatchOutcome>,
    before: Option<BTreeMap<String, (u128, u64)>>,
    worktree: &Path,
) -> (Vec<Captured>, CaptureMode, bool) {
    match (watch, before) {
        (Some(watch), _) => (watch.captured, CaptureMode::Inotify, watch.degraded),
        (None, Some(before)) => {
            let after = scan(worktree);
            (scan_changes(&before, &after), CaptureMode::Scan, false)
        }
        (None, None) => (Vec::new(), CaptureMode::Scan, false),
    }
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

/// Diff two scans into `Write` modifications (the scan fallback cannot tell
/// creates from writes, so it reports both as `Write`).
fn scan_changes(
    before: &BTreeMap<String, (u128, u64)>,
    after: &BTreeMap<String, (u128, u64)>,
) -> Vec<Captured> {
    let mut changed = Vec::new();
    for (path, meta) in after {
        if before.get(path) != Some(meta) {
            changed.push(Captured::Modified {
                at: SystemTime::now(),
                rel: path.clone(),
                kind: FileChangeKind::Write,
            });
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn sample_meta(id: &str) -> SessionMeta {
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId(id.to_owned()),
            ward_policy::ProjectId("proj_test".to_owned()),
        );
        SessionMeta {
            id: id.to_owned(),
            project: PathBuf::from("/tmp/demo"),
            project_id: "proj_test".to_owned(),
            entry_snapshot: "blake3:abc".to_owned(),
            origin_repo: None,
            manifest,
            started_unix_ms: 1_700_000_000_000,
            agent: None,
        }
    }

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
    fn collect_captured_surfaces_watch_degradation_through_run_report() {
        // A synthetic outcome, not a live watcher: `watch::tests` already
        // proves a real coverage gap sets `WatchOutcome::degraded` (at the
        // `add_watch_recursive`/`drain` level, with no background thread to
        // race). What this checks is only `collect_captured`'s own mapping —
        // that `degraded` reaches the `RunReport` tuple unchanged — which
        // needs no live watcher and must not depend on winning a race against
        // one.
        let worktree = tempfile::tempdir().unwrap();
        let watch = WatchOutcome {
            captured: Vec::new(),
            degraded: true,
            dropped: 0,
        };

        let (_, capture, observer_degraded) = collect_captured(Some(watch), None, worktree.path());

        assert_eq!(capture, CaptureMode::Inotify);
        assert!(
            observer_degraded,
            "a coverage gap in the watch must reach RunReport::observer_degraded"
        );
    }

    #[test]
    fn scan_diff_reports_only_changed_paths() {
        let mut before = BTreeMap::new();
        before.insert("a".to_string(), (1u128, 10u64));
        before.insert("b".to_string(), (1, 10));
        let mut after = before.clone();
        after.insert("b".to_string(), (2, 12)); // modified
        after.insert("c".to_string(), (1, 1)); // created
        let mut changed: Vec<String> = scan_changes(&before, &after)
            .into_iter()
            .map(|c| match c {
                Captured::Modified { rel, .. } | Captured::Read { rel, .. } => rel,
            })
            .collect();
        changed.sort();
        assert_eq!(changed, vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn missing_policy_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let policy = load_project_policy(dir.path()).unwrap();
        assert_eq!(policy, Policy::default());
    }

    #[test]
    fn session_meta_round_trips_through_json() {
        let meta = sample_meta("sess_round");
        let bytes = serde_json::to_vec_pretty(&meta).unwrap();
        let back: SessionMeta = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(meta, back);
    }

    #[test]
    fn run_dir_creates_a_private_directory() {
        use std::os::unix::fs::PermissionsExt;
        let id = "run_dir_test_create";
        let dir = run_dir_path(id);
        let _ = std::fs::remove_dir_all(&dir);
        let created = run_dir(id).unwrap();
        let meta = std::fs::symlink_metadata(&created).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        std::fs::remove_dir_all(&created).unwrap();
    }

    #[test]
    fn run_dir_reuses_its_own_private_directory() {
        let id = "run_dir_test_reuse0";
        let dir = run_dir_path(id);
        let _ = std::fs::remove_dir_all(&dir);
        let first = run_dir(id).unwrap();
        let second = run_dir(id).unwrap();
        assert_eq!(first, second);
        std::fs::remove_dir_all(&first).unwrap();
    }

    /// #151: a storage-usage scan tells a leftover run dir's owning session
    /// apart by this marker, not by parsing the truncated tail in its path or
    /// by any PID/mtime heuristic — so the marker must actually carry the full
    /// session id, on both a fresh directory and a reused one.
    #[test]
    fn run_dir_records_the_full_session_id_as_owner() {
        let id = "run_dir_test_owner_marker_sess";
        let dir = run_dir_path(id);
        let _ = std::fs::remove_dir_all(&dir);
        let created = run_dir(id).unwrap();
        let owner = std::fs::read_to_string(created.join(OWNER_MARKER)).unwrap();
        assert_eq!(owner, id);
        // Reusing the same dir (a second call within the same session) refreshes
        // the same marker rather than leaving it stale or duplicating it.
        run_dir(id).unwrap();
        let owner_again = std::fs::read_to_string(created.join(OWNER_MARKER)).unwrap();
        assert_eq!(owner_again, id);
        std::fs::remove_dir_all(&created).unwrap();
    }

    /// #155: a co-resident local user who wins the race between this session's
    /// `remove_dir_all` and its next `run_dir` call — or who simply pre-plants
    /// the fixed, predictable path — can leave a symlink at `run_dir_path`. A
    /// bare `AlreadyExists` on `mkdir` must never be trusted: the egress/hook
    /// sockets and seed files the caller then writes "into" that path would
    /// really land wherever the symlink points, outside `run_dir`'s 0700
    /// directory (ST-023).
    #[test]
    fn run_dir_refuses_a_planted_symlink() {
        let id = "run_dir_test_evilsym";
        let dir = run_dir_path(id);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&dir);
        let attacker_dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(attacker_dir.path(), &dir).unwrap();

        let err = run_dir(id).unwrap_err();
        assert!(!err.to_string().is_empty());
        // The symlink itself must be left alone (never followed/removed) so the
        // failure is visible rather than silently "fixed" out from under the
        // other user.
        assert!(std::fs::symlink_metadata(&dir).unwrap().is_symlink());

        std::fs::remove_file(&dir).unwrap();
    }

    #[test]
    fn current_pointer_set_and_clear() {
        let state = tempfile::tempdir().unwrap();
        let pid = "proj_test";
        assert_eq!(read_current(state.path(), pid).unwrap(), None);
        write_current(state.path(), pid, "sess_a").unwrap();
        assert_eq!(
            read_current(state.path(), pid).unwrap().as_deref(),
            Some("sess_a")
        );
        // A stale clear (different id) must not remove a newer pointer.
        clear_current(state.path(), pid, "sess_old").unwrap();
        assert_eq!(
            read_current(state.path(), pid).unwrap().as_deref(),
            Some("sess_a")
        );
        // Clearing the matching id removes it.
        clear_current(state.path(), pid, "sess_a").unwrap();
        assert_eq!(read_current(state.path(), pid).unwrap(), None);
    }

    #[test]
    fn current_meta_reads_back_what_was_written() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let worktree = project.path().canonicalize().unwrap();
        let project_id = project_id_for(&worktree).to_string();
        let id = "sess_persist";
        let mut meta = sample_meta(id);
        meta.project = worktree.clone();
        meta.project_id = project_id.clone();
        std::fs::create_dir_all(session_dir(state.path(), id)).unwrap();
        std::fs::write(
            meta_path(state.path(), id),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .unwrap();
        write_current(state.path(), &project_id, id).unwrap();

        let loaded = SessionMeta::current(project.path(), state.path())
            .unwrap()
            .unwrap();
        assert_eq!(loaded, meta);
    }

    /// Run `command` under `budget_secs` through [`Session::verify_prepared`] on an
    /// empty scratch tree, and return the report with the verification-kind records
    /// the attempt appended, in order.
    fn verify_command(command: &str, budget_secs: u64) -> (VerifyReport, Vec<WardEvent>) {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        let entry: ward_snapshot::SnapshotId = session.entry_snapshot.parse().unwrap();
        let candidate = ward_snapshot::SnapshotId(ward_snapshot::Digest::from_bytes([0xcd; 32]));
        let scratch_root = state.path().join("scratch-root");
        let scratch = scratch_root.join("tree");
        std::fs::create_dir_all(&scratch).unwrap();
        let prepared = verify::Verification {
            candidate,
            config: verify::Config {
                protected: verify::Protected::default(),
                verify: verify::VerifyCommand {
                    command: command.to_owned(),
                    budget_secs,
                },
            },
            manifest_hash: [7u8; 32],
            restored: Vec::new(),
            scratch,
        };
        let dir = session_dir(state.path(), session.id());
        let attempt = session.alloc_attempt();
        let guard = AttemptGuard::start(&dir, attempt, VerifyRequester::User).unwrap();
        let report = session
            .verify_prepared(&prepared, entry, &scratch_root, attempt, guard)
            .expect("the verifier ran");
        session.sync().unwrap();
        let events = ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap().event)
            .filter(|e| {
                matches!(
                    e.kind(),
                    ward_events::EventKind::VerificationPassed
                        | ward_events::EventKind::VerificationFailed
                        | ward_events::EventKind::VerificationTimedOut
                        | ward_events::EventKind::VerificationErrored
                )
            })
            .collect();
        (report, events)
    }

    /// #139 item 1: a verifier killed at its budget ends the attempt in
    /// `VerificationTimedOut` naming the attempt and the budget — never
    /// `VerificationFailed`, which means the command ran and exited non-zero.
    #[test]
    fn a_verifier_killed_at_its_budget_ends_in_verification_timed_out() {
        if !ward_sandbox::ci::isolation_ready(crate::sandbox::available(), "bubblewrap") {
            return;
        }
        let (report, events) = verify_command("sleep 30", 1);
        assert!(!report.passed);
        assert_eq!(report.timed_out, Some(1), "{}", report.output);
        match events.as_slice() {
            [WardEvent::VerificationTimedOut { budget_secs, .. }] => assert_eq!(*budget_secs, 1),
            other => panic!("expected exactly one VerificationTimedOut, got {other:?}"),
        }
    }

    /// The control for the test above: a command that exits non-zero within its
    /// budget is still `VerificationFailed`, with no timeout reported.
    #[test]
    fn a_verifier_that_exits_nonzero_in_budget_ends_in_verification_failed() {
        if !ward_sandbox::ci::isolation_ready(crate::sandbox::available(), "bubblewrap") {
            return;
        }
        let (report, events) = verify_command("exit 1", 30);
        assert!(!report.passed);
        assert_eq!(report.timed_out, None, "{}", report.output);
        assert!(
            matches!(events.as_slice(), [WardEvent::VerificationFailed { .. }]),
            "{events:?}"
        );
    }

    /// #139 acceptance: the plain success case, at this level. The two tests
    /// above already cover `VerificationFailed`/`VerificationTimedOut`; this is
    /// their control for an ordinary passing run — a command that exits zero
    /// within its budget ends the attempt in exactly one terminal record,
    /// `VerificationPassed`, naming the candidate. Before this test the only
    /// coverage of `VerificationPassed` at all was the heavier, protected e2e
    /// suite's `verify_ignores_a_weakened_protected_test_and_passes_the_real_fix`
    /// (`crates/ward-daemon/tests/e2e.rs`), which exercises the whole
    /// `ward init`-style project and the hostile-corpus harness around it; this
    /// one isolates the success path the same way its sibling failure/timeout
    /// tests already do, through `verify_prepared` directly.
    #[test]
    fn a_verifier_that_exits_zero_ends_in_verification_passed() {
        if !ward_sandbox::ci::isolation_ready(crate::sandbox::available(), "bubblewrap") {
            return;
        }
        let (report, events) = verify_command("exit 0", 30);
        assert!(report.passed, "{}", report.output);
        assert_eq!(report.timed_out, None, "{}", report.output);
        match events.as_slice() {
            [WardEvent::VerificationPassed { candidate, .. }] => {
                assert_eq!(*candidate, ev_snapshot(report.candidate.parse().unwrap()));
            }
            other => panic!("expected exactly one VerificationPassed, got {other:?}"),
        }
    }

    /// #139: once `VerificationStarted` is on the log, a `verify::execute` failure
    /// (the verifier could not even run) must still end the attempt in exactly one
    /// terminal record — `VerificationErrored` — never leaving `VerificationStarted`
    /// as the last verification-kind record.
    ///
    /// `verify::execute` is made to fail deterministically, on every host with or
    /// without bubblewrap installed: `Launch::run` canonicalises its worktree — here
    /// the verifier's own scratch tree — before it spawns anything, so handing it a
    /// `Verification` whose `scratch` does not exist fails at that first step, every
    /// time. This exercises [`Session::verify_prepared`], the exact code
    /// [`Session::verify`] runs once `verify::prepare` has produced a candidate.
    #[test]
    fn verify_execute_failure_ends_the_log_in_verification_errored() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();

        let entry: ward_snapshot::SnapshotId = session.entry_snapshot.parse().unwrap();
        let candidate = ward_snapshot::SnapshotId(ward_snapshot::Digest::from_bytes([0xab; 32]));
        let scratch_root = state.path().join("scratch-root");
        let prepared = verify::Verification {
            candidate,
            config: verify::Config {
                protected: verify::Protected::default(),
                verify: verify::VerifyCommand {
                    command: "true".to_owned(),
                    budget_secs: 5,
                },
            },
            manifest_hash: [7u8; 32],
            restored: Vec::new(),
            scratch: scratch_root.join("does-not-exist"),
        };

        let dir = session_dir(state.path(), session.id());
        let attempt = session.alloc_attempt();
        let guard = AttemptGuard::start(&dir, attempt, VerifyRequester::User).unwrap();
        let err = session
            .verify_prepared(&prepared, entry, &scratch_root, attempt, guard)
            .expect_err("execute must fail on a missing scratch tree");
        assert!(
            !err.to_string().is_empty(),
            "the real error still propagates to the caller"
        );
        session.sync().unwrap();

        let records: Vec<_> = ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let verification_kinds: Vec<&str> = records
            .iter()
            .filter_map(|r| match &r.event {
                WardEvent::VerificationRequested { .. } => Some("Requested"),
                WardEvent::VerificationStarted { .. } => Some("Started"),
                WardEvent::VerificationProgress { .. } => Some("Progress"),
                WardEvent::VerificationPassed { .. } => Some("Passed"),
                WardEvent::VerificationFailed { .. } => Some("Failed"),
                WardEvent::VerificationErrored { .. } => Some("Errored"),
                _ => None,
            })
            .collect();
        assert_eq!(
            verification_kinds,
            vec!["Requested", "Started", "Errored"],
            "the stream must end the attempt in VerificationErrored, not a bare Started"
        );
        match &records.last().unwrap().event {
            WardEvent::VerificationErrored {
                candidate: logged,
                reason,
            } => {
                assert_eq!(logged, &ev_snapshot(candidate));
                assert!(!reason.as_str().is_empty(), "the reason is never blank");
            }
            other => panic!("expected VerificationErrored last, got {other:?}"),
        }
    }

    /// A [`Sink`] wrapper that lets the first `allow` appends through to `inner`
    /// and fails every one after that — used to prove #139's terminal-record
    /// append itself is never silently discarded when it fails too.
    struct FailAfter {
        inner: Box<dyn Sink>,
        allow: usize,
    }

    impl Sink for FailAfter {
        fn append(
            &mut self,
            origin: Origin,
            event: WardEvent,
            at: SystemTime,
        ) -> Result<ward_events::EventRecord> {
            if self.allow == 0 {
                return Err(Error::Events("simulated sink failure".to_owned()));
            }
            self.allow -= 1;
            self.inner.append(origin, event, at)
        }

        fn sync(&mut self) -> Result<()> {
            self.inner.sync()
        }

        fn seal(self: Box<Self>) -> Result<()> {
            self.inner.seal()
        }

        fn stop(self: Box<Self>, reason: EndReason) -> Result<u32> {
            self.inner.stop(reason)
        }
    }

    /// #139 (review follow-up): if the terminal `VerificationErrored` append
    /// *itself* fails — the exact case the discarded `let _ = self.emit(..)` in
    /// an earlier revision of this fix silently swallowed — the caller's error
    /// must say so, not just return the original verification error as if the
    /// log had been left in a known-good state. Otherwise a subscriber has no
    /// way to learn that the log may still be stuck at `VerificationStarted`.
    #[test]
    fn a_terminal_append_failure_is_never_silently_discarded() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        // Let VerificationRequested and VerificationStarted through, then fail
        // every append after that — including the VerificationErrored this test
        // is about.
        session.sink = Box::new(FailAfter {
            inner: std::mem::replace(&mut session.sink, Box::new(NullSink)),
            allow: 2,
        });

        let entry: ward_snapshot::SnapshotId = session.entry_snapshot.parse().unwrap();
        let candidate = ward_snapshot::SnapshotId(ward_snapshot::Digest::from_bytes([0xcd; 32]));
        let scratch_root = state.path().join("scratch-root");
        let prepared = verify::Verification {
            candidate,
            config: verify::Config {
                protected: verify::Protected::default(),
                verify: verify::VerifyCommand {
                    command: "true".to_owned(),
                    budget_secs: 5,
                },
            },
            manifest_hash: [9u8; 32],
            restored: Vec::new(),
            scratch: scratch_root.join("does-not-exist"),
        };

        let dir = session_dir(state.path(), session.id());
        let attempt = session.alloc_attempt();
        let guard = AttemptGuard::start(&dir, attempt, VerifyRequester::User).unwrap();
        let err = session
            .verify_prepared(&prepared, entry, &scratch_root, attempt, guard)
            .expect_err("execute must fail on a missing scratch tree");
        let msg = err.to_string();
        assert!(
            msg.contains("simulated sink failure"),
            "the append failure must be surfaced, not discarded: {msg}"
        );
        assert!(
            !msg.is_empty(),
            "the original verification failure must still be represented: {msg}"
        );
    }

    /// A placeholder [`Sink`] only ever used as the `inner` `mem::replace`
    /// swaps out of `FailAfter` in the test above; every call would panic, but
    /// `FailAfter` never forwards to it once wrapped.
    struct NullSink;

    impl Sink for NullSink {
        fn append(
            &mut self,
            _origin: Origin,
            _event: WardEvent,
            _at: SystemTime,
        ) -> Result<ward_events::EventRecord> {
            unreachable!("NullSink is replaced before any append")
        }

        fn sync(&mut self) -> Result<()> {
            unreachable!("NullSink is replaced before any use")
        }

        fn seal(self: Box<Self>) -> Result<()> {
            unreachable!("NullSink is replaced before any use")
        }

        fn stop(self: Box<Self>, _reason: EndReason) -> Result<u32> {
            unreachable!("NullSink is replaced before any use")
        }
    }

    /// The verification-kind records of a log, by their short names, in order —
    /// shared by the `#139` tests below so each one asserts the exact shape of the
    /// attempt's records rather than just their last entry.
    fn verification_kinds(session: &mut Session) -> Vec<&'static str> {
        session.sync().unwrap();
        ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap())
            .filter_map(|r| {
                Some(match r.event {
                    WardEvent::VerificationAttemptStarted { .. } => "AttemptStarted",
                    WardEvent::VerificationRequested { .. } => "Requested",
                    WardEvent::VerificationStarted { .. } => "Started",
                    WardEvent::VerificationProgress { .. } => "Progress",
                    WardEvent::VerificationPassed { .. } => "Passed",
                    WardEvent::VerificationFailed { .. } => "Failed",
                    WardEvent::VerificationErrored { .. } => "Errored",
                    WardEvent::VerificationCancelled { .. } => "Cancelled",
                    WardEvent::VerificationInterrupted { .. } => "Interrupted",
                    _ => return None,
                })
            })
            .collect()
    }

    /// #139 item 3 + the "preparation failure" acceptance case: a `verify::prepare`
    /// failure (here: a project with no `.tamperward/config.yml`, so the candidate
    /// is captured but its config cannot be read) happens before any candidate is
    /// bound. The attempt still ends in a terminal record — `VerificationInterrupted`
    /// with no candidate, never an invented one, and never `VerificationErrored`
    /// (which requires a candidate this attempt never reached).
    #[test]
    fn verify_prepare_failure_ends_the_log_in_verification_interrupted_with_no_candidate() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();

        let err = session
            .verify()
            .expect_err("prepare must fail: no .tamperward/config.yml in the entry snapshot");
        assert!(!err.to_string().is_empty());

        assert_eq!(
            verification_kinds(&mut session),
            vec!["AttemptStarted", "Interrupted"],
            "no VerificationRequested/Started ever ran (no candidate existed for one), \
             and VerificationErrored never applies without a candidate to name"
        );
        let records: Vec<_> = ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        match &records.last().unwrap().event {
            WardEvent::VerificationInterrupted {
                candidate, reason, ..
            } => {
                assert_eq!(*candidate, None, "capture never succeeded");
                assert!(!reason.as_str().is_empty());
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }
        assert!(
            !session_dir(state.path(), session.id())
                .join("attempts")
                .join("1.json")
                .exists(),
            "the marker is removed once its terminal record is written"
        );
    }

    /// Review of #208, finding 4, class 1: `SnapshotStore::open` failing (here: its
    /// `cas` root exists as a plain file, so `create_dir_all` under it cannot
    /// succeed) after `VerificationAttemptStarted` is already on the log must still
    /// leave the attempt with exactly one terminal record — `VerificationInterrupted`
    /// with no candidate — not a bare `AttemptStarted` until some future reopen's
    /// reconciliation happens to notice.
    #[test]
    fn a_snapshot_store_open_failure_after_attempt_started_still_ends_in_interrupted() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        std::fs::remove_dir_all(state.path().join("cas")).unwrap();
        std::fs::write(state.path().join("cas"), b"not a directory").unwrap();

        let err = session
            .verify()
            .expect_err("SnapshotStore::open must fail on a non-directory cas root");
        assert!(!err.to_string().is_empty());
        assert_eq!(
            verification_kinds(&mut session),
            vec!["AttemptStarted", "Interrupted"],
            "a SnapshotStore::open failure must not leave the log stuck at AttemptStarted"
        );
        let records: Vec<_> = ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        match &records.last().unwrap().event {
            WardEvent::VerificationInterrupted { candidate, .. } => {
                assert_eq!(*candidate, None, "capture never even started");
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }
    }

    /// #151 item 6: the low-space preflight runs before `verify::prepare`'s own
    /// candidate capture (the worktree-walk-and-hash step), exactly like any other
    /// prep-step failure above — the attempt still ends in exactly one terminal
    /// record, `VerificationInterrupted` with no candidate (the capture that would
    /// have produced one never ran), and the error surfaced to the caller is the
    /// actionable `Error::LowSpace`, not folded into some other kind.
    #[test]
    fn verify_refuses_to_prepare_a_candidate_when_space_is_low() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        // No real disk clears an exabyte minimum: deterministic without mocking
        // `statvfs` or actually filling a filesystem.
        session.min_free_bytes = u64::MAX;

        let err = session
            .verify()
            .expect_err("the low-space preflight must refuse before any candidate capture");
        assert!(
            matches!(err, Error::LowSpace { .. }),
            "expected Error::LowSpace, got {err:?}"
        );

        assert_eq!(
            verification_kinds(&mut session),
            vec!["AttemptStarted", "Interrupted"],
            "a low-space refusal must not leave the log stuck at AttemptStarted"
        );
        let records: Vec<_> = ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        match &records.last().unwrap().event {
            WardEvent::VerificationInterrupted { candidate, .. } => {
                assert_eq!(*candidate, None, "the refused capture never produced one");
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }
    }

    /// The negative case the test above needs: with the minimum cleared (`0`),
    /// the preflight never trips, so `verify()` proceeds past it to the project's
    /// next real problem — the same missing `.tamperward/config.yml` that
    /// `verify_prepare_failure_ends_the_log_in_verification_interrupted_with_no_candidate`
    /// exercises — rather than ever returning `Error::LowSpace`. Proof the guard
    /// only trips when it is actually supposed to, not on every call.
    #[test]
    fn verify_does_not_trip_the_low_space_guard_when_space_is_fine() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        session.min_free_bytes = 0;

        let err = session.verify().expect_err(
            "prepare must still fail on its own terms: no .tamperward/config.yml in the entry snapshot",
        );
        assert!(
            !matches!(err, Error::LowSpace { .. }),
            "the low-space guard must not have tripped with a 0-byte minimum: {err}"
        );
    }

    /// #151 item 6: `ward snapshot create`'s own capture (`Session::snapshot`) is
    /// refused up front when the low-space preflight trips, before
    /// `store.capture` ever runs — never discovered partway through the walk.
    #[test]
    fn snapshot_refuses_to_capture_when_space_is_low() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        session.min_free_bytes = u64::MAX;

        let err = session
            .snapshot(SnapshotRole::Candidate)
            .expect_err("the low-space preflight must refuse before the capture starts");
        assert!(
            matches!(err, Error::LowSpace { .. }),
            "expected Error::LowSpace, got {err:?}"
        );
    }

    /// The negative case: with the minimum cleared, `ward snapshot create`'s
    /// capture proceeds exactly as it did before this guard existed, and records
    /// `SnapshotCreated` as normal.
    #[test]
    fn snapshot_captures_normally_when_space_is_fine() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        session.min_free_bytes = 0;
        std::fs::write(project.path().join("f"), b"content").unwrap();

        let meta = session
            .snapshot(SnapshotRole::Candidate)
            .expect("space is fine, so the capture must proceed");
        assert!(meta.entries > 0, "the project's own files were captured");
    }

    /// Review of #208, finding 4, class 2: the entry snapshot id failing to parse
    /// after `VerificationAttemptStarted` — corrupted `session.json`, in practice —
    /// must likewise still end the attempt in exactly one terminal record.
    #[test]
    fn an_entry_snapshot_parse_failure_after_attempt_started_still_ends_in_interrupted() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        session.entry_snapshot = "not-a-valid-snapshot-id".to_owned();

        let err = session
            .verify()
            .expect_err("an unparseable entry snapshot id must fail verify()");
        assert!(!err.to_string().is_empty());
        assert_eq!(
            verification_kinds(&mut session),
            vec!["AttemptStarted", "Interrupted"],
            "an entry-snapshot parse failure must not leave the log stuck at AttemptStarted"
        );
        let records: Vec<_> = ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        match &records.last().unwrap().event {
            WardEvent::VerificationInterrupted { candidate, .. } => {
                assert_eq!(*candidate, None);
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }
    }

    /// Review of #208, finding 4, class 3: `run_dir` failing (here: a planted
    /// symlink at its fixed path, ST-023 — see `run_dir_refuses_a_planted_symlink`)
    /// after `VerificationAttemptStarted` must likewise still end the attempt in
    /// exactly one terminal record instead of returning bare.
    #[test]
    fn a_run_dir_failure_after_attempt_started_still_ends_in_interrupted() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        let planted = run_dir_path(session.id());
        let _ = std::fs::remove_dir_all(&planted);
        let _ = std::fs::remove_file(&planted);
        let attacker_dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(attacker_dir.path(), &planted).unwrap();

        let err = session
            .verify()
            .expect_err("run_dir must refuse a planted symlink at its fixed path");
        assert!(!err.to_string().is_empty());
        assert_eq!(
            verification_kinds(&mut session),
            vec!["AttemptStarted", "Interrupted"],
            "a run_dir failure must not leave the log stuck at AttemptStarted"
        );
        let records: Vec<_> = ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        match &records.last().unwrap().event {
            WardEvent::VerificationInterrupted { candidate, .. } => {
                assert_eq!(*candidate, None);
            }
            other => panic!("expected VerificationInterrupted, got {other:?}"),
        }
        // The symlink itself must be left alone (never followed/removed), matching
        // `run_dir_refuses_a_planted_symlink`'s own assertion.
        assert!(std::fs::symlink_metadata(&planted).unwrap().is_symlink());
        std::fs::remove_file(&planted).unwrap();
    }

    /// #139 item 6: a cancel requested before `verify()` even starts preparing
    /// takes effect at the very first checkpoint, before any candidate is
    /// captured — a distinct terminal outcome, `VerificationCancelled`, never
    /// `VerificationErrored` or a silent nothing.
    #[test]
    fn a_cancel_requested_before_verify_ends_in_verification_cancelled_with_no_candidate() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();

        let token = session.begin_verify_cancel();
        token.cancel();

        let err = session
            .verify()
            .expect_err("a cancelled attempt is an error");
        assert!(
            matches!(err, Error::Cancelled(_)),
            "the caller can tell a cancel apart from an ordinary failure: {err}"
        );

        assert_eq!(
            verification_kinds(&mut session),
            vec!["AttemptStarted", "Cancelled"]
        );
        let records: Vec<_> = ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        match &records.last().unwrap().event {
            WardEvent::VerificationCancelled { candidate, .. } => assert_eq!(*candidate, None),
            other => panic!("expected VerificationCancelled, got {other:?}"),
        }
    }

    /// #139 item 6, the other checkpoint: a cancel that takes effect once the
    /// candidate is already known (after `verify::prepare` succeeded) still
    /// produces `VerificationCancelled`, now carrying that candidate — and never
    /// runs the verifier command at all (this test's hand-built `Verification`
    /// would fail `verify::execute` deterministically if it were ever reached, so
    /// reaching `Ok` here would also prove the checkpoint didn't fire).
    #[test]
    fn a_cancel_requested_after_capture_ends_in_verification_cancelled_with_the_candidate() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();

        let entry: ward_snapshot::SnapshotId = session.entry_snapshot.parse().unwrap();
        let candidate = ward_snapshot::SnapshotId(ward_snapshot::Digest::from_bytes([0x55; 32]));
        let scratch_root = state.path().join("scratch-root");
        let prepared = verify::Verification {
            candidate,
            config: verify::Config {
                protected: verify::Protected::default(),
                verify: verify::VerifyCommand {
                    command: "true".to_owned(),
                    budget_secs: 5,
                },
            },
            manifest_hash: [3u8; 32],
            restored: Vec::new(),
            scratch: scratch_root.join("does-not-exist"),
        };

        let dir = session_dir(state.path(), session.id());
        let attempt = session.alloc_attempt();
        let guard = AttemptGuard::start(&dir, attempt, VerifyRequester::User).unwrap();
        guard.bind_candidate(ev_snapshot(candidate));
        session.begin_verify_cancel().cancel();

        let err = session
            .verify_prepared(&prepared, entry, &scratch_root, attempt, guard)
            .expect_err("a cancelled attempt is an error");
        assert!(matches!(err, Error::Cancelled(_)), "{err}");

        assert_eq!(
            verification_kinds(&mut session),
            vec!["Requested", "Started", "Cancelled"],
            "the command itself never ran: no Progress record for it"
        );
        let records: Vec<_> = ward_events::LogReader::open(session.log_path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        match &records.last().unwrap().event {
            WardEvent::VerificationCancelled { candidate: got, .. } => {
                assert_eq!(*got, Some(ev_snapshot(candidate)));
            }
            other => panic!("expected VerificationCancelled, got {other:?}"),
        }
    }

    /// #139 item 5: a dangling attempt marker left by a process that ended without
    /// finishing it (a crash, or simply forgetting) is reconciled the moment
    /// another process reopens the session — here, `Session::open_current`,
    /// without any daemon involved (the `daemon` module has the equivalent test
    /// for `wardd`'s own startup).
    #[test]
    fn open_current_reconciles_a_dangling_attempt_left_by_a_previous_process() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let session = Session::start_in(project.path(), state.path()).unwrap();
        session.persist_current().unwrap();
        let dir = session_dir(state.path(), session.id());

        // Simulate a crash mid-attempt: `VerificationAttemptStarted` is on the log
        // and the marker exists, but nothing ever finishes it — the same shape an
        // `AttemptGuard` dropped without `finish()` leaves, or a hard process kill.
        let attempt = AttemptId::new(1);
        let marker = dir.join("attempts").join("1.json");
        {
            let mut session = session;
            session
                .emit(
                    Origin::Wardd,
                    WardEvent::VerificationAttemptStarted {
                        attempt,
                        requested_by: VerifyRequester::User,
                    },
                )
                .unwrap();
            session.sync().unwrap();
            drop(AttemptGuard::start(&dir, attempt, VerifyRequester::User).unwrap());
            // `session` (and its sink) drops here without ever calling `stop` —
            // the process is gone, exactly like a real crash.
        }
        assert!(marker.exists());

        let mut reopened = Session::open_current(project.path(), state.path())
            .unwrap()
            .expect("the persisted session is found");
        assert!(
            !marker.exists(),
            "open_current's own reconciliation consumes the marker"
        );
        assert_eq!(
            verification_kinds(&mut reopened),
            vec!["AttemptStarted", "Interrupted"]
        );
        // The next attempt this (or any) process allocates for the session does
        // not collide with the reconciled one.
        assert_eq!(reopened.alloc_attempt().get(), 2);
    }

    /// Review of #208, finding 1: a marker is not, by itself, evidence its owner
    /// died — it is equally present for a healthy in-flight verification. A second
    /// `ward` invocation that merely opens the same session (`open_current`) while
    /// a first one's `verify()` is genuinely still running elsewhere must never
    /// interrupt it. `LiveChild` stands in for that first, still-running process:
    /// a real, independently-alive pid the marker names as its owner.
    #[test]
    fn open_current_never_interrupts_an_attempt_a_live_process_still_owns() {
        use std::process::{Child, Command, Stdio};

        struct LiveChild(Child);
        impl LiveChild {
            fn spawn() -> Self {
                Self(
                    Command::new("sh")
                        .args(["-c", "while :; do :; done"])
                        .stdout(Stdio::null())
                        .spawn()
                        .unwrap(),
                )
            }
        }
        impl Drop for LiveChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let session = Session::start_in(project.path(), state.path()).unwrap();
        session.persist_current().unwrap();
        let dir = session_dir(state.path(), session.id());

        let attempt = AttemptId::new(1);
        let marker = dir.join("attempts").join("1.json");
        let owner = LiveChild::spawn();
        {
            let mut session = session;
            session
                .emit(
                    Origin::Wardd,
                    WardEvent::VerificationAttemptStarted {
                        attempt,
                        requested_by: VerifyRequester::User,
                    },
                )
                .unwrap();
            session.sync().unwrap();
            // A marker naming the still-running `owner` child as this attempt's
            // owner — the same shape a real `verify()` call leaves while it is
            // genuinely in flight — never a dead process's leftover.
            crate::attempt::test_marker_owned_by(&dir, attempt, owner.0.id()).unwrap();
        }
        assert!(marker.exists());

        // A second, independent `open_current` — exactly what a concurrent `ward`
        // command does — must find the attempt still live and leave it alone.
        let mut reopened = Session::open_current(project.path(), state.path())
            .unwrap()
            .expect("the persisted session is found");
        assert!(
            marker.exists(),
            "a live owner's marker must survive a second client's open_current"
        );
        assert_eq!(
            verification_kinds(&mut reopened),
            vec!["AttemptStarted"],
            "no VerificationInterrupted was ever emitted for the still-running attempt"
        );
    }

    /// Review 5284360930 of #208, finding 1 — the deterministic barrier regression the
    /// review asked for: two independent `Session` handles on the very same session
    /// (`open_current`, the shape two separate `ward verify` client processes take),
    /// both opened — and so both caching a `next_attempt` from the very same,
    /// still-empty log — before either ever calls `verify()`, exactly the ordering the
    /// finding describes. Racing them to call `verify()` at the same instant must not
    /// collide: the new session-scoped verify lock must serialize the two calls
    /// completely, so the log ends up with two distinct attempts, each one's own
    /// `AttemptStarted`/terminal pair fully written before the other's `AttemptStarted`
    /// ever appears, and neither ever clobbers the other's marker file.
    #[test]
    fn concurrent_verify_calls_on_two_session_handles_are_strictly_serialized() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let session = Session::start_in(project.path(), state.path()).unwrap();
        session.persist_current().unwrap();
        let dir = session_dir(state.path(), session.id());
        drop(session);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let project = project.path().to_path_buf();
                let state = state.path().to_path_buf();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    // Both handles open the session — caching the same
                    // `next_attempt` from the same, still-empty log — before either
                    // ever calls `verify()`.
                    let mut session = Session::open_current(&project, &state)
                        .unwrap()
                        .expect("the persisted session is found");
                    barrier.wait();
                    // Deterministically fails at `verify::prepare` (no
                    // `.tamperward/config.yml` in a bare `start_in` project), which
                    // still leaves the attempt with exactly one terminal record —
                    // `VerificationInterrupted` — the same shape
                    // `verify_prepare_failure_ends_the_log_in_verification_interrupted_with_no_candidate`
                    // above already relies on.
                    session.verify().expect_err("no .tamperward/config.yml")
                })
            })
            .collect();
        for handle in handles {
            let err = handle.join().unwrap();
            assert!(!err.to_string().is_empty());
        }

        let records: Vec<_> = ward_events::LogReader::open(dir.join("events.log"))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let attempts: Vec<(&str, u64)> = records
            .iter()
            .filter_map(|r| match &r.event {
                WardEvent::VerificationAttemptStarted { attempt, .. } => {
                    Some(("AttemptStarted", attempt.get()))
                }
                WardEvent::VerificationInterrupted { attempt, .. } => {
                    Some(("Interrupted", attempt.get()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            attempts,
            vec![
                ("AttemptStarted", 1),
                ("Interrupted", 1),
                ("AttemptStarted", 2),
                ("Interrupted", 2),
            ],
            "the two verify() calls must be strictly serialized by the verify lock — \
             distinct attempt ids, never interleaved: {attempts:?}"
        );
        assert!(
            !dir.join("attempts").join("1.json").exists()
                && !dir.join("attempts").join("2.json").exists(),
            "both attempts finish cleanly; neither marker is left dangling or was ever \
             clobbered by the other"
        );
    }

    /// Review 5284360930 of #208, finding 2 — the deterministic barrier regression for
    /// the other half of the finding: attempt 1's `AttemptGuard` is held (its marker
    /// genuinely live, `VerificationAttemptStarted` already durably on the log, nothing
    /// terminal yet) exactly as a real `verify()` call in flight would leave things,
    /// while a concurrent reconciliation pass runs and this test probes whether the
    /// verify lock is genuinely still held. Both must find attempt 1 still in flight:
    /// reconciliation must never remove its marker or treat it as terminal (the
    /// pid/`LIVE_PATHS` liveness checks this composes with, unchanged by this fix — see
    /// `lock_session_verification`'s own doc comment), and a non-blocking probe on the
    /// exact same lock file — deterministic proof, never a timing assumption — must
    /// fail while attempt 1's holder thread has not yet released it, then succeed once
    /// it has, at which point the next allocation correctly sees attempt 1 as done.
    #[test]
    fn a_still_running_attempt_survives_reconciliation_and_holds_its_lock() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let session = Session::start_in(project.path(), state.path()).unwrap();
        session.persist_current().unwrap();
        let dir = session_dir(state.path(), session.id());
        let project_path = project.path().to_path_buf();
        let state_path = state.path().to_path_buf();
        drop(session);

        let attempt = AttemptId::new(1);
        let marker = dir.join("attempts").join("1.json");

        let (holding_tx, holding_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let held_dir = dir.clone();
        let holder = std::thread::spawn(move || {
            // Stands in for a `verify()` call genuinely still in flight: the verify
            // lock held for the attempt's whole lifetime — exactly as `Session::verify`
            // itself now holds it — its `AttemptGuard` alive, and
            // `VerificationAttemptStarted` already durably on the log, but nothing
            // terminal yet.
            let _verify_lock = crate::attempt::lock_session_verification(&held_dir).unwrap();
            let mut log = LocalLog::open(&held_dir.join("events.log"), SystemTime::now()).unwrap();
            log.append(
                Origin::Wardd,
                WardEvent::VerificationAttemptStarted {
                    attempt,
                    requested_by: VerifyRequester::User,
                },
                SystemTime::now(),
            )
            .unwrap();
            log.sync().unwrap();
            let guard = AttemptGuard::start(&held_dir, attempt, VerifyRequester::User).unwrap();
            holding_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            guard.finish();
            // `_verify_lock` releases only once this closure returns, below.
        });

        holding_rx.recv().unwrap();
        assert!(marker.exists());

        // A non-blocking probe on the exact same lock file: it must fail while the
        // holder thread above has not yet released it, deterministically proving the
        // lock is genuinely held rather than merely assumed to be from timing.
        let probe_path = crate::attempt::verify_lock_path(&dir);
        let probe_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&probe_path)
            .unwrap();
        assert!(
            nix::fcntl::Flock::lock(probe_file, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .is_err(),
            "the verify lock must still be held while attempt 1 is in flight"
        );

        // A reconciliation pass — the same one `Session::open_current` runs — must
        // leave the still-live marker completely alone.
        let mut reopened = Session::open_current(&project_path, &state_path)
            .unwrap()
            .expect("the persisted session is found");
        assert!(
            marker.exists(),
            "reconciliation must never remove attempt 1's marker while its guard is still live"
        );
        assert_eq!(
            verification_kinds(&mut reopened),
            vec!["AttemptStarted"],
            "no VerificationInterrupted for the still-running attempt"
        );

        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert!(
            !marker.exists(),
            "attempt 1's marker is cleanly removed once it actually finishes"
        );

        // The lock is free now that `verify()` (simulated by the holder thread above)
        // has fully returned, and the next allocation correctly sees attempt 1's own
        // `AttemptStarted` already on the log.
        let probe_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&probe_path)
            .unwrap();
        let probe =
            nix::fcntl::Flock::lock(probe_file, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .expect("the lock is released once the holder's verify() call returns");
        drop(probe);
        assert_eq!(next_attempt_id(&dir.join("events.log")).get(), 2);
    }

    /// The kinds of every record in `log`, by name, in order.
    fn kinds_in(log: &Path) -> Vec<String> {
        ward_events::LogReader::open(log)
            .unwrap()
            .map(|r| format!("{:?}", r.unwrap().event.kind()))
            .collect()
    }

    /// #145 item 5 without a daemon: `Session::stop` itself ends the session's
    /// running sandbox and confirms it gone before sealing, and says how many
    /// processes it ended.
    #[test]
    fn a_daemonless_stop_ends_a_running_sandbox_before_sealing() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let session = Session::start_in(project.path(), state.path()).unwrap();
        let log = session.log_path();
        let mut sandbox = pause::FakeSandbox::spawn_for(session.id());
        let ended = session.stop(EndReason::UserStop).unwrap();
        assert!(ended >= 2, "{ended}");
        assert!(sandbox.was_killed());
        let kinds = kinds_in(&log);
        let at = |k: &str| kinds.iter().position(|x| x == k).unwrap();
        assert!(at("WorkloadsTerminated") < at("SessionEnded"), "{kinds:?}");
    }

    /// Without a daemon, a stop that cannot confirm termination is refused the
    /// same way: nothing sealed, the marker written so the proxy refuses, the
    /// partial outcome recorded. The retry, once nothing is left, clears the
    /// marker and seals.
    #[test]
    fn a_daemonless_stop_that_cannot_confirm_termination_is_refused_until_a_retry() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut session = Session::start_in(project.path(), state.path()).unwrap();
        let log = session.log_path();
        let err = session
            .record_termination(&pause::Termination {
                ended: 1,
                remaining: Some(pause::Frozen {
                    method: ward_events::PauseMethod::Sigstop,
                    pids: vec![999_999],
                    cgroup: None,
                }),
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("1 ended, 1 still present"), "{err}");
        assert!(err.contains("not sealed"), "{err}");
        assert!(session.paused(), "the marker holds the proxy closed");
        let kinds = kinds_in(&log);
        assert_eq!(
            kinds.last().map(String::as_str),
            Some("WorkloadsTerminated")
        );
        assert!(!kinds.iter().any(|k| k == "SessionEnded"));
        let marker = pause::marker_path(state.path(), session.id());
        assert_eq!(session.stop(EndReason::UserStop).unwrap(), 0);
        assert!(!marker.exists(), "a confirmed stop clears the hold");
        assert_eq!(
            kinds_in(&log).last().map(String::as_str),
            Some("SessionEnded")
        );
    }

    /// `ward stop --restore-entry` without a daemon: the workloads are ended
    /// *before* the restore (so nothing can write over the restored worktree
    /// afterwards), then the stop seals.
    #[test]
    fn stop_restoring_entry_ends_the_workloads_before_restoring() {
        let state = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("a.txt"), "entry\n").unwrap();
        let session = Session::start_in(project.path(), state.path()).unwrap();
        let log = session.log_path();
        std::fs::write(project.path().join("a.txt"), "agent\n").unwrap();
        let mut sandbox = pause::FakeSandbox::spawn_for(session.id());
        let (report, ended) = session.stop_restoring_entry(EndReason::UserStop).unwrap();
        assert!(ended >= 2, "{ended}");
        assert!(sandbox.was_killed());
        assert_eq!(report.files, 1);
        assert_eq!(
            std::fs::read_to_string(project.path().join("a.txt")).unwrap(),
            "entry\n"
        );
        let kinds = kinds_in(&log);
        let at = |k: &str| kinds.iter().position(|x| x == k).unwrap();
        assert!(at("WorkloadsTerminated") < at("EntryRestored"), "{kinds:?}");
        assert!(at("EntryRestored") < at("SessionEnded"), "{kinds:?}");
    }
}
