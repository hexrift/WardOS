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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use ward_events::{
    AgentIdentity, AgentKind, AgentState, BoundedArgv, BoundedText, Chain, EndReason, EventRecord,
    ExitStatus, FileChangeKind, FsyncPolicy, ImageDigest, LogWriter, NameText, Origin, Pid,
    ProcessRef, SandboxPath, SandboxRoot, ShortText, StepStatus, Timestamp, VerifyRequester,
    VerifySummary, WardEvent,
};
use ward_policy::{CapabilityManifest, NetworkCapability, ObserverMode, Policy, merge};
use ward_snapshot::{CaptureOptions, SnapshotRole, SnapshotStore};

use crate::egress::Egress;
use crate::error::{Error, Result};
use crate::gateway::Gateway;
use crate::hooks::{Hooks, protected_from_yaml};
use crate::ids::{ev_hash, ev_snapshot, new_session_id, project_id_for};
use crate::sandbox::{Launch, RELAY_ADDR, StdioMode, find_shim};
use crate::verify;
use crate::watch::{CaptureMode, Captured, Watcher};

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
    project_id: String,
    state: PathBuf,
    log_path: PathBuf,
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
    /// The effective capability manifest.
    pub manifest: CapabilityManifest,
    /// Session start time, milliseconds since the Unix epoch.
    pub started_unix_ms: u64,
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
        let path = meta_path(state, &id);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let meta = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Project(format!("{}: {e}", path.display())))?;
                Ok(Some(meta))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io(&path, e)),
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
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
}

/// What `ward verify` reports.
#[derive(Clone, Debug)]
pub struct VerifyReport {
    /// Candidate snapshot id.
    pub candidate: String,
    /// Whether the trusted verifier passed.
    pub passed: bool,
    /// Parsed counts.
    pub summary: VerifySummary,
    /// Protected paths the verifier took from the entry snapshot instead of the worktree.
    pub restored: Vec<String>,
    /// The verifier's combined output.
    pub output: String,
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
    /// A settings file seeded read-only into the sandbox: `(path, content)`.
    pub settings: Option<(String, String)>,
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
            ward_policy::ProjectId(project_id_str.clone()),
        );

        let store =
            SnapshotStore::open(state.join("cas")).map_err(|e| Error::Snapshot(e.to_string()))?;
        let entry = store
            .store_snapshot(&worktree, SnapshotRole::Entry, CaptureOptions::default())
            .map_err(|e| Error::Snapshot(e.to_string()))?;

        let session_dir = session_dir(state, &session_str);
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
            project_id: project_id_str,
            state: state.to_path_buf(),
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
        let log_path = session_dir(state, &meta.id).join("events.log");
        let log = LogWriter::open(&log_path, FsyncPolicy::DEFAULT)
            .map_err(|e| Error::Events(e.to_string()))?;
        let chain = Chain::resume(log.head());
        let started = UNIX_EPOCH + Duration::from_millis(meta.started_unix_ms);
        Ok(Some(Self {
            manifest: meta.manifest,
            worktree,
            entry_snapshot: meta.entry_snapshot,
            chain,
            log,
            started,
            next_pid: 1,
            root_pid: Pid::new(1).map_err(|e| Error::Events(e.to_string()))?,
            session_str: meta.id,
            project_id: meta.project_id,
            state: state.to_path_buf(),
            log_path,
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
            manifest: self.manifest.clone(),
            started_unix_ms: unix_ms(self.started),
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

    /// Paths TamperWard protects (`protected.tests` in
    /// `<worktree>/.tamperward/config.yml`); empty when the file or key is absent.
    #[must_use]
    pub fn protected_paths(&self) -> Vec<String> {
        let path = self.worktree.join(".tamperward").join("config.yml");
        std::fs::read_to_string(path)
            .map(|yaml| protected_from_yaml(&yaml))
            .unwrap_or_default()
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
        self.log.sync().map_err(|e| Error::Events(e.to_string()))
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
        let (command, opts) = self.agent_launch(name, args, pass_env)?;
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
        let gateways = profile
            .gateway
            .filter(|g| online && !pass_env.iter().any(|k| k == g.key_env))
            .map(|spec| Gateway::resolve(&spec, &self.state))
            .transpose()?
            .flatten()
            .into_iter()
            .collect::<Vec<_>>();
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
                settings: profile.settings.map(|s| (s.path.to_owned(), (s.content)())),
            },
        ))
    }

    /// Run a command with explicit options; every run gets the session egress proxy.
    pub fn launch(&mut self, argv: &[String], opts: &LaunchOpts) -> Result<RunReport> {
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

        let watch_reads = matches!(
            self.manifest.observer,
            ObserverMode::Live | ObserverMode::StepThrough(_)
        );
        let watcher = Watcher::start(&self.worktree, watch_reads).ok();
        let before = if watcher.is_none() {
            Some(scan(&self.worktree))
        } else {
            None
        };

        for g in &opts.gateways {
            self.emit(Origin::Wardd, g.granted(GATEWAY_TTL)?)?;
        }
        let run_dir = run_dir(&self.session_str)?;
        let egress = Egress::start(
            &run_dir,
            &self.manifest.network,
            opts.gateways.iter().map(|g| g.route.clone()).collect(),
        )?;
        let hooks = Hooks::start(&run_dir, self.manifest.observer, self.protected_paths())?;
        let launch = self.prepare(argv, opts, &run_dir, &egress, &hooks)?;
        let outcome = launch.run()?;

        let (captured, capture) = match (watcher, before) {
            (Some(w), _) => (w.finish(), CaptureMode::Inotify),
            (None, Some(before)) => {
                let after = scan(&self.worktree);
                (scan_changes(&before, &after), CaptureMode::Scan)
            }
            (None, None) => (Vec::new(), CaptureMode::Scan),
        };

        let comm = comm(argv);
        let changed_paths = self.emit_captured(&captured, pid, comm.as_ref())?;

        let by = ProcessRef {
            pid,
            comm: comm.clone(),
        };
        for (at, event) in egress.drain_events(&by) {
            self.emit_at(at, Origin::Proxy, event)?;
        }
        egress.stop();
        for (at, event) in hooks.drain_events() {
            self.emit_at(at, Origin::Agent, event)?;
        }
        hooks.stop();
        let _ = std::fs::remove_dir_all(&run_dir);

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
            files_changed: changed_paths.len(),
            duration: outcome.duration,
            capture,
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
        egress: &Egress,
        hooks: &Hooks,
    ) -> Result<Launch> {
        let mut launch = Launch::new(&self.worktree, argv.to_vec())
            .egress(egress.socket())
            .hooks(hooks.socket());
        if let Some((path, content)) = &opts.settings {
            let file = run_dir.join("settings.json");
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
    /// the candidate snapshot, the start with the pristine id and config hash, one
    /// progress step per restored protected path and one for the command, then the
    /// pass or fail with the parsed summary and the output hash.
    pub fn verify(&mut self) -> Result<VerifyReport> {
        let store = SnapshotStore::open(self.state.join("cas"))
            .map_err(|e| Error::Snapshot(e.to_string()))?;
        let entry: ward_snapshot::SnapshotId = self
            .entry_snapshot
            .parse()
            .map_err(|e: ward_snapshot::SnapshotError| Error::Snapshot(e.to_string()))?;
        let scratch_root = run_dir(&self.session_str)?;
        let prepared = verify::prepare(&store, &self.worktree, entry, &scratch_root)?;
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
        for rel in &prepared.restored {
            self.emit(
                Origin::Verifier,
                WardEvent::VerificationProgress {
                    step: ShortText::new(&format!("restore {rel}")),
                    status: StepStatus::Pass,
                },
            )?;
        }
        let outcome = verify::execute(&prepared);
        let _ = std::fs::remove_dir_all(&prepared.scratch);
        let _ = std::fs::remove_dir(&scratch_root);
        let outcome = outcome?;
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
        let event = if outcome.passed {
            WardEvent::VerificationPassed {
                candidate,
                summary: outcome.summary,
                result_hash,
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
            summary: outcome.summary,
            restored: prepared.restored,
            output: outcome.output,
        })
    }

    /// End the session, seal the log, and clear the project's current pointer.
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
        clear_current(&self.state, &self.project_id, &self.session_str)?;
        Ok(())
    }

    /// Emit kernel-origin file events for one command and return the changed paths.
    fn emit_captured(
        &mut self,
        captured: &[Captured],
        pid: Pid,
        comm: Option<&BoundedText<32>>,
    ) -> Result<BTreeSet<String>> {
        let mut changed_paths = BTreeSet::new();
        for item in captured {
            match item {
                Captured::Modified { at, rel, kind } => {
                    if let Ok(path) = SandboxPath::new(SandboxRoot::Work, rel) {
                        changed_paths.insert(rel.clone());
                        self.emit_at(
                            *at,
                            Origin::Kernel,
                            WardEvent::FileModified {
                                path,
                                by: ProcessRef {
                                    pid,
                                    comm: comm.cloned(),
                                },
                                kind: *kind,
                            },
                        )?;
                    }
                }
                Captured::Read { at, rel } => {
                    if let Ok(path) = SandboxPath::new(SandboxRoot::Work, rel) {
                        self.emit_at(
                            *at,
                            Origin::Kernel,
                            WardEvent::FileRead {
                                path,
                                by: ProcessRef {
                                    pid,
                                    comm: comm.cloned(),
                                },
                            },
                        )?;
                    }
                }
            }
        }

        Ok(changed_paths)
    }

    fn alloc_pid(&mut self) -> Pid {
        self.next_pid = self.next_pid.wrapping_add(1).max(2);
        Pid::new(self.next_pid).unwrap_or(self.root_pid)
    }

    fn emit(&mut self, origin: Origin, event: WardEvent) -> Result<()> {
        self.emit_at(SystemTime::now(), origin, event)
    }

    /// Append an event that happened at `at`: captured facts (proxy decisions, hook
    /// claims, file events) are drained after the command exits but keep their
    /// own time, so the observer timeline is truthful.
    fn emit_at(&mut self, at: SystemTime, origin: Origin, event: WardEvent) -> Result<()> {
        let record: EventRecord = self
            .chain
            .append(origin, event, ts_at(self.started, at))
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

/// Monotonic session time of `at`; anything before the session started is 0.
fn ts_at(started: SystemTime, at: SystemTime) -> Timestamp {
    Timestamp::mono(at.duration_since(started).unwrap_or_default())
}

fn unix_ms(t: SystemTime) -> u64 {
    u64::try_from(t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()).unwrap_or(u64::MAX)
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
fn run_dir(session_id: &str) -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let tail: String = session_id
        .chars()
        .rev()
        .take(10)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let dir = std::env::temp_dir().join(format!("ward-{tail}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => Ok(dir),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(dir),
        Err(e) => Err(Error::io(&dir, e)),
    }
}

fn session_dir(state: &Path, id: &str) -> PathBuf {
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
    #![allow(clippy::unwrap_used)]
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
            manifest,
            started_unix_ms: 1_700_000_000_000,
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

    #[test]
    fn ts_at_keeps_capture_time_and_clamps_before_start() {
        let started = SystemTime::now();
        let later = started + Duration::from_secs(5);
        assert_eq!(ts_at(started, later).mono, Duration::from_secs(5));
        assert_eq!(
            ts_at(started, started - Duration::from_secs(1)).mono,
            Duration::ZERO
        );
    }
}
