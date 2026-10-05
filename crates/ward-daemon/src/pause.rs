//! Pause as a host primitive (ADR-0019 §3): freezing and thawing every process
//! of a session's sandboxes, and the marker the session's proxies watch.
//!
//! The daemon owns the log and the approvals but not the sandboxes: each
//! `ward run` / `ward claude` launches its own `bwrap` and runs its own proxy
//! (ADR-0013). Pausing therefore reaches them from outside:
//!
//! * **Processes.** Every `bwrap` of the session is found through `/proc` (its
//!   command line binds the session's run directory, `session::run_dir_path`,
//!   into the sandbox), and its whole tree is frozen. When the daemon can create
//!   a delegated cgroup v2 for the session next to its own, the tree is moved
//!   there and `cgroup.freeze = 1` freezes it atomically; otherwise every
//!   process gets `SIGSTOP`, children first, so no parent can react to a child
//!   stopping. Which path was used is recorded in `SessionPaused`.
//! * **The proxy.** A marker file, `sessions/<id>/paused`, is written before
//!   the log record; every proxy of the session polls it ([`crate::egress`])
//!   and refuses new traffic while it exists. The processes are already frozen
//!   by then, so nothing in the sandbox can use the gap.
//!
//! Only the sandbox trees are touched: the `ward` client process that owns the
//! proxy and the hook listener keeps running, which is what lets the proxy
//! answer `paused by ward` and the desktop show the state.
//!
//! **Stop** ([`terminate`], #145 item 5) reaches the same trees the same way:
//! freeze them (unless a pause already holds them), confirm the freeze stable
//! — the fork barrier, [`stabilize`] — then kill every process, and watch
//! until each is confirmed gone, bounded by [`STOP_SETTLE`]. `ward stop` seals
//! the log only after that confirmation; a stop that could not confirm it is
//! refused and the session is held for the stop instead.
//!
//! **Restart reconciliation** ([`INTENT`], #145 item 7): every pause and stop
//! records its intent durably here before it signals anything, and removes it
//! once its outcome is on the log, so a daemon started on the session finishes
//! what a previous process left unfinished (`crate::daemon::serve`).
//!
//! **Hold ownership** ([`Holders`], #145 item 6): a hold on the session has
//! owners — the user (`ward pause`), a snapshot capture, a stop — recorded
//! durably beside the marker ([`HELD_BY`]). `ward resume` releases only the
//! user's layer; a capture's hold is released by the capture that took it, or
//! by reconciliation once its process is gone; a stop's only by the stop. The
//! marker, the held approvals and the freeze stand while any owner remains.
//! A capture ([`LocalCaptureHold`] here; `Request::HoldForCapture` when a
//! daemon serves the session) proceeds only from confirmed quiescence: the
//! freeze settled and every component acknowledged, the state a `SessionPaused`
//! records.
//!
//! **Launch admission** ([`admit_launch`], PR #253 review finding 2) takes the
//! same session lock ([`lock_pause_freeze`]) pause, resume, stop and the
//! capture freeze take, and holds it across the `bwrap` spawn; the stop marker
//! ([`STOP_MARKER`]), written under that lock when a stop begins, refuses
//! every later launch. A launch therefore either exists before a stop scans
//! (and is ended by it) or never spawns.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use ward_events::{EndReason, PauseMethod, ShortText, WardEvent};

use crate::acks::{self, Acknowledger, Phase};
use crate::error::{Error, Result};
use crate::session::{run_dir_path, session_dir};

/// File name of the pause marker inside `sessions/<id>/`.
pub const MARKER: &str = "paused";
/// Where cgroup v2 is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// How long a freeze is given to settle before it is trusted (or, for the signal path,
/// before `Served::pause` records it as unconfirmed rather than waiting longer — #145
/// items 3-4). Public so a caller reporting an unsettled pause (the CLI, `ward-cli`'s
/// `cmd_pause`) can name the actual bound instead of a copy of this number.
pub const FREEZE_SETTLE: Duration = Duration::from_secs(1);

/// The marker the session's proxies watch: present while paused.
#[must_use]
pub fn marker_path(state: &Path, session: &str) -> PathBuf {
    session_dir(state, session).join(MARKER)
}

/// File name of the stop marker inside `sessions/<id>/`: written, under
/// [`lock_pause_freeze`], the moment a stop (or a stop hold) begins, and never
/// removed. A session is ended by its first stop; once this exists no new
/// sandbox of it may start (PR #253 review finding 2).
pub const STOP_MARKER: &str = "stopped";

/// The stop marker of `session` (see [`STOP_MARKER`]).
#[must_use]
pub fn stop_marker_path(state: &Path, session: &str) -> PathBuf {
    session_dir(state, session).join(STOP_MARKER)
}

/// Write the stop marker for `session` (idempotent). A caller holds
/// [`lock_pause_freeze`] across this and the termination scan that follows it,
/// so no launch can be admitted in between.
pub fn write_stop_marker(state: &Path, session: &str) -> Result<()> {
    let path = stop_marker_path(state, session);
    fs::write(&path, "ward stop\n").map_err(|e| Error::io(&path, e))
}

/// Whether a stop of `session` has begun (see [`STOP_MARKER`]).
#[must_use]
pub fn stop_begun(state: &Path, session: &str) -> bool {
    stop_marker_path(state, session).exists()
}

/// File name of the lifecycle intent inside `sessions/<id>/` (#145 item 7): the
/// record that a pause or a stop has begun and has not yet reached its terminal
/// record. Written durably (temp file, `fsync`, rename, `fsync` of the directory)
/// before anything is signalled, and removed once the operation's outcome is on
/// the log — `SessionPaused`/`SessionPauseUnsettled` for a pause, the seal or
/// the refused stop's `WorkloadsTerminated` for a stop. A daemon starting on a
/// session directory that still holds one finishes that operation before it
/// serves ([`crate::daemon::serve`]).
pub const INTENT: &str = "intent.json";

/// Which operation an [`Intent`] records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum Verb {
    /// `ward pause`, or the hold a stop takes before restoring the entry state.
    Pause {
        /// The reason the pause's record carries.
        reason: String,
    },
    /// `ward stop`.
    Stop {
        /// The reason `SessionEnded` carries.
        reason: EndReason,
    },
    /// A snapshot capture taking its hold (#145 item 6): recorded only while
    /// the hold is being taken, cleared once the marker and the owners are
    /// written. A daemon that finds it releases that capture's hold: a hold
    /// whose taking was interrupted cannot be the quiescence any capture
    /// proceeds from.
    Capture {
        /// The reason the hold's record carries.
        reason: String,
        /// The process taking it.
        capturer: Capturer,
    },
    /// `ward resume` releasing the user's hold (#145 item 1, the `Resuming`
    /// state): recorded before the first component is released, cleared once
    /// `SessionResumed` is on the log or the release was taken back. A daemon
    /// that finds it finishes the release from what `/proc` shows, so a tree
    /// left frozen by a resume that died between clearing the marker and
    /// thawing is not frozen for ever with nothing saying so. Appended after
    /// the shipped variants: an intent written by this daemon reads back on
    /// one that predates it only by its own, older verbs.
    Resume,
}

/// The durable intent of one lifecycle operation (see [`INTENT`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// The operation's id ([`crate::ids::new_operation_id`]).
    pub op: String,
    /// When the operation began, milliseconds since the Unix epoch.
    pub started_unix_ms: u64,
    /// What it is.
    #[serde(flatten)]
    pub verb: Verb,
}

impl Intent {
    /// A fresh intent for `verb`, beginning now.
    pub fn begin(verb: Verb) -> Result<Self> {
        Ok(Self {
            op: crate::ids::new_operation_id()?,
            started_unix_ms: crate::control::unix_ms(std::time::SystemTime::now()),
            verb,
        })
    }
}

/// The intent file of `session` (see [`INTENT`]).
#[must_use]
pub fn intent_path(state: &Path, session: &str) -> PathBuf {
    session_dir(state, session).join(INTENT)
}

/// Record `intent` for `session` durably: written to a private temp file beside
/// [`intent_path`], `fsync`ed, renamed into place, and the directory `fsync`ed,
/// so a crash at any point leaves either the previous intent or this one, never
/// a partial file. Replaces an intent already there.
pub fn write_intent(state: &Path, session: &str, intent: &Intent) -> Result<()> {
    let path = intent_path(state, session);
    let bytes = serde_json::to_vec(intent).map_err(|e| Error::Events(format!("intent: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    crate::attempt::write_file_durably(&tmp, &bytes)?;
    fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))?;
    crate::attempt::sync_dir(&session_dir(state, session))
}

/// The intent recorded for `session`, if any. An intent that cannot be parsed is
/// an error: a daemon must not serve a session whose last lifecycle operation it
/// cannot name.
pub fn read_intent(state: &Path, session: &str) -> Result<Option<Intent>> {
    let path = intent_path(state, session);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(&path, e)),
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|e| {
        Error::Daemon(format!(
            "{}: unreadable lifecycle intent: {e}",
            path.display()
        ))
    })
}

/// Remove `session`'s intent durably; one already gone is fine.
pub fn clear_intent(state: &Path, session: &str) -> Result<()> {
    let path = intent_path(state, session);
    match fs::remove_file(&path) {
        Ok(()) => crate::attempt::sync_dir(&session_dir(state, session)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(&path, e)),
    }
}

/// File name of the hold's owners inside `sessions/<id>/` (#145 item 6):
/// written beside the marker whenever the owners change, removed with it. A
/// marker with no owners recorded is a hold from before owners were recorded,
/// and is the user's.
pub const HELD_BY: &str = "held_by.json";

/// Who holds a session paused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    /// `ward pause`: released by `ward resume`.
    User,
    /// A snapshot capture: released by the capture when it finishes, or by
    /// reconciliation once the capturing process is gone.
    Capture,
    /// A stop that has begun and not completed: released only by the stop.
    Stop,
}

impl Owner {
    /// The owner's name in `ward pause --status --json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Capture => "capture",
            Self::Stop => "stop",
        }
    }
}

/// One capture holding the session: its operation, the process taking it
/// (pid and `/proc` start time, so a reused pid is not mistaken for it) and
/// the reason its hold is recorded under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capturer {
    /// The operation's id ([`crate::ids::new_operation_id`]).
    pub op: String,
    /// The capturing process.
    pub pid: u32,
    /// Its `/proc/<pid>/stat` start time, as written.
    pub started: String,
    /// The reason the hold's record carries ([`capture_reason`]).
    pub reason: String,
}

impl Capturer {
    /// Whether the capturing process still exists.
    #[must_use]
    pub fn alive(&self, proc: &Path) -> bool {
        acks::start_time(proc, self.pid).as_deref() == Some(self.started.as_str())
    }
}

/// The `/proc` start time of this process, as [`Capturer::started`] records it.
#[must_use]
pub fn own_start_time() -> String {
    acks::start_time(Path::new("/proc"), std::process::id()).unwrap_or_default()
}

/// The owners of a session's hold (#145 item 6). Empty means nothing holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holders {
    /// `ward pause` holds it.
    #[serde(default)]
    pub user: bool,
    /// A stop has begun and holds it.
    #[serde(default)]
    pub stop: bool,
    /// Every capture holding it.
    #[serde(default)]
    pub captures: Vec<Capturer>,
}

impl Holders {
    /// The user's pause alone.
    #[must_use]
    pub const fn for_user() -> Self {
        Self {
            user: true,
            stop: false,
            captures: Vec::new(),
        }
    }

    /// A stop alone.
    #[must_use]
    pub const fn for_stop() -> Self {
        Self {
            user: false,
            stop: true,
            captures: Vec::new(),
        }
    }

    /// One capture alone.
    #[must_use]
    pub fn for_capture(capturer: Capturer) -> Self {
        Self {
            user: false,
            stop: false,
            captures: vec![capturer],
        }
    }

    /// Nothing holds the session.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.user && !self.stop && self.captures.is_empty()
    }

    /// Only captures hold the session: what `ward resume` cannot release.
    #[must_use]
    pub fn held_only_for_capture(&self) -> bool {
        !self.user && !self.stop && !self.captures.is_empty()
    }

    /// The owners, user first, then capture (once, however many), then stop.
    #[must_use]
    pub fn owners(&self) -> Vec<Owner> {
        let mut owners = Vec::new();
        if self.user {
            owners.push(Owner::User);
        }
        if !self.captures.is_empty() {
            owners.push(Owner::Capture);
        }
        if self.stop {
            owners.push(Owner::Stop);
        }
        owners
    }

    /// Add a capture.
    pub fn add_capture(&mut self, capturer: Capturer) {
        self.captures.push(capturer);
    }

    /// Remove the capture of operation `op`; whether it was there.
    pub fn remove_capture(&mut self, op: &str) -> bool {
        let before = self.captures.len();
        self.captures.retain(|c| c.op != op);
        self.captures.len() != before
    }

    /// Forget every capture whose process is gone; whether any was.
    pub fn prune_dead(&mut self, proc: &Path) -> bool {
        let before = self.captures.len();
        self.captures.retain(|c| c.alive(proc));
        self.captures.len() != before
    }
}

/// The owners file of `session` (see [`HELD_BY`]).
#[must_use]
pub fn held_by_path(state: &Path, session: &str) -> PathBuf {
    session_dir(state, session).join(HELD_BY)
}

/// Record who holds `session`.
pub fn write_held_by(state: &Path, session: &str, holders: &Holders) -> Result<()> {
    let path = held_by_path(state, session);
    let bytes = serde_json::to_vec(holders).map_err(|e| Error::Events(format!("held_by: {e}")))?;
    fs::write(&path, bytes).map_err(|e| Error::io(&path, e))
}

/// Who holds `session`, as recorded; `None` when nothing is recorded.
pub fn read_held_by(state: &Path, session: &str) -> Result<Option<Holders>> {
    let path = held_by_path(state, session);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(&path, e)),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| Error::Daemon(format!("{}: unreadable hold owners: {e}", path.display())))
}

/// Remove `session`'s owners record; one already gone is fine.
pub fn clear_held_by(state: &Path, session: &str) -> Result<()> {
    let path = held_by_path(state, session);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(&path, e)),
    }
}

/// The session's lifecycle (#145 item 1), as one explicit state: what the
/// markers, the intent and the log's last hold record implied separately
/// until now. `Running → Pausing → Paused → Resuming → Running`;
/// `Running | Paused → Stopping → Stopped`; and [`Incomplete`](Self::Incomplete),
/// what a pause or a stop that could not be confirmed leaves behind until a
/// retry (`ward resume` for a pause, `ward stop` for either) confirms an
/// outcome. The state is derived from the durable records
/// ([`lifecycle_on_disk`]) — the intent file ([`INTENT`]) for the operations
/// in flight, the pause marker ([`MARKER`]), the stop marker
/// ([`STOP_MARKER`]), the owners ([`HELD_BY`]) and the log's last hold record
/// — so a reader with no daemon derives the same state the daemon serves
/// (`Request::Lifecycle`), and every transition is decided by one table
/// ([`transition`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Nothing holds the session; launches are admitted.
    Running,
    /// A pause (or a capture's hold) has begun and has not reached its record.
    Pausing,
    /// A confirmed hold is in force: the freeze settled and every component
    /// acknowledged (`SessionPaused`).
    Paused,
    /// `ward resume` is releasing the hold, component by component.
    Resuming,
    /// A stop has begun — its intent recorded, or the session held for it
    /// (`HoldForStop`, confirmed) — and the log is not sealed yet.
    Stopping,
    /// The log is sealed: the session ended.
    Stopped,
    /// A pause or a stop could not be confirmed and recovery is required: an
    /// unsettled freeze, a component that did not acknowledge, or processes a
    /// stop could not confirm ended. The session is held in the safest state
    /// it could reach; this is never reported as `Paused` or `Stopped`.
    Incomplete,
}

impl Lifecycle {
    /// Every state, in the order of the lifecycle.
    pub const ALL: [Self; 7] = [
        Self::Running,
        Self::Pausing,
        Self::Paused,
        Self::Resuming,
        Self::Stopping,
        Self::Stopped,
        Self::Incomplete,
    ];

    /// The state's name in `ward pause --status --json`, `ward status` and
    /// every refusal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Pausing => "pausing",
            Self::Paused => "paused",
            Self::Resuming => "resuming",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Incomplete => "incomplete",
        }
    }

    /// The state [`as_str`](Self::as_str) names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == name.trim())
    }

    /// An operation is in flight: its intent is recorded and its outcome is
    /// not. Only a reader outside the daemon observes these (the daemon
    /// serves one lifecycle operation at a time).
    #[must_use]
    pub const fn in_flight(self) -> bool {
        matches!(self, Self::Pausing | Self::Resuming)
    }

    /// Whether a sandbox launch may be admitted in this state: only while
    /// running (#145 item 2).
    #[must_use]
    pub const fn admits_launch(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Whether a hold is in force (the marker stands, the approvals are held).
    #[must_use]
    pub const fn holds(self) -> bool {
        matches!(self, Self::Paused | Self::Stopping | Self::Incomplete)
    }
}

impl fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A lifecycle operation a request asks for ([`transition`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// `ward pause` (`Request::Pause`).
    Pause,
    /// `ward resume` (`Request::Resume`).
    Resume,
    /// `ward stop` (`Request::Stop`), first attempt or retry.
    Stop,
    /// `ward stop --restore-entry`'s hold (`Request::HoldForStop`).
    HoldForStop,
    /// A snapshot capture's hold (`Request::HoldForCapture`).
    HoldForCapture,
    /// A sandbox launch ([`admit_launch`]).
    Launch,
}

impl Operation {
    /// The operation's name in refusals.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Stop => "stop",
            Self::HoldForStop => "hold for stop",
            Self::HoldForCapture => "hold for capture",
            Self::Launch => "launch",
        }
    }

    /// The state the session is in while this operation runs from a state
    /// that admits it as a transition (not a layering over a hold in force).
    #[must_use]
    pub const fn enters(self) -> Lifecycle {
        match self {
            Self::Pause | Self::HoldForCapture => Lifecycle::Pausing,
            Self::Resume => Lifecycle::Resuming,
            Self::Stop | Self::HoldForStop => Lifecycle::Stopping,
            Self::Launch => Lifecycle::Running,
        }
    }
}

/// The refusal a resume gets while a stop of the session has begun.
#[must_use]
pub fn stop_begun_refusal(session: &str) -> String {
    format!(
        "a stop of session {session} has begun and not completed: its sandboxed processes are \
         held for that stop (some may already have been killed), so `ward resume` cannot \
         release them. Run `ward stop` to finish it"
    )
}

/// The refusal a resume gets when only captures hold the session.
#[must_use]
pub fn held_for_capture_refusal(session: &str, capture: &Capturer) -> String {
    format!(
        "session {session} is held for capture by operation {} (pid {}), not a user pause: `ward \
         resume` releases only a user's pause, and the capture releases its hold when it \
         finishes",
        capture.op, capture.pid
    )
}

/// The refusal a launch gets while an operation is in flight or the session
/// is held, naming the state (#145 item 2): [`PAUSED_REFUSAL`] and
/// [`STOPPED_REFUSAL`] for the states those name, else the state's own word.
#[must_use]
pub fn launch_refusal(state: Lifecycle) -> String {
    match state {
        Lifecycle::Paused | Lifecycle::Incomplete => PAUSED_REFUSAL.to_owned(),
        Lifecycle::Stopping | Lifecycle::Stopped => STOPPED_REFUSAL.to_owned(),
        Lifecycle::Running | Lifecycle::Pausing | Lifecycle::Resuming => {
            format!("session is {state} by ward; nothing new can start in it until that completes")
        }
    }
}

/// The one transition table (#145 item 1): what `op` does to a session in
/// `state` whose hold has `holders`, for `session`. `Ok(entered)` is the state
/// the session is in while the operation runs — the transient state
/// ([`Operation::enters`]) for a transition, `state` itself for an operation
/// that joins a hold in force without changing it (a capture over a pause, a
/// stop's hold over a pause, a user's pause over a capture's hold, a retried
/// stop over an incomplete one). `Err` is the refusal, naming the state. The
/// daemon (`Served::enter`) and launch admission ([`admit_launch`]) both
/// decide here; nothing else decides whether an operation is valid.
///
/// The words some refusals use are the ones clients and the desktop already
/// read (`already paused`, `not paused`, `log is sealed`, the stop-begun and
/// held-for-capture refusals), so every existing reader keeps working.
pub fn transition(
    session: &str,
    state: Lifecycle,
    holders: &Holders,
    op: Operation,
) -> Result<Lifecycle> {
    use Lifecycle as L;
    use Operation as O;
    let refuse = |text: String| Err(Error::Daemon(text));
    if op == O::Launch {
        return if state.admits_launch() {
            Ok(L::Running)
        } else {
            Err(Error::Sandbox(launch_refusal(state)))
        };
    }
    if state == L::Stopped {
        return refuse("log is sealed".to_owned());
    }
    let held = holders.user || holders.stop || !holders.captures.is_empty();
    match (state, op) {
        (L::Running, O::Resume) => refuse("not paused".to_owned()),
        (L::Running, _) => Ok(op.enters()),
        // An operation in flight, observed from outside the daemon: nothing
        // else may begin until it reaches its outcome.
        (L::Pausing | L::Resuming, _) => refuse(format!(
            "session {session} is {state}: a {} cannot begin until that operation has reached \
             its outcome (its intent is recorded; a daemon restarted on the session finishes \
             it)",
            op.as_str()
        )),
        // A stop has begun (the stop marker) and nothing holds the session in
        // this daemon's memory: a stop that could not take its hold, or a
        // restarted daemon reading the marker. Only a stop goes on from here.
        (L::Stopping | L::Paused | L::Incomplete, O::Stop | O::HoldForStop) => Ok(L::Stopping),
        (L::Stopping, O::Resume) => refuse(stop_begun_refusal(session)),
        (L::Stopping, O::Pause) if !held => refuse(format!(
            "session {session} is stopping: a stop has begun and not completed, so a pause \
             cannot be taken. Run `ward stop` to finish it"
        )),
        (L::Stopping, O::HoldForCapture) if !held => refuse(format!(
            "session {session} is stopping: a stop has begun and not completed, so nothing can \
             be captured from it"
        )),
        // A hold in force: the user's, a capture's, a stop's, confirmed or not.
        (L::Paused | L::Incomplete | L::Stopping, O::Pause) => {
            if holders.user || holders.stop {
                refuse("already paused".to_owned())
            } else {
                // Layered over a capture's hold: no transition, the hold stands.
                Ok(state)
            }
        }
        (L::Paused | L::Incomplete, O::Resume) => {
            if holders.stop {
                refuse(stop_begun_refusal(session))
            } else if let (false, Some(capture)) = (holders.user, holders.captures.first()) {
                refuse(held_for_capture_refusal(session, capture))
            } else {
                Ok(L::Resuming)
            }
        }
        (L::Paused | L::Incomplete | L::Stopping, O::HoldForCapture) => Ok(state),
        (L::Stopped, _) | (_, O::Launch) => unreachable!("decided above"),
    }
}

/// The lifecycle as a reader sees it (#145 item 1): the state, what is
/// uncertain about it, the operation in flight, who holds the session and
/// which launches are open. Serialised into `ward pause --status --json`'s
/// `lifecycle` field and `Response::Lifecycle`; every field but `state` is
/// optional on the wire, so a reader of an older daemon's answer, or a newer
/// daemon's, reads it the same.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleReport {
    /// The state.
    pub state: Lifecycle,
    /// What the state cannot confirm (`Incomplete`: the component or the
    /// processes), or the reason of the operation in flight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The id of the operation in flight ([`Intent::op`]), while one is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    /// Who holds the session, in [`Holders::owners`] order; empty while running.
    #[serde(default)]
    pub held_by: Vec<Owner>,
    /// The handles of every launch admitted and not yet ended
    /// ([`crate::launches`]).
    #[serde(default)]
    pub open_launches: Vec<u64>,
}

impl LifecycleReport {
    /// A report of `state` with nothing else known.
    #[must_use]
    pub const fn of(state: Lifecycle) -> Self {
        Self {
            state,
            detail: None,
            op: None,
            held_by: Vec::new(),
            open_launches: Vec::new(),
        }
    }

    /// `paused`, `incomplete (egress proxy (no acknowledgement within 2s))`,
    /// `pausing (looks wrong)`: the state and its detail, for a status line.
    #[must_use]
    pub fn text(&self) -> String {
        match &self.detail {
            Some(detail) if !detail.is_empty() => format!("{} ({detail})", self.state),
            _ => self.state.to_string(),
        }
    }
}

/// The lifecycle `session`'s durable records show, without reading its log
/// (#145 item 1): the intent names an operation in flight (`Pausing` for a
/// pause or a capture's hold, `Resuming`, `Stopping`); a sealed log is
/// `Stopped`; the stop marker is `Stopping`; the pause marker is `Paused`;
/// nothing is `Running`. `Paused` and `Stopping` here may read `Incomplete`
/// once the log is consulted ([`lifecycle_on_disk`]); for admission that
/// difference does not matter (neither admits a launch). Cheap: a few
/// `stat`s, so every launch can afford it under the session lock.
pub fn lifecycle_marks(state: &Path, session: &str) -> Result<(Lifecycle, Option<Intent>)> {
    if let Some(intent) = read_intent(state, session)? {
        let lifecycle = match intent.verb {
            Verb::Pause { .. } | Verb::Capture { .. } => Lifecycle::Pausing,
            Verb::Resume => Lifecycle::Resuming,
            Verb::Stop { .. } => Lifecycle::Stopping,
        };
        return Ok((lifecycle, Some(intent)));
    }
    let log = session_dir(state, session).join("events.log");
    if ward_events::log::head_file_path(&log).exists() {
        return Ok((Lifecycle::Stopped, None));
    }
    if stop_begun(state, session) {
        return Ok((Lifecycle::Stopping, None));
    }
    if marker_path(state, session).exists() {
        return Ok((Lifecycle::Paused, None));
    }
    Ok((Lifecycle::Running, None))
}

/// The lifecycle `session`'s durable records show, for a reader with no
/// daemon (`ward pause --status`, `ward status`): [`lifecycle_marks`] refined
/// by the log — a hold whose last record is unconfirmed (`SessionPauseUnsettled`,
/// or a `WorkloadsTerminated` with pending processes or an unconfirmed
/// barrier; [`acks::unconfirmed_detail`]) is `Incomplete`, with that detail —
/// and completed with the owners and the open launches
/// ([`crate::launches::read`]). A session whose log does not exist yet reads
/// from its marks alone.
pub fn lifecycle_on_disk(state: &Path, session: &str) -> Result<LifecycleReport> {
    let (mut lifecycle, intent) = lifecycle_marks(state, session)?;
    let log = session_dir(state, session).join("events.log");
    let mut detail = None;
    let mut op = None;
    match intent {
        Some(intent) => {
            op = Some(intent.op);
            detail = match intent.verb {
                Verb::Pause { reason } | Verb::Capture { reason, .. } => Some(reason),
                Verb::Stop { .. } | Verb::Resume => None,
            };
        }
        None if lifecycle.holds() => {
            let unconfirmed = match acks::unconfirmed_detail(&log) {
                Ok(detail) => detail,
                Err(_) if !log.exists() => None,
                Err(e) => return Err(e),
            };
            if let Some(unconfirmed) = unconfirmed {
                lifecycle = Lifecycle::Incomplete;
                detail = Some(unconfirmed);
            }
        }
        None => {}
    }
    let held_by = if marker_path(state, session).exists() {
        let mut holders = read_held_by(state, session)?.unwrap_or_else(Holders::for_user);
        holders.prune_dead(Path::new("/proc"));
        if stop_begun(state, session) {
            holders.stop = true;
        }
        holders.owners()
    } else {
        Vec::new()
    };
    let open_launches = crate::launches::read(state, session)?
        .open()
        .map(|l| l.handle)
        .collect();
    Ok(LifecycleReport {
        state: lifecycle,
        detail,
        op,
        held_by,
        open_launches,
    })
}

/// What a hold could not confirm, in words: its pending processes, the
/// component that did not acknowledge, or both.
#[must_use]
pub fn uncertainty(unsettled: Option<u32>, unconfirmed: Option<&acks::Acknowledgement>) -> String {
    let mut parts = Vec::new();
    if let Some(pending) = unsettled {
        parts.push(format!("{pending} process(es) still pending"));
    }
    if let Some(ack) = unconfirmed {
        parts.push(format!("{} unconfirmed", ack.text()));
    }
    parts.join("; ")
}

/// The refusal a capture answers with when the session's quiescence could not
/// be confirmed (#145 item 6): nothing is captured, and only what the capture
/// itself took is released.
#[must_use]
pub fn capture_refusal(
    session: &str,
    unsettled: Option<u32>,
    unconfirmed: Option<&acks::Acknowledgement>,
) -> Error {
    Error::Daemon(format!(
        "capture of session {session} refused: its quiescence could not be confirmed ({}); \
         nothing was captured, and only the hold the capture itself took was released",
        uncertainty(unsettled, unconfirmed)
    ))
}

/// The reason every capture's hold is recorded under begins with this.
pub const CAPTURE_REASON: &str = "ward capture";

/// The reason a capture's hold records: `ward capture: <what>`.
#[must_use]
pub fn capture_reason(what: &str) -> String {
    format!("{CAPTURE_REASON}: {what}")
}

/// Whether a hold record's reason is a capture's ([`capture_reason`]).
#[must_use]
pub fn is_capture_reason(reason: &str) -> bool {
    reason.starts_with(CAPTURE_REASON)
}

/// The reason the marker carries while a stop holds the session's components
/// for the termination it confirms (#145 item 3).
pub const STOP_REASON: &str = "ward stop";

/// The refusal a launch gets while the session is paused.
pub const PAUSED_REFUSAL: &str = "session is paused by ward; `ward resume` before running anything";
/// The refusal a launch gets once a stop of the session has begun.
pub const STOPPED_REFUSAL: &str = "session is being stopped by ward; nothing new can start in it";

/// Admit one sandbox launch of `session` (PR #253 review finding 2, #145 item
/// 2): take [`lock_pause_freeze`] — the lock pause, resume, stop and the
/// capture freeze all take — and, under it, refuse when the session is paused
/// or a stop has begun. The caller spawns its `bwrap` *while holding the
/// returned guard* and drops it only once the spawn has returned, so the
/// sandbox's root is already in `/proc` with its command line by the time any
/// pause or stop can take the lock and scan. Launch admission and pause/stop
/// are therefore one serialized lifecycle operation: a launch either spawns
/// before a stop's scan (and is found and ended by it) or is refused.
///
/// Fails closed: a lock that cannot be taken (the session directory is gone)
/// refuses the launch, since nothing could then serialize it against a stop.
pub fn admit_launch(state: &Path, session: &str) -> Result<Flock<std::fs::File>> {
    let lock = lock_pause_freeze(&session_dir(state, session)).map_err(|e| {
        Error::Sandbox(format!(
            "launch admission for session {session} could not take the session lock: {e}"
        ))
    })?;
    launch_admission(state, session)?;
    Ok(lock)
}

/// The admission decision alone (#145 item 2), from the session's durable
/// records ([`lifecycle_marks`]) through the one transition table
/// ([`transition`]): admitted only while the session is `Running`; refused,
/// naming the state, while an operation is in flight (`Pausing`, `Resuming`,
/// `Stopping`) or a hold stands (`Paused`, `Incomplete`) or the session ended.
/// [`admit_launch`] decides this under the session lock; `Session::launch`
/// asks it once more, unlocked, before anything is recorded, so a refusal
/// costs nothing. Fails closed: records that cannot be read refuse the launch.
pub fn launch_admission(state: &Path, session: &str) -> Result<()> {
    let (lifecycle, _) = lifecycle_marks(state, session).map_err(|e| {
        Error::Sandbox(format!(
            "launch admission for session {session} could not read the session's lifecycle: {e}"
        ))
    })?;
    let holders = read_held_by(state, session)
        .ok()
        .flatten()
        .unwrap_or_default();
    transition(session, lifecycle, &holders, Operation::Launch).map(drop)
}

/// What a freeze holds, so it can be thawed or killed later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frozen {
    /// How the processes were frozen.
    pub method: PauseMethod,
    /// Every process frozen, children before their parents.
    pub pids: Vec<u32>,
    /// The delegated cgroup holding them (freezer method only).
    pub cgroup: Option<PathBuf>,
}

/// Freeze every process of `session`'s sandboxes. A session with no sandbox
/// running freezes nothing and still reports the method it would use, so the
/// rest of the pause (proxy, credentials, approvals, the record) proceeds. A
/// pid gone since the scan is not a failure: its tree ended by itself.
///
/// The freeze returned is *stable* whenever it could be made so within
/// [`FREEZE_SETTLE`] ([`stabilize`], PR #253 review finding 4): a process that
/// was mid-`fork` when the scan ran has a child the scan could not see, and
/// that child does not inherit the parent's pending `SIGSTOP` (nor, forked
/// before its parent moved, the parent's cgroup). So the session is rescanned
/// once everything known is confirmed stopped, anything new is frozen too, and
/// that repeats until a rescan finds nothing new — at which point no member of
/// the tree can run, so none can fork, and the set is closed.
#[must_use]
pub fn freeze(session: &str) -> Frozen {
    freeze_confirmed(session).0
}

/// [`freeze`], also saying whether the freeze was confirmed stable within
/// [`FREEZE_SETTLE`] (see [`stabilize`]).
#[must_use]
pub fn freeze_confirmed(session: &str) -> (Frozen, bool) {
    let pids = sandbox_pids(Path::new("/proc"), session);
    if let Some(dir) = select_cgroup(own_cgroup().as_deref(), session) {
        if freeze_cgroup(&dir, &pids).is_ok() {
            return stabilize(
                session,
                Frozen {
                    method: PauseMethod::CgroupFreezer,
                    pids,
                    cgroup: Some(dir),
                },
            );
        }
        // The cgroup exists but will not take the tree (a controller rule, a
        // pid that moved): thaw whatever went in and use signals instead.
        let _ = fs::write(dir.join("cgroup.freeze"), "0");
        let _ = fs::remove_dir(&dir);
    }
    freeze_signals(&pids);
    stabilize(
        session,
        Frozen {
            method: PauseMethod::Sigstop,
            pids,
            cgroup: None,
        },
    )
}

/// [`freeze_confirmed`] for a capture's hold (#145 item 6): a session with no
/// sandbox process running is not touched at all — no cgroup created, nothing
/// signalled — and an empty, confirmed freeze says so, so the capture holds
/// nothing and records nothing for an idle session.
#[must_use]
pub fn freeze_for_capture(session: &str) -> (Frozen, bool) {
    let idle = || {
        (
            Frozen {
                method: PauseMethod::Sigstop,
                pids: Vec::new(),
                cgroup: None,
            },
            true,
        )
    };
    if sandbox_pids(Path::new("/proc"), session).is_empty() {
        return idle();
    }
    let (frozen, stable) = freeze_confirmed(session);
    if frozen.pids.is_empty() {
        thaw(&frozen);
        if let Some(dir) = &frozen.cgroup {
            let _ = fs::remove_dir(dir);
        }
        return idle();
    }
    (frozen, stable)
}

/// Make `frozen` a closed, confirmed freeze of `session` (PR #253 review
/// finding 4): wait until every process it holds is confirmed stopped (or
/// gone), then rescan the session; anything the rescan finds that the freeze
/// does not hold yet — a child forked while its parent's `SIGSTOP` was still in
/// flight, or one forked before its parent was moved into the cgroup — is
/// frozen as well, and the wait-then-rescan repeats until a rescan adds
/// nothing. Bounded by [`FREEZE_SETTLE`] overall; returns the freeze (every
/// process found, orphans and the newest first, the original children-first
/// order after them) and whether it was confirmed stable in time.
///
/// The rescan is only trusted once everything known is stopped: a stopped
/// process (or one held in vfork wait on a stopped child, #352) runs no code,
/// so it cannot fork, and a child created by a fork that was already in flight
/// still has that stopped parent as its parent, so the tree walk finds it. Membership is also taken from the sandbox's own pid
/// namespace ([`sandbox_pids`]), which finds a child whose parent exited on its
/// own and left it reparented outside the tree.
#[must_use]
pub fn stabilize(session: &str, frozen: Frozen) -> (Frozen, bool) {
    let proc = Path::new("/proc");
    let Frozen {
        method,
        mut pids,
        cgroup,
    } = frozen;
    let stable = stabilize_with(
        &mut pids,
        FREEZE_SETTLE,
        || sandbox_pids(proc, session),
        |fresh| {
            if let Some(dir) = &cgroup {
                let mut migrated = true;
                for pid in fresh {
                    if fs::write(dir.join("cgroup.procs"), pid.to_string()).is_err() {
                        migrated = false;
                        let _ = kill(Pid::from_raw(as_pid(*pid)), Signal::SIGSTOP);
                    }
                }
                migrated
            } else {
                freeze_signals(fresh);
                true
            }
        },
        |pid| match &cgroup {
            // The freezer is synchronous per `cgroup.events`: a member is
            // settled once the cgroup reports frozen again (or it is gone).
            Some(dir) => {
                !proc.join(pid.to_string()).exists()
                    || fs::read_to_string(dir.join("cgroup.events"))
                        .unwrap_or_default()
                        .lines()
                        .any(|l| l == "frozen 1")
            }
            None => stopped_or_gone(proc, pid),
        },
    );
    (
        Frozen {
            method,
            pids,
            cgroup,
        },
        stable,
    )
}

/// [`stabilize`]'s loop with every real dependency injected: `rescan` lists the
/// session's processes now, `freeze_more` freezes the ones just found, and
/// `settled` says whether one pid is confirmed stopped or gone. `pids` is
/// extended in place with everything found. Returns whether a rescan taken
/// with every known pid settled found nothing new before `bound` expired. The
/// seam a test uses to put a fork in the scan-to-stop window deterministically.
fn stabilize_with(
    pids: &mut Vec<u32>,
    bound: Duration,
    mut rescan: impl FnMut() -> Vec<u32>,
    mut freeze_more: impl FnMut(&[u32]) -> bool,
    settled: impl Fn(u32) -> bool,
) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        if pids.iter().all(|&pid| settled(pid)) {
            let fresh: Vec<u32> = rescan()
                .into_iter()
                .filter(|pid| !pids.contains(pid))
                .collect();
            if fresh.is_empty() {
                return true;
            }
            let froze_more = freeze_more(&fresh);
            // Newest first: whatever was found late is a child (or an orphan)
            // of something already held, so it still comes before its parent.
            // Merge even on a failed cgroup migration: terminate() must still
            // know about and kill every process the rescan discovered.
            let mut merged = fresh;
            merged.extend(pids.iter().copied());
            *pids = merged;
            if !froze_more || Instant::now() >= deadline {
                return false;
            }
            continue;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Wait until a freeze has actually taken hold: every process is stopped
/// (`State: T`/`t`), held in vfork wait on a stopped child (#352), or already
/// gone. The cgroup freezer is synchronous — [`freeze_cgroup`] already waited
/// on `cgroup.events` — so only the signal path polls, because `SIGSTOP` is
/// delivered asynchronously and a capture that began the instant [`freeze`]
/// returned could still race a not-yet-stopped process. Bounded by
/// [`FREEZE_SETTLE`]; returns whether every pid settled.
#[must_use]
pub fn wait_settled(frozen: &Frozen) -> bool {
    if frozen.method == PauseMethod::CgroupFreezer {
        return true;
    }
    let proc = Path::new("/proc");
    crate::daemon::wait_until(FREEZE_SETTLE, || {
        frozen.pids.iter().all(|&pid| stopped_or_gone(proc, pid))
    })
}

/// Whether a freeze settled within [`FREEZE_SETTLE`], and how many pids had not when
/// the bound expired: `None` once every pid is confirmed stopped or gone (always true
/// for [`PauseMethod::CgroupFreezer`], which is synchronous by construction, and also
/// true whenever the immediate recount below finds nothing pending — see below);
/// `Some(n)` (`n` always nonzero) otherwise, checked once, immediately, with no further
/// waiting — [`wait_settled`] already spent the bound.
///
/// This is what [`crate::daemon::Served::pause_with`] (ADR-0019 §3, #145 items 3-4, PR
/// #207 review finding 3) calls to decide whether the pause it is about to record can
/// be shown as confirmed, and, if not, how many processes a `SessionPauseUnsettled`
/// record should name.
///
/// `wait_settled` timing out is not itself proof anything is still pending: it can
/// return `false` and, by the time this function's own recount runs a moment later,
/// every pid has since actually stopped (a genuine race between the bound expiring and
/// the last `SIGSTOP` landing, not a bug in either function). A recount of zero is
/// therefore normalized to settled (`None`), never `Some(0)` — `Some(0)` would be
/// self-contradictory: an outcome the daemon reports as "unsettled" but that names no
/// process actually pending.
#[must_use]
pub fn settle_outcome(frozen: &Frozen) -> Option<u32> {
    let proc = Path::new("/proc");
    settle_outcome_with(frozen, wait_settled(frozen), |pid| {
        stopped_or_gone(proc, pid)
    })
}

/// [`settle_outcome`] for a freeze whose stabilization ([`stabilize`]) already
/// spent the bound: `None` when it was confirmed `stable`, otherwise how many of
/// its pids are still not stopped (normalized like [`settle_outcome`]).
#[must_use]
pub fn unsettled_count(frozen: &Frozen, stable: bool) -> Option<u32> {
    let proc = Path::new("/proc");
    settle_outcome_with(frozen, stable, |pid| stopped_or_gone(proc, pid))
}

/// [`settle_outcome`] with both of its real dependencies — whether the bound-limited
/// wait itself settled, and the per-pid proc-state check it would recount against —
/// taken as parameters instead of read from `/proc` and the real clock. The seam a test
/// uses to exercise the `Some(0)`-normalization edge and a genuine nonzero pending
/// count deterministically: `SIGSTOP` cannot be resisted by a real process for a test
/// to race against, and the recount itself must not depend on a real, unbounded wait.
fn settle_outcome_with(
    frozen: &Frozen,
    settled: bool,
    stopped: impl Fn(u32) -> bool,
) -> Option<u32> {
    if settled {
        return None;
    }
    let pending =
        u32::try_from(frozen.pids.iter().filter(|&&pid| !stopped(pid)).count()).unwrap_or(u32::MAX);
    if pending == 0 { None } else { Some(pending) }
}

/// Whether `pid` is stopped (`SIGSTOP` took hold) or no longer runs: gone from
/// `proc`, a zombie / dead entry waiting only to be reaped (it runs no code,
/// so it can neither fork nor stop), or held in vfork wait on a stopped child
/// ([`frozen_from`], #352). A vfork hold is read once more after its children,
/// so a child that `exec`ed and released it between the reads is not missed.
fn stopped_or_gone(proc: &Path, pid: u32) -> bool {
    let stat_path = proc.join(pid.to_string()).join("stat");
    let Ok(stat) = fs::read_to_string(&stat_path) else {
        return true;
    };
    let Some(target) = proc_facts(proc, pid, &stat) else {
        return false;
    };
    if !in_vfork_wait(&target) {
        return frozen_from(pid, &[target]);
    }
    let mut facts = vec![target];
    facts.extend(children_facts(proc, pid));
    frozen_from(pid, &facts)
        && fs::read_to_string(&stat_path)
            .ok()
            .and_then(|again| proc_facts(proc, pid, &again))
            .is_some_and(|again| in_vfork_wait(&again))
}

/// The state character of a `/proc/<pid>/stat` line: the field after the
/// parenthesised command name (which may itself hold spaces and parentheses,
/// so the last `)` is the anchor, as in [`parent_of`]).
fn proc_state(stat: &str) -> Option<char> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().next()?.chars().next()
}

/// What the settle check reads of one process from `/proc` (#352).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcFacts {
    pid: u32,
    ppid: u32,
    state: char,
    threads: Option<u32>,
    wchan: Option<String>,
}

/// The names `/proc/<pid>/wchan` gives a task waiting for its vfork child to
/// `exec` or exit: `wait_for_vfork_done` itself, or `kernel_clone`, its caller,
/// on kernels that inline it (6.x builds do). `kernel_clone` sleeps nowhere
/// else itself, so a task in `D` there is in that wait.
const VFORK_WAIT_WCHANS: [&str; 2] = ["wait_for_vfork_done", "kernel_clone"];

/// The facts of `pid` from its `stat` line, plus its `wchan` when in `D`.
fn proc_facts(proc: &Path, pid: u32, stat: &str) -> Option<ProcFacts> {
    let state = proc_state(stat)?;
    let parent = parent_of(stat)?;
    let wchan = (state == 'D')
        .then(|| fs::read_to_string(proc.join(pid.to_string()).join("wchan")).ok())
        .flatten()
        .map(|w| w.trim().to_owned());
    Some(ProcFacts {
        pid,
        ppid: parent,
        state,
        threads: thread_count(stat),
        wchan,
    })
}

/// The `num_threads` field of a `/proc/<pid>/stat` line.
fn thread_count(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(17)?.parse().ok()
}

/// Whether a `/proc` state runs no code: stopped, traced-stopped, zombie or dead.
fn stopped_or_ended_state(state: char) -> bool {
    matches!(state, 'T' | 't' | 'Z' | 'X' | 'x')
}

/// Whether `facts` show a single-threaded process in uninterruptible wait
/// for a vfork child to `exec` or exit. A wait channel that could not be read
/// (no permission, no `kallsyms`) never matches, nor does a process with more
/// than one thread, whose other threads `stat` does not describe.
fn in_vfork_wait(facts: &ProcFacts) -> bool {
    facts.state == 'D'
        && facts.threads == Some(1)
        && facts
            .wchan
            .as_deref()
            .is_some_and(|w| VFORK_WAIT_WCHANS.contains(&w))
}

/// Whether `pid` can make no progress, judged from `facts` (it and its
/// children): it is gone, stopped or ended, or (#352) it is held in vfork
/// wait and its children are all stopped or ended, at least one of them
/// stopped. A vforked child stopped before `exec` keeps its parent in `D`
/// until it continues, so that parent never reaches `T`; it runs no code
/// either, and the `SIGSTOP` already sent to it stops it the moment the wait
/// ends. Anything else in `D`, and any process with a child that still runs,
/// is not frozen.
fn frozen_from(pid: u32, facts: &[ProcFacts]) -> bool {
    let Some(target) = facts.iter().find(|f| f.pid == pid) else {
        return true;
    };
    if stopped_or_ended_state(target.state) {
        return true;
    }
    if !in_vfork_wait(target) {
        return false;
    }
    let mut children = facts.iter().filter(|f| f.ppid == pid && f.pid != pid);
    children.clone().any(|c| matches!(c.state, 'T' | 't'))
        && children.all(|c| stopped_or_ended_state(c.state))
}

/// The facts of every child of `parent` under `proc`.
fn children_facts(proc: &Path, parent: u32) -> Vec<ProcFacts> {
    proc_pids(proc)
        .into_iter()
        .filter(|&pid| pid != parent)
        .filter_map(|pid| {
            let stat = fs::read_to_string(proc.join(pid.to_string()).join("stat")).ok()?;
            proc_facts(proc, pid, &stat).filter(|f| f.ppid == parent)
        })
        .collect()
}

/// Let a frozen tree run again.
pub fn thaw(frozen: &Frozen) {
    match &frozen.cgroup {
        Some(dir) => {
            let _ = fs::write(dir.join("cgroup.freeze"), "0");
        }
        // Parents first: a parent that continues and finds a child still
        // stopped simply waits; the reverse could let a child's exit reach a
        // parent that cannot handle it yet.
        None => {
            for pid in frozen.pids.iter().rev() {
                let _ = kill(Pid::from_raw(as_pid(*pid)), Signal::SIGCONT);
            }
        }
    }
}

/// End a frozen tree without letting it run again (`stop` from paused): a
/// stopped process takes `SIGKILL` as it is. The cgroup, if any, is removed.
pub fn kill_frozen(frozen: &Frozen) {
    for pid in &frozen.pids {
        let _ = kill(Pid::from_raw(as_pid(*pid)), Signal::SIGKILL);
    }
    if let Some(dir) = &frozen.cgroup {
        let _ = fs::write(dir.join("cgroup.kill"), "1");
        let _ = fs::write(dir.join("cgroup.freeze"), "0");
        // The kernel keeps the directory until every process is reaped.
        let deadline = Instant::now() + FREEZE_SETTLE;
        while fs::remove_dir(dir).is_err() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// How long `ward stop` watches a session's killed sandbox processes before it
/// stops waiting for them to be confirmed gone (#145 item 5). `SIGKILL` cannot be
/// caught, but a process in uninterruptible sleep only dies once it wakes, so the
/// wait is bounded; what it could not confirm is reported, never assumed.
pub const STOP_SETTLE: Duration = Duration::from_secs(2);

/// What [`terminate`] achieved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Termination {
    /// How the processes were frozen before the kill: what a hold over what is
    /// left records ([`PauseMethod::Sigstop`] when nothing ran, the method a
    /// freeze of nothing would have used).
    pub method: PauseMethod,
    /// Processes found (in the freeze, or by a rescan while waiting) and
    /// confirmed gone — exited, or a zombie waiting only to be reaped.
    pub ended: u32,
    /// What was killed but not confirmed gone within [`STOP_SETTLE`]: `None`
    /// when everything ended (or nothing ran). Its `pids` are only the pending
    /// ones, so a caller can hold them as a pause and retry.
    pub remaining: Option<Frozen>,
    /// Whether the freeze was confirmed stable before anything was killed (see
    /// [`terminate`]'s fork barrier). `true` when nothing ran.
    pub barrier_confirmed: bool,
}

impl Termination {
    /// Nothing ran, nothing was touched.
    #[must_use]
    pub const fn nothing() -> Self {
        Self {
            method: PauseMethod::Sigstop,
            ended: 0,
            remaining: None,
            barrier_confirmed: true,
        }
    }

    /// Everything the stop found (`ended` processes) is confirmed gone, behind
    /// a confirmed fork barrier.
    #[must_use]
    pub const fn confirmed(ended: u32) -> Self {
        Self {
            method: PauseMethod::Sigstop,
            ended,
            remaining: None,
            barrier_confirmed: true,
        }
    }

    /// How many processes were not confirmed gone.
    #[must_use]
    pub fn pending(&self) -> u32 {
        self.remaining
            .as_ref()
            .map_or(0, |f| u32::try_from(f.pids.len()).unwrap_or(u32::MAX))
    }

    /// Whether the stop found anything to terminate at all.
    #[must_use]
    pub fn touched_anything(&self) -> bool {
        self.ended > 0 || self.remaining.is_some()
    }
}

/// End every process of `session`'s sandboxes and confirm it is gone (`ward
/// stop`, #145 item 5): the explicit counterpart of log-only closure.
///
/// `held` is the freeze of a pause already in force, if any; otherwise the tree
/// is frozen first ([`freeze`]), children before parents, so nothing in it can
/// react to — or fork around — the kill that follows. Every frozen process then
/// gets `SIGKILL` (a stopped or cgroup-frozen process takes a fatal signal as it
/// is), and for the freezer path `cgroup.kill` ends whatever the cgroup holds,
/// including anything forked after the scan. The session is then rescanned and
/// watched for up to [`STOP_SETTLE`]: any sandbox process that appears in the
/// meantime is killed too, and the call returns once every process seen is
/// confirmed gone, or the bound expires with some still present.
///
/// A session with no sandbox running (and no held freeze) is not touched at all:
/// no cgroup is created, nothing is signalled, and [`Termination::nothing`] is
/// returned.
///
/// **The fork barrier (PR #253 review finding 4).** Nothing is killed until the
/// freeze is confirmed stable ([`stabilize`]): every process held is confirmed
/// stopped and a rescan taken after that finds nothing new. Killing the scanned
/// pids straight after an asynchronous `SIGSTOP` would let a child forked in
/// the scan-to-stop window outlive its parent, be reparented away from the
/// known `bwrap` root, and never be found by a later root-based rescan. A held
/// freeze (from a pause, possibly an unsettled one) is stabilized the same way
/// before it is killed. If the freeze cannot be confirmed stable within
/// [`FREEZE_SETTLE`] (a process in an uninterruptible or killable-only wait
/// that never takes `SIGSTOP`), the kill still proceeds — it is the safest
/// action left — and the rescan-by-namespace in [`sandbox_pids`] is what still
/// finds a child reparented inside the sandbox's pid namespace; the outcome
/// says the barrier was not confirmed ([`Termination::barrier_confirmed`]).
#[must_use]
pub fn terminate(session: &str, held: Option<Frozen>) -> Termination {
    let proc = Path::new("/proc");
    let (frozen, stable) = match held {
        Some(frozen) => stabilize(session, frozen),
        None if sandbox_pids(proc, session).is_empty() => return Termination::nothing(),
        None => freeze_confirmed(session),
    };
    if let Some(dir) = &frozen.cgroup {
        let _ = fs::write(dir.join("cgroup.kill"), "1");
    }
    let (ended, pending) = terminate_with(
        &frozen.pids,
        STOP_SETTLE,
        || sandbox_pids(proc, session),
        |pid| ended_or_gone(proc, pid),
        |pid| {
            let _ = kill(Pid::from_raw(as_pid(pid)), Signal::SIGKILL);
        },
    );
    let cgroup = frozen.cgroup.and_then(|dir| {
        // Nothing left to hold frozen: let the kernel finish reaping and remove
        // the directory (it stays until every member is gone).
        let _ = fs::write(dir.join("cgroup.freeze"), "0");
        if pending.is_empty() {
            let _ = crate::daemon::wait_until(FREEZE_SETTLE, || fs::remove_dir(&dir).is_ok());
            None
        } else {
            Some(dir)
        }
    });
    Termination {
        method: frozen.method,
        ended,
        // An unconfirmed barrier is itself an incomplete stop even when every
        // currently known pid subsequently died. Preserve an empty hold in that
        // case so the daemon refuses to seal and a retry must re-scan/stabilize
        // before it can claim completion.
        remaining: (!pending.is_empty() || !stable).then_some(Frozen {
            method: frozen.method,
            pids: pending,
            cgroup,
        }),
        barrier_confirmed: stable,
    }
}

/// The pause-marker text a refused stop leaves behind: what the proxy's
/// `paused by ward` is holding for.
#[must_use]
pub fn stop_hold_reason(pending: u32) -> String {
    format!(
        "ward stop: {pending} process(es) not confirmed ended within {}s",
        STOP_SETTLE.as_secs()
    )
}

/// The refusal a stop answers with when it could not confirm termination:
/// what ended, what is still present, what state the session was left in
/// (`held`), and — never silently dropped — any failure to write the marker
/// or the record of it.
#[must_use]
pub fn stop_refusal(
    session: &str,
    ended: u32,
    pending: u32,
    held: &str,
    marker: Option<&Error>,
    logged: Option<&Error>,
) -> String {
    use std::fmt::Write as _;
    let mut message = format!(
        "stop could not confirm every sandboxed process of session {session} ended: {ended} \
         ended, {pending} still present after {}s. The log is not sealed; {held}",
        STOP_SETTLE.as_secs()
    );
    if let Some(e) = marker {
        let _ = write!(message, "; the pause marker could not be written ({e})");
    }
    if let Some(e) = logged {
        let _ = write!(message, "; the record of this could not be written ({e})");
    }
    message
}

/// [`terminate`]'s kill-and-confirm loop with every real dependency injected:
/// `rescan` finds the session's sandbox processes now, `gone` says whether a
/// pid has ended, `kill` sends it `SIGKILL`. Kills every pid in `frozen` and
/// every pid a rescan finds, then waits (polling every 20 ms, bounded by
/// `bound`) until everything it has seen is gone. Returns how many ended and
/// which were still present when the bound expired. The seam a test uses to
/// exercise a process that never dies, one that appears mid-stop, and a zombie,
/// deterministically.
fn terminate_with(
    frozen: &[u32],
    bound: Duration,
    mut rescan: impl FnMut() -> Vec<u32>,
    gone: impl Fn(u32) -> bool,
    mut kill_one: impl FnMut(u32),
) -> (u32, Vec<u32>) {
    let mut seen: Vec<u32> = Vec::with_capacity(frozen.len());
    for &pid in frozen {
        if !seen.contains(&pid) {
            seen.push(pid);
        }
        kill_one(pid);
    }
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let deadline = Instant::now() + bound;
    loop {
        for pid in rescan() {
            if !seen.contains(&pid) {
                seen.push(pid);
            }
            // A live sandbox process found again is killed again: harmless for
            // one already dying, and it catches one forked after the freeze.
            kill_one(pid);
        }
        let pending: Vec<u32> = seen.iter().copied().filter(|&pid| !gone(pid)).collect();
        if pending.is_empty() || Instant::now() >= deadline {
            return (count(seen.len() - pending.len()), pending);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether `pid` has ended: no longer in `proc`, or a zombie (`Z`) / dead (`X`)
/// entry waiting only to be reaped by its parent (for a sandbox root, the `ward`
/// process that launched it) — it runs no code and holds no file open.
fn ended_or_gone(proc: &Path, pid: u32) -> bool {
    match fs::read_to_string(proc.join(pid.to_string()).join("stat")) {
        Ok(stat) => matches!(proc_state(&stat), Some('Z' | 'X' | 'x')),
        Err(_) => true,
    }
}

/// A freeze held only for the length of a snapshot capture (ST-018), released
/// when dropped. This is the daemon's own hold, distinct from `ward pause`: it
/// writes no marker, appends no record, and touches neither the proxy nor
/// credential injection — it exists solely so the agent's process tree cannot
/// write to the worktree while a capture walks and hashes it, which is what
/// makes the capture atomic with respect to a running agent (the time-of-check/
/// time-of-use race of `docs/security-model.md` G5/G9).
///
/// Acquiring waits for the freeze to actually take hold ([`wait_settled`]) so
/// the capture that follows never races a not-yet-stopped process. A session
/// already paused by the user is already frozen; the guard then holds nothing
/// and thaws nothing, so a capture can never lift a user's pause — `ward resume`
/// stays the only thaw. When no sandbox of the session is running the guard also
/// holds nothing, so an idle `ward snapshot` costs nothing.
///
/// That invariant covers a pause already in place before [`acquire`](Self::acquire)
/// runs; a pause that instead lands *while* this guard is already held (#234) is
/// covered separately: [`acquire`](Self::acquire) and this guard's own [`Drop`] both
/// take [`lock_pause_freeze`], the same lock `pause`/`resume` take, and `Drop`
/// re-checks the marker under it immediately before thawing — so a pause that
/// arrives mid-capture is never silently undone by this guard's own release.
#[derive(Debug)]
#[must_use = "the freeze lasts only while the guard is held"]
pub struct CaptureFreeze {
    state: PathBuf,
    session: String,
    frozen: Option<Frozen>,
}

impl CaptureFreeze {
    /// Freeze `session`'s sandbox for a capture, unless it is already paused by
    /// the user (whose freeze must outlive the capture).
    ///
    /// The marker check and the freeze both happen under [`lock_pause_freeze`]
    /// (#234), so a `ward pause` that would otherwise land in the gap between
    /// them can no longer be missed. If the lock itself cannot be taken (best
    /// effort — e.g. the session directory has since been removed), this falls
    /// back to the plain, unlocked check rather than refusing to capture.
    pub fn acquire(state: &Path, session: &str) -> Self {
        Self::acquire_confirmed(state, session).0
    }

    /// [`acquire`](Self::acquire), also saying whether the session is confirmed
    /// quiescent (#145 item 6): `None` once every sandbox process is confirmed
    /// stopped or gone — the freeze this guard took settled, or the one a
    /// marker already in place stands for reads so from `/proc` — else how
    /// many are not, as [`settle_outcome`] counts them.
    pub fn acquire_confirmed(state: &Path, session: &str) -> (Self, Option<u32>) {
        let dir = session_dir(state, session);
        let _lock = lock_pause_freeze(&dir);
        let proc = Path::new("/proc");
        if marker_path(state, session).exists() {
            let pending = sandbox_pids(proc, session)
                .into_iter()
                .filter(|&pid| !stopped_or_gone(proc, pid))
                .count();
            return (
                Self {
                    state: state.to_path_buf(),
                    session: session.to_owned(),
                    frozen: None,
                },
                u32::try_from(pending).ok().filter(|&n| n > 0),
            );
        }
        let (frozen, stable) = freeze_confirmed(session);
        let unsettled = unsettled_count(&frozen, stable);
        (
            Self {
                state: state.to_path_buf(),
                session: session.to_owned(),
                frozen: Some(frozen),
            },
            unsettled,
        )
    }

    /// How the sandbox was frozen, or `None` when the guard holds nothing (the
    /// session was already paused, or nothing of it is running).
    #[must_use]
    pub fn method(&self) -> Option<PauseMethod> {
        self.frozen.as_ref().map(|f| f.method)
    }
}

impl Drop for CaptureFreeze {
    fn drop(&mut self) {
        let Some(frozen) = self.frozen.take() else {
            return;
        };
        // #234: re-take the lock and re-check the marker immediately before
        // thawing. A `ward pause` that landed while this guard's capture was in
        // progress writes the marker under this same lock; if it got there
        // first, only `ward resume` may thaw this tree now.
        //
        // A lock that cannot be taken at all still leaves the marker as the
        // record of a user pause, so it is checked either way. Leaving the tree
        // frozen with no marker would be unrecoverable: the daemon does not
        // consider the session paused, so `ward resume` answers "not paused" and
        // nothing ever thaws it. The lock only narrows the window against a
        // concurrent pause; the marker decides.
        let dir = session_dir(&self.state, &self.session);
        let _lock = lock_pause_freeze(&dir).ok();
        if marker_path(&self.state, &self.session).exists() {
            return;
        }
        thaw(&frozen);
    }
}

/// A capture's hold on a session no daemon serves (#145 item 6): the hold
/// `Request::HoldForCapture` takes in the daemon, taken in this process. The
/// capture proceeds only from confirmed quiescence — the freeze settled and
/// every component acknowledged ([`acks`]) — and the hold is the capture's
/// own: recorded among the session's [`Holders`], released by
/// [`release`](Self::release) alone. A hold already standing (a marker from a
/// user's pause) is reused, not taken over: the capture is added to its owners
/// and its release leaves that hold in place. A session with nothing running
/// holds nothing.
#[derive(Debug)]
#[must_use = "the hold lasts only while the guard is held; release it to record the release"]
pub struct LocalCaptureHold {
    state: PathBuf,
    session: String,
    freeze: Option<CaptureFreeze>,
    op: String,
    first: bool,
    since: Instant,
    method: Option<PauseMethod>,
    released: bool,
}

impl LocalCaptureHold {
    /// Hold `session` for a capture under `reason` ([`capture_reason`]),
    /// recording `SessionPaused` through `append` when nothing held it before.
    /// `Ok(None)` when nothing of the session runs and nothing holds it.
    pub fn take(
        state: &Path,
        session: &str,
        reason: &str,
        append: impl FnMut(WardEvent) -> Result<()>,
    ) -> Result<Option<Self>> {
        if !marker_path(state, session).exists()
            && sandbox_pids(Path::new("/proc"), session).is_empty()
        {
            return Ok(None);
        }
        let mut live = acks::Live::new();
        Self::take_with(
            state,
            session,
            reason,
            CaptureFreeze::acquire_confirmed,
            &mut live,
            append,
        )
    }

    /// [`take`](Self::take) with the freeze and the components injectable, for
    /// the same reason `Served::pause_with`'s settle check is.
    pub(crate) fn take_with(
        state: &Path,
        session: &str,
        reason: &str,
        acquire: impl FnOnce(&Path, &str) -> (CaptureFreeze, Option<u32>),
        acknowledger: &mut dyn Acknowledger,
        mut append: impl FnMut(WardEvent) -> Result<()>,
    ) -> Result<Option<Self>> {
        let op = crate::ids::new_operation_id()?;
        let capturer = Capturer {
            op: op.clone(),
            pid: std::process::id(),
            started: own_start_time(),
            reason: reason.to_owned(),
        };
        write_intent(
            state,
            session,
            &Intent::begin(Verb::Capture {
                reason: reason.to_owned(),
                capturer: capturer.clone(),
            })?,
        )?;
        let (mut freeze, unsettled) = acquire(state, session);
        let first = freeze.frozen.is_some();
        if freeze.frozen.as_ref().is_some_and(|f| f.pids.is_empty()) {
            let _ = clear_intent(state, session);
            return Ok(None);
        }
        let mut hold = Self {
            state: state.to_path_buf(),
            session: session.to_owned(),
            method: freeze.method(),
            freeze: None,
            op,
            first,
            since: Instant::now(),
            released: false,
        };
        let marked = (|| {
            if first {
                write_marker(state, session, reason)?;
            }
            let mut holders = read_held_by(state, session)?.unwrap_or_else(|| {
                if first {
                    Holders::default()
                } else {
                    Holders::for_user()
                }
            });
            holders.add_capture(capturer);
            write_held_by(state, session, &holders)
        })();
        if let Err(e) = marked {
            hold.take_back(&mut freeze);
            return Err(e);
        }
        let approvals = crate::approvals::Approvals::new();
        approvals.set_paused(true);
        let site = acks::Site {
            state,
            session,
            approvals: &approvals,
        };
        let acked = acks::collect(acknowledger, Phase::Held, &site);
        let unconfirmed = acks::first_unconfirmed(&acked);
        if unsettled.is_some() || unconfirmed.is_some() {
            hold.take_back(&mut freeze);
            return Err(capture_refusal(session, unsettled, unconfirmed));
        }
        if first
            && let Some(method) = hold.method
            && let Err(e) = append(WardEvent::SessionPaused {
                method,
                reason: ShortText::new(reason),
            })
        {
            hold.take_back(&mut freeze);
            return Err(e);
        }
        let _ = clear_intent(state, session);
        hold.freeze = Some(freeze);
        Ok(Some(hold))
    }

    /// How the sandbox was frozen, or `None` when a hold already in place
    /// holds it.
    #[must_use]
    pub fn method(&self) -> Option<PauseMethod> {
        self.method
    }

    /// Release the capture's hold: the session's owners lose this capture, and
    /// when none remains the marker is cleared, the tree thawed and
    /// `SessionResumed` recorded through `append`.
    pub fn release(mut self, mut append: impl FnMut(WardEvent) -> Result<()>) -> Result<()> {
        self.released = true;
        let Some(mut freeze) = self.freeze.take() else {
            return Ok(());
        };
        let last = self.let_go(&mut freeze)?;
        if last && self.first {
            append(WardEvent::SessionResumed {
                paused_for: self.since.elapsed(),
            })?;
        }
        Ok(())
    }

    /// Remove this capture from the owners; when it was the last, clear the
    /// marker and thaw what `freeze` holds. Returns whether it was the last.
    fn let_go(&self, freeze: &mut CaptureFreeze) -> Result<bool> {
        let dir = session_dir(&self.state, &self.session);
        let _lock = lock_pause_freeze(&dir).ok();
        let mut holders = read_held_by(&self.state, &self.session)?.unwrap_or_else(|| {
            if self.first {
                Holders::default()
            } else {
                Holders::for_user()
            }
        });
        holders.remove_capture(&self.op);
        if !holders.is_empty() {
            write_held_by(&self.state, &self.session, &holders)?;
            return Ok(false);
        }
        clear_held_by(&self.state, &self.session)?;
        clear_marker(&self.state, &self.session)?;
        if let Some(frozen) = freeze.frozen.take() {
            thaw(&frozen);
        }
        Ok(true)
    }

    /// Undo a hold that did not complete: only what this capture took.
    fn take_back(&mut self, freeze: &mut CaptureFreeze) {
        self.released = true;
        let _ = self.let_go(freeze);
        let _ = clear_intent(&self.state, &self.session);
    }
}

impl Drop for LocalCaptureHold {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Some(mut freeze) = self.freeze.take() {
            let _ = self.let_go(&mut freeze);
        }
    }
}

/// `<session_dir>/.pause-freeze.lock`: an empty file [`lock_pause_freeze`] takes an
/// exclusive, OS-enforced `flock` on for the marker-check-then-freeze/thaw critical
/// section [`CaptureFreeze::acquire`], its own [`Drop`], and `ward pause`/`ward
/// resume` (`Served::pause_with_appending`/`Served::resume` in `daemon.rs`) all
/// perform (#234) — and, since PR #253, the session's one lifecycle lock: `ward
/// stop` and its stop hold take it from the stop marker through the kill, and
/// every sandbox launch takes it across its spawn ([`admit_launch`]). Same idiom as `attempt.rs`'s `lock_session_reconciliation`/
/// `lock_session_verification` and `selection.rs`'s `lock_selection`: only this
/// file's existence matters, and an OS `flock` on an open file description needs no
/// staleness recovery, since the kernel releases it the instant the holder's last
/// reference closes, including on a crash.
fn pause_freeze_lock_path(session_dir: &Path) -> PathBuf {
    session_dir.join(".pause-freeze.lock")
}

/// Acquire the exclusive, session-scoped lock [`CaptureFreeze::acquire`]/[`Drop`]
/// and `ward pause`/`ward resume` share (#234), blocking until whichever of them —
/// another thread, or an entirely separate `ward`/`wardd` process — currently holds
/// it releases theirs. Without this, a `CaptureFreeze` in progress and a `ward
/// pause` landing at the same moment have no shared serialization at all: a pause
/// could write its marker between `CaptureFreeze::acquire`'s check and its own
/// freeze, or land entirely within the span `CaptureFreeze` holds its guard, and
/// either way the guard's own `Drop` would thaw over it with nothing left to show a
/// pause had ever intervened.
pub(crate) fn lock_pause_freeze(session_dir: &Path) -> Result<Flock<std::fs::File>> {
    let path = pause_freeze_lock_path(session_dir);
    // Only this file's *existence* matters — it is never read or written — so an
    // already-present lock file (from an earlier acquire/pause/resume) is opened
    // as-is rather than truncated, exactly as the other lock files in this crate.
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| Error::io(&path, e))?;
    Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_, errno)| Error::io(&path, std::io::Error::from(errno)))
}

/// Every process of `session`'s sandboxes under `proc`, children before their
/// parents: the trees of every `bwrap` whose command line binds the session's
/// run directory, and — first, since they have no known parent — every other
/// process in a pid namespace one of those trees' members lives in, when that
/// namespace is not the scanner's own.
///
/// The namespace half is the host-owned membership boundary a tree walk alone
/// is not (PR #253 review finding 4): `bwrap --unshare-pid` puts every sandbox
/// process in the sandbox's own pid namespace, and a process stays in it
/// whatever happens to its parent, so one reparented away from the tree (its
/// parent exited, or was killed first) is still found. A tree that shares the
/// scanner's own namespace (a test's stand-in for a sandbox) has only the tree.
#[must_use]
pub fn sandbox_pids(proc: &Path, session: &str) -> Vec<u32> {
    let needle = run_dir_path(session).to_string_lossy().into_owned();
    let mut pids = Vec::new();
    for root in sandbox_roots(proc, &needle) {
        for pid in tree(proc, root) {
            if !pids.contains(&pid) {
                pids.push(pid);
            }
        }
    }
    let own = pid_namespace(proc, "self");
    let mut spaces: Vec<String> = Vec::new();
    for pid in &pids {
        if let Some(ns) = pid_namespace(proc, &pid.to_string())
            && Some(&ns) != own.as_ref()
            && !spaces.contains(&ns)
        {
            spaces.push(ns);
        }
    }
    if spaces.is_empty() {
        return pids;
    }
    let mut members: Vec<u32> = proc_pids(proc)
        .into_iter()
        .filter(|pid| !pids.contains(pid))
        .filter(|pid| pid_namespace(proc, &pid.to_string()).is_some_and(|ns| spaces.contains(&ns)))
        .collect();
    members.sort_unstable();
    members.extend(pids);
    members
}

/// The pid namespace `proc/<entry>/ns/pid` names (`pid:[inode]`), if readable.
fn pid_namespace(proc: &Path, entry: &str) -> Option<String> {
    fs::read_link(proc.join(entry).join("ns").join("pid"))
        .ok()
        .map(|link| link.to_string_lossy().into_owned())
}

/// Every numeric entry of `proc`.
fn proc_pids(proc: &Path) -> Vec<u32> {
    fs::read_dir(proc)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
                .collect()
        })
        .unwrap_or_default()
}

/// The `bwrap` processes whose arguments mention `needle`.
fn sandbox_roots(proc: &Path, needle: &str) -> Vec<u32> {
    let mut roots = Vec::new();
    let Ok(entries) = fs::read_dir(proc) else {
        return roots;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let mut args = cmdline.split(|b| *b == 0);
        let is_bwrap = args
            .next()
            .and_then(|a| Path::new(std::str::from_utf8(a).ok()?).file_name())
            .is_some_and(|name| name == "bwrap");
        if is_bwrap && args.any(|a| String::from_utf8_lossy(a).starts_with(needle)) {
            roots.push(pid);
        }
    }
    roots.sort_unstable();
    roots
}

/// `root` and every descendant under `proc`, deepest first (post-order), the
/// root last.
#[must_use]
pub fn tree(proc: &Path, root: u32) -> Vec<u32> {
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    if let Ok(entries) = fs::read_dir(proc) {
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if let Some(ppid) = fs::read_to_string(entry.path().join("stat"))
                .ok()
                .and_then(|stat| parent_of(&stat))
            {
                children.entry(ppid).or_default().push(pid);
            }
        }
    }
    // read_dir order is not stable, so siblings could be frozen and reported in
    // any order; sort each parent's children by pid so the walk is deterministic
    // (still strictly children before parent).
    for kids in children.values_mut() {
        kids.sort_unstable();
    }
    let mut out = Vec::new();
    post_order(root, &children, &mut out, 0);
    out
}

fn post_order(pid: u32, children: &BTreeMap<u32, Vec<u32>>, out: &mut Vec<u32>, depth: usize) {
    // A cycle cannot occur in a real process tree; the bound guards a forged
    // fixture from recursing without end.
    if depth > 256 || out.contains(&pid) {
        return;
    }
    for child in children.get(&pid).into_iter().flatten() {
        post_order(*child, children, out, depth + 1);
    }
    out.push(pid);
}

/// The parent pid in a `/proc/<pid>/stat` line: the field after the state,
/// which follows the parenthesised command name (that name may itself hold
/// spaces and parentheses, so the last `)` is the anchor).
fn parent_of(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

fn freeze_signals(pids: &[u32]) {
    for pid in pids {
        // A pid gone since the scan is not an error: its tree ended by itself.
        let _ = kill(Pid::from_raw(as_pid(*pid)), Signal::SIGSTOP);
    }
}

/// Move `pids` into the cgroup at `dir` and freeze it, waiting for the kernel
/// to report the freeze settled. On any failure, every pid already migrated
/// in is moved back to `dir`'s parent first, so the caller always finds `dir`
/// with no live members left to remove — a cgroup can only be `rmdir`'d once
/// it has none (cgroup-v2 admin guide).
fn freeze_cgroup(dir: &Path, pids: &[u32]) -> std::io::Result<()> {
    let mut migrated = Vec::with_capacity(pids.len());
    for pid in pids {
        if let Err(e) = fs::write(dir.join("cgroup.procs"), pid.to_string()) {
            migrate_back(dir, &migrated);
            return Err(e);
        }
        migrated.push(*pid);
    }
    if let Err(e) = fs::write(dir.join("cgroup.freeze"), "1") {
        migrate_back(dir, &migrated);
        return Err(e);
    }
    let deadline = Instant::now() + FREEZE_SETTLE;
    loop {
        let events = fs::read_to_string(dir.join("cgroup.events")).unwrap_or_default();
        if events.lines().any(|l| l == "frozen 1") || pids.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            migrate_back(dir, &migrated);
            return Err(std::io::Error::other("cgroup did not freeze in time"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Move `pids` out of `dir` back to its parent cgroup. Best-effort, like the
/// rest of this module's cleanup: a pid already gone needs no migration (its
/// membership ended with it), and there is no parent to fall back to for a
/// root cgroup (`dir` is always `ward-<tail>` under one, so this is only
/// defensive).
fn migrate_back(dir: &Path, pids: &[u32]) {
    let Some(parent) = dir.parent() else {
        return;
    };
    for pid in pids {
        let _ = fs::write(parent.join("cgroup.procs"), pid.to_string());
    }
}

/// The daemon's own cgroup v2 directory, from `/proc/self/cgroup`'s `0::` line.
fn own_cgroup() -> Option<PathBuf> {
    let text = fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(Path::new(CGROUP_ROOT).join(rel.trim().trim_start_matches('/')))
}

/// The session's cgroup under `base` when one can be created there and the
/// kernel offers the freezer in it; `None` (and nothing left behind) otherwise.
/// A directory that appears but carries no `cgroup.freeze` is not a cgroup at
/// all (a plain tmpfs where cgroup v2 would be) and is removed again.
#[must_use]
pub fn select_cgroup(base: Option<&Path>, session: &str) -> Option<PathBuf> {
    let dir = base?.join(format!("ward-{}", session_tail(session)));
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    if dir.join("cgroup.freeze").is_file() && dir.join("cgroup.procs").is_file() {
        Some(dir)
    } else {
        let _ = fs::remove_dir(&dir);
        None
    }
}

/// The last ten characters of a session id, as `run_dir_path` names things.
fn session_tail(session: &str) -> String {
    let chars: Vec<char> = session.chars().collect();
    chars[chars.len().saturating_sub(10)..].iter().collect()
}

fn as_pid(pid: u32) -> i32 {
    i32::try_from(pid).unwrap_or(i32::MAX)
}

/// The reason text when none is given.
pub const DEFAULT_REASON: &str = "ward pause";

/// A reason that fits the record: the caller's words, or [`DEFAULT_REASON`].
#[must_use]
pub fn reason_text(reason: &str) -> String {
    let reason = reason.trim();
    if reason.is_empty() {
        DEFAULT_REASON.to_owned()
    } else {
        reason.to_owned()
    }
}

/// Write the marker for `session` (idempotent).
pub fn write_marker(state: &Path, session: &str, reason: &str) -> Result<()> {
    let path = marker_path(state, session);
    fs::write(&path, format!("{reason}\n")).map_err(|e| Error::io(&path, e))
}

/// Remove the marker for `session`; a marker already gone is fine.
pub fn clear_marker(state: &Path, session: &str) -> Result<()> {
    let path = marker_path(state, session);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(&path, e)),
    }
}

/// A real process tree the scan recognises as a session's sandbox, for tests of
/// `ward stop` against real processes where no `bwrap` is installed: a copy of
/// `sh` named `bwrap` whose arguments bind the session's run directory (exactly
/// what [`sandbox_roots`] matches), looping a `sleep` child under it. Killed and
/// reaped on drop whatever the test did.
#[cfg(test)]
pub(crate) struct FakeSandbox {
    /// The session id the tree belongs to (unique per test process).
    pub session: String,
    child: std::process::Child,
    _bin: tempfile::TempDir,
}

#[cfg(test)]
impl FakeSandbox {
    /// Start the tree for a session named from `stem` and this test process, and
    /// wait until the scan finds both the shell and its child.
    pub(crate) fn spawn(stem: &str) -> Self {
        Self::spawn_running(stem, "while :; do sleep 0.05; done")
    }

    /// [`Self::spawn`] with the shell running `script` instead of its loop.
    pub(crate) fn spawn_running(stem: &str, script: &str) -> Self {
        // `run_dir_path` keys on the last ten characters: keep them unique per
        // fixture and per process so parallel tests never see each other's tree.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 10_000;
        Self::spawn_script(
            &format!("{stem}_{n:04}{:06}", std::process::id() % 1_000_000),
            script,
        )
    }

    /// [`Self::spawn`] for an existing session id (a real `Session`'s own).
    pub(crate) fn spawn_for(session: &str) -> Self {
        Self::spawn_script(session, "while :; do sleep 0.05; done")
    }

    #[allow(clippy::unwrap_used, clippy::panic)]
    fn spawn_script(session: &str, script: &str) -> Self {
        let session = session.to_owned();
        let bin = tempfile::tempdir().unwrap();
        let bwrap = bin.path().join("bwrap");
        // A symlink, not a copy: the sandbox is found by its command line's
        // `bwrap` name, and a copied shell still open for writing in one test
        // fails another test's exec with ETXTBSY when they fork concurrently.
        std::os::unix::fs::symlink("/bin/sh", &bwrap).unwrap();
        let child = std::process::Command::new(&bwrap)
            .args(["-c", script])
            .arg(run_dir_path(&session).join("proxy.sock"))
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let sandbox = Self {
            session,
            child,
            _bin: bin,
        };
        if !crate::daemon::wait_until(Duration::from_secs(5), || {
            sandbox_pids(Path::new("/proc"), &sandbox.session).len() >= 2
        }) {
            panic!("the fake sandbox never showed up in /proc");
        }
        sandbox
    }

    /// The tree's root pid.
    pub(crate) fn root(&self) -> u32 {
        self.child.id()
    }

    /// Whether the tree's root is currently stopped (`State: T`).
    pub(crate) fn stopped(&self) -> bool {
        fs::read_to_string(format!("/proc/{}/stat", self.child.id()))
            .ok()
            .and_then(|s| proc_state(&s))
            == Some('T')
    }

    /// Whether the tree is held by `frozen`: its cgroup reports `frozen 1`
    /// (freezer path), or its root is stopped (signal path).
    pub(crate) fn frozen_by(&self, frozen: &Frozen) -> bool {
        match &frozen.cgroup {
            Some(dir) => fs::read_to_string(dir.join("cgroup.events"))
                .unwrap_or_default()
                .lines()
                .any(|l| l == "frozen 1"),
            None => self.stopped(),
        }
    }

    /// Whether the tree's root died of `SIGKILL` (reaping it).
    #[allow(clippy::unwrap_used)]
    pub(crate) fn was_killed(&mut self) -> bool {
        let status = self.child.wait().unwrap();
        std::os::unix::process::ExitStatusExt::signal(&status) == Some(9)
    }

    /// Whether the tree's root is still running (not exited, not a zombie).
    pub(crate) fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
            && !ended_or_gone(Path::new("/proc"), self.child.id())
    }
}

#[cfg(test)]
impl Drop for FakeSandbox {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A `/proc` with the given `(pid, ppid, argv)` processes.
    fn fake_proc(dir: &Path, procs: &[(u32, u32, &[&str])]) {
        for (pid, ppid, argv) in procs {
            let p = dir.join(pid.to_string());
            fs::create_dir_all(&p).unwrap();
            fs::write(
                p.join("stat"),
                format!("{pid} ({}) S {ppid} 1 1 0 -1", argv[0]),
            )
            .unwrap();
            let mut cmdline = argv.join("\0").into_bytes();
            cmdline.push(0);
            fs::write(p.join("cmdline"), cmdline).unwrap();
        }
        // Something that is not a process directory.
        fs::write(dir.join("uptime"), "1 1\n").unwrap();
    }

    #[test]
    fn the_sandbox_tree_is_found_by_its_run_dir_children_first() {
        let proc = tempfile::tempdir().unwrap();
        let session = "sess_01J8ZK3Q9X7VY2";
        let run_dir = run_dir_path(session).to_string_lossy().into_owned();
        let sock = format!("{run_dir}/proxy.sock");
        fake_proc(
            proc.path(),
            &[
                (1, 0, &["init"]),
                (10, 1, &["ward", "run"]),
                (
                    11,
                    10,
                    &["/usr/bin/bwrap", "--bind", &sock, "/run/ward/proxy.sock"],
                ),
                (12, 11, &["bwrap"]),
                (13, 12, &["sh (2) x", "-c", "sleep"]),
                (14, 13, &["sleep", "30"]),
                (15, 13, &["cat"]),
                (
                    20,
                    1,
                    &["bwrap", "--bind", "/tmp/ward-otherxxxxx/proxy.sock", "/x"],
                ),
                (21, 20, &["sleep"]),
            ],
        );
        assert_eq!(sandbox_roots(proc.path(), &run_dir), [11]);
        assert_eq!(
            sandbox_pids(proc.path(), session),
            [14, 15, 13, 12, 11],
            "children before parents, the root last"
        );
        assert_eq!(tree(proc.path(), 20), [21, 20]);
        assert_eq!(tree(proc.path(), 99), [99], "an unknown root is itself");
        assert!(sandbox_pids(proc.path(), "sess_nothing").is_empty());
    }

    #[test]
    fn stat_parent_survives_a_hostile_command_name() {
        assert_eq!(parent_of("14 (sleep) S 13 14 10 0 -1"), Some(13));
        assert_eq!(parent_of("14 (a) b) S 7) S 13 1"), Some(13));
        assert_eq!(parent_of("garbage"), None);
    }

    #[test]
    fn the_freezer_is_selected_only_where_a_real_cgroup_appears() {
        let base = tempfile::tempdir().unwrap();
        let session = "sess_01J8ZK3Q9X7VY2";
        // A writable directory that is not a cgroup mount (a tmpfs): the
        // directory is created, found to carry no freezer, and removed again.
        assert_eq!(select_cgroup(Some(base.path()), session), None);
        assert!(fs::read_dir(base.path()).unwrap().next().is_none());
        // No cgroup of our own at all.
        assert_eq!(select_cgroup(None, session), None);
        assert_eq!(
            select_cgroup(Some(&base.path().join("missing")), session),
            None
        );
        // A delegated cgroup v2: the kernel populates the new directory.
        let dir = base
            .path()
            .join(format!("ward-{}", &session[session.len() - 10..]));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("cgroup.freeze"), "0\n").unwrap();
        fs::write(dir.join("cgroup.procs"), "").unwrap();
        assert_eq!(select_cgroup(Some(base.path()), session), Some(dir));
    }

    /// A failure partway through `freeze_cgroup` (here: the `cgroup.freeze`
    /// write, once every pid has already been moved in) must not leave any
    /// pid behind in `dir` — otherwise the caller's `remove_dir` fails with
    /// `EBUSY` and the directory leaks (#171). Migrated pids land back in the
    /// parent cgroup's `cgroup.procs`, the same file a real kernel would use.
    #[test]
    fn a_failure_after_migrating_pids_moves_them_back_to_the_parent() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("ward-testxxxx");
        fs::create_dir(&dir).unwrap();
        // `cgroup.freeze` is a directory, not a file: the write after both
        // pids are already in `cgroup.procs` is guaranteed to fail.
        fs::create_dir(dir.join("cgroup.freeze")).unwrap();

        let err = freeze_cgroup(&dir, &[111, 222]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::IsADirectory);

        // Both pids were rolled back into the parent, last write winning
        // (the fake `cgroup.procs` is a plain file, not a real membership
        // set) — proof `migrate_back` ran rather than the dir being left
        // with live members.
        assert_eq!(
            fs::read_to_string(base.path().join("cgroup.procs")).unwrap(),
            "222"
        );
    }

    #[test]
    fn a_frozen_tree_is_recorded_by_method_and_the_marker_comes_and_goes() {
        let state = tempfile::tempdir().unwrap();
        let session = "sess_marker";
        fs::create_dir_all(session_dir(state.path(), session)).unwrap();
        assert!(!marker_path(state.path(), session).exists());
        write_marker(state.path(), session, "why").unwrap();
        assert_eq!(
            fs::read_to_string(marker_path(state.path(), session)).unwrap(),
            "why\n"
        );
        clear_marker(state.path(), session).unwrap();
        clear_marker(state.path(), session).expect("already gone is fine");
        assert!(!marker_path(state.path(), session).exists());
        assert_eq!(reason_text("  "), DEFAULT_REASON);
        assert_eq!(reason_text(" looks wrong "), "looks wrong");
        // Nothing of this session runs, so the freeze holds nothing; the
        // method is still decided (what this host offers).
        let frozen = freeze("sess_nothing_runs");
        assert!(frozen.pids.is_empty());
        thaw(&frozen);
        kill_frozen(&frozen);
        assert_eq!(
            frozen.cgroup.is_some(),
            frozen.method == PauseMethod::CgroupFreezer
        );
    }

    /// The signal path on a real process tree: a shell and its sleeping child
    /// are stopped children first, continue on thaw, and die on kill.
    #[test]
    fn sigstop_freezes_a_real_tree_and_thaw_lets_it_finish() {
        use std::process::{Command, Stdio};
        // Whatever the assertions below say, the shell must not be left stopped
        // holding the test's pipes.
        struct Reap(u32);
        impl Drop for Reap {
            fn drop(&mut self) {
                let _ = kill(Pid::from_raw(as_pid(self.0)), Signal::SIGKILL);
            }
        }
        let mut child = Command::new("sh")
            .args(["-c", "sleep 0.2; sleep 0.2; echo done"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let root = child.id();
        let _reap = Reap(root);
        let pids = tree(Path::new("/proc"), root);
        assert_eq!(pids.last(), Some(&root));
        let frozen = Frozen {
            method: PauseMethod::Sigstop,
            pids: pids.clone(),
            cgroup: None,
        };
        freeze_signals(&pids);
        let state = |pid: u32| {
            fs::read_to_string(format!("/proc/{pid}/status"))
                .unwrap_or_default()
                .lines()
                .find_map(|l| l.strip_prefix("State:\t").map(|s| s.chars().next()))
                .flatten()
        };
        // The signal is delivered asynchronously: give the kernel a moment.
        assert!(
            crate::daemon::wait_until(Duration::from_secs(2), || state(root) == Some('T')),
            "the shell is stopped: {:?}",
            state(root)
        );
        std::thread::sleep(Duration::from_millis(500));
        assert!(child.try_wait().unwrap().is_none(), "stopped, not finished");
        thaw(&frozen);
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "done");
    }

    #[test]
    fn proc_state_is_the_field_after_the_command_name() {
        assert_eq!(proc_state("14 (sleep) T 13 14 10 0 -1"), Some('T'));
        assert_eq!(proc_state("14 (a) b) S 7) t 13 1"), Some('t'));
        assert_eq!(proc_state("14 (x) R 1"), Some('R'));
        assert_eq!(proc_state("garbage"), None);
    }

    fn facts(pid: u32, parent: u32, state: char, wchan: Option<&str>) -> ProcFacts {
        ProcFacts {
            pid,
            ppid: parent,
            state,
            threads: Some(1),
            wchan: wchan.map(str::to_owned),
        }
    }

    /// #352: a dash parent whose vforked child was stopped before `exec`
    /// stays in `D` waiting for the vfork to complete and never reaches `T`.
    /// Nothing in that pair can run, so the parent counts as frozen, whichever
    /// name the kernel gives the wait (`kernel_clone` where it inlined it).
    #[test]
    fn a_vfork_parent_held_by_a_stopped_child_is_frozen() {
        for wchan in VFORK_WAIT_WCHANS {
            for child in ['T', 't'] {
                let tree = [facts(10, 1, 'D', Some(wchan)), facts(11, 10, child, None)];
                assert!(frozen_from(10, &tree), "{wchan} over a {child} child");
            }
        }
        let with_a_reaped_sibling = [
            facts(10, 1, 'D', Some("wait_for_vfork_done")),
            facts(11, 10, 'T', None),
            facts(12, 10, 'Z', None),
        ];
        assert!(frozen_from(10, &with_a_reaped_sibling));
    }

    /// The same parent while its vfork child still runs is not frozen: the
    /// child can `exec` and release it at any moment.
    #[test]
    fn a_vfork_parent_whose_child_still_runs_is_not_frozen() {
        for child in ['R', 'S', 'D'] {
            let tree = [
                facts(10, 1, 'D', Some("wait_for_vfork_done")),
                facts(11, 10, child, Some("pipe_read")),
            ];
            assert!(!frozen_from(10, &tree), "a {child} child");
        }
        let one_child_still_runs = [
            facts(10, 1, 'D', Some("kernel_clone")),
            facts(11, 10, 'T', None),
            facts(12, 10, 'R', None),
        ];
        assert!(!frozen_from(10, &one_child_still_runs));
        let no_child_of_its_own = [
            facts(10, 1, 'D', Some("wait_for_vfork_done")),
            facts(11, 9, 'T', None),
        ];
        assert!(!frozen_from(10, &no_child_of_its_own));
        let only_a_zombie = [
            facts(10, 1, 'D', Some("wait_for_vfork_done")),
            facts(11, 10, 'Z', None),
        ];
        assert!(!frozen_from(10, &only_a_zombie));
    }

    /// Uninterruptible sleep for anything other than a vfork, or with a wait
    /// channel that cannot be read, is not frozen (fail closed).
    #[test]
    fn an_uninterruptible_wait_for_anything_else_is_not_frozen() {
        for wchan in [Some("folio_wait_bit_common"), Some("0"), Some(""), None] {
            let tree = [facts(10, 1, 'D', wchan), facts(11, 10, 'T', None)];
            assert!(!frozen_from(10, &tree), "wchan {wchan:?}");
        }
        let mut threaded = facts(10, 1, 'D', Some("wait_for_vfork_done"));
        threaded.threads = Some(2);
        assert!(!frozen_from(
            10,
            &[threaded.clone(), facts(11, 10, 'T', None)]
        ));
        threaded.threads = None;
        assert!(!frozen_from(10, &[threaded, facts(11, 10, 'T', None)]));
    }

    /// A running or sleeping process is never frozen, whatever its children do.
    #[test]
    fn a_running_process_is_not_frozen() {
        for state in ['R', 'S', 'I', 'W'] {
            let tree = [
                facts(10, 1, state, Some("wait_for_vfork_done")),
                facts(11, 10, 'T', None),
            ];
            assert!(!frozen_from(10, &tree), "state {state}");
        }
    }

    /// A stopped, traced-stopped, zombie or dead process is frozen, and so is
    /// one gone from `/proc`.
    #[test]
    fn a_stopped_ended_or_missing_process_is_frozen() {
        for state in ['T', 't', 'Z', 'X', 'x'] {
            assert!(frozen_from(10, &[facts(10, 1, state, None)]), "{state}");
        }
        assert!(frozen_from(10, &[facts(11, 10, 'R', None)]), "10 is gone");
        assert!(frozen_from(10, &[]));
    }

    /// The settle check reads those facts from `/proc`: state, parent and
    /// thread count from `stat`, the wait channel from `wchan`.
    #[test]
    fn the_settle_check_reads_a_vfork_hold_from_proc() {
        let proc = tempfile::tempdir().unwrap();
        let process = |pid: u32, parent: u32, state: char, threads: u32, wchan: Option<&str>| {
            let dir = proc.path().join(pid.to_string());
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("stat"),
                format!(
                    "{pid} (sh (x)) {state} {parent} {pid} {pid} 0 -1 4194560 1 0 0 0 0 0 0 0 \
                     20 0 {threads} 0 1 2 3\n"
                ),
            )
            .unwrap();
            if let Some(wchan) = wchan {
                fs::write(dir.join("wchan"), wchan).unwrap();
            }
        };
        process(1, 0, 'S', 1, None);
        process(10, 1, 'D', 1, Some("wait_for_vfork_done"));
        process(11, 10, 'T', 1, None);
        process(20, 1, 'D', 1, Some("kernel_clone"));
        process(21, 20, 'S', 1, None);
        process(30, 1, 'D', 1, None);
        process(31, 30, 'T', 1, None);
        process(40, 1, 'D', 3, Some("kernel_clone"));
        process(41, 40, 'T', 1, None);
        fs::write(proc.path().join("uptime"), "1 1\n").unwrap();

        let stat = fs::read_to_string(proc.path().join("10/stat")).unwrap();
        assert_eq!(
            proc_facts(proc.path(), 10, &stat),
            Some(ProcFacts {
                pid: 10,
                ppid: 1,
                state: 'D',
                threads: Some(1),
                wchan: Some("wait_for_vfork_done".into()),
            })
        );
        assert!(stopped_or_gone(proc.path(), 10), "held by a stopped child");
        assert!(!stopped_or_gone(proc.path(), 20), "its child still sleeps");
        assert!(!stopped_or_gone(proc.path(), 30), "wchan unreadable");
        assert!(!stopped_or_gone(proc.path(), 40), "multi-threaded");
        assert!(!stopped_or_gone(proc.path(), 1));
        assert!(stopped_or_gone(proc.path(), 11));
        assert!(stopped_or_gone(proc.path(), 99), "gone");
        assert_eq!(
            settle_outcome_with(
                &Frozen {
                    method: PauseMethod::Sigstop,
                    pids: vec![11, 10],
                    cgroup: None,
                },
                false,
                |pid| stopped_or_gone(proc.path(), pid),
            ),
            None,
            "the stopped child and its vfork parent settle the pause"
        );
    }

    /// #352 on real processes: a dash loop whose vforked child is stopped
    /// before `exec` leaves the shell in `D`, and a pause holding both settles.
    /// The shell's `PATH` is long so the child spends long enough between
    /// `vfork` and `exec` to be caught there; each attempt is confirmed from
    /// `/proc` before anything is asserted, and a host without dash or a
    /// readable wait channel skips.
    #[test]
    fn a_dash_parent_held_in_vfork_wait_on_a_stopped_child_settles() {
        use std::process::{Child, Command, Stdio};
        struct Reap(Child);
        impl Drop for Reap {
            fn drop(&mut self) {
                for pid in tree(Path::new("/proc"), self.0.id()) {
                    let _ = kill(Pid::from_raw(as_pid(pid)), Signal::SIGKILL);
                }
                let _ = self.0.wait();
            }
        }
        let Some(dash) = ["/bin/dash", "/usr/bin/dash"]
            .into_iter()
            .find(|p| Path::new(p).exists())
        else {
            eprintln!("skipped: no dash on this host");
            return;
        };
        let proc = Path::new("/proc");
        let long_path = (0..12_000)
            .map(|i| format!("/nx{i}"))
            .chain(["/usr/bin".to_owned(), "/bin".to_owned()])
            .collect::<Vec<_>>()
            .join(":");
        let shell = Reap(
            Command::new(dash)
                .args(["-c", "while :; do uname; done"])
                .env_clear()
                .env("PATH", long_path)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let root = shell.0.id();
        let in_vfork_wait_now = |pid: u32| {
            fs::read_to_string(proc.join(pid.to_string()).join("stat"))
                .ok()
                .and_then(|stat| proc_facts(proc, pid, &stat))
                .is_some_and(|f| {
                    f.state == 'D'
                        && f.wchan
                            .as_deref()
                            .is_some_and(|w| VFORK_WAIT_WCHANS.contains(&w))
                })
        };
        let state = |pid: u32| {
            fs::read_to_string(proc.join(pid.to_string()).join("stat"))
                .ok()
                .and_then(|s| proc_state(&s))
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let held = loop {
            if Instant::now() >= deadline {
                break None;
            }
            if !in_vfork_wait_now(root) {
                std::thread::yield_now();
                continue;
            }
            let children: Vec<u32> = tree(proc, root)
                .into_iter()
                .filter(|&pid| pid != root)
                .collect();
            freeze_signals(&children);
            let stopped = crate::daemon::wait_until(Duration::from_millis(200), || {
                children.iter().all(|&pid| state(pid) == Some('T'))
            });
            if stopped && !children.is_empty() && in_vfork_wait_now(root) {
                break Some(children);
            }
            for pid in &children {
                let _ = kill(Pid::from_raw(as_pid(*pid)), Signal::SIGCONT);
            }
        };
        let Some(children) = held else {
            eprintln!("skipped: the shell was never seen waiting for a vfork child");
            return;
        };
        let mut pids = children;
        pids.push(root);
        freeze_signals(&pids);
        let frozen = Frozen {
            method: PauseMethod::Sigstop,
            pids,
            cgroup: None,
        };
        assert_eq!(settle_outcome(&frozen), None, "the held pair settles");
        assert_eq!(
            state(root),
            Some('D'),
            "the shell never reached `T`: the vfork hold is what settled it"
        );
        assert!(stopped_or_gone(proc, root));
    }

    #[test]
    fn wait_settled_is_immediate_for_the_cgroup_freezer_and_for_no_pids() {
        // The cgroup freezer already waited on `cgroup.events`, so settling is
        // trivially true; a signalled freeze of no pids has nothing to wait for.
        assert!(wait_settled(&Frozen {
            method: PauseMethod::CgroupFreezer,
            pids: vec![],
            cgroup: Some(PathBuf::from("/does/not/matter")),
        }));
        assert!(wait_settled(&Frozen {
            method: PauseMethod::Sigstop,
            pids: vec![],
            cgroup: None,
        }));
    }

    /// #145 items 3-4: `settle_outcome` mirrors `wait_settled` when a freeze
    /// settles, is always `None` for the cgroup freezer (synchronous by
    /// construction, even with a pid a real freeze could never actually hold —
    /// [`freeze_cgroup`]'s own wait is what makes this true, not a re-check
    /// against `/proc`), and, on the signal path, counts exactly the pids still
    /// not stopped or gone once the bound has expired.
    #[test]
    fn settle_outcome_counts_only_what_is_still_not_stopped_after_the_bound() {
        assert_eq!(
            settle_outcome(&Frozen {
                method: PauseMethod::CgroupFreezer,
                pids: vec![999_999],
                cgroup: Some(PathBuf::from("/does/not/matter")),
            }),
            None
        );
        assert_eq!(
            settle_outcome(&Frozen {
                method: PauseMethod::Sigstop,
                pids: vec![],
                cgroup: None,
            }),
            None,
            "nothing to wait for"
        );
        // A pid that never existed reads as `stopped_or_gone` (its tree ended by
        // itself), so a `Frozen` naming only such pids settles even though nothing
        // was ever really frozen — `wait_settled`'s existing, intentional behaviour
        // (`freeze`'s own doc comment: "a pid gone since the scan is not a
        // failure"); `settle_outcome` must not report it as pending.
        assert_eq!(
            settle_outcome(&Frozen {
                method: PauseMethod::Sigstop,
                pids: vec![999_999, 999_998],
                cgroup: None,
            }),
            None
        );
    }

    /// PR #207 review finding 3: `wait_settled` timing out is not itself proof
    /// anything is still pending — it can return `false` and, by the time the
    /// immediate recount runs a moment later, every pid has since actually
    /// stopped. `settle_outcome_with` must normalize that recount-of-zero to
    /// `None` (settled), never the self-contradictory `Some(0)` ("unsettled: 0
    /// pending"). Deterministic: `settled` and `stopped` are both injected, no
    /// real sleep and no real process.
    #[test]
    fn a_timeout_whose_immediate_recount_finds_nothing_pending_normalizes_to_settled() {
        let frozen = Frozen {
            method: PauseMethod::Sigstop,
            pids: vec![111, 222, 333],
            cgroup: None,
        };
        assert_eq!(
            settle_outcome_with(&frozen, false, |_pid| true),
            None,
            "wait_settled timed out, but every pid reads as stopped on the recount: \
             settled, not `Some(0)`"
        );
    }

    /// The companion case finding 3 asks for: a timeout whose recount finds a real,
    /// nonzero number still pending reports that count, unchanged, deterministically.
    #[test]
    fn a_timeout_with_a_genuinely_nonzero_recount_reports_it() {
        let frozen = Frozen {
            method: PauseMethod::Sigstop,
            pids: vec![111, 222, 333, 444],
            cgroup: None,
        };
        assert_eq!(
            settle_outcome_with(&frozen, false, |pid| pid == 111 || pid == 444),
            Some(2),
            "222 and 333 read as still not stopped"
        );
    }

    /// #145 item 5: every pid of the freeze is killed, a pid a rescan finds
    /// mid-stop (forked after the freeze) is killed and counted too, and the loop
    /// returns as soon as everything seen is gone. Deterministic: nothing real is
    /// signalled and `gone` answers from a shared set the fake `kill` fills.
    #[test]
    fn terminate_kills_the_freeze_and_what_a_rescan_finds_then_confirms_gone() {
        use std::cell::RefCell;
        let killed = RefCell::new(Vec::new());
        let mut scans = 0;
        let (ended, pending) = terminate_with(
            &[14, 13, 11],
            Duration::from_secs(5),
            || {
                scans += 1;
                // A child forked between the scan and the kill shows up once.
                if scans == 1 { vec![11, 15] } else { vec![] }
            },
            |pid| killed.borrow().contains(&pid),
            |pid| killed.borrow_mut().push(pid),
        );
        assert_eq!(ended, 4, "14, 13, 11 and the late 15");
        assert!(pending.is_empty());
        let killed = killed.into_inner();
        for pid in [14, 13, 11, 15] {
            assert!(killed.contains(&pid), "{pid} was killed: {killed:?}");
        }
        assert_eq!(
            &killed[..3],
            [14, 13, 11],
            "the freeze's order, children first"
        );
    }

    /// A process that does not die within the bound (uninterruptible sleep) is
    /// reported pending, never counted as ended — the stop must not claim more
    /// than it could confirm (#145 item 4).
    #[test]
    fn terminate_reports_what_is_still_present_when_the_bound_expires() {
        let (ended, pending) = terminate_with(
            &[20, 21, 22],
            Duration::from_millis(60),
            Vec::new,
            |pid| pid != 21,
            |_| {},
        );
        assert_eq!(ended, 2);
        assert_eq!(pending, [21]);
        // Nothing at all to kill: nothing ended, nothing pending, at once.
        assert_eq!(
            terminate_with(&[], Duration::from_secs(5), Vec::new, |_| false, |_| {}),
            (0, vec![])
        );
    }

    #[test]
    fn a_zombie_or_a_missing_pid_counts_as_ended() {
        let proc = tempfile::tempdir().unwrap();
        for (pid, state) in [(30, 'Z'), (31, 'T'), (32, 'R'), (33, 'X')] {
            let dir = proc.path().join(pid.to_string());
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("stat"), format!("{pid} (sh) {state} 1 1 1 0 -1")).unwrap();
        }
        assert!(ended_or_gone(proc.path(), 30), "a zombie runs no code");
        assert!(!ended_or_gone(proc.path(), 31), "stopped is not ended");
        assert!(!ended_or_gone(proc.path(), 32));
        assert!(ended_or_gone(proc.path(), 33));
        assert!(ended_or_gone(proc.path(), 99), "gone from /proc");
    }

    /// PR #253 review finding 4, the orphaning window, deterministically: the
    /// scan saw `[13, 11]`, and `13` was mid-`fork` when its `SIGSTOP` was
    /// sent, so its child `14` exists but was never scanned and never stopped
    /// (a child does not inherit a pending signal). `stabilize_with` must not
    /// declare the freeze stable — nor let anything be killed — until a rescan
    /// taken with every known pid stopped has found `14` and stopped it too.
    /// Rescans taken while `13` is still running are not trusted.
    #[test]
    fn a_child_forked_in_the_scan_to_stop_window_is_frozen_before_the_freeze_is_stable() {
        use std::cell::RefCell;
        let stopped = RefCell::new(vec![11]); // 13's SIGSTOP is still in flight
        let events = RefCell::new(Vec::new());
        let mut pids = vec![13, 11];
        let stable = stabilize_with(
            &mut pids,
            Duration::from_millis(60),
            || {
                events.borrow_mut().push("rescan");
                vec![14, 13, 11]
            },
            |_| {
                events.borrow_mut().push("stop-late");
                true
            },
            |pid| stopped.borrow().contains(&pid),
        );
        // 13 never stopped within this bound: the freeze cannot be stable,
        // and no rescan was trusted while it could still fork.
        assert!(!stable);
        assert!(events.borrow().is_empty(), "{:?}", events.borrow());

        // Now 13 has stopped: the rescan is trusted, finds 14, stops it, and a
        // second rescan finds nothing new.
        stopped.borrow_mut().push(13);
        let stable = stabilize_with(
            &mut pids,
            Duration::from_secs(5),
            || {
                events.borrow_mut().push("rescan");
                vec![14, 13, 11]
            },
            |fresh| {
                assert_eq!(fresh, [14]);
                events.borrow_mut().push("stop-late");
                stopped.borrow_mut().push(14);
                true
            },
            |pid| stopped.borrow().contains(&pid),
        );
        assert!(stable);
        assert_eq!(*events.borrow(), ["rescan", "stop-late", "rescan"]);
        assert_eq!(
            pids,
            [14, 13, 11],
            "the late child first, before its parent"
        );
    }

    /// The pid-namespace half of the membership boundary: a process that has
    /// been reparented away from the `bwrap` tree (its parent exited) is still
    /// the session's while it lives in the sandbox's pid namespace, and a
    /// process in the scanner's own namespace never is.
    #[test]
    fn a_failed_late_freeze_invalidates_the_barrier_even_when_the_pid_looks_settled() {
        let mut pids = vec![11];
        let mut rescans = 0;
        let stable = stabilize_with(
            &mut pids,
            Duration::from_secs(1),
            || {
                rescans += 1;
                vec![12, 11]
            },
            |fresh| {
                assert_eq!(fresh, [12]);
                false
            },
            |_| true,
        );
        assert!(
            !stable,
            "failed cgroup membership must never be a confirmed barrier"
        );
        assert_eq!(
            pids,
            [12, 11],
            "the failed-to-migrate pid must still be retained for kill"
        );
        assert_eq!(rescans, 1);
    }

    #[test]
    fn an_orphan_in_the_sandboxs_pid_namespace_is_still_found() {
        let proc = tempfile::tempdir().unwrap();
        let session = "sess_01J8ZK3Q9X7VY3";
        let sock = format!("{}/proxy.sock", run_dir_path(session).to_string_lossy());
        fake_proc(
            proc.path(),
            &[
                (1, 0, &["init"]),
                (11, 1, &["bwrap", "--bind", &sock, "/run/ward/proxy.sock"]),
                (12, 11, &["bwrap"]),
                (13, 12, &["sh"]),
                // Forked by 13's since-exited child: reparented to 1.
                (40, 1, &["sleep", "30"]),
                // An unrelated host process.
                (50, 1, &["sleep", "30"]),
            ],
        );
        let ns = |pid: &str, space: &str| {
            let dir = proc.path().join(pid).join("ns");
            fs::create_dir_all(&dir).unwrap();
            std::os::unix::fs::symlink(format!("pid:[{space}]"), dir.join("pid")).unwrap();
        };
        ns("self", "host");
        for (pid, space) in [("1", "host"), ("11", "host"), ("50", "host")] {
            ns(pid, space);
        }
        for pid in ["12", "13", "40"] {
            ns(pid, "sandbox");
        }
        assert_eq!(
            sandbox_pids(proc.path(), session),
            [40, 13, 12, 11],
            "the orphan first, then the tree children-first; never the host's 50"
        );
    }

    /// PR #253 review finding 4 on real processes: a sandbox-shaped tree that
    /// forks tagged children as fast as it can while the stop runs. Every one
    /// of them — including any forked between the scan and its parent's
    /// `SIGSTOP`, which would outlive the root's kill as an orphan of init — is
    /// ended by `terminate`: afterwards no live process carries the tag.
    #[test]
    fn terminate_leaves_no_orphan_of_a_tree_that_forks_during_the_stop() {
        // Whatever the assertions say, nothing tagged outlives the test.
        struct Sweep<'a>(&'a dyn Fn() -> Vec<u32>);
        impl Drop for Sweep<'_> {
            fn drop(&mut self) {
                for pid in (self.0)() {
                    let _ = kill(Pid::from_raw(as_pid(pid)), Signal::SIGKILL);
                }
            }
        }
        let bin = tempfile::tempdir().unwrap();
        let tag = format!("wardforktag{}", std::process::id());
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .expect("a sleep binary");
        let tagged = bin.path().join(&tag);
        fs::copy(sleep, &tagged).unwrap();
        let script = format!(
            "i=0; while [ $i -lt 300 ]; do '{}' 30 & i=$((i+1)); done; wait",
            tagged.display()
        );
        let live_tagged = || -> Vec<u32> {
            proc_pids(Path::new("/proc"))
                .into_iter()
                .filter(|&pid| {
                    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
                    String::from_utf8_lossy(&cmdline).contains(&tag)
                        && !ended_or_gone(Path::new("/proc"), pid)
                })
                .collect()
        };
        let _sweep = Sweep(&live_tagged);
        let mut sandbox = FakeSandbox::spawn_running("sess_forking", &script);
        let t = terminate(&sandbox.session, None);
        assert_eq!(t.remaining, None, "{t:?}");
        assert!(t.barrier_confirmed, "{t:?}");
        assert!(sandbox.was_killed());
        // Orphans are reparented and reaped by init; give that a moment, then
        // nothing tagged may still be alive.
        assert!(
            crate::daemon::wait_until(Duration::from_secs(2), || live_tagged().is_empty()),
            "orphans survived the stop: {:?}",
            live_tagged()
        );
    }

    /// A session with nothing running is left untouched: no freeze, no cgroup,
    /// nothing reported.
    #[test]
    fn terminating_a_session_with_nothing_running_touches_nothing() {
        let t = terminate("sess_nothing_to_stop", None);
        assert_eq!(t, Termination::nothing());
        assert!(!t.touched_anything());
        assert_eq!(t.pending(), 0);
    }

    /// The whole of [`terminate`] on a real process tree the scan recognises as a
    /// session sandbox: a copy of `sh` named `bwrap` whose arguments bind the
    /// session's run directory, with a child looping under it. Every process is
    /// found, frozen, killed and confirmed gone within the bound.
    #[test]
    fn terminate_ends_a_real_sandbox_shaped_tree() {
        let mut sandbox = FakeSandbox::spawn("sess_stoptree");
        let t = terminate(&sandbox.session, None);
        assert_eq!(t.remaining, None, "everything confirmed gone: {t:?}");
        assert!(t.ended >= 2, "{t:?}");
        assert!(sandbox.was_killed(), "killed, not merely stopped");
        assert!(sandbox_pids(Path::new("/proc"), &sandbox.session).is_empty());
    }

    /// A session the user has already paused is already frozen; the capture
    /// guard must hold nothing (and so thaw nothing on drop), leaving the user's
    /// pause the only thing that can be lifted, by `ward resume`.
    #[test]
    fn capture_freeze_leaves_a_user_pause_alone() {
        let state = tempfile::tempdir().unwrap();
        let session = "sess_already_paused";
        fs::create_dir_all(session_dir(state.path(), session)).unwrap();
        write_marker(state.path(), session, "held by the user").unwrap();
        let guard = CaptureFreeze::acquire(state.path(), session);
        assert_eq!(guard.method(), None, "a paused session is frozen already");
        drop(guard);
        // The marker is untouched: the guard did not thaw the user's pause.
        assert!(marker_path(state.path(), session).exists());
    }

    /// A freeze held around a capture stops a real writer and releases it on
    /// drop — the property ST-018 relies on, exercised on a plain process tree.
    #[test]
    fn capture_freeze_stops_a_real_tree_and_releases_it_on_drop() {
        use std::process::{Child, Command, Stdio};
        struct Reap(Child);
        impl Drop for Reap {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let reap = Reap(
            Command::new("sh")
                .args(["-c", "while :; do :; done"])
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let root = reap.0.id();
        let pids = tree(Path::new("/proc"), root);
        let frozen = Frozen {
            method: PauseMethod::Sigstop,
            pids: pids.clone(),
            cgroup: None,
        };
        freeze_signals(&pids);
        assert!(wait_settled(&frozen), "the tree settles into `stopped`");
        let state = |pid: u32| {
            fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| proc_state(&s))
        };
        assert_eq!(state(root), Some('T'), "stopped while the guard would hold");
        thaw(&frozen);
        assert!(
            crate::daemon::wait_until(Duration::from_secs(2), || state(root) != Some('T')),
            "running again after the guard releases it",
        );
    }

    /// #234: a pause landing while a `CaptureFreeze`'s capture is still in progress
    /// must never be silently undone by that guard's own `Drop` — only `ward resume`
    /// may thaw it once the marker is present. Exercised on a real, signal-stopped
    /// process so the assertion is that nothing actually resumed, not merely that
    /// some function was or wasn't called; the marker is written before the guard
    /// drops, so no real timing race is needed to make the scenario deterministic.
    #[test]
    fn a_guard_that_cannot_take_the_lock_still_thaws_when_no_pause_is_recorded() {
        use std::process::{Child, Command, Stdio};
        struct Reap(Child);
        impl Drop for Reap {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let reap = Reap(
            Command::new("sh")
                .args(["-c", "while :; do :; done"])
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let root = reap.0.id();
        let pids = tree(Path::new("/proc"), root);
        freeze_signals(&pids);
        let frozen = Frozen {
            method: PauseMethod::Sigstop,
            pids,
            cgroup: None,
        };
        assert!(wait_settled(&frozen), "the tree settles into `stopped`");

        // No session directory at all: the lock file cannot be created, so the
        // lock cannot be taken — and no pause marker exists either.
        let state = tempfile::tempdir().unwrap();
        let session = "sess_no_lock";
        assert!(lock_pause_freeze(&session_dir(state.path(), session)).is_err());
        let guard = CaptureFreeze {
            state: state.path().to_path_buf(),
            session: session.to_owned(),
            frozen: Some(frozen),
        };

        drop(guard);

        // Thawed: left stopped, nothing could ever resume it.
        let running = (0..100).any(|_| {
            let state = fs::read_to_string(format!("/proc/{root}/stat"))
                .ok()
                .and_then(|s| proc_state(&s));
            if state.is_some_and(|c| c != 'T') {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
            false
        });
        assert!(
            running,
            "no pause recorded: the guard must thaw what it froze"
        );
    }

    #[test]
    fn a_pause_that_lands_during_a_capture_is_not_undone_by_the_guards_drop() {
        use std::process::{Child, Command, Stdio};
        struct Reap(Child);
        impl Drop for Reap {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let reap = Reap(
            Command::new("sh")
                .args(["-c", "while :; do :; done"])
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let root = reap.0.id();
        let pids = tree(Path::new("/proc"), root);
        freeze_signals(&pids);
        let frozen = Frozen {
            method: PauseMethod::Sigstop,
            pids: pids.clone(),
            cgroup: None,
        };
        assert!(wait_settled(&frozen), "the tree settles into `stopped`");

        let state = tempfile::tempdir().unwrap();
        let session = "sess_race_234";
        fs::create_dir_all(session_dir(state.path(), session)).unwrap();
        // Constructed directly rather than through `acquire`, exactly as
        // `capture_freeze_stops_a_real_tree_and_releases_it_on_drop` above builds
        // its own `Frozen` directly: what's under test is `Drop`'s own re-check,
        // not `acquire`'s freezing (already covered by that test and by
        // `capture_freeze_leaves_a_user_pause_alone`).
        let guard = CaptureFreeze {
            state: state.path().to_path_buf(),
            session: session.to_owned(),
            frozen: Some(frozen),
        };

        // A pause lands (writes the marker) while the capture this guard
        // represents is still in progress, exactly as `pause_with_appending`
        // would under `lock_pause_freeze` before this guard's own drop runs.
        write_marker(state.path(), session, "held by the user").unwrap();

        drop(guard);

        let proc_state_of = |pid: u32| {
            fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| proc_state(&s))
        };
        assert_eq!(
            proc_state_of(root),
            Some('T'),
            "the pause landed first: the guard's drop must not have thawed it"
        );
    }

    #[test]
    fn holders_name_their_owners_in_order_round_trip_and_forget_dead_capturers() {
        let live = Capturer {
            op: "op_live".into(),
            pid: std::process::id(),
            started: own_start_time(),
            reason: "ward capture: test".into(),
        };
        let dead = Capturer {
            op: "op_dead".into(),
            pid: 999_999,
            started: "0".into(),
            reason: "ward capture: test".into(),
        };
        assert!(Holders::default().is_empty());
        assert_eq!(Holders::for_user().owners(), [Owner::User]);
        assert_eq!(Holders::for_stop().owners(), [Owner::Stop]);
        let mut holders = Holders::for_capture(dead.clone());
        assert_eq!(holders.owners(), [Owner::Capture]);
        assert!(holders.held_only_for_capture());
        holders.add_capture(live.clone());
        holders.user = true;
        holders.stop = true;
        assert_eq!(
            holders.owners(),
            [Owner::User, Owner::Capture, Owner::Stop],
            "user, capture, stop"
        );
        assert!(!holders.held_only_for_capture());
        let json = serde_json::to_string(&holders).unwrap();
        assert_eq!(serde_json::from_str::<Holders>(&json).unwrap(), holders);
        assert!(holders.prune_dead(Path::new("/proc")));
        assert_eq!(holders.captures, std::slice::from_ref(&live));
        assert!(
            !holders.prune_dead(Path::new("/proc")),
            "nothing more to forget"
        );
        assert!(holders.remove_capture("op_live"));
        assert!(!holders.remove_capture("op_live"));
        assert_eq!(holders.owners(), [Owner::User, Owner::Stop]);
        for owner in [Owner::User, Owner::Capture, Owner::Stop] {
            assert_eq!(
                serde_json::to_string(&owner).unwrap(),
                format!("\"{}\"", owner.as_str())
            );
        }

        let state = tempfile::tempdir().unwrap();
        let session = "sess_holders";
        fs::create_dir_all(session_dir(state.path(), session)).unwrap();
        assert_eq!(read_held_by(state.path(), session).unwrap(), None);
        write_held_by(state.path(), session, &holders).unwrap();
        assert_eq!(read_held_by(state.path(), session).unwrap(), Some(holders));
        clear_held_by(state.path(), session).unwrap();
        assert_eq!(read_held_by(state.path(), session).unwrap(), None);
        clear_held_by(state.path(), session).unwrap();
        assert!(is_capture_reason(&capture_reason("candidate snapshot")));
        assert!(!is_capture_reason("ward pause"));
    }

    /// #145 item 6 without a daemon: a capture's hold freezes the tree, writes
    /// the marker and the owners, confirms the proxy and records `SessionPaused`
    /// with the capture's reason; its release thaws, clears and records
    /// `SessionResumed`. A session with nothing running holds nothing.
    #[test]
    fn a_local_capture_hold_freezes_marks_records_and_releases() {
        let state = tempfile::tempdir().unwrap();
        let mut sandbox = FakeSandbox::spawn("sess_lcap");
        let session = sandbox.session.clone();
        fs::create_dir_all(session_dir(state.path(), &session)).unwrap();
        let mut events = Vec::new();
        let reason = capture_reason("test");

        let hold = LocalCaptureHold::take(state.path(), &session, &reason, |e| {
            events.push(e);
            Ok(())
        })
        .unwrap()
        .expect("something runs, so something is held");
        assert!(sandbox.stopped() || hold.method() == Some(PauseMethod::CgroupFreezer));
        assert_eq!(
            fs::read_to_string(marker_path(state.path(), &session)).unwrap(),
            format!("{reason}\n")
        );
        let holders = read_held_by(state.path(), &session).unwrap().unwrap();
        assert_eq!(holders.owners(), [Owner::Capture]);
        assert_eq!(holders.captures[0].pid, std::process::id());
        assert!(!intent_path(state.path(), &session).exists());
        assert!(matches!(
            events.as_slice(),
            [WardEvent::SessionPaused { reason: r, .. }] if r.as_str() == reason
        ));

        hold.release(|e| {
            events.push(e);
            Ok(())
        })
        .unwrap();
        assert!(!marker_path(state.path(), &session).exists());
        assert_eq!(read_held_by(state.path(), &session).unwrap(), None);
        assert!(crate::daemon::wait_until(Duration::from_secs(2), || {
            !sandbox.stopped()
        }));
        assert!(sandbox.running());
        assert!(matches!(
            events.as_slice(),
            [
                WardEvent::SessionPaused { .. },
                WardEvent::SessionResumed { .. }
            ]
        ));

        let mut none = Vec::new();
        let idle = LocalCaptureHold::take(state.path(), "sess_idle_cap", &reason, |e| {
            none.push(e);
            Ok(())
        })
        .unwrap();
        assert!(idle.is_none());
        assert!(none.is_empty());
    }

    /// Without a daemon, a capture whose freeze is not confirmed settled, or
    /// whose proxy does not acknowledge, is refused: nothing recorded, no
    /// marker left, and only the freeze the capture itself took is released.
    #[test]
    fn a_local_capture_that_cannot_confirm_quiescence_is_refused_and_leaves_nothing() {
        struct Silent;
        impl crate::acks::Acknowledger for Silent {
            fn confirm(
                &mut self,
                component: crate::acks::Component,
                _: crate::acks::Phase,
                _: &crate::acks::Site<'_>,
            ) -> crate::acks::Outcome {
                if component == crate::acks::Component::Proxy {
                    crate::acks::Outcome::TimedOut {
                        after: Duration::from_secs(2),
                    }
                } else {
                    crate::acks::Outcome::Acknowledged
                }
            }
        }
        let state = tempfile::tempdir().unwrap();
        let session = "sess_lcap_refused";
        fs::create_dir_all(session_dir(state.path(), session)).unwrap();
        let own = || CaptureFreeze {
            state: state.path().to_path_buf(),
            session: session.to_owned(),
            frozen: Some(Frozen {
                method: PauseMethod::Sigstop,
                pids: vec![std::process::id()],
                cgroup: None,
            }),
        };
        let mut events = Vec::new();

        let err = LocalCaptureHold::take_with(
            state.path(),
            session,
            "ward capture: test",
            |_, _| (own(), Some(1)),
            &mut crate::acks::Live::new(),
            |e| {
                events.push(e);
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("nothing was captured"), "{err}");
        assert!(err.contains("1 process(es) still pending"), "{err}");

        let err = LocalCaptureHold::take_with(
            state.path(),
            session,
            "ward capture: test",
            |_, _| (own(), None),
            &mut Silent,
            |e| {
                events.push(e);
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("nothing was captured"), "{err}");
        assert!(
            err.contains("egress proxy (no acknowledgement within 2s)"),
            "{err}"
        );
        assert!(events.is_empty(), "nothing recorded");
        assert!(!marker_path(state.path(), session).exists());
        assert_eq!(read_held_by(state.path(), session).unwrap(), None);
        assert!(!intent_path(state.path(), session).exists());
    }

    /// #145 item 1: the one transition table. Every state is tried against
    /// every operation, with the hold's owners where they decide.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn the_transition_table_admits_refuses_and_names_the_state() {
        use Lifecycle as L;
        use Operation as O;
        let none = Holders::default();
        let user = Holders::for_user();
        let stop = Holders::for_stop();
        let capture = Holders::for_capture(Capturer {
            op: "op1".into(),
            pid: 7,
            started: "1".into(),
            reason: capture_reason("test"),
        });
        let refusal = |state, holders: &Holders, op| {
            transition("sess_t", state, holders, op)
                .unwrap_err()
                .to_string()
        };
        // Running: a pause, a stop, a hold and a launch begin; nothing to resume.
        assert_eq!(
            transition("sess_t", L::Running, &none, O::Pause).unwrap(),
            L::Pausing
        );
        assert_eq!(
            transition("sess_t", L::Running, &none, O::Stop).unwrap(),
            L::Stopping
        );
        assert_eq!(
            transition("sess_t", L::Running, &none, O::HoldForStop).unwrap(),
            L::Stopping
        );
        assert_eq!(
            transition("sess_t", L::Running, &none, O::HoldForCapture).unwrap(),
            L::Pausing
        );
        assert_eq!(
            transition("sess_t", L::Running, &none, O::Launch).unwrap(),
            L::Running
        );
        assert!(refusal(L::Running, &none, O::Resume).ends_with("not paused"));
        // Paused by the user: no second pause, a resume, a stop, a capture layers.
        assert!(refusal(L::Paused, &user, O::Pause).ends_with("already paused"));
        assert_eq!(
            transition("sess_t", L::Paused, &user, O::Resume).unwrap(),
            L::Resuming
        );
        assert_eq!(
            transition("sess_t", L::Paused, &user, O::Stop).unwrap(),
            L::Stopping
        );
        assert_eq!(
            transition("sess_t", L::Paused, &user, O::HoldForCapture).unwrap(),
            L::Paused
        );
        assert!(refusal(L::Paused, &user, O::Launch).contains(PAUSED_REFUSAL));
        // Held only for a capture: the user's pause layers over it, a resume
        // has nothing of the user's to release.
        assert_eq!(
            transition("sess_t", L::Paused, &capture, O::Pause).unwrap(),
            L::Paused
        );
        let held = refusal(L::Paused, &capture, O::Resume);
        assert!(
            held.contains("held for capture by operation op1 (pid 7)"),
            "{held}"
        );
        assert!(held.contains("not a user pause"), "{held}");
        // Held for a stop (confirmed): only the stop goes on.
        assert!(refusal(L::Stopping, &stop, O::Pause).ends_with("already paused"));
        let begun = refusal(L::Stopping, &stop, O::Resume);
        assert!(begun.contains("has begun and not completed"), "{begun}");
        assert!(begun.contains("cannot release"), "{begun}");
        assert_eq!(
            transition("sess_t", L::Stopping, &stop, O::Stop).unwrap(),
            L::Stopping
        );
        assert_eq!(
            transition("sess_t", L::Stopping, &stop, O::HoldForStop).unwrap(),
            L::Stopping
        );
        assert_eq!(
            transition("sess_t", L::Stopping, &stop, O::HoldForCapture).unwrap(),
            L::Stopping
        );
        assert!(refusal(L::Stopping, &stop, O::Launch).contains(STOPPED_REFUSAL));
        // A stop begun with no hold in force (the marker alone): the stop
        // retries; a pause or a capture is refused naming the state.
        assert_eq!(
            transition("sess_t", L::Stopping, &none, O::Stop).unwrap(),
            L::Stopping
        );
        let stopping = refusal(L::Stopping, &none, O::Pause);
        assert!(
            stopping.contains("session sess_t is stopping"),
            "{stopping}"
        );
        assert!(refusal(L::Stopping, &none, O::HoldForCapture).contains("is stopping"),);
        assert!(refusal(L::Stopping, &none, O::Resume).contains("has begun and not completed"));
        // Incomplete: an unconfirmed pause resumes or stops; an unconfirmed
        // stop only stops.
        assert_eq!(
            transition("sess_t", L::Incomplete, &user, O::Resume).unwrap(),
            L::Resuming
        );
        assert_eq!(
            transition("sess_t", L::Incomplete, &user, O::Stop).unwrap(),
            L::Stopping
        );
        assert!(refusal(L::Incomplete, &user, O::Pause).ends_with("already paused"));
        assert!(refusal(L::Incomplete, &stop, O::Resume).contains("has begun and not completed"));
        assert_eq!(
            transition("sess_t", L::Incomplete, &stop, O::Stop).unwrap(),
            L::Stopping
        );
        assert!(refusal(L::Incomplete, &stop, O::Launch).contains(PAUSED_REFUSAL));
        // In flight (observed from outside the daemon): nothing begins.
        for state in [L::Pausing, L::Resuming] {
            for op in [
                O::Pause,
                O::Resume,
                O::Stop,
                O::HoldForStop,
                O::HoldForCapture,
            ] {
                let text = refusal(state, &none, op);
                assert!(
                    text.contains(&format!("session sess_t is {state}")),
                    "{state} {op:?}: {text}"
                );
                assert!(text.contains(op.as_str()), "{text}");
            }
            let launch = refusal(state, &none, O::Launch);
            assert!(launch.contains(&format!("session is {state}")), "{launch}");
        }
        // Stopped: the log is sealed; nothing at all.
        for op in [
            O::Pause,
            O::Resume,
            O::Stop,
            O::HoldForStop,
            O::HoldForCapture,
        ] {
            assert!(
                refusal(L::Stopped, &none, op).ends_with("log is sealed"),
                "{op:?}"
            );
        }
        assert!(refusal(L::Stopped, &none, O::Launch).contains(STOPPED_REFUSAL));
        // The words and the shape every reader relies on.
        for state in L::ALL {
            assert_eq!(L::parse(state.as_str()), Some(state));
            assert_eq!(state.to_string(), state.as_str());
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{}\"", state.as_str())
            );
            assert_eq!(state.admits_launch(), state == L::Running);
        }
        assert_eq!(L::parse("frozen"), None);
        assert!(L::Pausing.in_flight() && L::Resuming.in_flight());
        assert!(!L::Stopping.in_flight() && !L::Paused.in_flight());
        assert!(L::Paused.holds() && L::Incomplete.holds() && L::Stopping.holds());
        assert!(!L::Running.holds() && !L::Stopped.holds());
        for op in [
            O::Pause,
            O::Resume,
            O::Stop,
            O::HoldForStop,
            O::HoldForCapture,
            O::Launch,
        ] {
            assert!(!op.as_str().is_empty());
        }
        assert_eq!(O::Pause.enters(), L::Pausing);
        assert_eq!(O::HoldForCapture.enters(), L::Pausing);
        assert_eq!(O::Resume.enters(), L::Resuming);
        assert_eq!(O::Stop.enters(), L::Stopping);
        assert_eq!(O::HoldForStop.enters(), L::Stopping);
        assert_eq!(O::Launch.enters(), L::Running);
        assert_eq!(launch_refusal(L::Running), launch_refusal(L::Running));
    }

    /// #145 item 1: the lifecycle a reader with no daemon derives from the
    /// records, record by record — and that `Incomplete` is what an
    /// unconfirmed hold reads, never `paused` or `stopped`.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn the_lifecycle_on_disk_is_derived_from_the_records() {
        use ward_events::{Blake3Hash, Origin, SessionId};
        let dir = tempfile::tempdir().unwrap();
        let (state, session) = (dir.path(), "sess_life");
        let session_path = session_dir(state, session);
        fs::create_dir_all(&session_path).unwrap();
        let report = |expected: Lifecycle| {
            let report = lifecycle_on_disk(state, session).unwrap();
            assert_eq!(report.state, expected, "{report:?}");
            report
        };
        // Nothing recorded, no log yet: running.
        let running = report(Lifecycle::Running);
        assert_eq!(running, LifecycleReport::of(Lifecycle::Running));
        assert_eq!(running.text(), "running");
        assert!(launch_admission(state, session).is_ok());
        // Each intent names an operation in flight, and refuses a launch.
        let pause = Intent::begin(Verb::Pause {
            reason: "looks wrong".into(),
        })
        .unwrap();
        write_intent(state, session, &pause).unwrap();
        let pausing = report(Lifecycle::Pausing);
        assert_eq!(pausing.op.as_deref(), Some(pause.op.as_str()));
        assert_eq!(pausing.detail.as_deref(), Some("looks wrong"));
        assert_eq!(pausing.text(), "pausing (looks wrong)");
        let refused = launch_admission(state, session).unwrap_err().to_string();
        assert!(refused.contains("session is pausing"), "{refused}");
        write_intent(state, session, &Intent::begin(Verb::Resume).unwrap()).unwrap();
        let resuming = report(Lifecycle::Resuming);
        assert_eq!(resuming.detail, None);
        assert!(
            launch_admission(state, session)
                .unwrap_err()
                .to_string()
                .contains("session is resuming")
        );
        write_intent(
            state,
            session,
            &Intent::begin(Verb::Stop {
                reason: EndReason::UserStop,
            })
            .unwrap(),
        )
        .unwrap();
        report(Lifecycle::Stopping);
        assert!(
            launch_admission(state, session)
                .unwrap_err()
                .to_string()
                .contains(STOPPED_REFUSAL)
        );
        let capturer = Capturer {
            op: "cap".into(),
            pid: 1,
            started: "x".into(),
            reason: capture_reason("test"),
        };
        write_intent(
            state,
            session,
            &Intent::begin(Verb::Capture {
                reason: capture_reason("test"),
                capturer,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            report(Lifecycle::Pausing).detail.as_deref(),
            Some("ward capture: test")
        );
        clear_intent(state, session).unwrap();
        // A marker with no log yet: paused, held by the user.
        write_marker(state, session, "looks wrong").unwrap();
        let paused = report(Lifecycle::Paused);
        assert_eq!(paused.held_by, [Owner::User]);
        assert_eq!(paused.detail, None);
        assert!(
            launch_admission(state, session)
                .unwrap_err()
                .to_string()
                .contains(PAUSED_REFUSAL)
        );
        // The log's last hold record decides between paused and incomplete.
        let log_path = session_path.join("events.log");
        let mut log = crate::control::LocalLog::create(
            &log_path,
            SessionId::from_u128(3),
            Blake3Hash::from_bytes([3; 32]),
            std::time::SystemTime::now(),
        )
        .unwrap();
        let mut append = |event: WardEvent| {
            crate::control::Sink::append(
                &mut log,
                Origin::Wardd,
                event,
                std::time::SystemTime::now(),
            )
            .unwrap();
        };
        append(WardEvent::SessionPauseUnsettled {
            method: PauseMethod::Sigstop,
            reason: ShortText::new("looks wrong"),
            pending: 2,
        });
        let incomplete = report(Lifecycle::Incomplete);
        assert_eq!(
            incomplete.detail.as_deref(),
            Some("2 process(es) not confirmed stopped")
        );
        assert_eq!(
            incomplete.text(),
            "incomplete (2 process(es) not confirmed stopped)"
        );
        assert_eq!(incomplete.held_by, [Owner::User]);
        append(WardEvent::SessionPaused {
            method: PauseMethod::Sigstop,
            reason: ShortText::new("looks wrong"),
        });
        report(Lifecycle::Paused);
        // A stop that could not confirm termination: incomplete, held for the
        // stop; its retry's confirmed record makes it stopping.
        write_stop_marker(state, session).unwrap();
        write_held_by(state, session, &Holders::for_stop()).unwrap();
        append(WardEvent::WorkloadsTerminated {
            ended: 1,
            pending: 1,
            barrier_confirmed: true,
        });
        let stop_incomplete = report(Lifecycle::Incomplete);
        assert_eq!(
            stop_incomplete.detail.as_deref(),
            Some("1 process(es) not confirmed ended")
        );
        assert_eq!(stop_incomplete.held_by, [Owner::Stop]);
        append(WardEvent::WorkloadsTerminated {
            ended: 2,
            pending: 0,
            barrier_confirmed: true,
        });
        assert_eq!(report(Lifecycle::Stopping).held_by, [Owner::Stop]);
        // The seal ends it.
        crate::control::Sink::stop(Box::new(log), EndReason::UserStop).unwrap();
        let stopped = report(Lifecycle::Stopped);
        assert_eq!(stopped.text(), "stopped");
        assert!(
            launch_admission(state, session)
                .unwrap_err()
                .to_string()
                .contains(STOPPED_REFUSAL)
        );
        // The report's wire shape: `state` always, the rest only when set.
        assert_eq!(
            serde_json::to_string(&LifecycleReport::of(Lifecycle::Running)).unwrap(),
            r#"{"state":"running","held_by":[],"open_launches":[]}"#
        );
        let back: LifecycleReport = serde_json::from_str(r#"{"state":"incomplete"}"#).unwrap();
        assert_eq!(back, LifecycleReport::of(Lifecycle::Incomplete));
        assert_eq!(
            serde_json::to_string(&stop_incomplete).unwrap(),
            r#"{"state":"incomplete","detail":"1 process(es) not confirmed ended","held_by":["stop"],"open_launches":[]}"#
        );
    }

    /// An intent, an owners record or a register that cannot be read refuses
    /// a launch rather than admitting it on a guess.
    #[test]
    fn unreadable_records_refuse_a_launch() {
        let dir = tempfile::tempdir().unwrap();
        let (state, session) = (dir.path(), "sess_bad");
        fs::create_dir_all(session_dir(state, session)).unwrap();
        fs::write(intent_path(state, session), b"{").unwrap();
        let refused = launch_admission(state, session).unwrap_err().to_string();
        assert!(
            refused.contains("could not read the session's lifecycle"),
            "{refused}"
        );
        assert!(lifecycle_on_disk(state, session).is_err());
        fs::remove_file(intent_path(state, session)).unwrap();
        assert!(launch_admission(state, session).is_ok());
        fs::write(crate::launches::path(state, session), b"{").unwrap();
        assert!(lifecycle_on_disk(state, session).is_err());
    }
}
