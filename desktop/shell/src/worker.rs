//! The shared per-session projection worker (#138 item 2): one process that
//! subscribes to the daemon once, keeps one [`Snapshot`], digests the
//! worktree on the same schedule `bar --waybar --follow` always has, and
//! serves every Waybar segment's JSON from that one cache over a local Unix
//! socket — instead of the six `ward-shell bar --waybar --segment …
//! --follow` processes Waybar spawns (`desktop/config/waybar/config.jsonc`)
//! each subscribing and digesting independently.
//!
//! `ward-shell worker` (`desktop/systemd/user/wardos-shell-worker.service`,
//! bound to the graphical session the same way `wardos-approve.service` is,
//! and started before `waybar` execs — `desktop/hyprland/autostart.conf`)
//! runs [`run`]. `bar --waybar --follow` calls [`relay_from_worker`] first
//! and only falls back to subscribing itself (`main.rs`'s own `waybar`,
//! unchanged) when nothing answers there even after
//! [`connect_with_retries`]'s bounded retries — a machine without the unit
//! installed, the gap between the worker exiting and systemd restarting it,
//! or an explicit `--dir`/`--tick-ms` the desktop-wide worker cannot serve
//! ([`crate::may_use_worker`]) — still draws a correct bar, just paying each
//! segment's own subscription (and, for the verify segment, digest) cost,
//! exactly as before this change.
//!
//! # Protocol
//! One request line: a segment name ([`SegmentName::as_str`]) or `bar` for
//! the whole row. Then newline-delimited [`Module`] JSON, one line per
//! change — the exact bytes `bar --waybar` always printed — until the worker
//! closes the connection, which happens when the session it was showing
//! ends; Waybar's own `restart-interval` asking again from a fresh process is
//! what finds whatever comes next, unchanged from today. No acknowledgement
//! and no framing beyond the newline: this is a same-host, single-user,
//! same-binary protocol the worker and every client are built from one
//! source tree, not a stable interface anything else speaks.
//!
//! # Failure
//! A worker that has not bound its socket *yet* (the cold-start race:
//! `autostart.conf` starts the unit before `waybar`, but a `systemctl start`
//! that has returned only means the process was forked, not that it has
//! reached `bind_socket`) is bridged by [`connect_with_retries`]'s bounded
//! retry, not by anything the worker does. A wedged worker (accepting
//! connections but never answering) is bounded by [`relay_from_worker`]'s
//! own handshake timeout, likewise not by the worker side, which
//! deliberately stays as simple as a bind, an accept loop and one session
//! loop, with no timeout or health-check logic of its own to get wrong. If
//! the worker process dies outright, systemd's `Restart=on-failure` starts a
//! new one and every client currently relaying sees its connection close,
//! which (via [`relay_from_worker`] returning `Ok(true)`, the same as a
//! closed session) makes that segment's process exit 0 for Waybar's
//! `restart-interval` to relaunch — again, unchanged from what a segment
//! losing its own daemon connection already did.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ward_daemon::client::{self, WatchEnd, WatchUpdate};
use ward_shell_core::{DigestGate, Module, SegmentName};

use crate::{
    DIGEST_DEBOUNCE, Digester, Located, Snapshot, TICK_MS, load_from, locate_quietly, module_at,
    now_unix_ms, observe_event,
};

/// File name of the worker's socket, next to `sessions/` under the state
/// directory.
const SOCKET_NAME: &str = "shell-worker.sock";

/// How often the worker looks for a session again while it has none, and
/// how long it pauses after one ends before looking for the next: the same
/// 2s `wardos-shell-worker.service`'s `RestartSec` would pace a worker that
/// exited by, and inside Waybar's own `restart-interval: 5` (`config.jsonc`),
/// so a session started while the bar's segments are being answered
/// [`Module::none`] is being served by the time they ask again — the worker
/// never asks faster than this, a session or not, which is what keeps a
/// desktop with no session (a headless run, a machine before its first
/// `ward up`) from becoming a spin on `locate`. A bounded poll rather than
/// an inotify wake-up: liveness here is a socket answering, not a file
/// appearing, and `ward-shell` carries no inotify binding of its own.
const NO_SESSION_POLL: Duration = Duration::from_secs(2);

/// How long [`relay_from_worker`] waits for the worker's first line before
/// giving up on it and falling back to a direct subscription: generous next
/// to a live worker's near-instant reply (its first frame is whatever is
/// already cached, no I/O on the request path), small next to Waybar's own
/// 5s `restart-interval`, so a wedged worker costs at most one slow frame,
/// not a module frozen until someone notices.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1000);

/// How many times [`relay_from_worker`] retries connecting to an absent or
/// refused worker socket, and how long it waits between tries, before
/// falling back to a direct subscription (review finding 1 on #331): a
/// cold-start race where a Waybar segment's `--follow` process execs and
/// asks before `wardos-shell-worker.service`'s own `bind_socket` call has
/// run — `autostart.conf` starts that unit before `waybar`, but a
/// `systemctl --user start` that has returned only means the unit's process
/// was forked, not that it has bound its socket yet, so the race is still
/// possible without this. Without a retry, the very first ask of that
/// process's whole lifetime would lose the race, `relay_from_worker` would
/// answer `Ok(false)` exactly once, and — because a `--follow` process picks
/// this once at the top of `waybar()` and then runs its (also long-lived)
/// direct subscription for the rest of that process's life — that one
/// segment would keep subscribing and digesting for itself until Waybar's
/// own `restart-interval` eventually respawns it, silently defeating this
/// item's whole point for however long that takes. Five tries, 20ms apart:
/// generous next to how fast a freshly-started worker actually binds (one
/// `bind(2)` and a `chmod`, no I/O on that path), small enough that a
/// genuinely absent worker (no unit installed, or still mid-restart past
/// this budget) adds well under 100ms before falling back — imperceptible
/// next to Waybar's own 5s `restart-interval`.
const CONNECT_RETRIES: u32 = 5;

/// The interval between [`CONNECT_RETRIES`] connect attempts.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// The worker's socket path under `state`.
fn socket_path(state: &Path) -> PathBuf {
    state.join(SOCKET_NAME)
}

/// [`UnixStream::connect`] with [`CONNECT_RETRIES`] bounded retries
/// ([`CONNECT_RETRY_INTERVAL`] apart) before giving up — the cold-start-race
/// mitigation [`CONNECT_RETRIES`]'s own doc comment explains. `None` only
/// after every attempt has failed.
fn connect_with_retries(path: &Path) -> Option<UnixStream> {
    for attempt in 0..CONNECT_RETRIES {
        match UnixStream::connect(path) {
            Ok(stream) => return Some(stream),
            Err(_) if attempt + 1 < CONNECT_RETRIES => {
                std::thread::sleep(CONNECT_RETRY_INTERVAL);
            }
            Err(_) => return None,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Client side: `bar --waybar --follow` relaying from a running worker.
// ---------------------------------------------------------------------------

/// Ask the worker at `state`'s socket for `segment` and copy every line it
/// sends to stdout verbatim until it closes the connection.
///
/// `Ok(true)`: the worker answered and this function ran the relay to
/// completion — the caller (`main.rs`'s `waybar`) is done, exactly as if it
/// had subscribed and printed the lines itself. `Ok(false)`: there is no
/// worker to ask — nothing answered a connect within
/// [`connect_with_retries`]'s bounded retries (covers the cold-start race:
/// not installed, or not bound yet), or it accepted but did not answer
/// within [`HANDSHAKE_TIMEOUT`] (wedged) — so the caller falls back to its
/// own subscription. `Err`: a real I/O failure *after* the worker had
/// already committed to answering (its first line arrived), mirroring how
/// the direct path propagates a failure from mid-subscription rather than
/// silently swallowing it.
pub(crate) fn relay_from_worker(
    state: &Path,
    segment: Option<SegmentName>,
) -> ward_daemon::Result<bool> {
    let Some(stream) = connect_with_retries(&socket_path(state)) else {
        return Ok(false);
    };
    let request = segment.map_or_else(|| "bar".to_owned(), |s| s.to_string());
    let Ok(mut writer) = stream.try_clone() else {
        return Ok(false);
    };
    if writeln!(writer, "{request}").is_err() {
        return Ok(false);
    }
    if stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).is_err() {
        return Ok(false);
    }
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    // The handshake: the worker's first line, within `HANDSHAKE_TIMEOUT`. Any
    // failure here (timeout, EOF, a transport error) means "cannot rely on
    // this worker right now" — falling back, never erroring, since the
    // direct path is always correct on its own.
    if reader.read_line(&mut line).is_err() || line.is_empty() {
        return Ok(false);
    }
    print_line(&line)?;
    // A live worker answered: the rest of this connection's lifetime has no
    // deadline, the same as the direct path's own blocking subscription — a
    // quiet session is not a wedged one, only a quiet one.
    reader
        .get_ref()
        .set_read_timeout(None)
        .map_err(|e| io_err(state, e))?;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return Ok(true), // the worker closed the connection: its session ended
            Ok(_) => print_line(&line)?,
            Err(e) => return Err(io_err(state, e)),
        }
    }
}

/// Print one already-newline-terminated line from the worker to stdout,
/// flushed, since Waybar (and, in the fallback path, the direct subscriber)
/// waits on it.
fn print_line(line: &str) -> ward_daemon::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(line.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| ward_daemon::Error::Io {
            path: PathBuf::from("<stdout>"),
            source: e,
        })
}

fn io_err(path: &Path, source: std::io::Error) -> ward_daemon::Error {
    ward_daemon::Error::Io {
        path: path.to_path_buf(),
        source,
    }
}

// ---------------------------------------------------------------------------
// Worker side: `ward-shell worker`.
// ---------------------------------------------------------------------------

/// Run the worker forever: bind the socket, accept segment relay clients on
/// their own threads, and keep one [`Snapshot`] fed from whichever session
/// [`wait_for_session`] finds, looking again every [`NO_SESSION_POLL`] while
/// there is none and pausing as long after one ends. Returns only if the
/// socket itself cannot be bound — a one-time startup failure; anything that
/// goes wrong with one session (`wardd` disappearing, a transient I/O error)
/// is logged to stderr and the loop moves on to look for the next one, since
/// a shared worker outliving any one session is the entire point of it
/// existing. Waiting, not exiting: `wardos-shell-worker.service` is
/// `Restart=on-failure`, pacing for a crash, and a worker that exited to get
/// that pacing would spin unpaced anywhere else it is run (a headless
/// desktop, a shell), while the segments it serves expect its socket to stay
/// bound and answer [`Module::none`] for as long as there is nothing to show.
pub(crate) fn run(dir: &Path, state: &Path, settle: Duration) -> ward_daemon::Result<()> {
    let shared = Shared::new();
    let listener = bind_socket(&socket_path(state))?;
    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || accept_loop(&listener, &shared));
    }
    loop {
        let socket = wait_for_session(
            || locate_quietly(dir),
            std::thread::sleep,
            |line| eprintln!("ward-shell: {line}"),
        );
        if let Err(e) = serve_session(&socket, settle, &shared) {
            eprintln!("ward-shell: worker: {e}");
        }
        shared.end_session();
        std::thread::sleep(NO_SESSION_POLL);
    }
}

/// Look for a session with `look` until one is found, pausing
/// [`NO_SESSION_POLL`] through `pause` after every look that found none —
/// never a spin, whatever `look` keeps answering. The reason there is no
/// session, or the error looking failed with, goes to `log` when it first
/// appears and again only when it changes, so a desktop with no session says
/// so once rather than once per poll. `pause` and `log` are passed in so the
/// loop's cadence and its output can be asserted without sleeping or
/// capturing stderr.
fn wait_for_session(
    mut look: impl FnMut() -> ward_daemon::Result<Located>,
    mut pause: impl FnMut(Duration),
    mut log: impl FnMut(&str),
) -> PathBuf {
    let mut last_logged: Option<String> = None;
    loop {
        let message = match look() {
            Ok(Located::Session(socket)) => return socket,
            Ok(Located::NoSession(reason)) => reason,
            Err(e) => format!("worker: {e}"),
        };
        if last_logged.as_deref() != Some(message.as_str()) {
            log(&message);
            last_logged = Some(message);
        }
        pause(NO_SESSION_POLL);
    }
}

/// Bind the worker's socket at `path`: a leftover file nothing answers on is
/// removed first (the worker's last run ended without cleaning up, e.g. a
/// `SIGKILL`); one something answers on means a worker is already serving —
/// `systemd`'s `Type=simple` unit means at most one instance normally runs,
/// so this only guards a manual second run.
fn bind_socket(path: &Path) -> ward_daemon::Result<UnixListener> {
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            return Err(ward_daemon::Error::Daemon(format!(
                "{}: another ward-shell worker is already serving it",
                path.display()
            )));
        }
        std::fs::remove_file(path).map_err(|e| io_err(path, e))?;
    } else if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    }
    let listener = UnixListener::bind(path).map_err(|e| io_err(path, e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| io_err(path, e))?;
    Ok(listener)
}

/// One session, start to end: load it, publish every segment's first module
/// together, then follow the stream exactly as `main.rs`'s own `waybar` does
/// for a single segment — just publishing every segment on each change
/// instead of the one segment that process happened to be.
fn serve_session(socket: &Path, settle: Duration, shared: &Shared) -> ward_daemon::Result<()> {
    let Some(mut snapshot) = load_from(socket, settle)? else {
        return Ok(()); // raced: `locate` found the socket file, nothing answered it now
    };
    // The worker always digests, unconditionally — unlike a solo segment
    // process ([`SegmentName::needs_freshness`], #138 item 3), which only
    // pays that cost when it is itself rendering the verify segment. The
    // worker cannot know in advance which segments will connect (Waybar's
    // six processes reconnect on their own schedule, independent of this
    // session loop starting), and a late-connecting verify subscriber must
    // never miss the freshness this session already has: one digest per
    // cycle regardless of subscriber count still satisfies the "hash/replay
    // work is independent of the number of visible segments" acceptance
    // criterion — it was already exactly one before this change too (the
    // verify segment's own solo process), just paid by a different process.
    let mut digester = Digester::new();
    digester.observe(&mut snapshot);
    shared.begin_session(compute_all(&snapshot, now_unix_ms()));
    if snapshot.model.sealed {
        return Ok(());
    }
    let mut gate = DigestGate::new();
    let from_seq = snapshot.model.records.last().map_or(0, |r| r.seq + 1);
    let subscriber = client::connect(socket)?;
    let mut last_force = Instant::now();
    let poll_tick = Duration::from_millis(TICK_MS).min(DIGEST_DEBOUNCE);
    let end = client::watch_records_ticking(subscriber, from_seq, poll_tick, |watched| {
        let rec = match watched {
            WatchUpdate::Record(rec) => Some(*rec),
            WatchUpdate::Tick => None,
            WatchUpdate::CaughtUp => {
                snapshot.model.mark_connected();
                None
            }
        };
        let at = Instant::now();
        let force =
            rec.is_none() && at.duration_since(last_force) >= Duration::from_millis(TICK_MS);
        if observe_event(
            &mut snapshot,
            Some(&mut digester),
            &mut gate,
            rec,
            at,
            DIGEST_DEBOUNCE,
            force,
        ) {
            last_force = at;
        }
        shared.publish(compute_all(&snapshot, now_unix_ms()));
    })?;
    match end {
        WatchEnd::Sealed { .. } => snapshot.model.seal(),
        WatchEnd::Closed { .. } | WatchEnd::CaughtUp { .. } => snapshot.model.mark_disconnected(),
    }
    shared.publish(compute_all(&snapshot, now_unix_ms()));
    Ok(())
}

/// Every segment's module, computed together from one snapshot at one
/// instant (#138 item 2's "same session id and state generation" acceptance
/// criterion): the whole bar (`None`) and each of [`SegmentName::ALL`], all
/// sharing one `now_unix_ms` — before this worker, each of the six processes
/// called its own `now_unix_ms()` independently, so two segments' rendered
/// durations could read a millisecond or more apart depending on scheduling,
/// however unlikely to be noticed; now they cannot disagree, because there is
/// only one value.
fn compute_all(s: &Snapshot, now_unix_ms: u64) -> BTreeMap<Option<SegmentName>, Module> {
    let mut out = BTreeMap::new();
    out.insert(None, module_at(s, None, now_unix_ms));
    for name in SegmentName::ALL {
        out.insert(Some(name), module_at(s, Some(name), now_unix_ms));
    }
    out
}

/// The worker's live state, shared between the accept loop (registers and
/// serves connecting clients) and the session loop ([`serve_session`], which
/// feeds it).
struct Shared {
    state: Mutex<State>,
    next_id: AtomicU64,
}

enum State {
    /// No session to show: every request gets [`Module::none`] and an
    /// immediate close — the same as `bar --waybar --follow` does today with
    /// nothing to follow.
    NoSession,
    /// A session is live (or has just sealed, on its way back to
    /// [`State::NoSession`] once its last frame is delivered): the cache a
    /// new subscriber's first frame comes from, and every subscriber
    /// currently waiting on a change.
    Serving {
        cache: BTreeMap<Option<SegmentName>, Module>,
        subscribers: std::collections::HashMap<u64, (Option<SegmentName>, mpsc::Sender<Module>)>,
    },
}

impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::NoSession),
            next_id: AtomicU64::new(0),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A new session's first computed frame: every request from here on is
    /// served from `cache`/`subscribers` until [`Self::end_session`].
    fn begin_session(&self, cache: BTreeMap<Option<SegmentName>, Module>) {
        *self.lock() = State::Serving {
            cache,
            subscribers: std::collections::HashMap::new(),
        };
    }

    /// A later frame of the same session: update the cache and hand every
    /// subscriber whose segment actually changed its new module — mirrors
    /// `bar --waybar`'s own "only print when the module changes" rule, just
    /// for every segment at once instead of the one a solo process happened
    /// to be rendering.
    fn publish(&self, fresh: BTreeMap<Option<SegmentName>, Module>) {
        let mut guard = self.lock();
        let State::Serving { cache, subscribers } = &mut *guard else {
            return; // a stray publish after `end_session`; nothing to update
        };
        for (segment, module) in fresh {
            let changed = cache.get(&segment) != Some(&module);
            cache.insert(segment, module.clone());
            if changed {
                for (sub_segment, tx) in subscribers.values() {
                    if *sub_segment == segment {
                        let _ = tx.send(module.clone());
                    }
                }
            }
        }
    }

    /// The session this worker was showing is done: drop every subscriber's
    /// channel (its `rx.recv()` in [`handle_client`] then returns `Err`,
    /// which closes that client's connection — Waybar's `restart-interval`
    /// asking again is what finds whatever comes next, unchanged from
    /// today) and go back to [`State::NoSession`] for the next `locate`.
    fn end_session(&self) {
        *self.lock() = State::NoSession;
    }

    /// Register `segment` for updates: `None` when there is no session (the
    /// caller sends [`Module::none`] itself and closes), else this
    /// subscriber's id, its channel, and the module to send as its first
    /// frame — the cache's current value for `segment`, so a subscriber that
    /// arrives mid-session still draws its first frame immediately, the same
    /// as a solo process's own pre-loop digest-and-emit did.
    fn register(
        &self,
        segment: Option<SegmentName>,
    ) -> Option<(u64, mpsc::Receiver<Module>, Module)> {
        let mut guard = self.lock();
        let State::Serving { cache, subscribers } = &mut *guard else {
            return None;
        };
        let initial = cache
            .get(&segment)
            .cloned()
            .unwrap_or_else(|| Module::none(segment));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        subscribers.insert(id, (segment, tx));
        Some((id, rx, initial))
    }

    fn unregister(&self, id: u64) {
        if let State::Serving { subscribers, .. } = &mut *self.lock() {
            subscribers.remove(&id);
        }
    }
}

/// Accept relay clients until the process exits (it never does on purpose):
/// each connection is handled on its own short-lived thread so one slow or
/// stuck client never blocks another from being accepted or served.
fn accept_loop(listener: &UnixListener, shared: &Arc<Shared>) {
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        let shared = Arc::clone(shared);
        std::thread::spawn(move || handle_client(stream, &shared));
    }
}

/// Serve one relay client: read its one request line, then either answer
/// [`Module::none`] and close (no session) or stream that segment's cached
/// module and every subsequent change until the session ends or the client
/// disconnects, whichever comes first.
fn handle_client(mut stream: UnixStream, shared: &Shared) {
    let Ok(peer) = stream.try_clone() else { return };
    let mut reader = BufReader::new(peer);
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return; // disconnected before sending a request
    }
    let segment = match parse_request(line.trim()) {
        Request::Bar => None,
        Request::Segment(name) => Some(name),
        Request::Invalid => {
            eprintln!("ward-shell: worker: bad request {line:?}");
            return;
        }
    };
    match shared.register(segment) {
        None => {
            write_module(&mut stream, &Module::none(segment));
        }
        Some((id, rx, initial)) => {
            if write_module(&mut stream, &initial) {
                while let Ok(module) = rx.recv() {
                    if !write_module(&mut stream, &module) {
                        break;
                    }
                }
            }
            shared.unregister(id);
        }
    }
}

/// A parsed request line — a plain `Option<Option<SegmentName>>` reads as two
/// stacked "nothing"s once `Invalid` joins the "no session" (`None` segment)
/// case it would otherwise share a variant with, so this spells the three
/// outcomes out instead.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    /// The whole bar (`"bar"`).
    Bar,
    /// One segment, by its [`SegmentName::as_str`] name.
    Segment(SegmentName),
    /// Neither — a line [`relay_from_worker`] would never send.
    Invalid,
}

/// `"bar"` for the whole row, else a [`SegmentName`] by its
/// [`SegmentName::as_str`] name — the inverse of [`relay_from_worker`]'s own
/// request line.
fn parse_request(s: &str) -> Request {
    if s == "bar" {
        Request::Bar
    } else {
        s.parse::<SegmentName>()
            .map_or(Request::Invalid, Request::Segment)
    }
}

/// One [`Module`] JSON line, flushed. `false` on any write failure (the
/// client disconnected, or its buffer is gone) — the caller stops sending to
/// it and unregisters rather than treating that as fatal to the worker.
fn write_module(stream: &mut UnixStream, module: &Module) -> bool {
    let Ok(line) = serde_json::to_string(module) else {
        return false;
    };
    writeln!(stream, "{line}")
        .and_then(|()| stream.flush())
        .is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::thread::JoinHandle;
    use ward_shell_core::{Header, Model, SessionDescription};

    fn description_fixture(worktree: &Path) -> SessionDescription {
        use ward_policy::{Policy, merge};
        let manifest = merge(
            &Policy::default(),
            &Policy::default(),
            &Policy::default(),
            ward_policy::SessionId("sess_01J8ZK3Q9X7VY2".to_owned()),
            ward_policy::ProjectId("proj_x".to_owned()),
        );
        SessionDescription {
            session: "sess_01J8ZK3Q9X7VY2".to_owned(),
            project: "proj_x".to_owned(),
            worktree: worktree.to_path_buf(),
            started_unix_ms: 0,
            agent: None,
            entry_snapshot: format!("blake3:{}", "ab".repeat(32)),
            policy_hash: manifest.policy_hash.to_hex(),
            manifest,
        }
    }

    /// A minimal described session with an empty stream, for tests that only
    /// need a real [`Snapshot`] to compute modules from, not any particular
    /// event history.
    fn snapshot_fixture(worktree: &Path) -> Snapshot {
        let description = description_fixture(worktree);
        Snapshot {
            header: Header::from_description(&description),
            description,
            model: Model::new(false),
        }
    }

    fn bar(text: &str) -> Module {
        Module {
            text: text.to_owned(),
            tooltip: String::new(),
            class: vec!["ink".to_owned()],
        }
    }

    #[test]
    fn a_new_session_serves_the_cached_module_immediately_and_only_pushes_real_changes() {
        let shared = Shared::new();
        shared.begin_session(BTreeMap::from([
            (None, bar("bar v1")),
            (Some(SegmentName::Agent), bar("agent v1")),
            (Some(SegmentName::Verify), bar("verify v1")),
        ]));

        let (id, rx, initial) = shared.register(Some(SegmentName::Agent)).unwrap();
        assert_eq!(initial, bar("agent v1"), "a late subscriber's first frame");

        // A publish that changes only the verify segment must not wake the
        // agent subscriber at all.
        shared.publish(BTreeMap::from([
            (None, bar("bar v1")),
            (Some(SegmentName::Agent), bar("agent v1")),
            (Some(SegmentName::Verify), bar("verify v2")),
        ]));
        assert!(
            rx.try_recv().is_err(),
            "unrelated segment changing must not notify this subscriber"
        );

        shared.publish(BTreeMap::from([
            (None, bar("bar v1")),
            (Some(SegmentName::Agent), bar("agent v2")),
            (Some(SegmentName::Verify), bar("verify v2")),
        ]));
        assert_eq!(rx.recv().unwrap(), bar("agent v2"));

        shared.unregister(id);
    }

    #[test]
    fn every_segment_of_one_publish_shares_one_instant_and_one_snapshot() {
        // #138 item 2's acceptance criterion, "all six modules share the same
        // session id and state generation": `compute_all` derives every
        // segment from one `&Snapshot` borrow and one `now_unix_ms`, so two
        // segments that both render a duration must always agree, never
        // "off by however long the scheduler happened to delay one of them"
        // the way six independent `now_unix_ms()` calls could.
        let s = snapshot_fixture(Path::new("/tmp/proj"));
        let all = compute_all(&s, 12_345);
        let bar = &all[&None];
        let session = &all[&Some(SegmentName::Session)];
        assert!(bar.tooltip.contains("Duration"), "{}", bar.tooltip);
        assert!(session.tooltip.contains("Duration"), "{}", session.tooltip);
        // Both were derived from the same `now_unix_ms` argument, so the
        // duration *value* each panel reports agrees exactly (the padding
        // differs: each panel's own label column width, unrelated to #138
        // item 2's invariant this test is checking).
        let duration_value = |m: &Module| {
            m.tooltip
                .lines()
                .find(|l| l.starts_with("Duration"))
                .and_then(|l| l.split_whitespace().last())
                .unwrap()
                .to_owned()
        };
        assert_eq!(duration_value(bar), duration_value(session));
    }

    #[test]
    fn a_session_ending_closes_every_subscriber_and_a_later_one_gets_none() {
        let shared = Shared::new();
        shared.begin_session(BTreeMap::from([(Some(SegmentName::Agent), bar("v1"))]));
        let (_id, rx, _initial) = shared.register(Some(SegmentName::Agent)).unwrap();

        shared.end_session();
        assert!(
            rx.recv().is_err(),
            "the channel closes when the session ends"
        );
        assert!(
            shared.register(Some(SegmentName::Agent)).is_none(),
            "no session means no registration, only Module::none"
        );
    }

    #[test]
    fn parse_request_accepts_bar_and_every_segment_name_and_rejects_junk() {
        assert_eq!(parse_request("bar"), Request::Bar);
        assert_eq!(parse_request("agent"), Request::Segment(SegmentName::Agent));
        assert_eq!(
            parse_request("verify"),
            Request::Segment(SegmentName::Verify)
        );
        assert_eq!(parse_request(""), Request::Invalid);
        assert_eq!(parse_request("clock"), Request::Invalid);
    }

    /// The idle loop behind `run` while there is nothing to serve: one
    /// bounded pause after every empty look (never a spin on `locate`), and
    /// the reason said once, when it first appears — not once per poll, which
    /// is a line every [`NO_SESSION_POLL`] for as long as the desktop has no
    /// session, and a filled disk the moment the pause is ever lost.
    #[test]
    fn waiting_for_a_session_pauses_one_interval_per_empty_look_and_logs_the_reason_once() {
        let reason = "no session for . and no live session anywhere; run `ward up` to start one";
        let mut looks = 0;
        let mut pauses = Vec::new();
        let mut logged = Vec::new();
        let socket = wait_for_session(
            || {
                looks += 1;
                Ok(if looks < 4 {
                    Located::NoSession(reason.to_owned())
                } else {
                    Located::Session(PathBuf::from("/state/sessions/s/control.sock"))
                })
            },
            |pause| pauses.push(pause),
            |line| logged.push(line.to_owned()),
        );
        assert_eq!(socket, PathBuf::from("/state/sessions/s/control.sock"));
        assert_eq!(
            pauses,
            vec![NO_SESSION_POLL; 3],
            "one bounded pause after each of the three empty looks, none after the hit"
        );
        assert_eq!(logged, vec![reason], "the reason once, not once per poll");
    }

    /// A reason or error that changes while waiting is news, and is logged
    /// again — once per change — including the same reason coming back
    /// after something else; the same one repeating is not.
    #[test]
    fn a_changed_reason_or_error_while_waiting_is_logged_once_per_change() {
        let mut outcomes = vec![
            Ok(Located::NoSession("nothing".to_owned())),
            Ok(Located::NoSession("nothing".to_owned())),
            Err(ward_daemon::Error::Daemon(
                "sessions dir unreadable".to_owned(),
            )),
            Err(ward_daemon::Error::Daemon(
                "sessions dir unreadable".to_owned(),
            )),
            Ok(Located::NoSession("nothing".to_owned())),
            Ok(Located::Session(PathBuf::from("/s"))),
        ]
        .into_iter();
        let mut pauses = 0;
        let mut logged = Vec::new();
        let socket = wait_for_session(
            || {
                outcomes
                    .next()
                    .expect("the session is found before the script runs out")
            },
            |_| pauses += 1,
            |line| logged.push(line.to_owned()),
        );
        assert_eq!(socket, PathBuf::from("/s"));
        assert_eq!(
            pauses, 5,
            "every empty or failed look is followed by one pause"
        );
        assert_eq!(
            logged,
            [
                "nothing",
                "worker: daemon: sessions dir unreadable",
                "nothing"
            ]
        );
    }

    /// A fake worker: a bare listener that accepts and reads the request line
    /// but never answers. `relay_from_worker` must give up by
    /// [`HANDSHAKE_TIMEOUT`] and report "no worker to ask", not hang forever
    /// or wrongly claim it handled the request.
    #[test]
    fn relay_falls_back_when_the_worker_accepts_but_never_answers() {
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(dir.path());
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                // Deliberately never write anything back; hold the
                // connection open past the client's handshake timeout.
                std::thread::sleep(HANDSHAKE_TIMEOUT * 2);
            }
        });
        let ok = relay_from_worker(dir.path(), Some(SegmentName::Agent)).unwrap();
        assert!(!ok, "a wedged worker must fall back, not hang");
        handle.join().unwrap();
    }

    #[test]
    fn relay_falls_back_when_nothing_is_listening() {
        let dir = tempfile::tempdir().unwrap();
        // Retried CONNECT_RETRIES times (review finding 1 on #331) before
        // giving up — still fast (well under a second) and still `Ok(false)`,
        // not an error, when truly nothing is ever going to answer.
        let ok = relay_from_worker(dir.path(), Some(SegmentName::Agent)).unwrap();
        assert!(!ok, "no socket at all must fall back, not error");
    }

    /// Review finding 1 on #331: several Waybar segment processes can ask
    /// before `wardos-shell-worker.service` has bound its socket at all
    /// (nothing merely wedged — genuinely not listening yet), the exact
    /// cold-start race `autostart.conf` starting the unit before `waybar`
    /// only narrows, never closes on its own. Every one of them must still
    /// converge on the worker once it *does* bind, within
    /// `connect_with_retries`'s bounded retry budget — not fall back to a
    /// direct subscription permanently for that process's whole lifetime,
    /// which is what a single, un-retried connect attempt would do.
    #[test]
    fn a_cold_start_race_still_converges_every_relay_client_onto_the_worker() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().to_path_buf();
        let path = socket_path(dir.path());

        // Three segment processes ask while nothing is listening at all —
        // not started via `fake_daemon_once`/`bind_socket`, deliberately: at
        // this instant the worker has not even called `UnixListener::bind`
        // yet, the actual race this test is about.
        let segments = [
            SegmentName::Agent,
            SegmentName::Verify,
            SegmentName::Project,
        ];
        let clients: Vec<JoinHandle<ward_daemon::Result<bool>>> = segments
            .iter()
            .map(|&segment| {
                let dir_path = dir_path.clone();
                std::thread::spawn(move || relay_from_worker(&dir_path, Some(segment)))
            })
            .collect();

        // Bind partway through the retry budget (CONNECT_RETRIES *
        // CONNECT_RETRY_INTERVAL = 100ms): late enough that a single,
        // un-retried connect from each thread above would already have
        // failed almost every time, comfortably inside the retry window a
        // real worker's near-instant startup easily beats in practice.
        std::thread::sleep(CONNECT_RETRY_INTERVAL * 2);
        let listener = UnixListener::bind(&path).unwrap();
        let shared = Shared::new();
        {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || accept_loop(&listener, &shared));
        }
        // No session is ever started: each client's request is answered
        // `Module::none` and closed at once (`Shared::register` on
        // `State::NoSession`), which is still `relay_from_worker` reaching
        // and being answered by the worker — `Ok(true)` — the only thing
        // this test asserts. What the worker answers with is covered by the
        // multiplexing tests above; this one is only about whether the
        // connection is reached at all under a cold start.
        for (client, segment) in clients.into_iter().zip(segments) {
            assert!(
                client.join().unwrap().unwrap(),
                "{segment}: must converge onto the worker, not fall back permanently"
            );
        }
    }

    /// An end-to-end pass: a real worker thread (bind, accept, one fake
    /// session) and two real `relay_from_worker` clients for different
    /// segments, over real Unix sockets — no fake daemon needed, since
    /// `Shared` is driven directly the way [`serve_session`] would drive it.
    #[test]
    fn two_relay_clients_for_different_segments_each_get_only_their_own_updates() {
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(dir.path());
        let listener = UnixListener::bind(&path).unwrap();
        let shared = Shared::new();
        {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || accept_loop(&listener, &shared));
        }
        shared.begin_session(BTreeMap::from([
            (Some(SegmentName::Agent), bar("agent v1")),
            (Some(SegmentName::Verify), bar("verify v1")),
        ]));

        let dir_path = dir.path().to_path_buf();
        let agent_client = std::thread::spawn({
            let dir_path = dir_path.clone();
            move || read_n_lines(&dir_path, Some(SegmentName::Agent), 2)
        });
        let verify_client =
            std::thread::spawn(move || read_n_lines(&dir_path, Some(SegmentName::Verify), 1));

        // Wait for both clients to actually register (review finding 4 on
        // #331: not a fixed sleep) before publishing, so the change below is
        // guaranteed to be seen as a change, not folded into either one's
        // first frame.
        wait_for_subscribers(&shared, 2);
        shared.publish(BTreeMap::from([
            (Some(SegmentName::Agent), bar("agent v2")),
            (Some(SegmentName::Verify), bar("verify v1")), // unchanged
        ]));
        shared.end_session();

        let agent_lines = agent_client.join().unwrap();
        let verify_lines = verify_client.join().unwrap();
        assert_eq!(agent_lines, vec![bar("agent v1"), bar("agent v2")]);
        assert_eq!(verify_lines, vec![bar("verify v1")]);
    }

    /// How long a test helper's blocking read or registration wait is given
    /// before it panics instead of hanging (review finding 4 on #331): a
    /// genuine regression must fail the suite loudly within one bounded
    /// wait, never stall it — generous next to how fast these in-process,
    /// no-I/O operations actually complete, small next to a CI timeout.
    const TEST_BOUND: Duration = Duration::from_secs(5);

    /// Connect to the worker at `dir`, ask for `segment`, and collect the
    /// first `n` [`Module`] lines it sends (test helper, not
    /// [`relay_from_worker`]: that one relays to stdout, this one collects
    /// for assertion). Bounded by [`TEST_BOUND`]: a line that never arrives
    /// is a test failure (a clear panic), not a hung test binary.
    fn read_n_lines(dir: &Path, segment: Option<SegmentName>, n: usize) -> Vec<Module> {
        let stream = UnixStream::connect(socket_path(dir)).unwrap();
        stream.set_read_timeout(Some(TEST_BOUND)).unwrap();
        let mut writer = stream.try_clone().unwrap();
        let request = segment.map_or_else(|| "bar".to_owned(), |s| s.to_string());
        writeln!(writer, "{request}").unwrap();
        let mut reader = BufReader::new(stream);
        (0..n)
            .map(|_| {
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .expect("a Module line within TEST_BOUND, not a hang");
                serde_json::from_str(&line).unwrap()
            })
            .collect()
    }

    /// Block until `shared` has exactly `n` registered subscribers, or panic
    /// after [`TEST_BOUND`] (review finding 4 on #331): the deterministic
    /// replacement for a fixed sleep before publishing a change a test
    /// expects every subscriber to see. A fixed sleep only assumes the
    /// scheduler runs the spawned client threads far enough to register
    /// within that window — not guaranteed, and wrong on a slow or
    /// contended runner: a client that registers *after* the publish would
    /// see the published value as its own first frame instead of a second,
    /// distinct line, and then block forever in [`read_n_lines`] waiting for
    /// a change that will never come, hanging the whole suite rather than
    /// failing the one test. Polling `shared`'s own subscriber count instead
    /// waits for the actual condition the test depends on, however long the
    /// scheduler takes, and still fails loudly (not silently) if it never
    /// arrives.
    fn wait_for_subscribers(shared: &Shared, n: usize) {
        let deadline = Instant::now() + TEST_BOUND;
        loop {
            let count = match &*shared.lock() {
                State::Serving { subscribers, .. } => subscribers.len(),
                State::NoSession => 0,
            };
            if count >= n {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out after {TEST_BOUND:?} waiting for {n} subscribers to register (got {count})"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// A minimal fake `wardd`: answers exactly the three connections
    /// [`serve_session`] opens through `load_from` (`Describe`, then a
    /// catch-up `Subscribe`) and its own live `Subscribe`, in that order.
    /// `client::connect` (`RemoteSink::connect`) starts every one of them
    /// with its own `Ping`/`Response::Ok` handshake before the real request,
    /// so each connection here answers that first. The third connection
    /// closes with nothing further sent after its handshake — the simplest
    /// "the daemon is gone" a real `serve_session` run can see
    /// (`WatchEnd::Closed`).
    fn fake_daemon_once(socket: &Path, description: SessionDescription) -> JoinHandle<()> {
        // Bound synchronously, before this function returns: the caller's
        // very next line is `serve_session`'s own `client::connect`, which
        // must never race the listener's own bind (a client that connects
        // before `bind` has run gets `ECONNREFUSED`, not a queued
        // connection).
        let listener = UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let reply = |stream: &mut UnixStream, r: &ward_daemon::control::Response| {
                let mut b = serde_json::to_vec(r).unwrap();
                b.push(b'\n');
                stream.write_all(&b).unwrap();
            };
            let handshake = |stream: &mut UnixStream, reader: &mut BufReader<UnixStream>| {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request: ward_daemon::control::Request = serde_json::from_str(&line).unwrap();
                assert!(
                    matches!(request, ward_daemon::control::Request::Ping),
                    "every `client::connect` starts with a Ping: got {request:?}"
                );
                reply(stream, &ward_daemon::control::Response::Ok);
            };
            let next_line = |reader: &mut BufReader<UnixStream>| -> String {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                line
            };

            // 1. `Describe`: Ping, then the real request.
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            handshake(&mut stream, &mut reader);
            let _ = next_line(&mut reader);
            reply(
                &mut stream,
                &ward_daemon::control::Response::Description(
                    serde_json::to_value(&description).unwrap(),
                ),
            );

            // 2. The catch-up `Subscribe`: Ping, then an empty backlog caught
            // up at once.
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            handshake(&mut stream, &mut reader);
            let _ = next_line(&mut reader);
            reply(
                &mut stream,
                &ward_daemon::control::Response::CaughtUp { next_seq: 0 },
            );
            drop(stream);

            // 3. The live `Subscribe`: Ping (`client::connect` inside
            // `serve_session` itself), then read its `Subscribe` request —
            // so that write has already landed before this end closes — and
            // close without answering it: a clean EOF the client reads as
            // `WatchEnd::Closed`, not a `Broken pipe` mid-write from closing
            // before the client's next send.
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            handshake(&mut stream, &mut reader);
            let _ = next_line(&mut reader);
            drop(stream);
        })
    }

    /// The wiring `serve_session` adds over `waybar()`'s own already-tested
    /// per-segment logic: it publishes every segment's first frame together
    /// through `Shared`, from one real subscribed [`Snapshot`] — exercised
    /// here end to end against a real (if minimal) fake daemon, not by
    /// driving `Shared` directly the way the multiplexing tests above do.
    /// `run`'s own `end_session()` after every `serve_session` call (not
    /// exercised here; covered directly by
    /// `a_session_ending_closes_every_subscriber_and_a_later_one_gets_none`)
    /// is what returns the worker to [`State::NoSession`] once this
    /// function's fake daemon closes the live subscribe.
    #[test]
    fn serve_session_publishes_every_segment_from_one_real_subscription() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        // A real, existing worktree: `serve_session` always digests
        // ("the worker always digests, unconditionally", above), and a
        // worktree that cannot be read is a distinct, logged outcome this
        // test is not about.
        let description = description_fixture(dir.path());
        let daemon = fake_daemon_once(&socket, description);

        let shared = Shared::new();
        serve_session(&socket, Duration::from_millis(200), &shared).unwrap();
        daemon.join().unwrap();

        // Still `Serving` (the caller, `run`, is what calls `end_session`
        // afterwards): every segment's module was published from the one
        // subscribed snapshot, not left uncomputed or only the segment a
        // solo process would have rendered.
        let (_id, _rx, agent) = shared.register(Some(SegmentName::Agent)).unwrap();
        assert_eq!(agent.text, "");
        assert_eq!(agent.class, ["none"], "no agent record arrived: none");
        let (_id, _rx, whole_bar) = shared.register(None).unwrap();
        assert!(whole_bar.text.contains("WARD"), "{}", whole_bar.text);
        assert!(
            whole_bar.text.contains("UNKNOWN") && !whole_bar.text.contains("SEALED"),
            "a live subscription the daemon closed without a seal is unknown, never sealed: {}",
            whole_bar.text
        );
        assert!(
            whole_bar.class.iter().any(|c| c == "unknown"),
            "{:?}",
            whole_bar.class
        );
    }
}
