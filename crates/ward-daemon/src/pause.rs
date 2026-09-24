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
//! **Launch admission** ([`admit_launch`], PR #253 review finding 2) takes the
//! same session lock ([`lock_pause_freeze`]) pause, resume, stop and the
//! capture freeze take, and holds it across the `bwrap` spawn; the stop marker
//! ([`STOP_MARKER`]), written under that lock when a stop begins, refuses
//! every later launch. A launch therefore either exists before a stop scans
//! (and is ended by it) or never spawns.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use ward_events::PauseMethod;

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
    if stop_begun(state, session) {
        return Err(Error::Sandbox(STOPPED_REFUSAL.into()));
    }
    if marker_path(state, session).exists() {
        return Err(Error::Sandbox(PAUSED_REFUSAL.into()));
    }
    Ok(lock)
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
/// process runs no code, so it cannot fork, and a child created by a fork that
/// was already in flight still has that stopped parent as its parent, so the
/// tree walk finds it. Membership is also taken from the sandbox's own pid
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
        |fresh| match &cgroup {
            // A process moved into a frozen cgroup is frozen by the kernel.
            Some(dir) => {
                for pid in fresh {
                    let _ = fs::write(dir.join("cgroup.procs"), pid.to_string());
                }
            }
            None => freeze_signals(fresh),
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
    mut freeze_more: impl FnMut(&[u32]),
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
            freeze_more(&fresh);
            // Newest first: whatever was found late is a child (or an orphan)
            // of something already held, so it still comes before its parent.
            let mut merged = fresh;
            merged.extend(pids.iter().copied());
            *pids = merged;
            if Instant::now() >= deadline {
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
/// (`State: T`/`t`) or already gone. The cgroup freezer is synchronous —
/// [`freeze_cgroup`] already waited on `cgroup.events` — so only the signal
/// path polls, because `SIGSTOP` is delivered asynchronously and a capture that
/// began the instant [`freeze`] returned could still race a not-yet-stopped
/// process. Bounded by [`FREEZE_SETTLE`]; returns whether every pid settled.
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
/// `proc`, or a zombie / dead entry waiting only to be reaped (it runs no code,
/// so it can neither fork nor stop).
fn stopped_or_gone(proc: &Path, pid: u32) -> bool {
    match fs::read_to_string(proc.join(pid.to_string()).join("stat")) {
        Ok(stat) => matches!(proc_state(&stat), Some('T' | 't' | 'Z' | 'X' | 'x')),
        Err(_) => true,
    }
}

/// The state character of a `/proc/<pid>/stat` line: the field after the
/// parenthesised command name (which may itself hold spaces and parentheses,
/// so the last `)` is the anchor, as in [`parent_of`]).
fn proc_state(stat: &str) -> Option<char> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().next()?.chars().next()
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
        ended,
        remaining: (!pending.is_empty()).then_some(Frozen {
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
        let dir = session_dir(state, session);
        let _lock = lock_pause_freeze(&dir);
        if marker_path(state, session).exists() {
            return Self {
                state: state.to_path_buf(),
                session: session.to_owned(),
                frozen: None,
            };
        }
        let frozen = freeze(session);
        let _ = wait_settled(&frozen);
        Self {
            state: state.to_path_buf(),
            session: session.to_owned(),
            frozen: Some(frozen),
        }
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
        fs::copy("/bin/sh", &bwrap).unwrap();
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
            |_| events.borrow_mut().push("stop-late"),
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
}
