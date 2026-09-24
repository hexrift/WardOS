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
//! freeze them (unless a pause already holds them), kill every process, and
//! watch until each is confirmed gone, bounded by [`STOP_SETTLE`]. `ward stop`
//! seals the log only after that confirmation; a stop that could not confirm it
//! is refused and the session is held paused instead.

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
#[must_use]
pub fn freeze(session: &str) -> Frozen {
    let pids = sandbox_pids(Path::new("/proc"), session);
    if let Some(dir) = select_cgroup(own_cgroup().as_deref(), session) {
        if freeze_cgroup(&dir, &pids).is_ok() {
            return Frozen {
                method: PauseMethod::CgroupFreezer,
                pids,
                cgroup: Some(dir),
            };
        }
        // The cgroup exists but will not take the tree (a controller rule, a
        // pid that moved): thaw whatever went in and use signals instead.
        let _ = fs::write(dir.join("cgroup.freeze"), "0");
        let _ = fs::remove_dir(&dir);
    }
    freeze_signals(&pids);
    Frozen {
        method: PauseMethod::Sigstop,
        pids,
        cgroup: None,
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

/// Whether `pid` is stopped (`SIGSTOP` took hold) or no longer exists.
fn stopped_or_gone(proc: &Path, pid: u32) -> bool {
    match fs::read_to_string(proc.join(pid.to_string()).join("stat")) {
        Ok(stat) => matches!(proc_state(&stat), Some('T' | 't')),
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
}

impl Termination {
    /// Nothing ran, nothing was touched.
    #[must_use]
    pub const fn nothing() -> Self {
        Self {
            ended: 0,
            remaining: None,
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
#[must_use]
pub fn terminate(session: &str, held: Option<Frozen>) -> Termination {
    let proc = Path::new("/proc");
    let frozen = match held {
        Some(frozen) => frozen,
        None if sandbox_pids(proc, session).is_empty() => return Termination::nothing(),
        None => freeze(session),
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
/// perform (#234). Same idiom as `attempt.rs`'s `lock_session_reconciliation`/
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
/// run directory.
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
    pids
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
        // `run_dir_path` keys on the last ten characters: keep them unique per
        // fixture and per process so parallel tests never see each other's tree.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 10_000;
        Self::spawn_for(&format!(
            "{stem}_{n:04}{:06}",
            std::process::id() % 1_000_000
        ))
    }

    /// [`Self::spawn`] for an existing session id (a real `Session`'s own).
    #[allow(clippy::unwrap_used, clippy::panic)]
    pub(crate) fn spawn_for(session: &str) -> Self {
        let session = session.to_owned();
        let bin = tempfile::tempdir().unwrap();
        let bwrap = bin.path().join("bwrap");
        fs::copy("/bin/sh", &bwrap).unwrap();
        let child = std::process::Command::new(&bwrap)
            .args(["-c", "while :; do sleep 0.05; done"])
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
