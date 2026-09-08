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

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use ward_events::PauseMethod;

use crate::error::{Error, Result};
use crate::session::{run_dir_path, session_dir};

/// File name of the pause marker inside `sessions/<id>/`.
pub const MARKER: &str = "paused";
/// Where cgroup v2 is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// How long a cgroup freeze is given to settle before it is trusted.
const FREEZE_SETTLE: Duration = Duration::from_secs(1);

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
#[derive(Debug)]
#[must_use = "the freeze lasts only while the guard is held"]
pub struct CaptureFreeze {
    frozen: Option<Frozen>,
}

impl CaptureFreeze {
    /// Freeze `session`'s sandbox for a capture, unless it is already paused by
    /// the user (whose freeze must outlive the capture).
    pub fn acquire(state: &Path, session: &str) -> Self {
        if marker_path(state, session).exists() {
            return Self { frozen: None };
        }
        let frozen = freeze(session);
        let _ = wait_settled(&frozen);
        Self {
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
        if let Some(frozen) = &self.frozen {
            thaw(frozen);
        }
    }
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
/// to report the freeze settled.
fn freeze_cgroup(dir: &Path, pids: &[u32]) -> std::io::Result<()> {
    for pid in pids {
        fs::write(dir.join("cgroup.procs"), pid.to_string())?;
    }
    fs::write(dir.join("cgroup.freeze"), "1")?;
    let deadline = Instant::now() + FREEZE_SETTLE;
    loop {
        let events = fs::read_to_string(dir.join("cgroup.events")).unwrap_or_default();
        if events.lines().any(|l| l == "frozen 1") || pids.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other("cgroup did not freeze in time"));
        }
        std::thread::sleep(Duration::from_millis(20));
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
}
