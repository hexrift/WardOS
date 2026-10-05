//! Freezing and thawing one launch's process tree by signal (node `pause` and `resume`).
//!
//! The tree is rooted at the host pid of the launch's outer `bwrap`
//! ([`RunningLaunch::tree_root`](crate::RunningLaunch::tree_root)) and found by walking
//! `/proc` parent links. Because every launch unshares its pid namespace, an orphan inside
//! the sandbox is reparented to the sandbox's own init, which is in the tree, so the walk
//! reaches every process of the sandbox.
//!
//! [`freeze_tree`] sends `SIGSTOP` children first, so no parent can react to a child
//! stopping, then settles the freeze within a bound: it waits until every known process
//! is stopped, ended, or held in vfork wait on a stopped child (#352), rescans the tree,
//! and freezes anything the rescan finds that it does not hold yet (a child forked while
//! its parent's `SIGSTOP` was still in flight). A rescan taken while every known process
//! is stopped and adding nothing closes the set: nothing in it runs, so nothing can fork.
//! A freeze that cannot be confirmed within the bound is thawed back and reported
//! [`FreezeError::Unsettled`]. [`thaw_tree`] sends `SIGCONT` parents first and confirms
//! no process of the tree is still stopped.
//!
//! Only signals are used: a launch runs in its parent's cgroup and nothing here creates a
//! delegated cgroup, so the cgroup v2 freezer is not available to it. The root is
//! identified by pid and start time, so a pid reused after the root was reaped is never
//! signalled.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// Default bound on how long a freeze or a thaw is given to be confirmed.
pub const FREEZE_SETTLE: Duration = Duration::from_secs(1);

const SETTLE_POLL: Duration = Duration::from_millis(5);

const MAX_TREE_DEPTH: usize = 256;

/// The names `/proc/<pid>/wchan` gives a task waiting for its vfork child to `exec` or
/// exit: `wait_for_vfork_done`, or `kernel_clone` on kernels that inline it.
const VFORK_WAIT_WCHANS: [&str; 2] = ["wait_for_vfork_done", "kernel_clone"];

/// The root of a process tree: its pid and the start time `/proc` reports for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeRoot {
    pid: u32,
    start_time: u64,
}

impl TreeRoot {
    /// The live process `pid`, identified by its start time; `None` if it is gone.
    #[must_use]
    pub fn of(pid: u32) -> Option<Self> {
        Self::of_in(Path::new("/proc"), pid)
    }

    fn of_in(proc: &Path, pid: u32) -> Option<Self> {
        let stat = read_stat(proc, pid)?;
        Some(Self {
            pid,
            start_time: start_time(&stat)?,
        })
    }

    /// The root's host pid.
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    fn alive_in(self, proc: &Path) -> bool {
        read_stat(proc, self.pid).and_then(|stat| start_time(&stat)) == Some(self.start_time)
    }
}

/// Why a process tree was not frozen. Nothing is left stopped in either case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FreezeError {
    /// The root process is gone: the tree has ended.
    #[error("the process tree has ended")]
    Gone,
    /// The tree could not be confirmed stopped within the bound; it was thawed back.
    #[error("the process tree could not be confirmed stopped")]
    Unsettled,
}

/// A process tree confirmed stopped by [`freeze_tree`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenTree {
    root: TreeRoot,
    pids: Vec<u32>,
}

impl FrozenTree {
    /// The tree's root.
    #[must_use]
    pub const fn root(&self) -> TreeRoot {
        self.root
    }

    /// Every process stopped, children before their parents.
    #[must_use]
    pub fn pids(&self) -> &[u32] {
        &self.pids
    }
}

/// Stop every process of the tree under `root` and confirm it within `settle`.
///
/// # Errors
///
/// Returns [`FreezeError::Gone`] if the root has ended, and [`FreezeError::Unsettled`]
/// if the freeze could not be confirmed in time; either way every process signalled has
/// been continued again.
pub fn freeze_tree(root: TreeRoot, settle: Duration) -> Result<FrozenTree, FreezeError> {
    freeze_tree_with(Path::new("/proc"), root, settle, send)
}

/// Continue every process of `frozen`'s tree, parents first, and confirm within `settle`
/// that none is still stopped. A tree whose root has ended is trivially thawed.
#[must_use]
pub fn thaw_tree(frozen: &FrozenTree, settle: Duration) -> bool {
    thaw_tree_with(Path::new("/proc"), frozen, settle, send)
}

fn send(pid: u32, signal: Signal) {
    if let Ok(raw) = i32::try_from(pid)
        && raw > 0
    {
        let _ = kill(Pid::from_raw(raw), signal);
    }
}

fn freeze_tree_with(
    proc: &Path,
    root: TreeRoot,
    settle: Duration,
    mut signal: impl FnMut(u32, Signal),
) -> Result<FrozenTree, FreezeError> {
    if !root.alive_in(proc) {
        return Err(FreezeError::Gone);
    }
    let mut pids = tree(proc, root.pid);
    for pid in &pids {
        signal(*pid, Signal::SIGSTOP);
    }
    let deadline = Instant::now().checked_add(settle);
    loop {
        if !root.alive_in(proc) {
            continue_parents_first(&pids, &mut signal);
            return Err(FreezeError::Gone);
        }
        if pids.iter().all(|&pid| stopped_or_gone(proc, pid)) {
            let fresh: Vec<u32> = tree(proc, root.pid)
                .into_iter()
                .filter(|pid| !pids.contains(pid))
                .collect();
            if fresh.is_empty() {
                return Ok(FrozenTree { root, pids });
            }
            for pid in &fresh {
                signal(*pid, Signal::SIGSTOP);
            }
            let mut merged = fresh;
            merged.extend(pids);
            pids = merged;
        }
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            continue_parents_first(&pids, &mut signal);
            return Err(FreezeError::Unsettled);
        }
        std::thread::sleep(SETTLE_POLL);
    }
}

fn continue_parents_first(pids: &[u32], signal: &mut impl FnMut(u32, Signal)) {
    for pid in pids.iter().rev() {
        signal(*pid, Signal::SIGCONT);
    }
}

fn thaw_tree_with(
    proc: &Path,
    frozen: &FrozenTree,
    settle: Duration,
    mut signal: impl FnMut(u32, Signal),
) -> bool {
    if !frozen.root.alive_in(proc) {
        return true;
    }
    let mut pids = tree(proc, frozen.root.pid);
    for pid in &frozen.pids {
        if !pids.contains(pid) {
            pids.insert(0, *pid);
        }
    }
    continue_parents_first(&pids, &mut signal);
    let deadline = Instant::now().checked_add(settle);
    loop {
        if pids.iter().all(|&pid| !stopped(proc, pid)) {
            return true;
        }
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            return false;
        }
        std::thread::sleep(SETTLE_POLL);
    }
}

fn stopped(proc: &Path, pid: u32) -> bool {
    read_stat(proc, pid)
        .and_then(|stat| proc_state(&stat))
        .is_some_and(|state| matches!(state, 'T' | 't'))
}

fn read_stat(proc: &Path, pid: u32) -> Option<String> {
    fs::read_to_string(proc.join(pid.to_string()).join("stat")).ok()
}

/// The fields of a `/proc/<pid>/stat` line after the command name, which may itself hold
/// spaces and parentheses, so the last `)` is the anchor.
fn stat_fields(stat: &str) -> Option<std::str::SplitWhitespace<'_>> {
    stat.get(stat.rfind(')')?.checked_add(1)?..)
        .map(str::split_whitespace)
}

fn proc_state(stat: &str) -> Option<char> {
    stat_fields(stat)?.next()?.chars().next()
}

fn parent_of(stat: &str) -> Option<u32> {
    stat_fields(stat)?.nth(1)?.parse().ok()
}

fn thread_count(stat: &str) -> Option<u32> {
    stat_fields(stat)?.nth(17)?.parse().ok()
}

fn start_time(stat: &str) -> Option<u64> {
    stat_fields(stat)?.nth(19)?.parse().ok()
}

fn proc_pids(proc: &Path) -> Vec<u32> {
    fs::read_dir(proc)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// `root` and every descendant under `proc`, deepest first, the root last; empty if the
/// root is gone.
fn tree(proc: &Path, root: u32) -> Vec<u32> {
    if read_stat(proc, root).is_none() {
        return Vec::new();
    }
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for pid in proc_pids(proc) {
        if let Some(parent) = read_stat(proc, pid).and_then(|stat| parent_of(&stat)) {
            children.entry(parent).or_default().push(pid);
        }
    }
    for siblings in children.values_mut() {
        siblings.sort_unstable();
    }
    let mut out = Vec::new();
    post_order(root, &children, &mut out, 0);
    out
}

fn post_order(pid: u32, children: &BTreeMap<u32, Vec<u32>>, out: &mut Vec<u32>, depth: usize) {
    if depth > MAX_TREE_DEPTH || out.contains(&pid) {
        return;
    }
    for child in children.get(&pid).into_iter().flatten() {
        post_order(*child, children, out, depth.saturating_add(1));
    }
    out.push(pid);
}

/// What the settle check reads of one process.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcFacts {
    pid: u32,
    ppid: u32,
    state: char,
    threads: Option<u32>,
    wchan: Option<String>,
}

fn proc_facts(proc: &Path, pid: u32, stat: &str) -> Option<ProcFacts> {
    let state = proc_state(stat)?;
    let wchan = (state == 'D')
        .then(|| fs::read_to_string(proc.join(pid.to_string()).join("wchan")).ok())
        .flatten()
        .map(|wchan| wchan.trim().to_owned());
    Some(ProcFacts {
        pid,
        ppid: parent_of(stat)?,
        state,
        threads: thread_count(stat),
        wchan,
    })
}

const fn stopped_or_ended(state: char) -> bool {
    matches!(state, 'T' | 't' | 'Z' | 'X' | 'x')
}

fn in_vfork_wait(facts: &ProcFacts) -> bool {
    facts.state == 'D'
        && facts.threads == Some(1)
        && facts
            .wchan
            .as_deref()
            .is_some_and(|wchan| VFORK_WAIT_WCHANS.contains(&wchan))
}

/// Whether `pid` can make no progress: gone, stopped or ended, or held in vfork wait while
/// its children are all stopped or ended and at least one of them is stopped (#352).
fn frozen_from(pid: u32, facts: &[ProcFacts]) -> bool {
    let Some(target) = facts.iter().find(|facts| facts.pid == pid) else {
        return true;
    };
    if stopped_or_ended(target.state) {
        return true;
    }
    if !in_vfork_wait(target) {
        return false;
    }
    let mut children = facts
        .iter()
        .filter(|facts| facts.ppid == pid && facts.pid != pid);
    children
        .clone()
        .any(|child| matches!(child.state, 'T' | 't'))
        && children.all(|child| stopped_or_ended(child.state))
}

fn children_facts(proc: &Path, parent: u32) -> Vec<ProcFacts> {
    proc_pids(proc)
        .into_iter()
        .filter(|&pid| pid != parent)
        .filter_map(|pid| {
            let stat = read_stat(proc, pid)?;
            proc_facts(proc, pid, &stat).filter(|facts| facts.ppid == parent)
        })
        .collect()
}

/// Whether `pid` is confirmed stopped or no longer runs. A vfork hold is read once more
/// after its children, so a child that `exec`ed and released it in between is not missed.
fn stopped_or_gone(proc: &Path, pid: u32) -> bool {
    let Some(stat) = read_stat(proc, pid) else {
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
        && read_stat(proc, pid)
            .and_then(|again| proc_facts(proc, pid, &again))
            .is_some_and(|again| in_vfork_wait(&again))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::cell::RefCell;
    use std::path::PathBuf;

    use super::*;

    struct FakeProc {
        dir: tempfile::TempDir,
    }

    impl FakeProc {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn path(&self) -> PathBuf {
            self.dir.path().to_path_buf()
        }

        fn set(&self, pid: u32, parent: u32, state: char) {
            self.set_full(pid, parent, state, 1, 100 + u64::from(pid));
        }

        fn set_full(&self, pid: u32, parent: u32, state: char, threads: u32, start: u64) {
            let dir = self.dir.path().join(pid.to_string());
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("stat"),
                format!(
                    "{pid} (a (b) c) {state} {parent} 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 {threads} 0 {start} 0\n"
                ),
            )
            .unwrap();
        }

        fn wchan(&self, pid: u32, wchan: &str) {
            fs::write(self.dir.path().join(pid.to_string()).join("wchan"), wchan).unwrap();
        }

        fn remove(&self, pid: u32) {
            fs::remove_dir_all(self.dir.path().join(pid.to_string())).unwrap();
        }

        fn state(&self, pid: u32) -> char {
            proc_state(&read_stat(self.dir.path(), pid).unwrap()).unwrap()
        }

        fn ppid(&self, pid: u32) -> u32 {
            parent_of(&read_stat(self.dir.path(), pid).unwrap()).unwrap()
        }

        fn signal(&self, pid: u32, signal: Signal) {
            let parent = self.ppid(pid);
            match signal {
                Signal::SIGSTOP => self.set(pid, parent, 'T'),
                Signal::SIGCONT => self.set(pid, parent, 'S'),
                _ => {}
            }
        }
    }

    fn sandbox() -> FakeProc {
        let proc = FakeProc::new();
        proc.set(1, 0, 'S');
        proc.set(10, 1, 'S');
        proc.set(11, 10, 'S');
        proc.set(12, 11, 'S');
        proc.set(13, 11, 'R');
        proc.set(20, 1, 'S');
        proc
    }

    #[test]
    fn stat_parsing_anchors_on_the_last_parenthesis() {
        let stat = "42 (a (b) c) S 7 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 3 0 12345 0\n";
        assert_eq!(proc_state(stat), Some('S'));
        assert_eq!(parent_of(stat), Some(7));
        assert_eq!(thread_count(stat), Some(3));
        assert_eq!(start_time(stat), Some(12_345));
        assert_eq!(proc_state("garbage"), None);
    }

    #[test]
    fn the_tree_lists_descendants_children_first_and_the_root_last() {
        let proc = sandbox();
        assert_eq!(tree(&proc.path(), 10), vec![12, 13, 11, 10]);
        assert_eq!(tree(&proc.path(), 99), Vec::<u32>::new());
    }

    #[test]
    fn a_root_is_identified_by_its_start_time() {
        let proc = sandbox();
        let root = TreeRoot::of_in(&proc.path(), 10).unwrap();
        assert_eq!(root.pid(), 10);
        assert!(root.alive_in(&proc.path()));
        proc.set_full(10, 1, 'S', 1, 999);
        assert!(!root.alive_in(&proc.path()));
        proc.remove(10);
        assert!(!root.alive_in(&proc.path()));
        assert_eq!(TreeRoot::of_in(&proc.path(), 10), None);
    }

    #[test]
    fn the_settle_check_accepts_stopped_ended_gone_and_vfork_held_processes() {
        let proc = sandbox();
        let path = proc.path();
        for state in ['T', 't', 'Z', 'X'] {
            proc.set(12, 11, state);
            assert!(stopped_or_gone(&path, 12), "{state}");
        }
        for state in ['S', 'R', 'D'] {
            proc.set(12, 11, state);
            assert!(!stopped_or_gone(&path, 12), "{state}");
        }
        assert!(stopped_or_gone(&path, 77));

        proc.set(13, 11, 'T');
        proc.set(12, 11, 'T');
        proc.set(11, 10, 'D');
        proc.wchan(11, "wait_for_vfork_done");
        assert!(stopped_or_gone(&path, 11), "vfork wait on stopped children");
        proc.wchan(11, "kernel_clone");
        assert!(stopped_or_gone(&path, 11));
        proc.wchan(11, "do_sys_poll");
        assert!(!stopped_or_gone(&path, 11), "any other D wait runs");
        proc.wchan(11, "wait_for_vfork_done");
        proc.set(13, 11, 'R');
        assert!(!stopped_or_gone(&path, 11), "a running child releases it");
        proc.set(13, 11, 'Z');
        proc.set(12, 11, 'Z');
        assert!(!stopped_or_gone(&path, 11), "no stopped child holds it");
        proc.set(12, 11, 'T');
        proc.set_full(11, 10, 'D', 2, 111);
        proc.wchan(11, "wait_for_vfork_done");
        assert!(
            !stopped_or_gone(&path, 11),
            "multi-threaded is never trusted"
        );
    }

    #[test]
    fn freeze_stops_children_first_and_confirms_the_tree() {
        let proc = sandbox();
        let root = TreeRoot::of_in(&proc.path(), 10).unwrap();
        let sent = RefCell::new(Vec::new());
        let frozen = freeze_tree_with(&proc.path(), root, FREEZE_SETTLE, |pid, signal| {
            sent.borrow_mut().push((pid, signal));
            proc.signal(pid, signal);
        })
        .unwrap();
        assert_eq!(frozen.root(), root);
        assert_eq!(frozen.pids(), &[12, 13, 11, 10]);
        assert_eq!(
            sent.into_inner(),
            vec![
                (12, Signal::SIGSTOP),
                (13, Signal::SIGSTOP),
                (11, Signal::SIGSTOP),
                (10, Signal::SIGSTOP),
            ]
        );
        for pid in [10, 11, 12, 13] {
            assert_eq!(proc.state(pid), 'T');
        }
        assert_eq!(proc.state(20), 'S', "outside the tree");
    }

    #[test]
    fn freeze_also_stops_a_child_forked_while_its_parent_was_stopping() {
        let proc = sandbox();
        let root = TreeRoot::of_in(&proc.path(), 10).unwrap();
        let forked = RefCell::new(false);
        let frozen = freeze_tree_with(&proc.path(), root, FREEZE_SETTLE, |pid, signal| {
            proc.signal(pid, signal);
            if pid == 11 && !forked.replace(true) {
                proc.set(14, 11, 'R');
            }
        })
        .unwrap();
        assert_eq!(frozen.pids(), &[14, 12, 13, 11, 10]);
        assert_eq!(proc.state(14), 'T');
    }

    #[test]
    fn an_unconfirmed_freeze_is_thawed_back_and_refused() {
        let proc = sandbox();
        let root = TreeRoot::of_in(&proc.path(), 10).unwrap();
        let sent = RefCell::new(Vec::new());
        let result = freeze_tree_with(
            &proc.path(),
            root,
            Duration::from_millis(50),
            |pid, signal| {
                sent.borrow_mut().push((pid, signal));
                if pid != 13 {
                    proc.signal(pid, signal);
                }
            },
        );
        assert_eq!(result, Err(FreezeError::Unsettled));
        for pid in [10, 11, 12] {
            assert_eq!(proc.state(pid), 'S', "{pid} was thawed back");
        }
        let continued: Vec<u32> = sent
            .into_inner()
            .into_iter()
            .filter(|(_, signal)| *signal == Signal::SIGCONT)
            .map(|(pid, _)| pid)
            .collect();
        assert_eq!(continued, vec![10, 11, 13, 12], "parents first");
    }

    #[test]
    fn a_gone_or_reused_root_is_never_signalled() {
        let proc = sandbox();
        let root = TreeRoot::of_in(&proc.path(), 10).unwrap();
        proc.set_full(10, 1, 'S', 1, 999);
        let sent = RefCell::new(Vec::new());
        assert_eq!(
            freeze_tree_with(&proc.path(), root, FREEZE_SETTLE, |pid, signal| {
                sent.borrow_mut().push((pid, signal));
            }),
            Err(FreezeError::Gone)
        );
        let frozen = FrozenTree {
            root,
            pids: vec![12, 13, 11, 10],
        };
        assert!(thaw_tree_with(
            &proc.path(),
            &frozen,
            FREEZE_SETTLE,
            |pid, signal| {
                sent.borrow_mut().push((pid, signal));
            }
        ));
        assert!(sent.into_inner().is_empty());
    }

    #[test]
    fn thaw_continues_parents_first_and_confirms_nothing_is_stopped() {
        let proc = sandbox();
        let root = TreeRoot::of_in(&proc.path(), 10).unwrap();
        let frozen = freeze_tree_with(&proc.path(), root, FREEZE_SETTLE, |pid, signal| {
            proc.signal(pid, signal);
        })
        .unwrap();
        let sent = RefCell::new(Vec::new());
        assert!(thaw_tree_with(
            &proc.path(),
            &frozen,
            FREEZE_SETTLE,
            |pid, signal| {
                sent.borrow_mut().push((pid, signal));
                proc.signal(pid, signal);
            }
        ));
        assert_eq!(
            sent.into_inner(),
            vec![
                (10, Signal::SIGCONT),
                (11, Signal::SIGCONT),
                (13, Signal::SIGCONT),
                (12, Signal::SIGCONT),
            ]
        );
        for pid in [10, 11, 12, 13] {
            assert_eq!(proc.state(pid), 'S');
        }

        let frozen = freeze_tree_with(&proc.path(), root, FREEZE_SETTLE, |pid, signal| {
            proc.signal(pid, signal);
        })
        .unwrap();
        assert!(!thaw_tree_with(
            &proc.path(),
            &frozen,
            Duration::from_millis(50),
            |pid, signal| {
                if pid != 12 {
                    proc.signal(pid, signal);
                }
            }
        ));
    }

    fn host_state(pid: u32) -> Option<char> {
        read_stat(Path::new("/proc"), pid).and_then(|stat| proc_state(&stat))
    }

    #[test]
    fn a_real_process_tree_is_stopped_and_continued() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30 & sleep 30 & wait"])
            .spawn()
            .unwrap();
        let root = TreeRoot::of(child.id()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while tree(Path::new("/proc"), root.pid()).len() < 3 {
            assert!(Instant::now() < deadline, "the children never started");
            std::thread::sleep(Duration::from_millis(10));
        }

        let frozen = freeze_tree(root, FREEZE_SETTLE).unwrap();
        assert_eq!(frozen.pids().len(), 3);
        assert_eq!(frozen.pids().last(), Some(&root.pid()));
        for pid in frozen.pids() {
            assert_eq!(host_state(*pid), Some('T'), "{pid}");
        }

        assert!(thaw_tree(&frozen, FREEZE_SETTLE));
        for pid in frozen.pids() {
            assert_ne!(host_state(*pid), Some('T'), "{pid}");
        }

        for pid in &frozen.pids()[..2] {
            send(*pid, Signal::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(freeze_tree(root, FREEZE_SETTLE), Err(FreezeError::Gone));
    }
}
