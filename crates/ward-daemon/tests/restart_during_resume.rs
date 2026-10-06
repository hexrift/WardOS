#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A `wardd` restarted during a resume finishes that resume before it serves
//! (#145 items 1 and 7), end to end on a real bubblewrap sandbox: a running
//! workload is paused to a confirmed `paused`, `ward resume` is asked, and the
//! daemon is killed after the resume's intent is durable and before its
//! outcome is. The restarted daemon reconciles to one confirmed state —
//! `running`, with the workload thawed and `SessionResumed` recorded exactly
//! once — instead of leaving a tree frozen with nothing saying so.
//!
//! The kill point is a condition, not a timer: a stand-in egress registered
//! beside the real ones (the file protocol of `ward_daemon::acks`) confirms the
//! pause and then withholds its release, so the daemon waits, for up to
//! `acks::ACK_TIMEOUT`, with the intent recorded, the marker cleared and the
//! tree still frozen — the point a resume reaches after releasing the proxy's
//! marker and before its thaw. The test kills it as soon as the records show
//! that point, and proves afterwards that the resume had not ended on its own.
//!
//! Requires bubblewrap; skips without it, and fails under
//! `WARD_REQUIRE_ISOLATION=1`. The freeze is whichever the host offers (the
//! cgroup v2 freezer where a delegated cgroup can be made, `SIGSTOP`
//! otherwise); every assertion about the processes holds for both.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use ward_daemon::acks::{self, Registration};
use ward_daemon::control::RemoteSink;
use ward_daemon::pause::{self, Lifecycle};
use ward_daemon::{Session, SessionMeta, client, daemon, sandbox};
use ward_events::{EndReason, EventRecord, LogReader, WardEvent};

fn scratch_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join(".ward")).unwrap();
    fs::write(dir.path().join("README.md"), "demo\n").unwrap();
    fs::write(
        dir.path().join(".ward/policy.yaml"),
        "network: localhost_only\ncontainers: none\n",
    )
    .unwrap();
    dir
}

/// A fresh, persisted session of `project`, as `ward up` leaves one.
fn new_session(project: &Path, state: &Path) -> (String, PathBuf) {
    let up = Session::start_in(project, state).expect("up");
    let id = up.id().to_owned();
    let log = up.log_path();
    up.persist_current().expect("persist");
    (id, log)
}

/// `wardd serve` as its own process, so it can be killed the way a crash kills
/// it. Killed and reaped on drop whatever the test did.
struct Wardd(Child);

impl Wardd {
    fn serve(state: &Path, session: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_wardd"))
            .args(["serve", "--state"])
            .arg(state)
            .arg("--session")
            .arg(session)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("wardd starts");
        Self(child)
    }

    fn kill(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }

    fn wait_exit(&mut self, within: Duration) -> ExitStatus {
        let deadline = std::time::Instant::now() + within;
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "wardd is still running after {within:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Wardd {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// A control connection to the daemon serving `session`, once it answers a
/// request. The socket is bound before a restarted daemon reconciles, but no
/// request is read until reconciliation has finished, so the first answer is
/// the reconciled state.
fn control_of(state: &Path, session: &str) -> RemoteSink {
    let socket = daemon::socket_path(state, session);
    let mut control = None;
    assert!(
        daemon::wait_until(daemon::STARTUP_TIMEOUT, || {
            control = RemoteSink::connect(&socket);
            control.is_some()
        }),
        "wardd answers on the session's socket"
    );
    control.unwrap()
}

fn lifecycle_of(control: &mut RemoteSink) -> pause::LifecycleReport {
    control
        .lifecycle()
        .expect("lifecycle answered")
        .expect("this daemon serves the lifecycle")
}

fn records_in(log: &Path) -> Vec<EventRecord> {
    LogReader::open(log)
        .unwrap()
        .filter_map(Result::ok)
        .collect()
}

fn kinds_of(records: &[EventRecord]) -> Vec<String> {
    records
        .iter()
        .map(|r| format!("{:?}", r.event.kind()))
        .collect()
}

fn count(kinds: &[String], kind: &str) -> usize {
    kinds.iter().filter(|k| *k == kind).count()
}

/// Every pid whose command line mentions `marker`.
fn pids_tagged(marker: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let cmdline = fs::read(entry.path().join("cmdline")).unwrap_or_default();
        if String::from_utf8_lossy(&cmdline).contains(marker) {
            pids.push(pid);
        }
    }
    pids
}

/// Every process of `session`'s sandboxes, found as `ward pause` finds them.
fn sandbox_of(session: &str) -> Vec<u32> {
    pause::sandbox_pids(Path::new("/proc"), session)
}

fn state_of(pid: u32) -> Option<char> {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("State:\t").and_then(|s| s.chars().next()))
}

fn frozen_in_cgroup(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
        })
        .and_then(|rel| fs::read_to_string(format!("/sys/fs/cgroup{rel}/cgroup.events")).ok())
        .is_some_and(|events| events.lines().any(|l| l == "frozen 1"))
}

/// Held by either freeze: stopped by `SIGSTOP`, or in a frozen cgroup.
fn held_still(pid: u32) -> bool {
    matches!(state_of(pid), Some('T' | 't')) || frozen_in_cgroup(pid)
}

fn parent_of(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat[stat.rfind(')')? + 1..]
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Held as `pause` defines it for a process the freeze cannot move to `T`
/// (#352): in uninterruptible wait for a vforked child that is itself held,
/// so it runs no code until that child continues.
fn held_in_vfork_wait(pid: u32, among: &[u32]) -> bool {
    let wchan = fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default();
    let children: Vec<u32> = among
        .iter()
        .copied()
        .filter(|&c| parent_of(c) == Some(pid))
        .collect();
    state_of(pid) == Some('D')
        && ["wait_for_vfork_done", "kernel_clone"].contains(&wchan.trim())
        && !children.is_empty()
        && children.iter().all(|&c| held_still(c))
}

/// Every process of the sandbox the freeze does not hold, with its state:
/// empty when the whole tree is held (a pid that ended since the scan is not
/// counted).
fn unheld(session: &str) -> Vec<(u32, Option<char>)> {
    let pids = sandbox_of(session);
    assert!(!pids.is_empty(), "the sandbox of {session} is running");
    pids.iter()
        .copied()
        .filter(|&pid| {
            !(held_still(pid)
                || matches!(state_of(pid), None | Some('Z' | 'X' | 'x'))
                || held_in_vfork_wait(pid, &pids))
        })
        .map(|pid| (pid, state_of(pid)))
        .collect()
}

/// The workload runs: nothing of the sandbox is held, and it makes progress —
/// its loop forks a process the sandbox did not have a moment ago. A frozen
/// tree cannot fork, so this is never true of a held one.
fn runs_again(session: &str) -> bool {
    let unheld = daemon::wait_until(Duration::from_secs(5), || {
        sandbox_of(session).into_iter().all(|pid| !held_still(pid))
    });
    let before = sandbox_of(session);
    unheld
        && daemon::wait_until(Duration::from_secs(5), || {
            sandbox_of(session).iter().any(|pid| !before.contains(pid))
        })
}

/// Kills whatever is left of a sandbox the test started, whatever the test
/// did — a stopped process takes `SIGKILL` as it is — so a failed run never
/// leaves a frozen tree behind.
struct Reap {
    session: String,
    marker: String,
}

impl Drop for Reap {
    fn drop(&mut self) {
        for pid in sandbox_of(&self.session)
            .into_iter()
            .chain(pids_tagged(&self.marker))
        {
            let _ = kill(
                Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX)),
                Signal::SIGKILL,
            );
        }
    }
}

/// A session paused to a confirmed `paused` on a real sandbox, whose resume
/// was interrupted by its daemon's death after the resume's intent was
/// recorded and the proxy's marker released, before the proxy confirmed the
/// release, the thaw and the record.
struct Interrupted {
    // Declared first, so it is dropped first: the sandbox is gone before the
    // directories it uses are removed.
    _reap: Reap,
    gate: Registration,
    runner: JoinHandle<()>,
    id: String,
    log: PathBuf,
    project: tempfile::TempDir,
    state: tempfile::TempDir,
}

fn interrupt_a_resume(tag: &str) -> Interrupted {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    let mut wardd = Wardd::serve(state.path(), &id);
    let mut control = control_of(state.path(), &id);
    assert_eq!(lifecycle_of(&mut control).state, Lifecycle::Running);

    // A workload that keeps forking (one `sleep` per turn), bounded so a
    // sandbox the reaper somehow missed still ends by itself.
    let marker = format!("ward-resume-restart-{tag}-{}", std::process::id());
    let reap = Reap {
        session: id.clone(),
        marker: marker.clone(),
    };
    let script = format!("i=0; while [ $i -lt 1200 ]; do sleep 0.05; i=$((i+1)); done # {marker}");
    let runner = {
        let (p, s) = (project.path().to_path_buf(), state.path().to_path_buf());
        std::thread::spawn(move || {
            let mut run = Session::open_current(&p, &s).unwrap().unwrap();
            let _ = run.run(&["/bin/sh".into(), "-c".into(), script]);
        })
    };
    assert!(
        daemon::wait_until(Duration::from_secs(10), || pids_tagged(&marker).len() >= 2),
        "the command runs inside the sandbox"
    );
    assert!(runs_again(&id), "the workload runs before the pause");

    // The stand-in egress: confirms the hold, then withholds the release.
    let gate = Registration::register(&acks::proxies_dir(state.path(), &id), true).unwrap();
    let paused = client::pause(&mut control, "inspect").expect("paused");
    assert_eq!(paused.unsettled, None, "the freeze settled");
    assert_eq!(paused.unconfirmed, None, "every component confirmed");
    assert!(matches!(
        paused.record.event,
        WardEvent::SessionPaused { .. }
    ));
    assert_eq!(lifecycle_of(&mut control).state, Lifecycle::Paused);
    assert_eq!(unheld(&id), [], "the paused workload is frozen");

    let resumer = {
        let socket = daemon::socket_path(state.path(), &id);
        std::thread::spawn(move || {
            let mut sink = RemoteSink::connect(&socket).unwrap();
            client::resume(&mut sink)
        })
    };
    let marker_file = pause::marker_path(state.path(), &id);
    let mut resume_op = None;
    assert!(
        daemon::wait_until(acks::ACK_TIMEOUT, || {
            resume_op = match pause::read_intent(state.path(), &id).unwrap() {
                Some(pause::Intent {
                    op,
                    verb: pause::Verb::Resume,
                    ..
                }) if !marker_file.exists() => Some(op),
                _ => None,
            };
            resume_op.is_some()
        }),
        "the resume records its intent and releases the proxy's marker"
    );
    let resume_op = resume_op.unwrap();
    let lane = lifecycle_of(&mut control);
    assert_eq!(lane.state, Lifecycle::Resuming, "{lane:?}");
    assert_eq!(lane.op.as_deref(), Some(resume_op.as_str()));
    wardd.kill();
    drop(control);
    assert!(
        resumer.join().unwrap().is_err(),
        "the client's resume fails with its daemon"
    );

    // The resume had not reached an outcome of its own: a resume refused for
    // the withheld release would have cleared its intent and rewritten the
    // marker; a completed one would have thawed and recorded.
    let intent = pause::read_intent(state.path(), &id).unwrap();
    assert!(
        matches!(&intent, Some(pause::Intent { op, verb: pause::Verb::Resume, .. }) if *op == resume_op),
        "the daemon died inside the resume: {intent:?}"
    );
    assert!(!marker_file.exists());
    assert_eq!(unheld(&id), [], "nothing was thawed before the daemon died");
    let kinds = kinds_of(&records_in(&log));
    assert_eq!(count(&kinds, "SessionPaused"), 1, "{kinds:?}");
    assert_eq!(count(&kinds, "SessionResumed"), 0, "{kinds:?}");
    assert_eq!(
        pause::lifecycle_on_disk(state.path(), &id).unwrap().state,
        Lifecycle::Resuming
    );

    Interrupted {
        _reap: reap,
        gate,
        runner,
        id,
        log,
        project,
        state,
    }
}

/// Start `wardd` again on the interrupted session and prove it reconciled to
/// one confirmed `running`: the resume's records cleared, the workload thawed
/// and running, `SessionResumed` recorded once after the one `SessionPaused`,
/// launches admitted — then stop the session through it.
fn restart_and_confirm_running(fx: Interrupted) {
    let (state, id) = (fx.state.path(), fx.id.as_str());
    let mut wardd = Wardd::serve(state, id);
    let mut control = control_of(state, id);

    let lane = lifecycle_of(&mut control);
    assert_eq!(lane.state, Lifecycle::Running, "{lane:?}");
    assert!(lane.held_by.is_empty(), "{lane:?}");
    assert_eq!(lane.op, None, "nothing is in flight: {lane:?}");
    let on_disk = pause::lifecycle_on_disk(state, id).unwrap();
    assert_eq!(on_disk.state, Lifecycle::Running, "{on_disk:?}");
    assert!(pause::read_intent(state, id).unwrap().is_none());
    assert!(!pause::marker_path(state, id).exists());
    assert!(!pause::held_by_path(state, id).exists());

    assert!(
        runs_again(id),
        "the workload is thawed and running, as the lifecycle reports"
    );
    drop(pause::admit_launch(state, id).expect("a launch is admitted again"));

    let records = records_in(&fx.log);
    let kinds = kinds_of(&records);
    assert_eq!(count(&kinds, "SessionPaused"), 1, "{kinds:?}");
    assert_eq!(count(&kinds, "SessionResumed"), 1, "{kinds:?}");
    assert_eq!(count(&kinds, "SessionPauseUnsettled"), 0, "{kinds:?}");
    let paused_at = kinds.iter().position(|k| k == "SessionPaused").unwrap();
    let resumed_at = kinds.iter().position(|k| k == "SessionResumed").unwrap();
    assert!(paused_at < resumed_at, "{kinds:?}");
    drop(control);

    // The stop reads the stand-in as holding, as a real egress would read
    // once the stop's marker is written.
    fx.gate.set(true).unwrap();
    Session::open_current(fx.project.path(), state)
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .expect("the reconciled session stops");
    assert!(wardd.wait_exit(Duration::from_secs(20)).success());
    fx.runner.join().unwrap();
    fx.gate.remove();
    assert!(sandbox_of(id).is_empty(), "the stop ended the sandbox");
    let kinds = kinds_of(&records_in(&fx.log));
    assert_eq!(count(&kinds, "SessionResumed"), 1, "{kinds:?}");
    assert_eq!(kinds.last().map(String::as_str), Some("SessionEnded"));
    assert!(
        SessionMeta::current(fx.project.path(), state)
            .unwrap()
            .is_none()
    );
}

/// The daemon dies after the resume's intent is durable and the proxy's
/// marker is released, before the proxy confirms, the tree is thawed or
/// `SessionResumed` is recorded: the session reads `resuming`, its workload
/// frozen. The proxy then confirms (it reads `running`, as a real egress
/// does once the marker is gone), and the restarted `wardd` finishes the
/// resume before it serves: `running`, the workload thawed, one
/// `SessionResumed`.
#[test]
fn a_restart_before_the_resume_thaws_finishes_the_resume_on_a_real_sandbox() {
    if !ward_sandbox::ci::isolation_ready(sandbox::available(), "bubblewrap") {
        return;
    }
    let fx = interrupt_a_resume("before-thaw");
    fx.gate.set(false).unwrap();
    restart_and_confirm_running(fx);
}

/// The daemon dies after the thaw and before `SessionResumed` is recorded.
/// No seam stops a daemon between those two statements, so the test takes the
/// resume interrupted as above and plays its remaining steps before the record
/// with the daemon's own primitives, in the daemon's order: the proxy confirms
/// its release, the owners are cleared, the tree is thawed. The workload runs
/// while the log still says paused and the intent says resuming. The
/// restarted `wardd` records the resume exactly once and leaves the workload
/// running.
#[test]
fn a_restart_after_the_thaw_before_the_record_records_the_resume_once() {
    if !ward_sandbox::ci::isolation_ready(sandbox::available(), "bubblewrap") {
        return;
    }
    let fx = interrupt_a_resume("after-thaw");
    let (state, id) = (fx.state.path(), fx.id.as_str());
    fx.gate.set(false).unwrap();
    pause::clear_held_by(state, id).unwrap();
    let (frozen, _) = pause::freeze_confirmed(id);
    pause::thaw(&frozen);
    assert!(runs_again(id), "the dying resume had thawed the workload");
    let kinds = kinds_of(&records_in(&fx.log));
    assert_eq!(count(&kinds, "SessionResumed"), 0, "{kinds:?}");
    assert_eq!(
        pause::lifecycle_on_disk(state, id).unwrap().state,
        Lifecycle::Resuming
    );
    restart_and_confirm_running(fx);
}
