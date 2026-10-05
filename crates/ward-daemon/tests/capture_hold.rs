#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A snapshot capture holds the session only from confirmed quiescence, and
//! the hold it takes is its own (#145 item 6): `ward resume` releases a user's
//! pause, never a capture's hold, and a capture's release never lifts a user's
//! pause. A real daemon serves the session; an "agent" discovered and frozen
//! exactly as `ward pause` finds a session's `bwrap` tree (ST-018's harness)
//! writes continuously; a stand-in egress acknowledges each flip of the marker
//! through the real registration protocol. Nothing here needs bubblewrap.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ward_daemon::acks::{self, Registration};
use ward_daemon::control::{RemoteSink, Request, Response};
use ward_daemon::daemon::wait_until;
use ward_daemon::session::run_dir_path;
use ward_daemon::{Session, daemon, pause};
use ward_events::{EndReason, EventRecord, LogReader, WardEvent};
use ward_snapshot::{CaptureOptions, SnapshotRole, SnapshotStore};

/// Copying a shim and spawning from one are never concurrent across the tests
/// of this process: a fork in one test while another's copy still holds the
/// shim open for writing fails that other's `exec` with `ETXTBSY`.
static FORK: Mutex<()> = Mutex::new(());

struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn bwrap_shim(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let shell = ["/bin/sh", "/usr/bin/sh", "/bin/dash", "/bin/bash"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())
        .expect("a system shell");
    let shim = dir.join("bwrap");
    fs::copy(shell, &shim).expect("copy shell to bwrap shim");
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    shim
}

/// A writer that rewrites `target` with a counter as fast as it can, found as
/// `session`'s sandbox by the run directory on its command line.
fn spawn_writer(shim: &Path, session: &str, target: &Path) -> Reap {
    let run_dir = run_dir_path(session).to_string_lossy().into_owned();
    let script = "t=$2; i=0; while :; do i=$((i+1)); printf '%s\\n' \"$i\" > \"$t\"; done";
    Reap(
        Command::new(shim)
            .arg("-c")
            .arg(script)
            .arg("ward-agent")
            .arg(run_dir)
            .arg(target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn writer"),
    )
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

fn held_still(pid: u32) -> bool {
    matches!(state_of(pid), Some('T' | 't')) || frozen_in_cgroup(pid)
}

fn writes_again(target: &Path) -> bool {
    let before = fs::read(target).unwrap_or_default();
    wait_until(Duration::from_secs(5), || {
        fs::read(target).unwrap_or_default() != before
    })
}

fn scratch_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join(".ward")).unwrap();
    fs::write(dir.path().join("README.md"), "demo\n").unwrap();
    fs::write(
        dir.path().join(".ward/policy.yaml"),
        "network: localhost_only\ncontainers: none\n",
    )
    .unwrap();
    fs::write(dir.path().join("hot.txt"), "0\n").unwrap();
    dir
}

fn new_session(project: &Path, state: &Path) -> (String, PathBuf) {
    let up = Session::start_in(project, state).expect("up");
    let id = up.id().to_owned();
    let log = up.log_path();
    up.persist_current().expect("persist");
    (id, log)
}

fn serve(state: &Path, id: &str) -> JoinHandle<ward_daemon::Result<()>> {
    let (state_path, session) = (state.to_path_buf(), id.to_owned());
    let served = std::thread::spawn(move || daemon::serve(&state_path, &session));
    assert!(
        wait_until(daemon::STARTUP_TIMEOUT, || daemon::serving(state, id)),
        "wardd answers on the session's socket"
    );
    served
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

struct FollowingProxy {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FollowingProxy {
    fn start(state: &Path, id: &str) -> Self {
        let registration =
            Registration::register(&acks::proxies_dir(state, id), false).expect("registered");
        let marker = pause::marker_path(state, id);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut paused = false;
            while !flag.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(20));
                let now = marker.exists();
                if now != paused {
                    paused = now;
                    registration.set(paused).unwrap();
                }
            }
            registration.remove();
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for FollowingProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The session, its daemon, a writer found as its sandbox and an egress that
/// acknowledges: what every test here starts from.
struct Live {
    state: tempfile::TempDir,
    project: tempfile::TempDir,
    id: String,
    log: PathBuf,
    writer: Reap,
    proxy: Option<FollowingProxy>,
    served: Option<JoinHandle<ward_daemon::Result<()>>>,
}

impl Live {
    fn start() -> Self {
        let state = tempfile::tempdir().unwrap();
        let project = scratch_project();
        let (id, log) = new_session(project.path(), state.path());
        let writer = {
            let _fork = FORK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let shim = bwrap_shim(state.path());
            spawn_writer(&shim, &id, &project.path().join("hot.txt"))
        };
        let pid = writer.0.id();
        assert!(
            wait_until(Duration::from_secs(5), || pause::sandbox_pids(
                Path::new("/proc"),
                &id
            )
            .contains(&pid)),
            "the writer must be discoverable as {id}'s sandbox"
        );
        assert!(
            writes_again(&project.path().join("hot.txt")),
            "the writer is writing"
        );
        let proxy = FollowingProxy::start(state.path(), &id);
        let served = serve(state.path(), &id);
        Self {
            state,
            project,
            id,
            log,
            writer,
            proxy: Some(proxy),
            served: Some(served),
        }
    }

    fn control(&self) -> RemoteSink {
        RemoteSink::connect(&daemon::socket_path(self.state.path(), &self.id)).unwrap()
    }

    fn hot(&self) -> PathBuf {
        self.project.path().join("hot.txt")
    }

    fn writer_pid(&self) -> u32 {
        self.writer.0.id()
    }

    fn marker(&self) -> PathBuf {
        pause::marker_path(self.state.path(), &self.id)
    }

    fn held_by(&self) -> Vec<pause::Owner> {
        pause::read_held_by(self.state.path(), &self.id)
            .unwrap()
            .map(|holders| holders.owners())
            .unwrap_or_default()
    }

    fn hold_for_capture(control: &mut RemoteSink) -> String {
        match control
            .call(&Request::HoldForCapture {
                reason: pause::capture_reason("test"),
                pid: std::process::id(),
                started: pause::own_start_time(),
            })
            .unwrap()
        {
            Response::HeldForCapture { op: Some(op) } => op,
            other => panic!("{other:?}"),
        }
    }

    fn finish(mut self) -> Vec<EventRecord> {
        drop(self.proxy.take());
        Session::open_current(self.project.path(), self.state.path())
            .unwrap()
            .unwrap()
            .stop(EndReason::UserStop)
            .unwrap();
        self.served.take().unwrap().join().unwrap().unwrap();
        records_in(&self.log)
    }
}

/// A capture's hold brings the session to the state a confirmed pause records
/// — frozen, marker, approvals held, proxy acknowledged — and records it; two
/// captures under the one hold see the same tree; `ward resume` cannot release
/// it; its release lets the agent continue and records the release.
#[test]
fn a_capture_holds_confirmed_quiescence_that_a_user_resume_cannot_release() {
    let live = Live::start();
    let mut control = live.control();
    let store = SnapshotStore::open(live.state.path().join("cas")).unwrap();

    let op = Live::hold_for_capture(&mut control);
    assert!(held_still(live.writer_pid()), "the writer is frozen");
    assert!(live.marker().exists(), "the marker closes the proxy");
    assert_eq!(live.held_by(), [pause::Owner::Capture]);
    let first = store
        .store_snapshot(
            live.project.path(),
            SnapshotRole::Candidate,
            CaptureOptions::default(),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let second = store
        .store_snapshot(
            live.project.path(),
            SnapshotRole::Candidate,
            CaptureOptions::default(),
        )
        .unwrap();
    assert_eq!(first, second, "nothing moved under the hold");

    let refused = control.call(&Request::Resume).unwrap();
    assert!(
        matches!(&refused, Response::Error(e) if e.contains("held for capture") && e.contains("not a user pause")),
        "{refused:?}"
    );
    assert!(
        held_still(live.writer_pid()),
        "the refused resume thawed nothing"
    );
    assert!(live.marker().exists());

    let released = control.call(&Request::ReleaseCapture { op }).unwrap();
    assert!(
        matches!(&released, Response::Record(r) if matches!(r.event, WardEvent::SessionResumed { .. })),
        "{released:?}"
    );
    assert!(!live.marker().exists());
    assert!(live.held_by().is_empty());
    assert!(writes_again(&live.hot()), "the writer continues");

    assert!(matches!(
        control.call(&Request::Resume).unwrap(),
        Response::Error(e) if e == "not paused"
    ));
    drop(control);
    let records = live.finish();
    let kinds = kinds_of(&records);
    let at = |k: &str| kinds.iter().position(|x| x == k).unwrap();
    assert!(at("SessionPaused") < at("SessionResumed"), "{kinds:?}");
    assert!(records.iter().any(|r| matches!(
        &r.event,
        WardEvent::SessionPaused { reason, .. } if pause::is_capture_reason(reason.as_str())
    )));
}

/// A user's pause over a capture is layered: `ward resume` releases the user's
/// layer and the session stays held (and frozen) for the capture, recorded as
/// such; the capture's release is what lets the agent continue.
#[test]
fn a_user_pause_over_a_capture_is_released_without_lifting_the_captures_hold() {
    let live = Live::start();
    let mut control = live.control();

    let op = Live::hold_for_capture(&mut control);
    let paused = control
        .call(&Request::Pause {
            reason: "mine".into(),
        })
        .unwrap();
    assert!(
        matches!(&paused, Response::Paused { record, unsettled: None, unconfirmed: None }
            if matches!(&record.event, WardEvent::SessionPaused { reason, .. } if reason.as_str() == "mine")),
        "{paused:?}"
    );
    assert_eq!(live.held_by(), [pause::Owner::User, pause::Owner::Capture]);
    assert_eq!(fs::read_to_string(live.marker()).unwrap(), "mine\n");

    let resumed = control.call(&Request::Resume).unwrap();
    assert!(
        matches!(&resumed, Response::Record(r)
            if matches!(&r.event, WardEvent::SessionPaused { reason, .. } if pause::is_capture_reason(reason.as_str()))),
        "the user's layer is gone; the record says what still holds: {resumed:?}"
    );
    assert_eq!(live.held_by(), [pause::Owner::Capture]);
    assert!(
        held_still(live.writer_pid()),
        "still frozen for the capture"
    );
    assert!(live.marker().exists());

    let released = control.call(&Request::ReleaseCapture { op }).unwrap();
    assert!(
        matches!(&released, Response::Record(r) if matches!(r.event, WardEvent::SessionResumed { .. })),
        "{released:?}"
    );
    assert!(writes_again(&live.hot()));
    drop(control);
    let kinds = kinds_of(&live.finish());
    assert_eq!(
        kinds
            .iter()
            .filter(|k| k.starts_with("Session") && k.as_str() != "SessionEnded")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "SessionStarted",
            "SessionPaused",
            "SessionPaused",
            "SessionPaused",
            "SessionResumed"
        ],
        "{kinds:?}"
    );
}

/// The reverse layering: a capture taken while the user holds the session
/// reuses that quiescence, takes no record of its own, and its release leaves
/// the user's pause — marker, freeze, record — exactly in place.
#[test]
fn a_capture_under_a_user_pause_leaves_the_pause_in_place_when_it_releases() {
    let live = Live::start();
    let mut control = live.control();
    assert!(matches!(
        control
            .call(&Request::Pause {
                reason: "mine".into()
            })
            .unwrap(),
        Response::Paused { .. }
    ));
    assert!(wait_until(Duration::from_secs(2), || held_still(
        live.writer_pid()
    )));

    let op = Live::hold_for_capture(&mut control);
    assert_eq!(live.held_by(), [pause::Owner::User, pause::Owner::Capture]);
    let released = control.call(&Request::ReleaseCapture { op }).unwrap();
    assert!(matches!(released, Response::Ok), "{released:?}");
    assert_eq!(live.held_by(), [pause::Owner::User]);
    assert!(held_still(live.writer_pid()), "the user's pause stands");
    assert_eq!(fs::read_to_string(live.marker()).unwrap(), "mine\n");

    let resumed = control.call(&Request::Resume).unwrap();
    assert!(
        matches!(&resumed, Response::Record(r) if matches!(r.event, WardEvent::SessionResumed { .. })),
        "{resumed:?}"
    );
    assert!(writes_again(&live.hot()));
    drop(control);
    let kinds = kinds_of(&live.finish());
    assert_eq!(
        kinds
            .iter()
            .filter(|k| k.starts_with("SessionPause") || k.as_str() == "SessionResumed")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["SessionPaused", "SessionResumed"],
        "the capture recorded nothing of its own: {kinds:?}"
    );
}

/// `ward snapshot create` through the daemon: the capture itself takes the hold,
/// the snapshot is recorded between the hold and its release, and the agent
/// continues afterwards.
#[test]
fn a_snapshot_through_the_daemon_is_captured_under_its_own_hold() {
    let live = Live::start();
    let mut session = Session::open_current(live.project.path(), live.state.path())
        .unwrap()
        .unwrap();
    let meta = session.snapshot(SnapshotRole::Candidate).unwrap();
    assert!(meta.entries >= 3, "{meta:?}");
    session.sync().unwrap();
    drop(session);
    assert!(!live.marker().exists());
    assert!(live.held_by().is_empty());
    assert!(writes_again(&live.hot()));

    let kinds = kinds_of(&live.finish());
    let at = |k: &str| kinds.iter().position(|x| x == k).unwrap();
    assert!(at("SessionPaused") < at("SnapshotCreated"), "{kinds:?}");
    assert!(at("SnapshotCreated") < at("SessionResumed"), "{kinds:?}");
}
