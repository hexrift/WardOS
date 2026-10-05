#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A `wardd` restarted on a session whose pause or stop was interrupted finishes
//! that operation before it serves (#145 item 7). The real-sandbox case requires
//! bubblewrap and skips cleanly without it; the others run on any host.

use std::fs;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use ward_daemon::control::{RemoteSink, Request, Response};
use ward_daemon::{Session, SessionMeta, daemon, pause, sandbox};
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
fn new_session(project: &std::path::Path, state: &std::path::Path) -> (String, std::path::PathBuf) {
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
    fn serve(state: &std::path::Path, session: &str) -> Self {
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

    fn serving(state: &std::path::Path, session: &str) -> Self {
        let wardd = Self::serve(state, session);
        assert!(
            daemon::wait_until(daemon::STARTUP_TIMEOUT, || daemon::serving(state, session)),
            "wardd answers on the session's socket"
        );
        wardd
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

fn records_in(log: &std::path::Path) -> Vec<EventRecord> {
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

fn stop_intent() -> pause::Intent {
    pause::Intent::begin(pause::Verb::Stop {
        reason: EndReason::UserStop,
    })
    .unwrap()
}

/// `ward stop` on a real sandbox, with `wardd` killed the moment the stop's
/// intent is durable and before it has signalled anything: the sandbox keeps
/// running and the log stays open. A `wardd` started again on the same
/// session directory finishes the stop before serving — ends the sandbox,
/// records the real counts, records `Finished` and `SessionEnded`, seals, and
/// exits — and clears the project's current pointer, so a retried `ward stop`
/// finds nothing left to do.
#[test]
fn a_restarted_wardd_finishes_a_stop_interrupted_on_a_running_sandbox() {
    if !ward_sandbox::ci::isolation_ready(sandbox::available(), "bubblewrap") {
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    let mut wardd = Wardd::serving(state.path(), &id);

    let marker = format!("ward-restart-e2e-{}", std::process::id());
    let script = format!("i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done # {marker}");
    let runner = {
        let (p, s) = (project.path().to_path_buf(), state.path().to_path_buf());
        std::thread::spawn(move || {
            let mut run = Session::open_current(&p, &s).unwrap().unwrap();
            let _ = run.run(&["/bin/sh".into(), "-c".into(), script]);
        })
    };
    assert!(
        daemon::wait_until(Duration::from_secs(5), || pids_tagged(&marker).len() >= 2),
        "the command runs inside the sandbox"
    );

    let intent = pause::intent_path(state.path(), &id);
    let lifecycle_lock = pause::admit_launch(state.path(), &id).unwrap();
    let stopper = {
        let (p, s) = (project.path().to_path_buf(), state.path().to_path_buf());
        std::thread::spawn(move || {
            Session::open_current(&p, &s)
                .unwrap()
                .unwrap()
                .stop(EndReason::UserStop)
        })
    };
    assert!(
        daemon::wait_until(Duration::from_secs(5), || intent.exists()),
        "the stop's intent is durable before the stop takes the lifecycle lock"
    );
    wardd.kill();
    drop(lifecycle_lock);
    assert!(
        stopper.join().unwrap().is_err(),
        "the client's stop fails with its daemon"
    );
    assert!(
        pids_tagged(&marker).len() >= 2,
        "nothing was signalled before the daemon died"
    );
    assert!(
        !kinds_of(&records_in(&log))
            .iter()
            .any(|k| k == "SessionEnded")
    );
    assert!(intent.exists());

    let status = Wardd::serve(state.path(), &id).wait_exit(Duration::from_secs(20));
    assert!(status.success(), "{status:?}");
    runner.join().unwrap();
    assert!(
        pids_tagged(&marker).is_empty(),
        "nothing of the sandbox survives the reconciled stop: {:?}",
        pids_tagged(&marker)
    );

    let records = records_in(&log);
    let kinds = kinds_of(&records);
    let at = |k: &str| {
        kinds
            .iter()
            .position(|x| x == k)
            .unwrap_or_else(|| panic!("{k} in {kinds:?}"))
    };
    assert!(
        at("CommandStarted") < at("WorkloadsTerminated"),
        "{kinds:?}"
    );
    assert!(at("WorkloadsTerminated") < at("SessionEnded"), "{kinds:?}");
    assert_eq!(kinds.last().map(String::as_str), Some("SessionEnded"));
    assert!(matches!(
        records[at("WorkloadsTerminated")].event,
        WardEvent::WorkloadsTerminated {
            ended,
            pending: 0,
            barrier_confirmed: true
        } if ended >= 2
    ));
    assert!(!intent.exists());
    assert!(pause::stop_begun(state.path(), &id));
    assert!(!daemon::serving(state.path(), &id));
    assert!(
        SessionMeta::current(project.path(), state.path())
            .unwrap()
            .is_none(),
        "the project's current pointer is cleared by the reconciled stop"
    );
    assert!(
        Session::open_current(project.path(), state.path())
            .unwrap()
            .is_none(),
        "a retried `ward stop` finds no session: the retry is a no-op"
    );
}

/// The same reconciliation on any host, with nothing running: a stop intent
/// left by a process that died before it got anywhere is finished by the next
/// `wardd serve`, which seals and exits without ever serving.
#[test]
fn a_restarted_wardd_finishes_a_stop_interrupted_before_anything_ran() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    pause::write_intent(state.path(), &id, &stop_intent()).unwrap();

    let status = Wardd::serve(state.path(), &id).wait_exit(Duration::from_secs(20));
    assert!(status.success(), "{status:?}");
    let kinds = kinds_of(&records_in(&log));
    assert_eq!(
        &kinds[kinds.len() - 2..],
        ["AgentStateChanged", "SessionEnded"],
        "{kinds:?}"
    );
    assert!(
        !kinds.iter().any(|k| k == "WorkloadsTerminated"),
        "{kinds:?}"
    );
    assert!(!pause::intent_path(state.path(), &id).exists());
    assert!(
        SessionMeta::current(project.path(), state.path())
            .unwrap()
            .is_none()
    );
}

/// A pause interrupted before anything was frozen is finished by the next
/// `wardd serve`: it records the pause, holds the session, and then serves it
/// — so `ward resume` releases exactly that hold and `ward stop` ends it.
#[test]
fn a_restarted_wardd_finishes_an_interrupted_pause_and_serves_the_hold() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    pause::write_intent(
        state.path(),
        &id,
        &pause::Intent::begin(pause::Verb::Pause {
            reason: "ops asked".into(),
        })
        .unwrap(),
    )
    .unwrap();

    let mut wardd = Wardd::serving(state.path(), &id);
    assert!(!pause::intent_path(state.path(), &id).exists());
    assert_eq!(
        fs::read_to_string(pause::marker_path(state.path(), &id)).unwrap(),
        "ops asked\n"
    );
    let records = records_in(&log);
    assert!(matches!(
        &records.last().unwrap().event,
        WardEvent::SessionPaused { reason, .. } if reason.as_str() == "ops asked"
    ));

    let socket = daemon::socket_path(state.path(), &id);
    let mut control = RemoteSink::connect(&socket).unwrap();
    assert!(matches!(
        control.call(&Request::Pause { reason: String::new() }).unwrap(),
        Response::Error(e) if e == "already paused"
    ));
    assert!(matches!(
        control.call(&Request::Resume).unwrap(),
        Response::Record(record) if matches!(record.event, WardEvent::SessionResumed { .. })
    ));
    assert!(!pause::marker_path(state.path(), &id).exists());
    drop(control);

    let ended = Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .unwrap();
    assert_eq!(ended, 0);
    assert!(wardd.wait_exit(Duration::from_secs(10)).success());
    let kinds = kinds_of(&records_in(&log));
    assert!(kinds.contains(&"SessionResumed".to_owned()), "{kinds:?}");
    assert_eq!(kinds.last().map(String::as_str), Some("SessionEnded"));
}
