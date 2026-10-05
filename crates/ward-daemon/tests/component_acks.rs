#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A pause, a resume and a stop are confirmed by every component that must
//! hold — the egress proxy, the approvals, credential mediation — not by the
//! freeze alone (#145 item 3). The proxy lives in another process and
//! acknowledges through its registration under `sessions/<id>/proxies/`, so a
//! stand-in registration drives the real daemon through the real protocol
//! here: one that acknowledges every flip of the marker, and one that never
//! answers. Nothing here needs bubblewrap.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use ward_daemon::acks::{self, Registration};
use ward_daemon::control::{RemoteSink, Request, Response};
use ward_daemon::{Session, client, daemon, pause};
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

/// `wardd serve` in this process, on its own thread.
fn serve(state: &Path, id: &str) -> JoinHandle<ward_daemon::Result<()>> {
    let (state_path, session) = (state.to_path_buf(), id.to_owned());
    let served = std::thread::spawn(move || daemon::serve(&state_path, &session));
    assert!(
        daemon::wait_until(daemon::STARTUP_TIMEOUT, || daemon::serving(state, id)),
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

/// A stand-in egress that follows the marker exactly as the real one does:
/// paused when it exists, running when it is gone, each state acknowledged
/// through its registration.
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

/// Ask the daemon a question on its own connection and keep it open, as a
/// hook broker does, so the daemon holds a pending approval.
fn ask(socket: &Path) -> JoinHandle<Response> {
    let socket = socket.to_path_buf();
    std::thread::spawn(move || {
        let mut control = RemoteSink::connect(&socket).expect("hold connection");
        control
            .call(&Request::Hold {
                tool: "Write".into(),
                summary: "/work/a.rs".into(),
                reason: "r".into(),
                timeout_secs: 600,
            })
            .expect("hold answered")
    })
}

fn pending_held(control: &mut RemoteSink) -> Option<bool> {
    match control.call(&Request::Pending).unwrap() {
        Response::Pending(pending) => pending.first().and_then(|a| a.countdown).map(|c| c.held),
        other => panic!("{other:?}"),
    }
}

/// Every component acknowledges: the pause is `SessionPaused`, confirmed in
/// the response too, and the resume is confirmed by the proxy reading
/// running again before the record is appended.
#[test]
fn a_pause_and_its_resume_are_confirmed_by_the_proxy_acknowledging_each() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    let proxy = FollowingProxy::start(state.path(), &id);
    let served = serve(state.path(), &id);
    let socket = daemon::socket_path(state.path(), &id);
    let mut control = RemoteSink::connect(&socket).unwrap();

    let paused = client::pause(&mut control, "looks wrong").expect("pause");
    assert!(matches!(
        &paused.record.event,
        WardEvent::SessionPaused { reason, .. } if reason.as_str() == "looks wrong"
    ));
    assert_eq!(paused.unsettled, None);
    assert_eq!(paused.unconfirmed, None);
    assert_eq!(acks::unconfirmed_detail(&log).unwrap(), None);

    let resumed = client::resume(&mut control).expect("resume");
    assert!(matches!(resumed.event, WardEvent::SessionResumed { .. }));
    assert!(!pause::marker_path(state.path(), &id).exists());
    drop(control);
    drop(proxy);

    Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .unwrap();
    served.join().unwrap().unwrap();
    let kinds = kinds_of(&records_in(&log));
    assert!(kinds.contains(&"SessionPaused".to_owned()), "{kinds:?}");
    assert!(kinds.contains(&"SessionResumed".to_owned()), "{kinds:?}");
    assert_eq!(kinds.last().map(String::as_str), Some("SessionEnded"));
}

/// A live proxy that never acknowledges: the pause still holds everything (the
/// marker, the approvals), but is recorded as `SessionPauseUnsettled` naming
/// the egress proxy, the response says so, the log's detail says so. A proxy
/// that acknowledged the hold late and then does not acknowledge its release
/// has the resume refused — the session stays paused — until it confirms.
#[test]
fn a_proxy_that_never_acknowledges_leaves_the_pause_unconfirmed_and_named() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    let silent = Registration::register(&acks::proxies_dir(state.path(), &id), false).unwrap();
    let served = serve(state.path(), &id);
    let socket = daemon::socket_path(state.path(), &id);
    let mut control = RemoteSink::connect(&socket).unwrap();
    let asking = ask(&socket);
    assert!(daemon::wait_until(Duration::from_secs(2), || {
        pending_held(&mut control) == Some(false)
    }));

    let paused = client::pause(&mut control, "looks wrong").expect("the pause itself proceeds");
    let expected = "egress proxy (no acknowledgement within 2s)";
    assert!(
        matches!(
            &paused.record.event,
            WardEvent::SessionPauseUnsettled { reason, pending: 0, .. }
                if reason.as_str() == format!("looks wrong - unconfirmed: {expected}")
        ),
        "{:?}",
        paused.record.event
    );
    assert_eq!(paused.unsettled, None, "the freeze itself settled");
    assert_eq!(paused.unconfirmed.as_deref(), Some(expected));
    assert_eq!(
        fs::read_to_string(pause::marker_path(state.path(), &id)).unwrap(),
        "looks wrong\n",
        "the marker stands"
    );
    assert_eq!(pending_held(&mut control), Some(true), "approvals held");
    assert_eq!(
        acks::unconfirmed_detail(&log).unwrap().as_deref(),
        Some(expected)
    );

    silent.set(true).unwrap();
    let refused = client::resume(&mut control).expect_err("the proxy never confirms release");
    assert!(refused.to_string().contains("egress proxy"), "{refused}");
    assert!(
        pause::marker_path(state.path(), &id).exists(),
        "the marker is back: the session stays paused"
    );
    assert_eq!(
        pending_held(&mut control),
        Some(true),
        "approvals held again"
    );
    assert!(matches!(
        control.call(&Request::Pause { reason: String::new() }).unwrap(),
        Response::Error(e) if e == "already paused"
    ));

    silent.set(false).unwrap();
    let resumed = client::resume(&mut control).expect("the proxy now reads running");
    assert!(matches!(resumed.event, WardEvent::SessionResumed { .. }));
    assert_eq!(pending_held(&mut control), Some(false));
    assert_eq!(acks::unconfirmed_detail(&log).unwrap(), None);
    drop(control);
    silent.remove();

    Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .unwrap();
    served.join().unwrap().unwrap();
    assert!(matches!(asking.join().unwrap(), Response::Decision { .. }));
    let kinds = kinds_of(&records_in(&log));
    assert_eq!(
        kinds
            .iter()
            .filter(|k| k.starts_with("SessionPause"))
            .collect::<Vec<_>>(),
        ["SessionPauseUnsettled"],
        "{kinds:?}"
    );
}

/// A stop waits for the same acknowledgements before `WorkloadsTerminated` and
/// the seal: with a proxy that never acknowledges, the stop is refused and the
/// session held for it, naming the proxy; once the proxy confirms, the retry
/// finishes the stop.
#[test]
fn a_stop_is_refused_until_the_proxy_acknowledges_the_hold() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    let silent = Registration::register(&acks::proxies_dir(state.path(), &id), false).unwrap();
    let served = serve(state.path(), &id);

    let refused = Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .expect_err("refused");
    assert!(refused.to_string().contains("egress proxy"), "{refused}");
    assert!(pause::stop_begun(state.path(), &id));
    assert!(pause::marker_path(state.path(), &id).exists());
    let records = records_in(&log);
    let kinds = kinds_of(&records);
    assert!(!kinds.contains(&"SessionEnded".to_owned()), "{kinds:?}");
    assert!(
        !kinds.contains(&"WorkloadsTerminated".to_owned()),
        "{kinds:?}"
    );
    assert!(
        matches!(
            &records.last().unwrap().event,
            WardEvent::SessionPauseUnsettled { reason, pending: 0, .. }
                if reason.as_str() == "ward stop - unconfirmed: egress proxy (no acknowledgement within 2s)"
        ),
        "{kinds:?}"
    );
    assert_eq!(
        acks::unconfirmed_detail(&log).unwrap().as_deref(),
        Some("egress proxy (no acknowledgement within 2s)")
    );
    let socket = daemon::socket_path(state.path(), &id);
    let mut control = RemoteSink::connect(&socket).unwrap();
    assert!(matches!(
        control.call(&Request::Resume).unwrap(),
        Response::Error(e) if e.contains("has begun and not completed")
    ));
    drop(control);

    silent.set(true).unwrap();
    let ended = Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .expect("the retry finishes");
    assert_eq!(ended, 0);
    served.join().unwrap().unwrap();
    silent.remove();
    let kinds = kinds_of(&records_in(&log));
    assert_eq!(
        &kinds[kinds.len() - 3..],
        ["WorkloadsTerminated", "AgentStateChanged", "SessionEnded"],
        "{kinds:?}"
    );
}

/// A daemon that finishes an interrupted pause re-collects the
/// acknowledgements: with a proxy that never answers, the reconciled record
/// is `SessionPauseUnsettled` naming it, never a confirmed `SessionPaused`.
#[test]
fn a_restarted_daemon_re_collects_acknowledgements_for_an_interrupted_pause() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    let silent = Registration::register(&acks::proxies_dir(state.path(), &id), false).unwrap();
    pause::write_intent(
        state.path(),
        &id,
        &pause::Intent::begin(pause::Verb::Pause {
            reason: "ops asked".into(),
        })
        .unwrap(),
    )
    .unwrap();

    let served = serve(state.path(), &id);
    assert!(!pause::intent_path(state.path(), &id).exists());
    assert_eq!(
        fs::read_to_string(pause::marker_path(state.path(), &id)).unwrap(),
        "ops asked\n"
    );
    let records = records_in(&log);
    assert!(
        matches!(
            &records.last().unwrap().event,
            WardEvent::SessionPauseUnsettled { reason, pending: 0, .. }
                if reason.as_str() == "ops asked - unconfirmed: egress proxy (no acknowledgement within 2s)"
        ),
        "{:?}",
        kinds_of(&records)
    );

    silent.set(true).unwrap();
    silent.set(false).unwrap();
    let socket = daemon::socket_path(state.path(), &id);
    let mut control = RemoteSink::connect(&socket).unwrap();
    assert!(matches!(
        control.call(&Request::Resume).unwrap(),
        Response::Record(record) if matches!(record.event, WardEvent::SessionResumed { .. })
    ));
    drop(control);
    silent.remove();
    Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .unwrap();
    served.join().unwrap().unwrap();
}
