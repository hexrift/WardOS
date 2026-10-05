#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The explicit, daemon-owned lifecycle (#145 items 1, 2 and 8) through a real
//! daemon and the real protocol: one state served on its own lane while an
//! operation is in flight, launch admission serialised with that state, each
//! component's progress reported as it happens, and a pause that does not
//! wait behind subscribers replaying a long log. Nothing here needs
//! bubblewrap.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ward_daemon::acks::{self, Registration};
use ward_daemon::control::{Progress, RemoteSink, Request, Response};
use ward_daemon::pause::{self, Lifecycle, Owner};
use ward_daemon::{Session, client, daemon};
use ward_events::{AgentState, EndReason, EventRecord, LogReader, Origin, WardEvent};

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

/// A stand-in egress that follows the marker as the real one does — paused
/// when it exists, running when it is gone — acknowledging each state through
/// its registration after `delay`.
struct FollowingProxy {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FollowingProxy {
    fn start(state: &Path, id: &str, delay: Duration) -> Self {
        let registration =
            Registration::register(&acks::proxies_dir(state, id), false).expect("registered");
        let marker = pause::marker_path(state, id);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut paused = false;
            while !flag.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(10));
                let now = marker.exists();
                if now != paused {
                    paused = now;
                    std::thread::sleep(delay);
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

fn lifecycle_of(control: &mut RemoteSink) -> pause::LifecycleReport {
    control
        .lifecycle()
        .expect("lifecycle answered")
        .expect("this daemon serves the lifecycle")
}

/// #145 item 1: while a pause waits on a component, the lifecycle lane
/// answers `pausing` — not after the pause, as a request behind the daemon's
/// mutex would. A pause the proxy never acknowledges leaves `incomplete`,
/// naming the proxy, which the records on disk read the same; it is never
/// `paused`. Launch admission refuses it; a pause over it is refused in the
/// words every client reads; the resume releases it to `running`; the stop
/// ends it as `stopped`.
#[test]
#[allow(clippy::too_many_lines)]
fn the_lifecycle_is_served_on_its_own_lane_and_incomplete_is_never_paused() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    let silent = Registration::register(&acks::proxies_dir(state.path(), &id), false).unwrap();
    let served = serve(state.path(), &id);
    let socket = daemon::socket_path(state.path(), &id);
    let mut control = RemoteSink::connect(&socket).unwrap();
    assert_eq!(lifecycle_of(&mut control).state, Lifecycle::Running);
    assert_eq!(
        pause::lifecycle_on_disk(state.path(), &id).unwrap().state,
        Lifecycle::Running
    );

    let pausing = {
        let socket = socket.clone();
        std::thread::spawn(move || {
            let mut sink = RemoteSink::connect(&socket).unwrap();
            let started = Instant::now();
            let outcome = client::pause(&mut sink, "looks wrong").expect("the pause proceeds");
            (outcome, started.elapsed())
        })
    };
    let asked = Instant::now();
    assert!(
        daemon::wait_until(Duration::from_secs(1), || {
            let lane = lifecycle_of(&mut control);
            lane.state == Lifecycle::Pausing && lane.op.is_some()
        }),
        "the lane reads pausing, naming the operation, while the pause waits on the proxy"
    );
    assert!(
        asked.elapsed() < acks::ACK_TIMEOUT,
        "answered before the pause's own wait ended: {:?}",
        asked.elapsed()
    );
    let in_flight = lifecycle_of(&mut control);
    assert_eq!(in_flight.state, Lifecycle::Pausing);
    assert!(
        in_flight.held_by.is_empty(),
        "nothing holds the session until the pause has: {in_flight:?}"
    );
    assert!(in_flight.op.is_some(), "the operation in flight is named");
    // The records say the same once the pause's intent is durable (the lane
    // publishes `pausing` as the operation is admitted, the intent follows).
    assert!(
        daemon::wait_until(Duration::from_secs(1), || {
            pause::lifecycle_on_disk(state.path(), &id).unwrap().state == Lifecycle::Pausing
        }),
        "{:?}",
        pause::lifecycle_on_disk(state.path(), &id).unwrap()
    );
    let on_disk = pause::lifecycle_on_disk(state.path(), &id).unwrap();
    assert_eq!(on_disk.op, in_flight.op);
    let (outcome, took) = pausing.join().unwrap();
    assert!(took >= acks::ACK_TIMEOUT, "{took:?}");
    let expected = "egress proxy (no acknowledgement within 2s)";
    assert_eq!(outcome.unconfirmed.as_deref(), Some(expected));

    let incomplete = lifecycle_of(&mut control);
    assert_eq!(incomplete.state, Lifecycle::Incomplete);
    assert_eq!(incomplete.detail.as_deref(), Some(expected));
    assert_eq!(incomplete.held_by, [Owner::User]);
    assert_eq!(incomplete.op, None);
    let on_disk = pause::lifecycle_on_disk(state.path(), &id).unwrap();
    assert_eq!(on_disk.state, Lifecycle::Incomplete, "{on_disk:?}");
    assert_eq!(on_disk.detail.as_deref(), Some(expected));
    assert_eq!(on_disk.held_by, [Owner::User]);
    let refused = pause::admit_launch(state.path(), &id)
        .unwrap_err()
        .to_string();
    assert!(refused.contains(pause::PAUSED_REFUSAL), "{refused}");
    assert!(matches!(
        control.call(&Request::Pause { reason: String::new() }).unwrap(),
        Response::Error(e) if e == "already paused"
    ));

    let resumed = client::resume(&mut control).expect("the proxy reads running already");
    assert!(matches!(resumed.event, WardEvent::SessionResumed { .. }));
    assert_eq!(lifecycle_of(&mut control).state, Lifecycle::Running);
    assert_eq!(
        pause::lifecycle_on_disk(state.path(), &id).unwrap().state,
        Lifecycle::Running
    );
    drop(pause::admit_launch(state.path(), &id).expect("admitted again"));
    assert!(matches!(
        control.call(&Request::Resume).unwrap(),
        Response::Error(e) if e == "not paused"
    ));
    drop(control);
    // The stop collects the same acknowledgements: the stand-in reads paused.
    silent.set(true).unwrap();

    Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .unwrap();
    served.join().unwrap().unwrap();
    silent.remove();
    let stopped = pause::lifecycle_on_disk(state.path(), &id).unwrap();
    assert_eq!(stopped.state, Lifecycle::Stopped, "{stopped:?}");
    assert!(
        pause::admit_launch(state.path(), &id)
            .unwrap_err()
            .to_string()
            .contains(pause::STOPPED_REFUSAL)
    );
    let kinds = kinds_of(&records_in(&log));
    assert!(
        kinds.contains(&"SessionPauseUnsettled".to_owned()),
        "{kinds:?}"
    );
    assert_eq!(kinds.last().map(String::as_str), Some("SessionEnded"));
}

/// #145 item 2: launch admission is decided by the lifecycle, under the
/// session lock pause and stop take. An operation in flight (its intent
/// recorded, as a daemon mid-operation leaves it) refuses a launch naming the
/// state; a hold for a stop refuses it as stopping; a sealed session refuses
/// it for good.
#[test]
fn a_launch_is_admitted_only_while_the_session_runs() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, _) = new_session(project.path(), state.path());
    let refusal = || {
        pause::admit_launch(state.path(), &id)
            .unwrap_err()
            .to_string()
    };
    drop(pause::admit_launch(state.path(), &id).expect("admitted while running"));
    for (verb, word) in [
        (
            pause::Verb::Pause {
                reason: "ops".into(),
            },
            "pausing",
        ),
        (pause::Verb::Resume, "resuming"),
        (
            pause::Verb::Stop {
                reason: EndReason::UserStop,
            },
            "stopping",
        ),
    ] {
        pause::write_intent(state.path(), &id, &pause::Intent::begin(verb).unwrap()).unwrap();
        let text = refusal();
        assert!(
            text.contains(word) || text.contains(pause::STOPPED_REFUSAL),
            "{word}: {text}"
        );
        assert_eq!(
            pause::lifecycle_on_disk(state.path(), &id).unwrap().state,
            Lifecycle::parse(word).unwrap()
        );
    }
    pause::clear_intent(state.path(), &id).unwrap();
    drop(pause::admit_launch(state.path(), &id).expect("admitted once the intent is gone"));

    let proxy = FollowingProxy::start(state.path(), &id, Duration::ZERO);
    let served = serve(state.path(), &id);
    let socket = daemon::socket_path(state.path(), &id);
    let mut control = RemoteSink::connect(&socket).unwrap();
    assert!(matches!(
        control
            .call(&Request::HoldForStop {
                reason: "restore".into()
            })
            .unwrap(),
        Response::HeldForStop { unsettled: None }
    ));
    assert_eq!(lifecycle_of(&mut control).state, Lifecycle::Stopping);
    assert_eq!(lifecycle_of(&mut control).held_by, [Owner::Stop]);
    let on_disk = pause::lifecycle_on_disk(state.path(), &id).unwrap();
    assert_eq!(on_disk.state, Lifecycle::Stopping, "{on_disk:?}");
    assert!(refusal().contains(pause::STOPPED_REFUSAL));
    let refused = control.call(&Request::Resume).unwrap();
    assert!(
        matches!(&refused, Response::Error(e) if e.contains("has begun and not completed")),
        "{refused:?}"
    );
    assert!(matches!(
        control.call(&Request::Pause { reason: String::new() }).unwrap(),
        Response::Error(e) if e == "already paused"
    ));
    drop(control);
    Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .unwrap();
    served.join().unwrap().unwrap();
    drop(proxy);
    assert!(refusal().contains(pause::STOPPED_REFUSAL));
    assert_eq!(
        pause::lifecycle_on_disk(state.path(), &id).unwrap().state,
        Lifecycle::Stopped
    );
}

/// Read one connection's answers to a request until the request's own answer
/// arrives: every `Progress` line before it, stamped with when it arrived.
fn answers(control: &mut RemoteSink, request: &Request) -> (Vec<(Progress, Duration)>, Response) {
    let started = Instant::now();
    control.send(request).unwrap();
    let mut progress = Vec::new();
    loop {
        match control.next_response().unwrap().expect("open") {
            Response::Progress(p) => progress.push((p, started.elapsed())),
            answer => return (progress, answer),
        }
    }
}

/// #145 item 8: a connection that asked for progress hears each component as
/// it confirms — the processes first, then the egress proxy, the approvals
/// and the credentials in hold order — before the pause's own answer, and
/// the first line arrives while the proxy is still being waited on, not with
/// the answer. A resume reports the release order, a stop the termination.
#[test]
#[allow(clippy::too_many_lines)]
fn progress_is_reported_per_component_as_it_happens() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, log) = new_session(project.path(), state.path());
    let delay = Duration::from_millis(700);
    let proxy = FollowingProxy::start(state.path(), &id, delay);
    let served = serve(state.path(), &id);
    let socket = daemon::socket_path(state.path(), &id);

    // A connection that never asks gets exactly the one answer it always got.
    let mut plain = RemoteSink::connect(&socket).unwrap();
    assert!(matches!(
        plain.call(&Request::Lifecycle).unwrap(),
        Response::Lifecycle(report) if report.state == Lifecycle::Running
    ));

    let mut control = RemoteSink::connect(&socket).unwrap();
    assert!(matches!(
        control.call(&Request::ReportProgress).unwrap(),
        Response::Ok
    ));
    let (progress, answer) = answers(
        &mut control,
        &Request::Pause {
            reason: "looks wrong".into(),
        },
    );
    assert!(
        matches!(
            &answer,
            Response::Paused {
                unsettled: None,
                unconfirmed: None,
                ..
            }
        ),
        "{answer:?}"
    );
    let steps: Vec<&str> = progress.iter().map(|(p, _)| p.component.as_str()).collect();
    assert_eq!(
        steps,
        [
            Progress::PROCESSES,
            "egress proxy",
            "approvals",
            "credentials"
        ],
        "{progress:?}"
    );
    assert!(progress.iter().all(|(p, _)| p.confirmed), "{progress:?}");
    assert_eq!(progress[0].0.detail, "0 frozen (sigstop), settled");
    assert_eq!(progress[1].0.detail, "acknowledged");
    assert!(
        progress[0].1 < delay / 2,
        "the processes step was reported before the proxy answered: {:?}",
        progress[0].1
    );
    assert!(
        progress[1].1 >= delay / 2,
        "the proxy's step waited for its acknowledgement: {:?}",
        progress[1].1
    );
    assert_eq!(
        progress[0].0.text(),
        "processes · 0 frozen (sigstop), settled"
    );
    // The plain connection is unaffected by another connection's progress.
    assert!(matches!(
        plain.call(&Request::Pause { reason: String::new() }).unwrap(),
        Response::Error(e) if e == "already paused"
    ));

    let (progress, answer) = answers(&mut control, &Request::Resume);
    assert!(
        matches!(&answer, Response::Record(r) if matches!(r.event, WardEvent::SessionResumed { .. })),
        "{answer:?}"
    );
    let steps: Vec<&str> = progress.iter().map(|(p, _)| p.component.as_str()).collect();
    assert_eq!(
        steps,
        [
            "credentials",
            "approvals",
            "egress proxy",
            Progress::PROCESSES
        ],
        "{progress:?}"
    );
    assert_eq!(progress[2].0.detail, "released");
    assert_eq!(progress[3].0.detail, "0 thawed");
    drop(plain);
    drop(control);

    // A stop through the session's own sink reports the same way.
    let mut session = Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    session.set_progress(Box::new(move |p: &Progress| {
        sink.lock().unwrap().push(p.clone());
    }));
    assert_eq!(session.stop(EndReason::UserStop).unwrap(), 0);
    served.join().unwrap().unwrap();
    drop(proxy);
    let seen = seen.lock().unwrap();
    let steps: Vec<&str> = seen.iter().map(|p| p.component.as_str()).collect();
    assert_eq!(
        steps,
        [
            Progress::PROCESSES,
            "egress proxy",
            "approvals",
            "credentials"
        ],
        "{seen:?}"
    );
    assert_eq!(seen[0].detail, "0 ended, 0 pending, barrier confirmed");
    assert!(seen.iter().all(|p| p.confirmed), "{seen:?}");
    let kinds = kinds_of(&records_in(&log));
    assert_eq!(kinds.last().map(String::as_str), Some("SessionEnded"));
}

/// #145 item 8: an intervention does not wait behind a replay. With a long
/// log and several subscribers replaying it at once, a pause completes well
/// within its own bound, and every subscriber still sees the whole replay,
/// the boundary marker, and the pause's record live after it — no gap, no
/// duplicate.
#[test]
fn a_pause_completes_promptly_while_subscribers_replay_a_long_log() {
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let (id, _) = new_session(project.path(), state.path());
    let proxy = FollowingProxy::start(state.path(), &id, Duration::ZERO);
    let served = serve(state.path(), &id);
    let socket = daemon::socket_path(state.path(), &id);
    let mut control = RemoteSink::connect(&socket).unwrap();
    let records = 6_000u64;
    for i in 0..records {
        let event = WardEvent::AgentStateChanged {
            state: if i % 2 == 0 {
                AgentState::Working
            } else {
                AgentState::Idle
            },
        };
        assert!(matches!(
            control
                .call(&Request::Append {
                    origin: Origin::Wardd,
                    event,
                    at_unix_ms: i,
                })
                .unwrap(),
            Response::Record(_)
        ));
    }

    // Each subscriber says when its first record has arrived: by then its
    // replay boundary is fixed, so the pause below lands after every boundary
    // and while every replay is still in flight. Without this a subscriber
    // that connected after the pause would replay the pause's record before
    // its own boundary marker.
    let (subscribed, all_subscribed) = std::sync::mpsc::channel::<()>();
    let subscribers: Vec<JoinHandle<Vec<Response>>> = (0..6)
        .map(|_| {
            let socket = socket.clone();
            let subscribed = subscribed.clone();
            std::thread::spawn(move || {
                let mut sub = RemoteSink::connect(&socket).unwrap();
                sub.send(&Request::Subscribe { from_seq: 0 }).unwrap();
                let mut seen = Vec::new();
                loop {
                    let response = sub.next_response().unwrap().expect("open");
                    if seen.is_empty() {
                        let _ = subscribed.send(());
                    }
                    // A slow consumer, so the replay is still in flight when
                    // the pause lands.
                    std::thread::sleep(Duration::from_micros(50));
                    let paused = matches!(
                        &response,
                        Response::Record(r) if matches!(r.event, WardEvent::SessionPaused { .. })
                    );
                    seen.push(response);
                    if paused {
                        return seen;
                    }
                }
            })
        })
        .collect();
    drop(subscribed);
    for _ in 0..6 {
        all_subscribed
            .recv_timeout(Duration::from_secs(10))
            .expect("every subscriber's replay began");
    }
    let started = Instant::now();
    let paused = client::pause(&mut control, "mid-replay").expect("pause");
    let took = started.elapsed();
    assert!(matches!(
        paused.record.event,
        WardEvent::SessionPaused { .. }
    ));
    assert!(
        took < Duration::from_secs(1),
        "the pause did not wait behind the replays: {took:?}"
    );
    for subscriber in subscribers {
        let seen = subscriber.join().unwrap();
        let mut seqs = Vec::new();
        let mut caught_up = None;
        for response in &seen {
            match response {
                Response::Record(r) => seqs.push(r.seq),
                Response::CaughtUp { next_seq } => caught_up = Some(*next_seq),
                other => panic!("{other:?}"),
            }
        }
        let expected: Vec<u64> = (0..seqs.len() as u64).collect();
        assert_eq!(seqs, expected, "every record once, in order");
        let boundary = caught_up.expect("the boundary marker");
        assert!(boundary > records, "{boundary}");
        assert_eq!(*seqs.last().unwrap(), paused.record.seq);
    }
    drop(control);
    Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .unwrap();
    served.join().unwrap().unwrap();
    drop(proxy);
}
