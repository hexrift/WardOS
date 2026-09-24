//! #137 — file and network observations reach the event log *during* a command.
//!
//! Before this, `Session::launch` started the file watch and the egress recorder,
//! blocked for the whole life of the child, and only then drained what they had
//! accumulated. A long interactive agent session therefore showed nothing on the
//! log — and nothing in any observer built on it — until the command exited, which
//! is precisely when the decision to intervene is no longer available.
//!
//! The proof here is a rendezvous, not a sleep: the sandboxed command writes a file
//! and makes an approved request to a loopback fixture through the session proxy,
//! then blocks on a barrier file that only this test can create. Everything asserted
//! about the log is asserted *while the child is still blocked*, so a run that had
//! gone back to batching at the end would never satisfy it — it would time out with
//! an empty log instead. The barrier is released only after the assertions, and the
//! test then checks the terminal records are written exactly once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

use ward_daemon::session::run_dir_path;
use ward_daemon::{Session, daemon, sandbox};
use ward_events::{EndReason, EventRecord, FileChangeKind, LogReader, WardEvent};

/// How long the test waits for the live records before giving up. Generous: the
/// drain runs about every [`sandbox::WAIT_POLL`], so anything approaching this is a
/// real failure.
const LIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// The file the sandboxed command writes, watched for on the log.
const EVIDENCE: &str = "live-evidence.txt";
/// The barrier the sandboxed command blocks on until this test releases it.
const BARRIER: &str = "barrier-release";

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

/// A loopback TCP fixture the session proxy is allowed to reach under
/// `localhost_only`. It accepts and drops; the point is a real, approved
/// destination, not a protocol exchange.
fn spawn_fixture() -> (u16, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepting = listener.try_clone().unwrap();
    std::thread::spawn(move || {
        for stream in accepting.incoming() {
            drop(stream);
        }
    });
    (port, listener)
}

/// Every record currently on `log`. A record still being written shows up as a
/// truncated tail, after which the reader yields nothing further, so a partly
/// written frame is simply not there yet rather than an error.
fn records(log: &Path) -> Vec<EventRecord> {
    LogReader::open(log)
        .map(|r| r.map_while(Result::ok).collect())
        .unwrap_or_default()
}

fn created(records: &[EventRecord], name: &str) -> usize {
    records
        .iter()
        .filter(|r| {
            matches!(&r.event, WardEvent::FileModified { path, kind, .. }
                if *kind == FileChangeKind::Create && path.to_string().contains(name))
        })
        .count()
}

fn network_allowed(records: &[EventRecord]) -> usize {
    records
        .iter()
        .filter(|r| matches!(&r.event, WardEvent::NetworkRequested { .. }))
        .count()
}

fn finished(records: &[EventRecord]) -> usize {
    records
        .iter()
        .filter(|r| matches!(&r.event, WardEvent::CommandFinished { .. }))
        .count()
}

#[test]
fn file_and_network_observations_reach_the_log_before_the_command_exits() {
    let have_python =
        Path::new("/usr/bin/python3").exists() || Path::new("/usr/local/bin/python3").exists();
    if !ward_sandbox::ci::isolation_ready(sandbox::available(), "bubblewrap")
        || !ward_sandbox::ci::isolation_ready(have_python, "python3")
    {
        return;
    }

    let (port, _fixture) = spawn_fixture();
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let worktree = project.path().to_path_buf();
    let barrier = worktree.join(BARRIER);

    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();

    // The agent's side of the rendezvous: one file write, one approved request to
    // the loopback fixture through the bind-mounted proxy socket, then block until
    // the test releases the barrier. Nothing here sleeps for a fixed time; the
    // command simply does not end until this test says so.
    let script = format!(
        "import os,socket,time\n\
         open('/work/{EVIDENCE}','w').write('observed\\n')\n\
         s=socket.socket(socket.AF_UNIX)\n\
         s.connect('/run/ward/proxy.sock')\n\
         s.sendall(b'CONNECT localhost:{port} HTTP/1.1\\r\\nHost: localhost:{port}\\r\\n\\r\\n')\n\
         print(s.recv(200).split(b'\\r\\n')[0].decode())\n\
         while not os.path.exists('/work/{BARRIER}'):\n\
        \x20   time.sleep(0.02)\n\
         print('released')\n"
    );
    let running = std::thread::spawn(move || {
        let report = session.run(&["python3".into(), "-c".into(), script]);
        (session, report)
    });

    // --- while the child is still blocked on the barrier ---
    let mut live = Vec::new();
    let streamed = daemon::wait_until(LIVE_TIMEOUT, || {
        live = records(&log);
        created(&live, EVIDENCE) > 0 && network_allowed(&live) > 0
    });
    let saw_finish = finished(&live) > 0;
    // Release the barrier whatever happened, so a failure reports rather than hangs.
    fs::write(&barrier, b"go\n").unwrap();

    assert!(
        streamed,
        "the file write and the approved network request must be on the log while the \
         command is still running; the log held {} records instead: {:?}",
        live.len(),
        live.iter().map(EventRecord::kind).collect::<Vec<_>>()
    );
    assert!(
        !saw_finish,
        "the command had already finished, so this proves nothing about live streaming"
    );

    // --- after the barrier is released ---
    let (session, report) = running.join().expect("launch thread");
    let report = report.expect("run");
    assert_eq!(report.code, Some(0));
    assert!(
        report.stdout.contains("200") && report.stdout.contains("released"),
        "the proxy must have answered and the barrier released: {}\n{}",
        report.stdout,
        report.stderr
    );
    assert!(
        report.files_changed >= 1,
        "live-drained writes must still be counted in the report"
    );
    session.stop(EndReason::UserStop).expect("stop");

    // The terminal records are written exactly once, and nothing that was already
    // streamed was appended a second time by the final flush.
    let sealed = records(&log);
    assert_eq!(finished(&sealed), 1, "exactly one CommandFinished");
    assert_eq!(
        created(&sealed, EVIDENCE),
        1,
        "the create must be recorded once, not once live and once again at the end"
    );
    assert_eq!(
        network_allowed(&sealed),
        network_allowed(&live),
        "the approved request must not be appended a second time by the final flush"
    );

    // Ordering is preserved across the drains: the live records keep their places,
    // and the terminal record is last of the command's records.
    let live_seqs: Vec<u64> = live.iter().map(|r| r.seq).collect();
    let sealed_seqs: Vec<u64> = sealed.iter().take(live.len()).map(|r| r.seq).collect();
    assert_eq!(
        live_seqs, sealed_seqs,
        "a later drain must not reorder or rewrite what an earlier one appended"
    );
    let finish_at = sealed
        .iter()
        .position(|r| matches!(r.event, WardEvent::CommandFinished { .. }))
        .expect("a CommandFinished");
    assert!(
        finish_at >= live.len(),
        "every live observation must precede the terminal record"
    );
}

/// #137: a launch that never gets off the ground must still shut its producers
/// down. Before this, an error between starting the watch/proxy/hook broker and
/// `CommandFinished` returned straight to the caller: the watch thread was left
/// spinning for the life of the process, the proxy and hook sockets were left
/// bound in the run directory, and whatever they had already recorded went with
/// them. Ownership is RAII now, so leaving the scope any way at all stops them.
#[test]
fn a_launch_that_cannot_run_still_shuts_its_producers_down() {
    if !ward_sandbox::ci::isolation_ready(sandbox::available(), "bubblewrap") {
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let run_dir = run_dir_path(session.id());

    // An empty command fails inside the sandbox launch, after the watch, the
    // proxy and the hook broker are all running.
    let failed = session.run(&[]);
    assert!(failed.is_err(), "an empty command must fail the launch");

    assert!(
        !run_dir.exists(),
        "the run directory (and the proxy and hook sockets in it) must not be left \
         behind by a failed launch: {}",
        run_dir.display()
    );
    assert_eq!(
        finished(&records(&log)),
        0,
        "a launch that never ran has no CommandFinished"
    );

    // And the session is still usable: nothing from the failed launch is holding a
    // socket, a thread or the run directory against the next one.
    let report = session
        .run(&[
            "/bin/sh".into(),
            "-c".into(),
            format!("echo ok > {EVIDENCE}"),
        ])
        .expect("a later run must still work");
    assert_eq!(report.code, Some(0));
    assert_eq!(
        created(&records(&log), EVIDENCE),
        1,
        "the later run's own observation must be recorded exactly once"
    );
    session.stop(EndReason::UserStop).expect("stop");
    assert!(!run_dir.exists(), "and the run directory is gone again");
}
