#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End-to-end session test. Requires bubblewrap; skips cleanly without it.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use ward_daemon::control::{RemoteSink, Request, Response};
use ward_daemon::session::LaunchOpts;
use ward_daemon::{Session, SessionMeta, daemon, sandbox, selftest};
use ward_events::{EndReason, EventRecord, FileChangeKind, LogReader, Origin, WardEvent};

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

#[test]
fn session_runs_and_seals_a_log() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let report = session
        .run(&["/bin/sh".into(), "-c".into(), "echo hi > note.txt".into()])
        .expect("run");
    assert_eq!(report.code, Some(0));
    assert!(report.files_changed >= 1, "the write should be observed");
    session.stop(EndReason::UserStop).expect("stop");

    assert!(fs::metadata(&log).expect("log exists").len() > 0);
}

#[test]
fn up_run_status_stop_lifecycle() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();

    // `ward up`: start a session and record it as the project's current session.
    let up = Session::start_in(project.path(), state.path()).expect("up");
    let session_id = up.id().to_owned();
    let log = up.log_path();
    up.persist_current().expect("persist");
    drop(up);

    // `ward run`: reopen the current session, run a command that creates a file, and
    // keep the session active.
    let mut run = Session::open_current(project.path(), state.path())
        .expect("open current")
        .expect("a current session exists");
    assert_eq!(run.id(), session_id, "run resumes the same session");
    let report = run
        .run(&[
            "/bin/sh".into(),
            "-c".into(),
            "echo hi > created.txt".into(),
        ])
        .expect("run");
    assert_eq!(report.code, Some(0));
    assert!(
        report.files_changed >= 1,
        "the created file must be counted, got {}",
        report.files_changed
    );
    run.sync().expect("sync");
    drop(run);

    // The log must carry a FileModified{Create} for the new file.
    let reader = LogReader::open(&log).expect("open log");
    let mut saw_create = false;
    for rec in reader {
        let rec = rec.expect("record");
        if let WardEvent::FileModified { path, kind, .. } = &rec.event
            && *kind == FileChangeKind::Create
            && path.to_string().contains("created.txt")
        {
            saw_create = true;
        }
    }
    assert!(
        saw_create,
        "expected a FileModified{{Create}} for created.txt"
    );

    // `ward status`: the current session is visible without starting a new one.
    let meta = SessionMeta::current(project.path(), state.path())
        .expect("status")
        .expect("status shows the active session");
    assert_eq!(meta.id, session_id);

    // `ward stop`: end the session and clear the current pointer.
    let stop = Session::open_current(project.path(), state.path())
        .expect("open current")
        .expect("still active");
    stop.stop(EndReason::UserStop).expect("stop");
    assert!(
        SessionMeta::current(project.path(), state.path())
            .expect("status after stop")
            .is_none(),
        "the current pointer must be cleared on stop"
    );
    assert!(
        Session::open_current(project.path(), state.path())
            .expect("open after stop")
            .is_none(),
        "no session should reopen after stop"
    );
}

#[test]
fn selftest_blocks_every_probe() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let project = scratch_project();
    let results = selftest(project.path()).expect("selftest");
    assert!(
        results.iter().all(|r| r.blocked),
        "all probes must be blocked"
    );
    // The escape probes added for this work must be present and denied.
    for id in ["ST-013", "ST-014", "ST-015"] {
        let probe = results.iter().find(|r| r.name.starts_with(id));
        assert!(probe.is_some(), "{id} probe must exist");
        assert!(
            probe.is_some_and(|p| p.blocked),
            "{id} must be denied in the sandbox"
        );
    }

    // Credential probes run inside a session with a canary key on the host.
    let state = tempfile::tempdir().unwrap();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let creds = ward_daemon::selftest_credentials(&mut session).expect("credential probes");
    let evidence = ward_daemon::selftest_evidence(&mut session).expect("evidence probes");
    assert_eq!(evidence.len(), 3);
    for r in &evidence {
        assert!(r.blocked, "{} must be denied in the sandbox", r.name);
    }
    let verifier = ward_daemon::selftest_verifier(&mut session).expect("verifier probes");
    assert_eq!(verifier.len(), 3);
    for r in &verifier {
        assert!(r.blocked, "{} must be denied in the sandbox", r.name);
    }
    session.stop(EndReason::UserStop).expect("stop");
    let names: Vec<&str> = creds.iter().map(|r| r.name).collect();
    assert_eq!(names.len(), 2, "{names:?}");
    for r in &creds {
        assert!(r.blocked, "{} must be denied in the sandbox", r.name);
    }

    // The probe itself must be able to fail: a key leaked into the environment REACHES.
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let leaked = LaunchOpts {
        env: vec![("ANTHROPIC_API_KEY".into(), "canary-xyz".into())],
        ..LaunchOpts::default()
    };
    let argv: Vec<String> = [
        "/bin/sh",
        "-c",
        ward_daemon::selftest::ST_012,
        "sh",
        "canary-xyz",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let report = session.launch(&argv, &leaked).expect("launch");
    session.stop(EndReason::UserStop).expect("stop");
    assert_eq!(report.code, Some(0), "ST-012 must detect a leaked key");
}

/// A sandboxed process can reach the session proxy only through the bind-mounted Unix
/// socket, and a private destination is denied there and recorded (ADR-0014).
#[test]
fn sandboxed_egress_goes_through_the_proxy_and_private_is_denied() {
    if !sandbox::available()
        || !std::path::Path::new("/usr/bin/python3").exists()
            && !std::path::Path::new("/usr/local/bin/python3").exists()
    {
        eprintln!("skipping: bubblewrap or python3 not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let script = "import socket\n\
s=socket.socket(socket.AF_UNIX)\ns.connect('/run/ward/proxy.sock')\n\
s.sendall(b'CONNECT 10.0.0.1:80 HTTP/1.1\\r\\nHost: 10.0.0.1:80\\r\\n\\r\\n')\n\
print(s.recv(200).split(b'\\r\\n')[0].decode())";
    let report = session
        .run(&["python3".into(), "-c".into(), script.into()])
        .expect("run");
    assert!(
        report.stdout.contains("403"),
        "expected 403 from proxy, got: {}",
        report.stdout
    );
    session.stop(EndReason::UserStop).expect("stop");

    let denied = ward_events::LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .any(|r| matches!(r.event, ward_events::WardEvent::NetworkDenied { .. }));
    assert!(denied, "a NetworkDenied record must be in the sealed log");
}

/// A loopback "model API" that records the request head and answers 200.
fn spawn_upstream() -> (u16, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(String::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        if let Some(Ok(mut s)) = listener.incoming().next() {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while s.read(&mut byte).unwrap_or(0) == 1 {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            *log.lock().unwrap() = String::from_utf8_lossy(&buf).into_owned();
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, seen)
}

#[test]
fn gateway_injects_the_host_key_and_the_sandbox_never_holds_it() {
    if !sandbox::available() || !std::path::Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping: bubblewrap or python3 not available");
        return;
    }
    let (port, seen) = spawn_upstream();
    let spec = ward_daemon::agents::profile("claude")
        .and_then(|p| p.gateway)
        .unwrap();
    let route = ward_proxy::GatewayRoute::new(
        spec.prefix,
        "127.0.0.1",
        port,
        spec.header,
        ward_proxy::Secret::from("sk-ant-real"),
    )
    .unwrap()
    .strip_headers(spec.strip)
    .plain_upstream(true);
    let gateway = ward_daemon::gateway::Gateway::new(&spec, route);

    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    // The agent's view: base URL and key from its environment, nothing else.
    let script = "import os,socket\n\
base=os.environ['ANTHROPIC_BASE_URL']\nkey=os.environ['ANTHROPIC_API_KEY']\n\
s=socket.socket(socket.AF_UNIX)\ns.connect('/run/ward/proxy.sock')\n\
path=base.split('3128',1)[1]+'/v1/messages'\n\
s.sendall(('POST '+path+' HTTP/1.1\\r\\nHost: 127.0.0.1:3128\\r\\nx-api-key: '+key+'\\r\\n\
Content-Length: 0\\r\\n\\r\\n').encode())\n\
print(s.recv(200).split(b'\\r\\n')[0].decode()); print('key='+key)";
    let opts = LaunchOpts {
        env: gateway.env.clone(),
        gateways: vec![gateway],
        ..LaunchOpts::default()
    };
    let report = session
        .launch(&["python3".into(), "-c".into(), script.into()], &opts)
        .expect("launch");
    assert!(
        report.stdout.contains("200"),
        "{}\n{}",
        report.stdout,
        report.stderr
    );
    assert!(
        report.stdout.contains("key=ward-gateway"),
        "{}",
        report.stdout
    );
    session.stop(EndReason::UserStop).expect("stop");

    let head = seen.lock().unwrap().clone();
    assert!(head.starts_with("POST /v1/messages HTTP/1.1"), "{head}");
    assert!(head.contains("x-api-key: sk-ant-real"), "{head}");
    assert!(!head.contains("ward-gateway"), "{head}");

    let granted = ward_events::LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .any(|r| matches!(r.event, ward_events::WardEvent::CredentialGranted { .. }));
    assert!(
        granted,
        "a CredentialGranted record must be in the sealed log"
    );
}

#[test]
fn hooks_answer_ask_under_step_through_and_are_logged_as_claims() {
    if !sandbox::available() || !std::path::Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping: bubblewrap or python3 not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    fs::write(
        project.path().join(".ward/policy.yaml"),
        "network: localhost_only\ncontainers: none\nobserver: !step_through\n  pause_before_writes: true\n",
    )
    .unwrap();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    // The agent's view: the seeded settings file and the hook socket.
    let script = r"import json, os, socket
print(open('/home/agent/.claude/settings.json').read().count('ward-agent hook'))
def ask(req):
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.environ['WARD_SOCKET'])
    s.sendall((json.dumps(req) + '\n').encode())
    return s.makefile().readline().strip()
print(ask({'hook': 'PreToolUse', 'tool': 'Write', 'summary': '/work/a.rs'}))
print(ask({'hook': 'PreToolUse', 'tool': 'Read', 'summary': '/work/a.rs'}))
print(ask({'hook': 'Stop'}))";
    let seeds = ward_daemon::agents::profile("claude")
        .and_then(|p| p.settings)
        .map(|s| (s.path.to_owned(), (s.content)()))
        .into_iter()
        .collect();
    let opts = LaunchOpts {
        seeds,
        ..LaunchOpts::default()
    };
    let report = session
        .launch(&["python3".into(), "-c".into(), script.into()], &opts)
        .expect("launch");
    let lines: Vec<&str> = report.stdout.lines().collect();
    assert_eq!(
        lines.first(),
        Some(&"5"),
        "{}\n{}",
        report.stdout,
        report.stderr
    );
    assert!(lines[1].contains("\"ask\""), "{}", lines[1]);
    assert!(lines[2].contains("\"allow\""), "{}", lines[2]);
    session.stop(EndReason::UserStop).expect("stop");

    let claims: Vec<String> = LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|r| r.origin == ward_events::Origin::Agent)
        .filter_map(|r| match r.event {
            // Payload text isolates non-ASCII (the arrow) in BiDi wrappers; strip them.
            WardEvent::AgentClaim { payload, .. } => {
                Some(payload.to_string().replace(['\u{2068}', '\u{2069}'], ""))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        claims,
        [
            "PreToolUse Write /work/a.rs → ask",
            "PreToolUse Read /work/a.rs → allow",
            "Stop"
        ]
    );
}

/// The Phase 3 demo in test form: the bug fails verification, weakening the
/// protected test changes nothing (the verifier takes it from the entry snapshot),
/// and the real fix passes.
#[test]
fn verify_ignores_a_weakened_protected_test_and_passes_the_real_fix() {
    if !sandbox::available() || !ward_daemon::verify::Toolchains::detect().has_rust() {
        eprintln!("skipping: bubblewrap or a Rust toolchain not available");
        return;
    }
    let demo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/ward-demo");
    let project = tempfile::tempdir().unwrap();
    let w = project.path();
    for entry in walk(&demo) {
        let rel = entry.strip_prefix(&demo).unwrap();
        if rel.starts_with("target") {
            continue;
        }
        let dest = w.join(rel);
        if entry.is_dir() {
            fs::create_dir_all(&dest).unwrap();
        } else {
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            fs::copy(&entry, &dest).unwrap();
        }
    }
    let state = tempfile::tempdir().unwrap();
    let mut session = Session::start_in(w, state.path()).expect("start");

    let buggy = session.verify().expect("verify");
    assert!(!buggy.passed, "{}", buggy.output);
    assert_eq!(buggy.summary.tests_failed, 1, "{}", buggy.output);
    assert!(buggy.restored.is_empty());

    // The shortcut: make the judge lenient.
    fs::write(
        w.join("tests/security_expiry.rs"),
        "#[test]\nfn rejected_at_exact_expiry() {}\n",
    )
    .unwrap();
    let weakened = session.verify().expect("verify");
    assert!(!weakened.passed, "a weakened protected test must not count");
    assert_eq!(weakened.restored, vec!["tests/security_expiry.rs"]);

    // The real fix.
    let lib = w.join("src/lib.rs");
    let src = fs::read_to_string(&lib).unwrap();
    assert!(src.contains(" || now == self.expires_at"));
    fs::write(&lib, src.replace(" || now == self.expires_at", "")).unwrap();
    let fixed = session.verify().expect("verify");
    assert!(fixed.passed, "{}", fixed.output);
    assert!(fixed.summary.tests_run >= 3, "{:?}", fixed.summary);
    // The candidate the verdict names is what the worktree digests to with the
    // verifier's capture options: the shell's `VERIFY ✓` compares exactly this
    // (ADR-0019 decision 1), and one more edit makes it stale.
    let mut cache = ward_snapshot::HashCache::new();
    let digest = |cache: &mut ward_snapshot::HashCache| {
        ward_snapshot::digest_worktree(w, ward_daemon::verify::candidate_options(), cache)
            .expect("digest")
            .to_string()
    };
    assert_eq!(digest(&mut cache), fixed.candidate);
    fs::write(w.join("README.md"), "edited after the verdict\n").unwrap();
    assert_ne!(digest(&mut cache), fixed.candidate);
    let log = session.log_path();
    session.stop(EndReason::UserStop).expect("stop");

    let verifier: Vec<EventRecord> = LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|r| r.origin == ward_events::Origin::Verifier)
        .collect();
    let passed_candidates: Vec<String> = verifier
        .iter()
        .filter_map(|r| match &r.event {
            WardEvent::VerificationPassed { candidate, .. } => Some(candidate.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(
        passed_candidates,
        vec![fixed.candidate.clone()],
        "the record names the candidate the shell compares against"
    );
    let kinds: Vec<String> = verifier
        .iter()
        .map(|r| format!("{:?}", r.event.kind()))
        .collect();
    assert!(
        kinds.contains(&"VerificationFailed".to_string()),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&"VerificationPassed".to_string()),
        "{kinds:?}"
    );
}

/// The `TamperWard` primitives (`docs/tamperward-integration.md` §2): a candidate
/// snapshot after an edit, `diff` and `cat` answered from the CAS, and `describe`
/// carrying the entry id and policy hash.
#[test]
fn snapshot_primitives_answer_from_the_cas_and_describe_carries_the_facts() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let entry = ward_daemon::snapshot::parse_id(session.entry_snapshot()).expect("entry id");

    fs::write(project.path().join("README.md"), "edited\n").unwrap();
    let candidate = session
        .snapshot(ward_daemon::SnapshotRole::Candidate)
        .expect("candidate");
    assert_ne!(candidate.id, entry);

    let diff = ward_daemon::snapshot::diff(state.path(), entry, candidate.id).expect("diff");
    assert_eq!(diff.changed, vec!["README.md".to_string()]);
    assert!(diff.added.is_empty() && diff.removed.is_empty(), "{diff:?}");
    assert!(
        ward_daemon::snapshot::diff(state.path(), entry, entry)
            .unwrap()
            .is_empty()
    );

    let pristine =
        ward_daemon::snapshot::cat(state.path(), entry, std::path::Path::new("README.md"))
            .expect("cat");
    assert_eq!(
        pristine, b"demo\n",
        "the entry bytes are untouched by the edit"
    );
    assert!(
        ward_daemon::snapshot::cat(state.path(), entry, std::path::Path::new("missing.txt"))
            .is_err()
    );

    let d = session.describe();
    assert_eq!(d.session, session.id());
    assert_eq!(d.entry_snapshot, entry.to_string());
    assert_eq!(d.policy_hash, session.manifest().policy_hash.to_hex());
    assert_eq!(d.manifest, *session.manifest());
    assert_eq!(d.worktree, project.path().canonicalize().unwrap());
    assert_eq!(d.agent.as_ref().map(|a| a.name.as_str()), Some("shell"));

    // A reopened session describes the same facts, and the log records the capture.
    session.persist_current().expect("persist");
    let log = session.log_path();
    drop(session);
    let reopened = Session::open_current(project.path(), state.path())
        .expect("open")
        .expect("current");
    assert_eq!(reopened.describe(), d);
    reopened.stop(EndReason::UserStop).expect("stop");
    let created = LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|r| match r.event {
            WardEvent::SnapshotCreated { role, id, .. } => Some((role, id.to_string())),
            _ => None,
        })
        .expect("a SnapshotCreated record");
    assert_eq!(created.0, ward_events::SnapshotRole::Candidate);
    assert_eq!(created.1, candidate.id.to_string());
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.push(p.clone());
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// ST-007: a project policy rewritten mid-session changes nothing; the manifest was
/// computed at `ward up` and the proxy enforces that one.
#[test]
fn st007_policy_rewrite_mid_session_does_not_widen_the_network() {
    if !sandbox::available() || !std::path::Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping: bubblewrap or python3 not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    fs::write(
        project.path().join(".ward/policy.yaml"),
        "network: unrestricted\ncontainers: none\n",
    )
    .unwrap();
    // A public IP literal is allowed under `unrestricted` and refused under
    // `localhost_only`, so a 403 proves the session still runs the entry policy.
    let script = "import socket\n\
s=socket.socket(socket.AF_UNIX)\ns.connect('/run/ward/proxy.sock')\n\
s.sendall(b'CONNECT 93.184.216.34:80 HTTP/1.1\\r\\nHost: 93.184.216.34:80\\r\\n\\r\\n')\n\
print(s.recv(200).split(b'\\r\\n')[0].decode())";
    let report = session
        .run(&["python3".into(), "-c".into(), script.into()])
        .expect("run");
    assert!(report.stdout.contains("403"), "{}", report.stdout);
    let reopened = Session::open_current(project.path(), state.path()).unwrap();
    assert!(
        reopened.is_none(),
        "throwaway sessions never become current"
    );
    session.stop(EndReason::UserStop).expect("stop");
}

/// ST-016: whatever the agent sends through the hook socket lands as an
/// `Origin::Agent` claim, never as a kernel, proxy or daemon fact.
#[test]
fn st016_forged_semantic_events_stay_agent_origin_claims() {
    if !sandbox::available() || !std::path::Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping: bubblewrap or python3 not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let script = r"import json, os, socket
for req in ({'hook': 'PostToolUse', 'tool': 'Read', 'summary': 'FORGED kernel read'},
            {'hook': 'SessionStart', 'origin': 'kernel', 'seq': 0}):
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.environ['WARD_SOCKET'])
    s.sendall((json.dumps(req) + '\n').encode())
    s.makefile().readline()";
    session
        .run(&["python3".into(), "-c".into(), script.into()])
        .expect("run");
    session.stop(EndReason::UserStop).expect("stop");
    let records: Vec<_> = LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    // The command line itself carries the string too; only claims count here.
    let forged: Vec<_> = records
        .iter()
        .filter(|r| matches!(&r.event, WardEvent::AgentClaim { payload, .. } if payload.to_string().contains("FORGED")))
        .collect();
    assert_eq!(forged.len(), 1, "the forged claim is recorded once");
    assert_eq!(forged[0].origin, ward_events::Origin::Agent);
    assert!(
        records
            .iter()
            .filter(|r| r.origin != ward_events::Origin::Agent)
            .all(|r| !matches!(r.event, WardEvent::AgentClaim { .. })),
        "no claim carries an enforcement origin"
    );
}

/// ADR-0015 end to end: a live `wardd` owns the log. A reopened session appends
/// through it, a second client adds `TamperWard` evidence, a subscriber from seq 0
/// sees the run's records and the evidence in order with no gap across the
/// replay/live boundary, and `stop` seals a log that verifies.
#[test]
fn daemon_owns_the_log_streams_to_a_subscriber_and_seals_on_stop() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();

    // `ward up`: start, persist, hand the log over to the daemon.
    let up = Session::start_in(project.path(), state.path()).expect("up");
    let session_id = up.id().to_owned();
    let log = up.log_path();
    up.persist_current().expect("persist");
    drop(up);
    let (state_path, id) = (state.path().to_path_buf(), session_id.clone());
    let served = std::thread::spawn(move || daemon::serve(&state_path, &id));
    assert!(
        daemon::wait_until(daemon::STARTUP_TIMEOUT, || daemon::serving(
            state.path(),
            &session_id
        )),
        "the daemon answers a Ping"
    );
    let socket = daemon::socket_path(state.path(), &session_id);
    assert!(daemon::pid_path(state.path(), &session_id).exists());

    let collector = subscribe_from_zero(&socket);

    // `ward run`: the reopened session writes through the socket.
    let mut run = Session::open_current(project.path(), state.path())
        .expect("open current")
        .expect("a current session exists");
    let report = run
        .run(&[
            "/bin/sh".into(),
            "-c".into(),
            "echo hi > created.txt".into(),
        ])
        .expect("run");
    assert_eq!(report.code, Some(0));
    run.sync().expect("sync through the daemon");

    // TamperWard: evidence from a second connection, and the session facts.
    let mut tamperward = RemoteSink::connect(&socket).expect("second client");
    let evidence = WardEvent::PolicyDenied {
        subject: ward_events::PolicySubject::ProtectedTests,
        rule: ward_events::RuleRef::new("tests").unwrap(),
        detail: ward_events::DetailText::new("tests/security_expiry.rs"),
    };
    let appended = match tamperward
        .call(&Request::Evidence { event: evidence })
        .expect("evidence")
    {
        Response::Record(r) => *r,
        other => panic!("{other:?}"),
    };
    assert_eq!(appended.origin, Origin::TamperWard);
    match tamperward.call(&Request::Describe).expect("describe") {
        Response::Description(v) => {
            assert_eq!(v, serde_json::to_value(run.describe()).unwrap());
        }
        other => panic!("{other:?}"),
    }
    let forged = tamperward
        .call(&Request::Append {
            origin: Origin::TamperWard,
            event: WardEvent::AgentStateChanged {
                state: ward_events::AgentState::Working,
            },
            at_unix_ms: 0,
        })
        .expect("answered");
    assert!(matches!(forged, Response::Error(_)), "{forged:?}");

    // `ward stop`: a `Request::Stop` through the sink; the daemon seals and exits.
    run.stop(EndReason::UserStop).expect("stop");
    served
        .join()
        .unwrap()
        .expect("serve returns Ok once the log is sealed");
    assert!(!socket.exists(), "the socket is unlinked on exit");
    assert!(
        !daemon::pid_path(state.path(), &session_id).exists(),
        "the pid file is removed on exit"
    );
    assert!(
        SessionMeta::current(project.path(), state.path())
            .unwrap()
            .is_none(),
        "the current pointer is cleared"
    );
    assert!(
        RemoteSink::connect(&socket).is_none(),
        "nothing answers after the seal"
    );

    // The subscriber saw exactly the sealed log, in order, with no gap or repeat.
    let seen = collector.join().unwrap();
    assert_stream_matches_sealed_log(&seen, &log);
}

/// A subscriber from seq 0 on its own thread, collecting until the daemon closes
/// the stream. A raw stream: the replay is instant but live records arrive
/// whenever the sandboxed command produces them, so no client read timeout applies.
fn subscribe_from_zero(socket: &std::path::Path) -> std::thread::JoinHandle<Vec<EventRecord>> {
    let stream = UnixStream::connect(socket).expect("subscriber connects");
    std::thread::spawn(move || {
        let mut writer = stream.try_clone().unwrap();
        let mut line = serde_json::to_vec(&Request::Subscribe { from_seq: 0 }).unwrap();
        line.push(b'\n');
        writer.write_all(&line).unwrap();
        let mut seen: Vec<EventRecord> = Vec::new();
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            match serde_json::from_str::<Response>(&line).expect("a response line") {
                Response::Record(r) => seen.push(*r),
                other => panic!("unexpected on a subscription: {other:?}"),
            }
        }
        seen
    })
}

/// `seen` (what a subscriber from seq 0 received) is the sealed log at `log`,
/// record for record, and carries the run's records and the evidence in seq order.
fn assert_stream_matches_sealed_log(seen: &[EventRecord], log: &std::path::Path) {
    let head = LogReader::open(log)
        .unwrap()
        .verify_all()
        .expect("sealed log verifies");
    let on_disk: Vec<EventRecord> = LogReader::open(log)
        .unwrap()
        .map(|r| r.expect("record"))
        .collect();
    assert_eq!(seen, on_disk);
    let seqs: Vec<u64> = seen.iter().map(|r| r.seq).collect();
    assert_eq!(seqs, (0..head.next_seq).collect::<Vec<_>>());
    let position =
        |pred: &dyn Fn(&EventRecord) -> bool| seen.iter().position(pred).expect("record present");
    let started = position(&|r| matches!(r.event, WardEvent::CommandStarted { .. }));
    let created = position(&|r| {
        matches!(&r.event, WardEvent::FileModified { path, kind, .. }
            if *kind == FileChangeKind::Create && path.to_string().contains("created.txt"))
    });
    let finished = position(&|r| matches!(r.event, WardEvent::CommandFinished { .. }));
    let evidence = position(&|r| r.origin == Origin::TamperWard);
    assert!(
        started < created && created < finished && finished < evidence,
        "{seqs:?}"
    );
    assert!(matches!(
        seen.last().map(|r| &r.event),
        Some(WardEvent::SessionEnded { .. })
    ));
    assert_eq!(
        seen.iter()
            .filter(|r| r.origin == Origin::TamperWard)
            .count(),
        1,
        "the forged append never reached the log"
    );
}

/// The GitHub adapter: a `github.com` remote inside the sandbox is rewritten to the
/// relay, the gateway injects `Authorization: Basic x-access-token:<token>`, and
/// the sandbox never holds the token.
#[test]
fn github_remote_goes_through_the_gateway_with_the_host_token() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let (port, seen) = spawn_upstream();
    let route = ward_proxy::GatewayRoute::new(
        ward_daemon::github::GIT.prefix,
        "127.0.0.1",
        port,
        ward_daemon::github::GIT.header,
        ward_proxy::Secret::from(format!(
            "Basic {}",
            ward_daemon::gateway::base64(b"x-access-token:ghp_secret")
        )),
    )
    .unwrap()
    .strip_headers(ward_daemon::github::GIT.strip)
    .plain_upstream(true);
    let (git_paths, _) = ward_daemon::github::scope_paths(&["hexrift/WardOS".to_owned()]);
    let gateway = ward_daemon::gateway::Gateway::new(&ward_daemon::github::GIT, route)
        .with_permissions(vec!["contents:read".into()])
        .map_route(|r| r.scope(git_paths, false));

    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let opts = LaunchOpts {
        gateways: vec![gateway],
        seeds: vec![(
            ward_daemon::github::GITCONFIG_PATH.to_owned(),
            ward_daemon::github::gitconfig(),
        )],
        ..LaunchOpts::default()
    };
    // Real git, the real remote spelling; the fake upstream answers nonsense, so
    // git fails, but the request it made is what matters.
    // The e2e sandbox has no shim relay, so a Python stand-in bridges the loopback
    // port to the egress socket the way `ward-agent --relay` does.
    let relay = r"import socket, threading
def pump(a, b):
    while True:
        d = a.recv(65536)
        if not d:
            break
        b.sendall(d)
    b.shutdown(socket.SHUT_WR)
srv = socket.socket(); srv.bind(('127.0.0.1', 3128)); srv.listen(8)
while True:
    c, _ = srv.accept()
    u = socket.socket(socket.AF_UNIX); u.connect('/run/ward/proxy.sock')
    threading.Thread(target=pump, args=(c, u), daemon=True).start()
    threading.Thread(target=pump, args=(u, c), daemon=True).start()";
    let script = format!(
        "python3 -c \"{relay}\" & sleep 0.5; \
         git ls-remote https://github.com/hexrift/WardOS.git 2>&1 | head -2; \
         curl -s -o /dev/null -w 'other:%{{http_code}}\n' http://127.0.0.1:3128/github/other/repo.git/info/refs; \
         env | grep -c ghp_ || true"
    );
    let argv: Vec<String> = ["sh", "-c", &script]
        .iter()
        .map(ToString::to_string)
        .collect();
    let report = session.launch(&argv, &opts).expect("launch");
    session.stop(EndReason::UserStop).expect("stop");
    assert!(
        report.stdout.trim().ends_with('0'),
        "the token must not be in the sandbox environment: {}",
        report.stdout
    );
    assert!(
        report.stdout.contains("other:403"),
        "another repository is outside the credential scope: {}",
        report.stdout
    );

    let head = seen.lock().unwrap().clone();
    assert!(
        head.starts_with("GET /hexrift/WardOS.git/info/refs?service=git-upload-pack HTTP/1.1"),
        "{head}"
    );
    assert!(
        head.contains("authorization: Basic eC1hY2Nlc3MtdG9rZW46Z2hwX3NlY3JldA=="),
        "{head}"
    );
    assert!(!head.contains("ward-gateway"), "{head}");

    let granted = LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .any(|r| {
            matches!(r.event, WardEvent::CredentialGranted { ref scope, .. }
            if scope.permissions.iter().any(|p| p.as_str() == "contents:read"))
        });
    assert!(granted, "the grant records the policy scope");
}

/// ST-019: a hostile verify command gets no network, cannot see the real worktree
/// or the host, and nothing it writes survives into the next verification.
#[test]
fn st019_hostile_verify_command_is_contained_and_disposable() {
    if !sandbox::available() {
        eprintln!("skipping: bubblewrap not available");
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let project = scratch_project();
    let w = project.path();
    fs::create_dir_all(w.join(".tamperward")).unwrap();
    // Exit 0 (a "pass") only if the network, a host-only file (`/etc/hostname` is
    // never bound), or a /tmp marker from a previous run is reachable; also try to
    // leave a file behind in what the verifier sees as the worktree.
    fs::write(
        w.join(".tamperward/config.yml"),
        "verify:\n  command: >-\n    (timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' && exit 0);\n    test -e /etc/hostname && exit 0; test -e /tmp/marker && exit 0; touch /tmp/marker;\n    echo scratch > /work/leak; exit 1\n  budget_secs: 20\n",
    )
    .unwrap();
    let mut session = Session::start_in(w, state.path()).expect("start");
    let first = session.verify().expect("verify");
    assert!(!first.passed, "{}", first.output);
    let second = session.verify().expect("verify");
    assert!(
        !second.passed,
        "a marker from the first run must not persist: {}",
        second.output
    );
    assert!(
        !w.join("leak").exists(),
        "the verifier wrote to its scratch tree, not the worktree"
    );
    session.stop(EndReason::UserStop).expect("stop");
}
