#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end session test. Requires bubblewrap; skips cleanly without it.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use ward_daemon::session::LaunchOpts;
use ward_daemon::{Session, SessionMeta, sandbox, selftest};
use ward_events::{EndReason, FileChangeKind, LogReader, WardEvent};

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
    let settings = ward_daemon::agents::profile("claude")
        .and_then(|p| p.settings)
        .map(|s| (s.path.to_owned(), (s.content)()));
    let opts = LaunchOpts {
        settings,
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
    let log = session.log_path();
    session.stop(EndReason::UserStop).expect("stop");

    let kinds: Vec<String> = LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|r| r.origin == ward_events::Origin::Verifier)
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
