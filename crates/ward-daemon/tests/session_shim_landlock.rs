#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A session's Claude Code hooks under the `ward-agent` shim's enforced Landlock ruleset
//! (#426): the seeded settings run `/run/ward/ward-agent hook`, so the shim must be able
//! to exec itself, and a runtime installed under `/opt` must stay readable.
//!
//! The shim is the `ward-agent` binary of this build (`WARD_AGENT_BIN`, or beside the
//! test's target directory, which `cargo test --workspace` builds); without
//! `WARD_AGENT_BIN` the test runs itself again with it set, since the session finds its
//! shim through the process environment. Requires bubblewrap and that shim; skips without
//! them except under `WARD_REQUIRE_ISOLATION=1`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use ward_daemon::session::LaunchOpts;
use ward_daemon::{Session, agents, sandbox};
use ward_events::{EndReason, LogReader, Origin, WardEvent};

const TEST: &str =
    "a_claude_code_hook_runs_the_bound_shim_and_the_runtime_under_opt_stays_readable";

fn shim() -> Option<PathBuf> {
    let path = std::env::var_os("WARD_AGENT_BIN").map_or_else(
        || {
            let exe = std::env::current_exe().unwrap();
            exe.parent().unwrap().parent().unwrap().join("ward-agent")
        },
        PathBuf::from,
    );
    path.is_file().then_some(path)
}

fn hook_command(settings: &str) -> String {
    let settings: serde_json::Value = serde_json::from_str(settings).unwrap();
    settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn a_claude_code_hook_runs_the_bound_shim_and_the_runtime_under_opt_stays_readable() {
    if !ward_sandbox::ci::isolation_ready(sandbox::available(), "bubblewrap")
        || !ward_sandbox::ci::isolation_ready(
            shim().is_some(),
            "the ward-agent shim of this build (cargo build -p ward-agent, or WARD_AGENT_BIN)",
        )
    {
        return;
    }
    let shim = shim().unwrap();
    if std::env::var_os("WARD_AGENT_BIN").is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env("WARD_AGENT_BIN", &shim)
            .status()
            .unwrap();
        assert!(status.success(), "{status}");
        return;
    }
    assert!(sandbox::find_shim().is_some_and(|found| found.relay));

    let state = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    fs::create_dir_all(project.path().join(".ward")).unwrap();
    fs::write(
        project.path().join(".ward/policy.yaml"),
        "network: localhost_only\ncontainers: none\nobserver: !step_through\n  pause_before_writes: true\n",
    )
    .unwrap();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let settings = agents::profile("claude").and_then(|p| p.settings).unwrap();
    let content = (settings.content)();
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/work/a.rs","content":"x"}}"#;
    let script = format!(
        "printf '%s' '{payload}' | /bin/sh -c '{}'; echo \"hook $?\"; ls -A /opt; echo \"opt $?\"",
        hook_command(&content)
    );
    let opts = LaunchOpts {
        seeds: vec![(settings.path.to_owned(), content)],
        ..LaunchOpts::default()
    };
    let report = session
        .launch(&["/bin/sh".into(), "-c".into(), script], &opts)
        .expect("launch");
    let output = format!("{}\n{}", report.stdout, report.stderr);
    let lines: Vec<&str> = report.stdout.lines().collect();
    assert!(
        lines
            .first()
            .is_some_and(|line| line.contains("\"permissionDecision\":\"ask\"")),
        "{output}"
    );
    assert!(lines.contains(&"hook 0"), "{output}");
    if let Ok(entries) = fs::read_dir("/opt") {
        assert!(lines.contains(&"opt 0"), "{output}");
        for entry in entries {
            let name = entry.unwrap().file_name();
            assert!(
                lines.contains(&name.to_string_lossy().as_ref()),
                "{name:?}: {output}"
            );
        }
    }
    session.stop(EndReason::UserStop).expect("stop");

    let claims: Vec<String> = LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|r| r.origin == Origin::Agent)
        .filter_map(|r| match r.event {
            WardEvent::AgentClaim { payload, .. } => {
                Some(payload.to_string().replace(['\u{2068}', '\u{2069}'], ""))
            }
            _ => None,
        })
        .collect();
    assert_eq!(claims, ["PreToolUse Write /work/a.rs → ask"]);
}
