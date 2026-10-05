//! Runs the built `ward` binary's `replay --stats --json` over a log this test writes
//! and checks the E-13 report: requests are paired to their terminal outcome by
//! identity, a still-pending request is censored rather than decided, and the output
//! is identical across runs (`docs/experiments.md` E-13; #150 item 6).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ward_events::{
    AgentIdentity, AgentKind, Blake3Hash, CapabilityKind, CapabilityRequest, Chain, Decision,
    DecisionSource, EndReason, FsyncPolicy, GrantScope, LogWriter, NameText, Origin, ProjectId,
    SessionId, ShortText, SnapshotId, Timestamp, WardEvent,
};

const BIN: &str = env!("CARGO_BIN_EXE_ward");

fn cap(target: &str) -> CapabilityRequest {
    CapabilityRequest {
        kind: CapabilityKind::FileWrite,
        target: ShortText::new(target),
    }
}

fn requested(target: &str) -> WardEvent {
    WardEvent::CapabilityRequested {
        cap: cap(target),
        reason: None,
    }
}

fn decided(target: &str, decision: Decision, grant: Option<GrantScope>) -> WardEvent {
    WardEvent::CapabilityDecided {
        cap: cap(target),
        decision,
        by: DecisionSource::User,
        grant,
    }
}

fn events() -> Vec<(u64, WardEvent)> {
    vec![
        (
            0,
            WardEvent::SessionStarted {
                project: ProjectId::from_u128(9),
                agent: AgentIdentity {
                    kind: AgentKind::Other,
                    name: NameText::new("shell"),
                    version: NameText::new("0.1.0"),
                    image: None,
                },
                manifest_hash: Blake3Hash::hash(b"manifest"),
                entry_snapshot: SnapshotId::new(Blake3Hash::hash(b"entry")),
                policy_hash: Blake3Hash::hash(b"policy"),
                tool_images: Vec::new(),
            },
        ),
        (1_000, requested("Write /work/a.rs")),
        (2_000, requested("Write /work/b.rs")),
        (
            4_000,
            decided("Write /work/b.rs", Decision::Allow, Some(GrantScope::Once)),
        ),
        (7_000, decided("Write /work/a.rs", Decision::Deny, None)),
        (8_000, requested("Write /work/c.rs")),
        (
            10_000,
            WardEvent::SessionEnded {
                reason: EndReason::UserStop,
                final_snapshot: None,
            },
        ),
    ]
}

fn write_log(dir: &Path) -> PathBuf {
    let log = dir.join("events.log");
    let mut chain = Chain::genesis(SessionId::from_u128(42), Blake3Hash::hash(b"manifest"));
    let mut w = LogWriter::create(&log, chain.head(), FsyncPolicy::Never).unwrap();
    for (ms, event) in events() {
        let ts = Timestamp::mono(Duration::from_millis(ms));
        let r = chain.append(Origin::Wardd, event, ts).unwrap();
        w.append(&r).unwrap();
    }
    w.seal().unwrap();
    log
}

fn run_stats(log: &Path) -> (bool, String) {
    let out = Command::new(BIN)
        .args(["replay", "--stats", "--json"])
        .arg(log)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "stderr: {}\nstdout: {stdout}",
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), stdout)
}

#[test]
fn stats_json_pairs_by_identity_and_censors_the_pending_request() {
    let dir = tempfile::tempdir().unwrap();
    let log = write_log(dir.path());
    let (ok, stdout) = run_stats(&log);
    assert!(ok);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["session"], SessionId::from_u128(42).to_string());
    assert_eq!(report["log"]["verified"], true);
    assert_eq!(report["log"]["sealed"], "matches");
    assert_eq!(report["log"]["records"], 7);

    assert_eq!(report["requests"]["total"], 3);
    assert_eq!(report["requests"]["prompts"], 3);
    assert_eq!(report["outcomes"]["allowed_once"], 1);
    assert_eq!(report["outcomes"]["denied"], 1);
    assert_eq!(report["outcomes"]["censored"], 1);
    assert_eq!(report["decisions"], 2);

    let latency = &report["decision_latency"];
    assert_eq!(latency["status"], "measured");
    assert_eq!(latency["value"]["samples"], 2);
    assert_eq!(latency["value"]["p50_ms"], 2000.0);
    assert_eq!(latency["value"]["p99_ms"], 6000.0);

    assert_eq!(report["wall"]["active_ms"], 10_000);
    assert_eq!(report["prompts_per_agent_hour"]["status"], "measured");
    assert_eq!(report["missing_policy_requests"]["status"], "unmeasured");
}

#[test]
fn stats_json_is_identical_across_runs() {
    let dir = tempfile::tempdir().unwrap();
    let log = write_log(dir.path());
    let (_, first) = run_stats(&log);
    let (_, second) = run_stats(&log);
    let (_, third) = run_stats(&log);
    assert_eq!(first, second);
    assert_eq!(second, third);
}

#[test]
fn stats_text_names_the_censored_request_and_never_calls_it_a_decision() {
    let dir = tempfile::tempdir().unwrap();
    let log = write_log(dir.path());
    let out = Command::new(BIN)
        .args(["replay", "--stats"])
        .arg(log)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("decisions 2"), "{text}");
    assert!(text.contains("censored 1"), "{text}");
    assert!(text.contains("chain VERIFIED"), "{text}");
}
