//! The `ward-node-adapter` process speaks JSON lines on stdin/stdout for non-Rust control
//! planes: a pre-signed or self-signed `run` streams its events and ends in `done`, a
//! `SIGTERM` mid-run revokes and seals before the adapter exits, and malformed input fails
//! closed. The node-backed cases need a working bubblewrap and skip without one, except
//! under `WARD_REQUIRE_ISOLATION=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{
    Node, binding, envelope, envelope_input, imported, isolation, issuer, marker, private_dir,
    seed_file, wait_until_gone, wait_until_sandboxed,
};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};
use ward_node_client::{IssuerKey, evidence_log_path};

struct Adapter {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Adapter {
    fn spawn(socket: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ward-node-adapter"))
            .arg("--socket")
            .arg(socket)
            .arg("--timeout-ms")
            .arg("90000")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self { child, stdout }
    }

    fn send(&mut self, command: &Value) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{command}").unwrap();
        stdin.flush().unwrap();
    }

    fn event(&mut self) -> Value {
        let mut line = String::new();
        assert!(
            self.stdout.read_line(&mut line).unwrap() > 0,
            "the adapter closed stdout"
        );
        let event: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(event["schema"], json!(1), "{event}");
        event
    }

    fn events_until(&mut self, terminal: &str) -> Vec<Value> {
        let mut events = Vec::new();
        loop {
            let event = self.event();
            let done = event["event"] == json!(terminal);
            events.push(event);
            if done {
                return events;
            }
        }
    }

    fn finish(mut self) -> i32 {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap();
            }
            assert!(Instant::now() < deadline, "the adapter did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn names(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .map(|event| event["event"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_malformed_command_is_an_error_event_and_a_non_zero_exit() {
    let dir = private_dir();
    let mut adapter = Adapter::spawn(&dir.path().join("absent.sock"));
    adapter.send(&json!({"cmd": "dance"}));
    let event = adapter.event();
    assert_eq!(event["event"], json!("error"));
    assert!(event["error"].as_str().unwrap().contains("command"));
    assert_eq!(adapter.finish(), 1);

    let mut adapter = Adapter::spawn(&dir.path().join("absent.sock"));
    adapter.send(&json!({"cmd": "capabilities"}));
    let event = adapter.event();
    assert_eq!(event["event"], json!("error"), "{event}");
    assert_eq!(adapter.finish(), 1);

    let mut adapter = Adapter::spawn(&dir.path().join("absent.sock"));
    adapter.send(&json!({
        "cmd": "run",
        "envelope_json": "{}",
        "proof": {"issuer_key_id": "00", "signature": "00"},
    }));
    let event = adapter.event();
    assert_eq!(event["event"], json!("error"), "{event}");
    assert_eq!(adapter.finish(), 1);
}

#[test]
fn a_pre_signed_run_streams_its_events_and_ends_in_done() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path());
    let mut adapter = Adapter::spawn(&node.socket);

    adapter.send(&json!({"cmd": "capabilities"}));
    let capabilities = adapter.event();
    assert_eq!(capabilities["event"], json!("capabilities"));
    assert_eq!(capabilities["protocol"], json!({"major": 1, "minor": 3}));
    assert_eq!(
        capabilities["capabilities"]["lifecycle"]["start"],
        json!(true)
    );

    let signed = issuer()
        .sign(&envelope(
            binding(),
            snapshot,
            &["sh", "-c", "echo ok > out.txt"],
        ))
        .unwrap();
    let envelope_json = String::from_utf8(signed.envelope_json.as_bytes().to_vec()).unwrap();
    adapter.send(&json!({
        "cmd": "run",
        "envelope_json": envelope_json,
        "proof": signed.proof,
        "operation_ids": {"start_at": 20},
        "poll_ms": 50,
        "task_root": node.task_root,
    }));
    let events = adapter.events_until("done");
    assert_eq!(
        names(&events),
        [
            "state", "state", "admitted", "state", "receipt", "state", "evidence", "done"
        ],
        "{events:?}"
    );
    assert_eq!(events[0]["verb"], json!("create"));
    assert_eq!(events[0]["operation_id"], json!(20));
    assert_eq!(events[0]["state"], json!("created"));
    assert_eq!(events[1]["state"], json!("ready"));
    assert_eq!(events[2]["envelope_json"], json!(envelope_json));
    assert_eq!(
        events[2]["proof"],
        serde_json::to_value(signed.proof).unwrap()
    );
    assert_eq!(events[3]["state"], json!("running"));
    assert_eq!(events[4]["state"], json!("exited"));
    assert_eq!(events[4]["outcome"], json!("completed"));
    assert_eq!(events[5]["verb"], json!("seal"));
    assert_eq!(events[5]["operation_id"], json!(25));
    assert_eq!(events[5]["state"], json!("sealed"));
    assert_eq!(
        events[6]["path"],
        json!(evidence_log_path(&node.task_root, binding()))
    );
    let report = &events[7]["report"];
    assert_eq!(report["outcome"], json!("completed"));
    assert_eq!(report["outcome_certain"], json!(true));
    assert_eq!(report["receipt"], json!("completed"));
    assert_eq!(report["final_state"], json!("sealed"));
    assert_eq!(report["sealed"], json!(true));
    assert_eq!(report["cause"], json!({"Exited": {"code": 0}}));
    assert!(report["evidence_head"].as_str().unwrap().len() == 64);
    assert_eq!(
        report["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|operation| operation["operation_id"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [20, 21, 22, 25]
    );

    adapter.send(&json!({"cmd": "inspect", "binding": binding()}));
    let inspected = adapter.event();
    assert_eq!(inspected["event"], json!("inspected"));
    assert_eq!(inspected["state"], json!("sealed"));
    assert_eq!(inspected["outcome"], json!("completed"));

    adapter.send(&json!({"cmd": "revoke", "binding": binding(), "operation_id": 30}));
    let revoked = adapter.event();
    assert_eq!(revoked["event"], json!("verb"));
    assert_eq!(revoked["verb"], json!("revoke"));
    assert_eq!(revoked["result"], json!("rejected"));
    assert_eq!(revoked["reason"], json!("invalid_state"));

    assert_eq!(adapter.finish(), 0);
    assert_eq!(
        std::fs::read_to_string(node.workspace(binding()).join("out.txt")).unwrap(),
        "ok\n"
    );
}

#[test]
fn a_self_signed_run_signs_from_a_private_seed_file_and_reports_the_bytes_it_signed() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path());
    let seed = seed_file(dir.path());
    let mut adapter = Adapter::spawn(&node.socket);
    let input = envelope_input(binding(), snapshot, &["sh", "-c", "exit 3"]);
    adapter.send(&json!({
        "cmd": "run",
        "issuer_seed_file": seed,
        "envelope": serde_json::to_value(&input).unwrap(),
        "poll_ms": 50,
    }));
    let events = adapter.events_until("done");
    assert_eq!(
        names(&events),
        [
            "state", "state", "admitted", "state", "receipt", "state", "done"
        ],
        "{events:?}"
    );
    let admitted = &events[2];
    let expected = IssuerKey::from_seed_file(&seed)
        .unwrap()
        .sign(&input.build().unwrap())
        .unwrap();
    assert_eq!(
        admitted["envelope_json"],
        json!(String::from_utf8(expected.envelope_json.as_bytes().to_vec()).unwrap())
    );
    assert_eq!(
        admitted["proof"],
        serde_json::to_value(expected.proof).unwrap()
    );
    let report = &events[6]["report"];
    assert_eq!(report["outcome"], json!("failed"));
    assert_eq!(report["receipt"], json!("failed"));
    assert_eq!(report["outcome_certain"], json!(true));
    assert_eq!(report["evidence_log"], Value::Null);
    assert_eq!(report["evidence_head"], Value::Null);
    assert_eq!(report["operations"][0]["operation_id"], json!(1));
    assert_eq!(report["operations"][3]["operation_id"], json!(6));
    assert_eq!(adapter.finish(), 0);
}

#[test]
fn sigterm_mid_run_revokes_seals_and_leaves_no_process_behind() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path());
    let marker = marker("ward-node-adapter-sigterm");
    let script = format!("sleep 300; echo {marker}");
    let signed = issuer()
        .sign(&envelope(binding(), snapshot, &["sh", "-c", &script]))
        .unwrap();
    let mut adapter = Adapter::spawn(&node.socket);
    adapter.send(&json!({
        "cmd": "run",
        "envelope_json": String::from_utf8(signed.envelope_json.as_bytes().to_vec()).unwrap(),
        "proof": signed.proof,
        "poll_ms": 50,
        "task_root": node.task_root,
    }));
    wait_until_sandboxed(&marker);
    kill(
        Pid::from_raw(i32::try_from(adapter.child.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    let events = adapter.events_until("done");
    wait_until_gone(&marker);
    let report = &events.last().unwrap()["report"];
    assert_eq!(report["cancelled"], json!(true), "{report}");
    assert_eq!(report["final_state"], json!("sealed"));
    assert_eq!(report["sealed"], json!(true));
    assert!(
        report["outcome"] == json!("failed") || report["outcome"] == json!("unknown"),
        "{report}"
    );
    assert_eq!(
        report["outcome_certain"],
        json!(report["outcome"] == json!("failed"))
    );
    let verbs: Vec<&str> = report["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|operation| operation["verb"].as_str().unwrap())
        .collect();
    assert!(
        verbs.contains(&"revoke") && !verbs.contains(&"stop"),
        "{verbs:?}"
    );
    assert!(names(&events).contains(&"receipt".to_owned()));
    assert_eq!(adapter.finish(), 0);
    assert_eq!(common::processes_with(&marker), 0);
}
