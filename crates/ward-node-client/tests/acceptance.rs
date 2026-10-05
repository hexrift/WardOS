//! Cross-system acceptance of the `ward-node` contract (#332 slice 9, ADR-0030): a real
//! node, driven through the real transport by `ward-node-client` and, for one replay path,
//! by the `ward-node-adapter` process, proves bounded execution, isolation, interruption,
//! authorization failure, replay safety and recovery. One `#[test]` per case; each case's
//! pass criterion is stated in [`CASES`] and, word for word, in `docs/node-acceptance.md`,
//! and `scripts/acceptance/node.sh` runs exactly these cases and prints the verdicts the
//! cases write. The cases need a working bubblewrap and skip without one, except under
//! `WARD_REQUIRE_ISOLATION=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{
    NODE, envelope_input, isolation, issuer, marker, now_ms, private_dir, processes_with,
    trust_store, wait_until_gone, wait_until_sandboxed, ward_node_binary,
};
use serde_json::{Value, json};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::log::{head_file_path, parse_head};
use ward_events::{
    AgentId, ChainHead, DelegationId, ExecutionAttemptId, LeaseId, LogReader, NodeAttemptEnd,
    NodeAttemptOutcome, NodeAttemptState, NodeId, NodeIntervention, SnapshotId, TaskId, WardEvent,
};
use ward_node::evidence::{self, VerifiedEvidence};
use ward_node_client::{
    Applied, AttemptEvent, AttemptOutcome, AttemptReport, AttemptRequest, CancelToken, Client,
    Driver, EnvelopeInput, Inspection, IssuerKey, OperationIds, RunConfig, Timeouts, UnixTransport,
    Verb, evidence_log_path,
};
use ward_node_protocol::{
    CapabilityManifestBytes, OperationId, TaskAdmissionAuthority, TaskBinding,
    TaskExecutionOutcome, TaskLifecycleRejectionReason, TaskLifecycleState,
};

/// One acceptance case: the test of that name and the criterion it passes on.
struct Case {
    name: &'static str,
    criterion: &'static str,
}

/// The acceptance cases, in the order `docs/node-acceptance.md` lists them.
const CASES: [Case; 8] = [
    Case {
        name: "bounded_execution_kills_at_the_budget_and_completes_within_bounds",
        criterion: "a workload past its wall-clock budget ends exited/failed with cause BudgetExceeded in its evidence log within budget + 30 s and leaves no process; a completing one ends exited/completed with cause Exited 0 within 60 s; both seal with a verifying log",
    },
    Case {
        name: "isolation_holds_against_an_in_sandbox_probe",
        criterion: "one attempt runs every isolation probe and exits 0 only if no hole was found: no route off the host (loopback works), no read of a host secret, the node state dir or the evidence log, no write into a bound host directory, nothing written to /tmp or HOME reaches the host, the environment is exactly what the contract names and the node's own environment never leaks",
    },
    Case {
        name: "interruption_revoke_ends_the_workload_and_seals_its_evidence",
        criterion: "revoke mid-run is answered revoked within 15 s, every workload process is gone, inspect reports revoked with a receipt, the evidence log seals with the revoke's NodeAttemptEnded record, the lease is in revocations.json, and a replayed revoke acts again on nothing",
    },
    Case {
        name: "interruption_pause_and_resume_leave_the_workload_alive",
        criterion: "pause stops the workload's output for a 400 ms observation window with its whole process tree still present, resume lets the output continue, and the evidence log records both interventions in order",
    },
    Case {
        name: "interruption_node_kill_recovers_exited_unknown_and_never_reruns",
        criterion: "after SIGKILL of the node mid-run and a restart the attempt reads exited/unknown, the workload is gone and its output stops, a replayed start answers exited and a new start is invalid_state, the workload's run marker was written once, and a full client replay seals it with outcome unknown",
    },
    Case {
        name: "authorization_failures_are_refused_with_nothing_materialised",
        criterion: "an untrusted key, an expired lease, a wrong node audience and a manifest asking for network are each refused at admit with authority_denied, lease_expired, authority_denied and unsupported_grant and no task directory exists; a stale version is stale_operation and a revoked lease is lease_revoked with no workspace and no evidence log for the refused attempt",
    },
    Case {
        name: "replay_after_a_client_restart_runs_nothing_twice",
        criterion: "the same operation ids replayed in process and from a new ward-node-adapter process with the pre-signed bytes answer sealed/completed with the same receipt, cause and evidence head, the workload's marker has one line and the log is unchanged; a retired attempt is refused stale_operation by create",
    },
    Case {
        name: "durable_records_survive_a_node_restart",
        criterion: "after SIGKILL and restart a sealed attempt reads sealed/completed, its evidence log and HEAD verify to the same head, every replayed operation id answers sealed, a client replay reports the same outcome, and a retired attempt stays stale_operation across a further restart",
    },
];

const COMPLETION_BOUND: Duration = Duration::from_secs(60);
const BUDGET_KILL_BOUND: Duration = Duration::from_secs(30);
const REVOKE_BOUND: Duration = Duration::from_secs(15);
const PAUSE_WINDOW: Duration = Duration::from_millis(400);
const SETTLE: Duration = Duration::from_millis(500);

const PROBE: &str = r#"
import os
import socket
import sys
import traceback

results_path, secret, secret_marker, state_dir, evidence_log, host_pid, canary, tmp_marker = sys.argv[1:9]
rows = []


def record(name, intact, detail=""):
    rows.append((name, "ok" if intact else "HOLE", str(detail).replace("\n", " ")))


def connects(host, port):
    peer = socket.socket()
    peer.settimeout(3)
    try:
        peer.connect((host, port))
        return True, "connected"
    except OSError as error:
        return False, "%s %s" % (error.errno, error.strerror)
    finally:
        peer.close()


def readable(path):
    try:
        with open(path, "rb") as handle:
            return True, handle.read(64)
    except OSError as error:
        return False, error.strerror


def writable(path):
    try:
        with open(path, "w") as handle:
            handle.write("x")
        return True, "written"
    except OSError as error:
        return False, error.strerror


def main():
    reached, detail = connects("10.255.255.1", 9)
    record("net.private", not reached, detail)
    reached, detail = connects("1.1.1.1", 80)
    record("net.external", not reached, detail)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    reached, detail = connects("127.0.0.1", listener.getsockname()[1])
    record("net.loopback", reached, detail)
    with open("/proc/net/dev") as handle:
        names = [line.split(":")[0].strip() for line in handle.readlines()[2:]]
    record("net.interfaces", names == ["lo"], ",".join(names))

    found, detail = readable(secret)
    record("fs.secret", not (found and detail.startswith(secret_marker.encode())), detail)
    found, detail = readable(os.path.join(state_dir, "node-id"))
    record("fs.state_dir", not found, detail)
    found, detail = readable(evidence_log)
    record("fs.evidence_log", not found, detail)
    record("fs.task_root", not os.path.exists(os.path.dirname(os.path.dirname(evidence_log))))
    found, detail = readable("src/input.txt")
    record("fs.work_read", found, detail)

    for path in ["/usr/" + tmp_marker, "/usr/bin/" + tmp_marker, "/etc/ssl/" + tmp_marker,
                 os.path.join(state_dir, tmp_marker), os.path.join(os.path.dirname(evidence_log), tmp_marker)]:
        wrote, detail = writable(path)
        record("fs.write." + path, not wrote, detail)
    for path in ["/tmp/" + tmp_marker, os.path.join(os.environ.get("HOME", "/nonexistent"), tmp_marker),
                 "/" + tmp_marker]:
        wrote, detail = writable(path)
        record("fs.private." + path, True, "sandbox-private: " + detail)

    with open("/proc/self/environ", "rb") as handle:
        keys = sorted(entry.split(b"=", 1)[0].decode() for entry in handle.read().split(b"\0") if entry)
    record("env.keys", set(keys) <= {"HOME", "PATH", "TERM", "PWD"}, ",".join(keys))
    record("env.home", os.environ.get("HOME") == "/home/agent", os.environ.get("HOME"))
    record("env.term", os.environ.get("TERM") == "xterm", os.environ.get("TERM"))
    record("env.canary", canary not in keys, canary)
    record("pid.host", not os.path.exists("/proc/" + host_pid), host_pid)
    record("cwd", os.getcwd() == "/work", os.getcwd())


try:
    main()
except Exception:
    rows.append(("probe", "ERROR", traceback.format_exc().replace("\n", " | ")))
with open(results_path, "w") as handle:
    for name, verdict, detail in rows:
        handle.write("%s\t%s\t%s\n" % (name, verdict, detail))
if any(verdict == "ERROR" for _, verdict, _ in rows):
    sys.exit(2)
sys.exit(1 if any(verdict == "HOLE" for _, verdict, _ in rows) else 0)
"#;

const BEATS: &str = "import time\nopen('runs', 'a').write('run\\n')\nwhile True:\n    open('beats', 'a').write('beat\\n')\n    time.sleep(0.05)\n";

fn case(name: &str) -> &'static Case {
    CASES.iter().find(|case| case.name == name).unwrap()
}

fn pass(name: &str, started: Instant) {
    let case = case(name);
    eprintln!(
        "acceptance {}: PASS in {} ms -- {}",
        case.name,
        started.elapsed().as_millis(),
        case.criterion
    );
}

fn op(value: u64) -> OperationId {
    OperationId::new(value).unwrap()
}

fn binding(task: u128, attempt: u128, lease: u128) -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(task),
        ExecutionAttemptId::from_u128(attempt),
        LeaseId::from_u128(lease),
    )
}

fn config() -> RunConfig {
    RunConfig {
        poll_interval: Duration::from_millis(50),
        max_poll_interval: Duration::from_millis(200),
        grace: Duration::from_secs(30),
    }
}

fn connect(socket: &Path) -> Client<UnixTransport> {
    Client::connect(UnixTransport::new(socket, Timeouts::default())).unwrap()
}

fn workload(
    binding: TaskBinding,
    snapshot: SnapshotId,
    argv: &[&str],
    budget_ms: u64,
) -> EnvelopeInput {
    let mut input = envelope_input(binding, snapshot, argv);
    input.workload.wall_clock_budget_ms = budget_ms;
    input
}

fn signed(node: &Node, input: &EnvelopeInput) -> AttemptRequest {
    AttemptRequest::sign(
        &input.clone().build().unwrap(),
        &issuer(),
        Some(node.task_root.clone()),
    )
    .unwrap()
}

fn run(
    client: &Client<UnixTransport>,
    request: &AttemptRequest,
    ids: &OperationIds,
) -> (AttemptReport, Vec<AttemptEvent>) {
    let mut events = Vec::new();
    let report = Driver::new(client, config()).run_attempt(
        request,
        ids,
        &CancelToken::default(),
        &mut |event| events.push(event.clone()),
    );
    (report, events)
}

fn operations(
    report: &AttemptReport,
) -> Vec<(
    Verb,
    u64,
    Option<TaskLifecycleState>,
    Option<TaskLifecycleRejectionReason>,
)> {
    report
        .operations
        .iter()
        .map(|operation| {
            (
                operation.verb,
                operation.operation_id.get(),
                operation.state,
                operation.reason,
            )
        })
        .collect()
}

fn verified(node: &Node, binding: TaskBinding) -> VerifiedEvidence {
    let dir = evidence::evidence_dir(&node.task_root, binding);
    let verified = evidence::verify(&dir, binding).unwrap();
    let log = dir.join(evidence::EVIDENCE_LOG);
    assert_eq!(log, evidence_log_path(&node.task_root, binding));
    let head = LogReader::open(&log).unwrap().verify_all().unwrap();
    assert_eq!(head, verified.head());
    if verified.is_sealed() {
        assert_eq!(
            parse_head(&std::fs::read_to_string(head_file_path(&log)).unwrap()).unwrap(),
            head
        );
    }
    verified
}

fn ended(
    verified: &VerifiedEvidence,
) -> Option<(
    NodeAttemptState,
    NodeAttemptOutcome,
    NodeAttemptEnd,
    Option<u64>,
)> {
    verified
        .records()
        .iter()
        .find_map(|record| match record.event {
            WardEvent::NodeAttemptEnded {
                state,
                outcome,
                end,
                operation,
            } => Some((state, outcome, end, operation)),
            _ => None,
        })
}

fn interventions(verified: &VerifiedEvidence) -> Vec<(NodeIntervention, u64)> {
    verified
        .records()
        .iter()
        .filter_map(|record| match record.event {
            WardEvent::NodeAttemptIntervened { action, operation } => Some((action, operation)),
            _ => None,
        })
        .collect()
}

fn lines(path: &Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |text| text.lines().count())
}

fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn project(dir: &Path) -> SnapshotId {
    let project = dir.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/input.txt"), b"from the snapshot\n").unwrap();
    std::fs::write(project.join("probe.py"), PROBE).unwrap();
    let output = Command::new(ward_node_binary())
        .args(["snapshot", "import", "--state-dir"])
        .arg(dir.join("state"))
        .arg(&project)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

struct Node {
    child: Child,
    socket: PathBuf,
    state_dir: PathBuf,
    task_root: PathBuf,
}

impl Node {
    fn spawn(dir: &Path) -> Self {
        Self::spawn_with_env(dir, &[])
    }

    fn spawn_with_env(dir: &Path, env: &[(&str, &str)]) -> Self {
        let socket = dir.join("node.sock");
        let state_dir = dir.join("state");
        let task_root = dir.join("tasks");
        let _ = std::fs::remove_file(&socket);
        let mut command = Command::new(ward_node_binary());
        command
            .arg("--socket")
            .arg(&socket)
            .arg("--state-dir")
            .arg(&state_dir)
            .arg("--node-id")
            .arg(NODE.to_string())
            .arg("--trusted-issuers")
            .arg(trust_store(dir))
            .arg("--task-root")
            .arg(&task_root)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&socket).is_err() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "ward-node exited before serving"
            );
            assert!(
                Instant::now() < deadline,
                "ward-node did not bind its socket"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            child,
            socket,
            state_dir,
            task_root,
        }
    }

    fn kill(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }

    fn workspace(&self, binding: TaskBinding) -> PathBuf {
        self.task_root
            .join(binding.task().to_string())
            .join(binding.attempt().to_string())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Adapter {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Adapter {
    fn spawn(socket: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ward-node-adapter"))
            .arg("--socket")
            .arg(socket)
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

    fn events_until(&mut self, terminal: &str) -> Vec<Value> {
        let mut events = Vec::new();
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "the adapter closed stdout"
            );
            let event: Value = serde_json::from_str(line.trim_end()).unwrap();
            assert_eq!(event["schema"], json!(1), "{event}");
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

fn accepted(applied: Result<Applied, ward_node_client::ClientError>) -> TaskLifecycleState {
    match applied.unwrap() {
        Applied::Accepted { state } => state,
        Applied::Rejected { reason } => panic!("rejected: {reason:?}"),
    }
}

fn rejected(
    applied: Result<Applied, ward_node_client::ClientError>,
) -> TaskLifecycleRejectionReason {
    match applied.unwrap() {
        Applied::Rejected { reason } => reason,
        Applied::Accepted { state } => panic!("accepted: {state:?}"),
    }
}

fn inspected(
    client: &Client<UnixTransport>,
    binding: TaskBinding,
) -> (TaskLifecycleState, Option<TaskExecutionOutcome>) {
    match client.inspect(binding).unwrap() {
        Inspection::Inspected { state, outcome } => (state, outcome),
        Inspection::Rejected { reason } => panic!("inspect rejected: {reason:?}"),
    }
}

fn start_beats(
    client: &Client<UnixTransport>,
    node: &Node,
    binding: TaskBinding,
    snapshot: SnapshotId,
    marker: &str,
) -> AttemptRequest {
    let request = signed(
        node,
        &workload(
            binding,
            snapshot,
            &["python3", "-c", BEATS, marker],
            600_000,
        ),
    );
    assert_eq!(
        accepted(client.create(binding, op(1))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        accepted(client.admit(binding, op(2), &request.envelope)),
        TaskLifecycleState::Ready
    );
    assert_eq!(
        accepted(client.start(binding, op(3))),
        TaskLifecycleState::Running
    );
    let beats = node.workspace(binding).join("beats");
    eventually("the workload never started beating", || {
        lines(&beats) > 0 && processes_with(marker) >= 3
    });
    request
}

#[test]
fn every_acceptance_case_is_documented() {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/node-acceptance.md"),
    )
    .unwrap();
    for case in &CASES {
        assert!(doc.contains(case.name), "undocumented case {}", case.name);
        assert!(
            doc.contains(case.criterion),
            "the documented criterion of {} differs from the code's",
            case.name
        );
    }
    let runner = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/acceptance/node.sh"),
    )
    .unwrap();
    assert!(runner.contains("--test acceptance"));
}

#[test]
fn bounded_execution_kills_at_the_budget_and_completes_within_bounds() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let node = Node::spawn(dir.path());
    let client = connect(&node.socket);

    let completing = binding(0x10, 0x11, 0x12);
    let done_marker = marker("ward-acceptance-complete");
    let script = format!("echo {done_marker} >> out.txt");
    let completion_started = Instant::now();
    let (report, _) = run(
        &client,
        &signed(
            &node,
            &workload(completing, snapshot, &["sh", "-c", &script], 60_000),
        ),
        &OperationIds::starting_at(10).unwrap(),
    );
    assert!(
        completion_started.elapsed() <= COMPLETION_BOUND,
        "{:?}",
        completion_started.elapsed()
    );
    assert_eq!(report.outcome, AttemptOutcome::Completed, "{report:?}");
    assert_eq!(report.receipt, Some(TaskExecutionOutcome::Completed));
    assert_eq!(report.cause, Some(NodeAttemptEnd::Exited { code: Some(0) }));
    assert_eq!(report.final_state, Some(TaskLifecycleState::Sealed));
    assert!(report.sealed && !report.deadline_exceeded && !report.cancelled);
    assert_eq!(lines(&node.workspace(completing).join("out.txt")), 1);
    let completed = verified(&node, completing);
    assert!(completed.is_sealed());
    assert_eq!(
        ended(&completed),
        Some((
            NodeAttemptState::Exited,
            NodeAttemptOutcome::Completed,
            NodeAttemptEnd::Exited { code: Some(0) },
            None
        ))
    );

    let overrunning = binding(0x13, 0x14, 0x15);
    let budget_marker = marker("ward-acceptance-budget");
    let script = format!("sleep 300; echo {budget_marker}");
    let budget = Duration::from_millis(500);
    let kill_started = Instant::now();
    let (report, events) = run(
        &client,
        &signed(
            &node,
            &workload(
                overrunning,
                snapshot,
                &["sh", "-c", &script],
                u64::try_from(budget.as_millis()).unwrap(),
            ),
        ),
        &OperationIds::starting_at(20).unwrap(),
    );
    assert!(
        kill_started.elapsed() <= budget + BUDGET_KILL_BOUND,
        "{:?}",
        kill_started.elapsed()
    );
    assert_eq!(report.outcome, AttemptOutcome::Failed, "{report:?}");
    assert_eq!(report.receipt, Some(TaskExecutionOutcome::Failed));
    assert_eq!(report.cause, Some(NodeAttemptEnd::BudgetExceeded));
    assert_eq!(report.final_state, Some(TaskLifecycleState::Sealed));
    assert!(report.sealed && !report.deadline_exceeded && !report.cancelled);
    assert!(events.contains(&AttemptEvent::Receipt {
        state: TaskLifecycleState::Exited,
        outcome: Some(TaskExecutionOutcome::Failed),
    }));
    wait_until_gone(&budget_marker);
    let killed = verified(&node, overrunning);
    assert!(killed.is_sealed());
    assert_eq!(
        ended(&killed),
        Some((
            NodeAttemptState::Exited,
            NodeAttemptOutcome::Failed,
            NodeAttemptEnd::BudgetExceeded,
            None
        ))
    );
    assert!(!node.workspace(overrunning).join("out.txt").exists());
    pass(
        "bounded_execution_kills_at_the_budget_and_completes_within_bounds",
        started,
    );
}

#[test]
fn isolation_holds_against_an_in_sandbox_probe() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let secret_marker = marker("ward-acceptance-secret");
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, format!("{secret_marker}\n")).unwrap();
    let canary = marker("ward-acceptance-canary");
    let node = Node::spawn_with_env(dir.path(), &[("WARD_ACCEPTANCE_CANARY", &canary)]);
    let client = connect(&node.socket);
    let probed = binding(0x20, 0x21, 0x22);
    let tmp_marker = marker("ward-acceptance-tmp");
    let evidence_log = evidence_log_path(&node.task_root, probed);
    let host_pid = std::process::id().to_string();
    let argv = [
        "python3",
        "probe.py",
        "isolation-results.txt",
        secret.to_str().unwrap(),
        &secret_marker,
        node.state_dir.to_str().unwrap(),
        evidence_log.to_str().unwrap(),
        &host_pid,
        "WARD_ACCEPTANCE_CANARY",
        &tmp_marker,
    ];

    let (report, _) = run(
        &client,
        &signed(&node, &workload(probed, snapshot, &argv, 60_000)),
        &OperationIds::starting_at(1).unwrap(),
    );
    let results_path = node.workspace(probed).join("isolation-results.txt");
    let results = std::fs::read_to_string(&results_path).unwrap_or_default();
    assert_eq!(
        report.cause,
        Some(NodeAttemptEnd::Exited { code: Some(0) }),
        "the probe found an isolation hole or could not run:\n{results}\n{report:?}"
    );
    assert_eq!(report.outcome, AttemptOutcome::Completed, "{report:?}");
    assert_eq!(report.receipt, Some(TaskExecutionOutcome::Completed));
    assert!(report.sealed);

    let rows: Vec<Vec<&str>> = results
        .lines()
        .map(|line| line.split('\t').collect())
        .collect();
    let names: Vec<&str> = rows.iter().map(|row| row[0]).collect();
    for probe in [
        "net.private",
        "net.external",
        "net.loopback",
        "net.interfaces",
        "fs.secret",
        "fs.state_dir",
        "fs.evidence_log",
        "fs.task_root",
        "fs.work_read",
        "env.keys",
        "env.home",
        "env.term",
        "env.canary",
        "pid.host",
        "cwd",
    ] {
        assert!(
            names.contains(&probe),
            "probe {probe} did not run:\n{results}"
        );
    }
    assert!(
        names
            .iter()
            .filter(|name| name.starts_with("fs.write."))
            .count()
            == 5,
        "{results}"
    );
    assert!(
        rows.iter().all(|row| row[1] == "ok"),
        "an isolation probe reported a hole:\n{results}"
    );
    let env_keys = rows
        .iter()
        .find(|row| row[0] == "env.keys")
        .map(|row| row[2])
        .unwrap();
    eprintln!("isolation: the workload's environment keys are {env_keys}");

    assert!(!Path::new("/tmp").join(&tmp_marker).exists());
    assert!(!Path::new("/home/agent").join(&tmp_marker).exists());
    assert!(!Path::new("/").join(&tmp_marker).exists());
    assert!(!dir.path().join(&tmp_marker).exists());
    assert_eq!(
        std::fs::read_to_string(&secret).unwrap(),
        format!("{secret_marker}\n")
    );
    assert!(verified(&node, probed).is_sealed());
    pass("isolation_holds_against_an_in_sandbox_probe", started);
}

#[test]
fn interruption_revoke_ends_the_workload_and_seals_its_evidence() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let node = Node::spawn(dir.path());
    let client = connect(&node.socket);
    let revoked = binding(0x30, 0x31, 0x32);
    let marker = marker("ward-acceptance-revoke");
    let script = format!("sleep 300; echo {marker}");
    let request = signed(
        &node,
        &workload(revoked, snapshot, &["sh", "-c", &script], 600_000),
    );
    assert_eq!(
        accepted(client.create(revoked, op(1))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        accepted(client.admit(revoked, op(2), &request.envelope)),
        TaskLifecycleState::Ready
    );
    assert_eq!(
        accepted(client.start(revoked, op(3))),
        TaskLifecycleState::Running
    );
    wait_until_sandboxed(&marker);

    let revoke_started = Instant::now();
    assert_eq!(
        accepted(client.revoke(revoked, op(5))),
        TaskLifecycleState::Revoked
    );
    assert!(
        revoke_started.elapsed() <= REVOKE_BOUND,
        "{:?}",
        revoke_started.elapsed()
    );
    wait_until_gone(&marker);
    let (state, outcome) = inspected(&client, revoked);
    assert_eq!(state, TaskLifecycleState::Revoked);
    assert_eq!(outcome, Some(TaskExecutionOutcome::Failed));
    assert_eq!(
        accepted(client.seal(revoked, op(6))),
        TaskLifecycleState::Sealed
    );
    let log = verified(&node, revoked);
    assert!(log.is_sealed());
    assert_eq!(
        ended(&log),
        Some((
            NodeAttemptState::Revoked,
            NodeAttemptOutcome::Failed,
            NodeAttemptEnd::Killed,
            Some(5)
        ))
    );
    assert!(
        std::fs::read_to_string(node.state_dir.join("revocations.json"))
            .unwrap()
            .contains(&revoked.lease().to_string())
    );
    assert_eq!(
        accepted(client.revoke(revoked, op(5))),
        TaskLifecycleState::Sealed
    );
    assert_eq!(
        rejected(client.revoke(revoked, op(50))),
        TaskLifecycleRejectionReason::InvalidState
    );
    assert_eq!(
        accepted(client.start(revoked, op(3))),
        TaskLifecycleState::Sealed
    );
    assert_eq!(
        rejected(client.start(revoked, op(30))),
        TaskLifecycleRejectionReason::InvalidState
    );
    assert_eq!(processes_with(&marker), 0);
    assert_eq!(verified(&node, revoked).head(), log.head());
    pass(
        "interruption_revoke_ends_the_workload_and_seals_its_evidence",
        started,
    );
}

#[test]
fn interruption_pause_and_resume_leave_the_workload_alive() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let node = Node::spawn(dir.path());
    let client = connect(&node.socket);
    let paused = binding(0x33, 0x34, 0x35);
    let marker = marker("ward-acceptance-pause");
    start_beats(&client, &node, paused, snapshot, &marker);
    let beats = node.workspace(paused).join("beats");

    assert_eq!(
        accepted(client.pause(paused, op(7))),
        TaskLifecycleState::Paused
    );
    let frozen = lines(&beats);
    std::thread::sleep(PAUSE_WINDOW);
    assert_eq!(lines(&beats), frozen, "the paused workload kept writing");
    assert!(processes_with(&marker) >= 3, "the paused tree is gone");
    assert_eq!(
        inspected(&client, paused),
        (TaskLifecycleState::Paused, None)
    );

    assert_eq!(
        accepted(client.resume(paused, op(8))),
        TaskLifecycleState::Running
    );
    eventually("the resumed workload never continued", || {
        lines(&beats) > frozen
    });
    assert!(processes_with(&marker) >= 3);
    assert_eq!(
        inspected(&client, paused),
        (TaskLifecycleState::Running, None)
    );

    assert_eq!(
        accepted(client.revoke(paused, op(5))),
        TaskLifecycleState::Revoked
    );
    wait_until_gone(&marker);
    assert_eq!(
        accepted(client.seal(paused, op(6))),
        TaskLifecycleState::Sealed
    );
    let log = verified(&node, paused);
    assert!(log.is_sealed());
    assert_eq!(
        interventions(&log),
        [(NodeIntervention::Pause, 7), (NodeIntervention::Resume, 8)]
    );
    assert_eq!(
        ended(&log).map(|(state, _, _, operation)| (state, operation)),
        Some((NodeAttemptState::Revoked, Some(5)))
    );
    assert_eq!(lines(&node.workspace(paused).join("runs")), 1);
    pass(
        "interruption_pause_and_resume_leave_the_workload_alive",
        started,
    );
}

#[test]
fn interruption_node_kill_recovers_exited_unknown_and_never_reruns() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let node = Node::spawn(dir.path());
    let interrupted = binding(0x36, 0x37, 0x38);
    let marker = marker("ward-acceptance-node-kill");
    let request = start_beats(
        &connect(&node.socket),
        &node,
        interrupted,
        snapshot,
        &marker,
    );
    let beats = node.workspace(interrupted).join("beats");
    let runs = node.workspace(interrupted).join("runs");
    assert_eq!(lines(&runs), 1);
    node.kill();

    let node = Node::spawn(dir.path());
    let client = connect(&node.socket);
    assert_eq!(
        inspected(&client, interrupted),
        (
            TaskLifecycleState::Exited,
            Some(TaskExecutionOutcome::Unknown)
        )
    );
    wait_until_gone(&marker);
    let settled = lines(&beats);
    std::thread::sleep(SETTLE);
    assert_eq!(lines(&beats), settled, "the workload still runs");

    assert_eq!(
        accepted(client.start(interrupted, op(3))),
        TaskLifecycleState::Exited
    );
    assert_eq!(
        rejected(client.start(interrupted, op(9))),
        TaskLifecycleRejectionReason::InvalidState
    );
    let (report, _) = run(&client, &request, &OperationIds::default());
    assert_eq!(report.outcome, AttemptOutcome::Unknown, "{report:?}");
    assert!(!report.outcome_certain);
    assert_eq!(report.receipt, Some(TaskExecutionOutcome::Unknown));
    assert_eq!(report.final_state, Some(TaskLifecycleState::Sealed));
    assert!(report.sealed);
    assert_eq!(
        operations(&report),
        [
            (Verb::Create, 1, Some(TaskLifecycleState::Exited), None),
            (Verb::Admit, 2, Some(TaskLifecycleState::Exited), None),
            (Verb::Seal, 6, Some(TaskLifecycleState::Sealed), None),
        ]
    );
    let log = verified(&node, interrupted);
    assert!(log.is_sealed());
    assert!(ended(&log).is_none());
    assert!(log.records().iter().any(|record| matches!(
        record.event,
        WardEvent::NodeAttemptRecovered {
            state: NodeAttemptState::Exited,
            outcome: Some(NodeAttemptOutcome::Unknown),
        }
    )));
    std::thread::sleep(SETTLE);
    assert_eq!(lines(&runs), 1, "the attempt ran again");
    assert_eq!(lines(&beats), settled);
    assert_eq!(processes_with(&marker), 0);
    pass(
        "interruption_node_kill_recovers_exited_unknown_and_never_reruns",
        started,
    );
}

fn expired_lease(input: &mut EnvelopeInput) {
    let now = now_ms();
    let binding = input.binding;
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer: common::ISSUER,
            subject: AgentId::from_u128(3),
            task: binding.task(),
            grants: GrantSet::new([CapabilityGrant::new(
                CapabilityName::new("repo.read").unwrap(),
                ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                false,
            )])
            .unwrap(),
            issued_at_unix_ms: now - 120_000,
            expires_at_unix_ms: now - 60_000,
            version: LeaseVersion::new(1).unwrap(),
        },
        now - 90_000,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap();
    input.authority =
        TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new()).unwrap();
}

fn refused_admit(report: &AttemptReport) -> TaskLifecycleRejectionReason {
    assert_eq!(
        report.final_state,
        Some(TaskLifecycleState::Created),
        "{report:?}"
    );
    assert!(!report.sealed && report.receipt.is_none() && report.cause.is_none());
    match (report.outcome, operations(report).as_slice()) {
        (
            AttemptOutcome::Refused {
                verb: Verb::Admit,
                reason,
            },
            [
                (Verb::Create, _, Some(TaskLifecycleState::Created), None),
                (Verb::Admit, _, None, Some(recorded)),
            ],
        ) if *recorded == reason => reason,
        _ => panic!("not a refused admit: {report:?}"),
    }
}

fn fresh_tasks_are_refused_unmaterialised(
    node: &Node,
    client: &Client<UnixTransport>,
    snapshot: SnapshotId,
) {
    let ids = OperationIds::starting_at(1).unwrap();
    let untrusted = binding(0x40, 0x41, 0x42);
    let request = AttemptRequest::sign(
        &workload(untrusted, snapshot, &["true"], 60_000)
            .build()
            .unwrap(),
        &IssuerKey::from_seed([8; 32]).unwrap(),
        Some(node.task_root.clone()),
    )
    .unwrap();
    let (report, _) = run(client, &request, &ids);
    assert_eq!(
        refused_admit(&report),
        TaskLifecycleRejectionReason::AuthorityDenied
    );

    let expired = binding(0x43, 0x44, 0x45);
    let mut input = workload(expired, snapshot, &["true"], 60_000);
    expired_lease(&mut input);
    let (report, _) = run(client, &signed(node, &input), &ids);
    assert_eq!(
        refused_admit(&report),
        TaskLifecycleRejectionReason::LeaseExpired
    );

    let misaddressed = binding(0x46, 0x47, 0x48);
    let mut input = workload(misaddressed, snapshot, &["true"], 60_000);
    input.node = NodeId::from_u128(99);
    let (report, _) = run(client, &signed(node, &input), &ids);
    assert_eq!(
        refused_admit(&report),
        TaskLifecycleRejectionReason::AuthorityDenied
    );

    let networked = binding(0x49, 0x4a, 0x4b);
    let mut input = workload(networked, snapshot, &["true"], 60_000);
    input.workload.capability_manifest = Some(
        CapabilityManifestBytes::new(br#"{"network":{"custom":["github.com"]}}"#.to_vec()).unwrap(),
    );
    let (report, _) = run(client, &signed(node, &input), &ids);
    assert_eq!(
        refused_admit(&report),
        TaskLifecycleRejectionReason::UnsupportedGrant
    );

    for refused in [untrusted, expired, misaddressed, networked] {
        assert!(
            !node.task_root.join(refused.task().to_string()).exists(),
            "{refused:?} materialised something"
        );
        assert_eq!(
            inspected(client, refused),
            (TaskLifecycleState::Created, None)
        );
    }
}

fn a_new_attempt_is_refused_stale_then_revoked(
    node: &Node,
    client: &Client<UnixTransport>,
    snapshot: SnapshotId,
) {
    let ids = OperationIds::starting_at(1).unwrap();
    let first = binding(0x50, 0x51, 0x52);
    let request = signed(node, &workload(first, snapshot, &["true"], 60_000));
    assert_eq!(
        accepted(client.create(first, op(1))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        accepted(client.admit(first, op(2), &request.envelope)),
        TaskLifecycleState::Ready
    );
    assert_eq!(
        accepted(client.revoke(first, op(5))),
        TaskLifecycleState::Revoked
    );
    assert_eq!(
        accepted(client.seal(first, op(6))),
        TaskLifecycleState::Sealed
    );
    assert_eq!(
        ended(&verified(node, first)),
        Some((
            NodeAttemptState::Revoked,
            NodeAttemptOutcome::Failed,
            NodeAttemptEnd::NotStarted,
            Some(5)
        ))
    );

    let second = binding(0x50, 0x53, 0x52);
    let mut input = workload(second, snapshot, &["true"], 60_000);
    let (report, _) = run(client, &signed(node, &input), &ids);
    assert_eq!(
        refused_admit(&report),
        TaskLifecycleRejectionReason::StaleOperation
    );
    input.version = 2;
    let (report, _) = run(client, &signed(node, &input), &ids);
    assert_eq!(
        refused_admit(&report),
        TaskLifecycleRejectionReason::LeaseRevoked
    );
    assert!(!node.workspace(second).exists());
    assert!(!evidence::evidence_dir(&node.task_root, second).exists());
    assert!(!node.workspace(first).exists());
    assert_eq!(
        inspected(client, second),
        (TaskLifecycleState::Created, None)
    );
    assert_eq!(
        rejected(client.start(second, op(3))),
        TaskLifecycleRejectionReason::InvalidState
    );
}

#[test]
fn authorization_failures_are_refused_with_nothing_materialised() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let node = Node::spawn(dir.path());
    let client = connect(&node.socket);
    fresh_tasks_are_refused_unmaterialised(&node, &client, snapshot);
    a_new_attempt_is_refused_stale_then_revoked(&node, &client, snapshot);
    pass(
        "authorization_failures_are_refused_with_nothing_materialised",
        started,
    );
}

fn adapter_replays_without_running(node: &Node, request: &AttemptRequest, head: ChainHead) {
    let mut adapter = Adapter::spawn(&node.socket);
    adapter.send(&json!({
        "cmd": "run",
        "envelope_json": String::from_utf8(request.envelope.envelope_json.as_bytes().to_vec()).unwrap(),
        "proof": request.envelope.proof,
        "operation_ids": {"start_at": 100},
        "poll_ms": 50,
        "task_root": node.task_root,
    }));
    let events = adapter.events_until("done");
    let names: Vec<&str> = events
        .iter()
        .map(|event| event["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "state", "state", "admitted", "receipt", "state", "evidence", "done"
        ],
        "{events:?}"
    );
    let report = &events[6]["report"];
    assert_eq!(report["outcome"], json!("completed"));
    assert_eq!(report["receipt"], json!("completed"));
    assert_eq!(report["final_state"], json!("sealed"));
    assert_eq!(report["cause"], json!({"Exited": {"code": 0}}));
    assert_eq!(report["evidence_head"], json!(head.hash.to_hex()));
    let operations: Vec<(u64, &str)> = report["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|operation| {
            (
                operation["operation_id"].as_u64().unwrap(),
                operation["state"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        operations,
        [(100, "sealed"), (101, "sealed"), (105, "sealed")]
    );
    assert_eq!(adapter.finish(), 0);
}

fn a_retired_attempt_is_never_recreated(
    client: &Client<UnixTransport>,
    request: &AttemptRequest,
    ids: &OperationIds,
    replayed: TaskBinding,
    successor: TaskBinding,
) {
    assert_eq!(
        accepted(client.create(successor, op(200))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        rejected(client.create(replayed, op(100))),
        TaskLifecycleRejectionReason::StaleOperation
    );
    assert_eq!(
        rejected(client.create(replayed, op(201))),
        TaskLifecycleRejectionReason::StaleOperation
    );
    assert_eq!(
        client.inspect(replayed).unwrap(),
        Inspection::Rejected {
            reason: TaskLifecycleRejectionReason::AttemptMismatch
        }
    );
    let (retired, _) = run(client, request, ids);
    assert_eq!(
        retired.outcome,
        AttemptOutcome::Refused {
            verb: Verb::Create,
            reason: TaskLifecycleRejectionReason::StaleOperation
        },
        "{retired:?}"
    );
    assert_eq!(retired.operations.len(), 1);
}

#[test]
fn replay_after_a_client_restart_runs_nothing_twice() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let node = Node::spawn(dir.path());
    let client = connect(&node.socket);
    let replayed = binding(0x60, 0x61, 0x62);
    let marker = marker("ward-acceptance-replay");
    let script = format!("cat src/input.txt > copy.txt && echo {marker} >> out.txt");
    let request = signed(
        &node,
        &workload(replayed, snapshot, &["sh", "-c", &script], 60_000),
    );
    let ids = OperationIds::starting_at(100).unwrap();
    let out = node.workspace(replayed).join("out.txt");

    let (first, _) = run(&client, &request, &ids);
    assert_eq!(first.outcome, AttemptOutcome::Completed, "{first:?}");
    assert_eq!(lines(&out), 1);
    let log = verified(&node, replayed);
    assert!(log.is_sealed());
    let head = log.head();
    assert_eq!(first.evidence_head, Some(head.hash));

    let (second, _) = run(&client, &request, &ids);
    assert_eq!(
        operations(&second),
        [
            (Verb::Create, 100, Some(TaskLifecycleState::Sealed), None),
            (Verb::Admit, 101, Some(TaskLifecycleState::Sealed), None),
            (Verb::Seal, 105, Some(TaskLifecycleState::Sealed), None),
        ]
    );
    assert_eq!(second.outcome, first.outcome);
    assert_eq!(second.receipt, first.receipt);
    assert_eq!(second.cause, first.cause);
    assert_eq!(second.evidence_head, first.evidence_head);
    assert_eq!(second.final_state, Some(TaskLifecycleState::Sealed));
    assert_eq!(lines(&out), 1);
    assert_eq!(verified(&node, replayed).head(), head);

    adapter_replays_without_running(&node, &request, head);
    assert_eq!(lines(&out), 1, "the adapter replay ran the workload again");
    assert_eq!(verified(&node, replayed).head(), head);

    a_retired_attempt_is_never_recreated(
        &client,
        &request,
        &ids,
        replayed,
        binding(0x60, 0x63, 0x62),
    );
    assert_eq!(lines(&out), 1);
    assert_eq!(verified(&node, replayed).head(), head);
    assert_eq!(processes_with(&marker), 0);
    pass("replay_after_a_client_restart_runs_nothing_twice", started);
}

fn a_restarted_node_answers_every_replay_sealed(
    node: &Node,
    client: &Client<UnixTransport>,
    request: &AttemptRequest,
    first: &AttemptReport,
    head: ChainHead,
) {
    let durable = request.binding;
    assert_eq!(
        inspected(client, durable),
        (
            TaskLifecycleState::Sealed,
            Some(TaskExecutionOutcome::Completed)
        )
    );
    let log = verified(node, durable);
    assert!(log.is_sealed());
    assert_eq!(log.head(), head);
    assert_eq!(
        ended(&log),
        Some((
            NodeAttemptState::Exited,
            NodeAttemptOutcome::Completed,
            NodeAttemptEnd::Exited { code: Some(0) },
            None
        ))
    );
    assert_eq!(
        accepted(client.create(durable, op(100))),
        TaskLifecycleState::Sealed
    );
    assert_eq!(
        accepted(client.admit(durable, op(101), &request.envelope)),
        TaskLifecycleState::Sealed
    );
    assert_eq!(
        accepted(client.start(durable, op(102))),
        TaskLifecycleState::Sealed
    );
    assert_eq!(
        accepted(client.seal(durable, op(105))),
        TaskLifecycleState::Sealed
    );
    let (replay, _) = run(client, request, &OperationIds::starting_at(100).unwrap());
    assert_eq!(replay.outcome, AttemptOutcome::Completed, "{replay:?}");
    assert_eq!(replay.receipt, first.receipt);
    assert_eq!(replay.cause, first.cause);
    assert_eq!(replay.evidence_head, first.evidence_head);
    assert_eq!(
        operations(&replay),
        [
            (Verb::Create, 100, Some(TaskLifecycleState::Sealed), None),
            (Verb::Admit, 101, Some(TaskLifecycleState::Sealed), None),
            (Verb::Seal, 105, Some(TaskLifecycleState::Sealed), None),
        ]
    );
}

#[test]
fn durable_records_survive_a_node_restart() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let node = Node::spawn(dir.path());
    let durable = binding(0x70, 0x71, 0x72);
    let marker = marker("ward-acceptance-recovery");
    let script = format!("echo {marker} >> out.txt");
    let request = signed(
        &node,
        &workload(durable, snapshot, &["sh", "-c", &script], 60_000),
    );
    let ids = OperationIds::starting_at(100).unwrap();
    let out = node.workspace(durable).join("out.txt");
    let (first, _) = run(&connect(&node.socket), &request, &ids);
    assert_eq!(first.outcome, AttemptOutcome::Completed, "{first:?}");
    let head = verified(&node, durable).head();
    assert_eq!(first.evidence_head, Some(head.hash));
    node.kill();

    let node = Node::spawn(dir.path());
    let client = connect(&node.socket);
    a_restarted_node_answers_every_replay_sealed(&node, &client, &request, &first, head);
    assert_eq!(lines(&out), 1);

    let successor = binding(0x70, 0x73, 0x72);
    assert_eq!(
        accepted(client.create(successor, op(300))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        rejected(client.create(durable, op(100))),
        TaskLifecycleRejectionReason::StaleOperation
    );
    node.kill();

    let node = Node::spawn(dir.path());
    let client = connect(&node.socket);
    assert_eq!(
        rejected(client.create(durable, op(100))),
        TaskLifecycleRejectionReason::StaleOperation
    );
    assert_eq!(
        rejected(client.create(durable, op(301))),
        TaskLifecycleRejectionReason::StaleOperation
    );
    assert_eq!(
        accepted(client.create(successor, op(300))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        inspected(&client, successor),
        (TaskLifecycleState::Created, None)
    );
    let log = verified(&node, durable);
    assert!(log.is_sealed());
    assert_eq!(log.head(), head);
    assert_eq!(lines(&out), 1);
    assert_eq!(processes_with(&marker), 0);
    pass("durable_records_survive_a_node_restart", started);
}
