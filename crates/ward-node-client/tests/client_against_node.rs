//! The client drives a real `ward-node` end to end: a workload runs to `exited`/`completed`
//! and is sealed with a verifying evidence log, a replay with the same operation ids never
//! runs it twice, and a cancellation revokes a long workload and seals it. The cases need a
//! working bubblewrap and skip without one, except under `WARD_REQUIRE_ISOLATION=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::{
    Node, binding, envelope, imported, isolation, issuer, marker, private_dir, wait_until_gone,
    wait_until_sandboxed,
};
use ward_events::log::{head_file_path, parse_head};
use ward_events::{ChainHead, LogReader, NodeAttemptEnd, WardEvent};
use ward_node::evidence;
use ward_node_client::{
    AttemptEvent, AttemptOutcome, AttemptRequest, CancelToken, Client, Driver, OperationIds,
    RunConfig, Timeouts, UnixTransport, Verb, evidence_log_path,
};
use ward_node_protocol::{TaskExecutionOutcome, TaskLifecycleState};

fn client(node: &Node) -> Client<UnixTransport> {
    Client::connect(UnixTransport::new(&node.socket, Timeouts::default())).unwrap()
}

fn config() -> RunConfig {
    RunConfig {
        poll_interval: Duration::from_millis(50),
        max_poll_interval: Duration::from_millis(200),
        grace: Duration::from_secs(30),
    }
}

fn operations_used(report: &ward_node_client::AttemptReport) -> Vec<(Verb, u64)> {
    report
        .operations
        .iter()
        .map(|operation| (operation.verb, operation.operation_id.get()))
        .collect()
}

fn verified_sealed_log(node: &Node, report: &ward_node_client::AttemptReport) -> ChainHead {
    let log = evidence_log_path(&node.task_root, binding());
    assert_eq!(report.evidence_log.as_deref(), Some(log.as_path()));
    assert_eq!(
        log,
        evidence::evidence_dir(&node.task_root, binding()).join(evidence::EVIDENCE_LOG)
    );
    let verified = evidence::verify(
        &evidence::evidence_dir(&node.task_root, binding()),
        binding(),
    )
    .unwrap();
    assert!(verified.is_sealed());
    let head = LogReader::open(&log).unwrap().verify_all().unwrap();
    assert_eq!(
        parse_head(&std::fs::read_to_string(head_file_path(&log)).unwrap()).unwrap(),
        head
    );
    assert_eq!(report.evidence_head, Some(head.hash));
    let kinds: Vec<&str> = verified
        .records()
        .iter()
        .map(|record| match record.event {
            WardEvent::NodeAttemptAdmitted { operation: 101, .. } => "admitted",
            WardEvent::NodeAttemptLaunched { operation: 102, .. } => "launched",
            WardEvent::NodeAttemptEnded { .. } => "ended",
            WardEvent::NodeAttemptSealed { operation: 105 } => "sealed",
            ref other => panic!("unexpected record {other:?}"),
        })
        .collect();
    assert_eq!(kinds, ["admitted", "launched", "ended", "sealed"]);
    head
}

#[test]
fn the_client_negotiates_1_3_and_reads_an_executing_nodes_capabilities() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let node = Node::spawn(dir.path());
    let client = client(&node);
    assert_eq!(client.protocol().minor(), 3);
    let capabilities = client.capabilities().unwrap();
    assert!(capabilities.lifecycle().admit);
    assert!(capabilities.lifecycle().start && capabilities.lifecycle().stop);
    assert!(capabilities.network().offline);
}

#[test]
fn a_run_completes_seals_and_leaves_a_verifying_log_and_a_replay_never_runs_twice() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path());
    let marker = marker("ward-node-client-run");
    let script = format!("cat src/input.txt > copy.txt && echo {marker} >> out.txt");
    let request = AttemptRequest::sign(
        &envelope(binding(), snapshot, &["sh", "-c", &script]),
        &issuer(),
        Some(node.task_root.clone()),
    )
    .unwrap();
    let client = client(&node);
    let driver = Driver::new(&client, config());
    let ids = OperationIds::starting_at(100).unwrap();

    let mut events = Vec::new();
    let report = driver.run_attempt(&request, &ids, &CancelToken::default(), &mut |event| {
        events.push(event.clone());
    });
    assert_eq!(report.outcome, AttemptOutcome::Completed, "{report:?}");
    assert!(report.outcome_certain);
    assert_eq!(report.receipt, Some(TaskExecutionOutcome::Completed));
    assert_eq!(report.final_state, Some(TaskLifecycleState::Sealed));
    assert!(report.sealed);
    assert_eq!(report.cause, Some(NodeAttemptEnd::Exited { code: Some(0) }));
    assert_eq!(
        operations_used(&report),
        [
            (Verb::Create, 100),
            (Verb::Admit, 101),
            (Verb::Start, 102),
            (Verb::Seal, 105)
        ]
    );

    let log = evidence_log_path(&node.task_root, binding());
    let head = verified_sealed_log(&node, &report);
    assert!(events.contains(&AttemptEvent::Evidence { path: log.clone() }));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, AttemptEvent::Admitted { .. }))
    );
    let out = node.workspace(binding()).join("out.txt");
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        format!("{marker}\n")
    );

    let replay = driver.run_attempt(&request, &ids, &CancelToken::default(), &mut |_| {});
    assert_eq!(replay.outcome, AttemptOutcome::Completed, "{replay:?}");
    assert_eq!(replay.final_state, Some(TaskLifecycleState::Sealed));
    assert!(replay.sealed);
    assert_eq!(replay.transport_error, None);
    assert_eq!(
        operations_used(&replay),
        [(Verb::Create, 100), (Verb::Admit, 101), (Verb::Seal, 105)],
        "a replay of an ended run sends only ids that already took effect; nothing to start"
    );
    assert!(replay.operations.iter().all(|operation| {
        operation.state == Some(TaskLifecycleState::Sealed) && operation.reason.is_none()
    }));
    assert_eq!(replay.receipt, report.receipt);
    assert_eq!(replay.evidence_head, report.evidence_head);
    assert_eq!(replay.cause, report.cause);
    assert_eq!(
        std::fs::read_to_string(&out).unwrap().lines().count(),
        1,
        "the replay ran nothing"
    );
    assert_eq!(
        LogReader::open(&log).unwrap().verify_all().unwrap(),
        head,
        "the replay appended nothing"
    );
}

#[test]
fn a_cancellation_revokes_a_long_workload_and_seals_it() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path());
    let marker = marker("ward-node-client-cancel");
    let script = format!("sleep 300; echo {marker}");
    let request = AttemptRequest::sign(
        &envelope(binding(), snapshot, &["sh", "-c", &script]),
        &issuer(),
        Some(node.task_root.clone()),
    )
    .unwrap();
    let cancel = CancelToken::default();
    let socket = node.socket.clone();
    let worker = {
        let cancel = cancel.clone();
        std::thread::spawn(move || {
            let client = Client::connect(UnixTransport::new(&socket, Timeouts::default())).unwrap();
            Driver::new(&client, config()).run_attempt(
                &request,
                &OperationIds::default(),
                &cancel,
                &mut |_| {},
            )
        })
    };
    wait_until_sandboxed(&marker);
    cancel.cancel();
    let report = worker.join().unwrap();
    wait_until_gone(&marker);

    assert!(report.cancelled);
    assert!(
        matches!(
            report.outcome,
            AttemptOutcome::Failed | AttemptOutcome::Unknown
        ),
        "{report:?}"
    );
    assert_eq!(report.final_state, Some(TaskLifecycleState::Sealed));
    assert!(report.sealed);
    assert!(
        report
            .operations
            .iter()
            .any(|operation| operation.verb == Verb::Revoke)
    );
    assert!(
        report
            .operations
            .iter()
            .all(|operation| operation.verb != Verb::Stop)
    );
    let verified = evidence::verify(
        &evidence::evidence_dir(&node.task_root, binding()),
        binding(),
    )
    .unwrap();
    assert!(verified.is_sealed());
    assert!(verified.records().iter().any(|record| matches!(
        record.event,
        WardEvent::NodeAttemptEnded {
            operation: Some(5),
            ..
        }
    )));
    assert_eq!(
        client(&node).inspect(binding()).unwrap(),
        ward_node_client::Inspection::Inspected {
            state: TaskLifecycleState::Sealed,
            outcome: report.receipt,
        }
    );
}
