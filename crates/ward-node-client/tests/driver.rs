//! The attempt driver's state machine over a scripted transport: happy path, refusal,
//! transport failure, recovery by inspect-and-replay, cancellation and the deadline.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Mutex;
use std::time::Duration;

use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId,
};
use ward_node_client::{
    AttemptEvent, AttemptOutcome, AttemptReport, AttemptRequest, CancelToken, Client, Driver,
    EnvelopeInput, Exchange, IssuerKey, OperationIds, OperationIdsError, RunConfig, Transport,
    TransportError, Verb, WorkloadInput,
};
use ward_node_protocol::{
    HandshakeRequest, HandshakeResponse, OperationId, ProtocolVersion, TaskAdmissionAuthority,
    TaskBinding, TaskExecutionOutcome, TaskLifecycleContext, TaskLifecycleRejectionReason,
    TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState,
};

fn binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

fn op(value: u64) -> OperationId {
    OperationId::new(value).unwrap()
}

fn context() -> TaskLifecycleContext {
    TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
}

fn request(budget_ms: u64) -> AttemptRequest {
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding().lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer: PrincipalId::from_u128(2),
            subject: AgentId::from_u128(3),
            task: binding().task(),
            grants: GrantSet::new([CapabilityGrant::new(
                CapabilityName::new("repo.read").unwrap(),
                ResourceRef::new("repo:hexrift/WardOS").unwrap(),
                false,
            )])
            .unwrap(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 9_000,
            version: LeaseVersion::new(1).unwrap(),
        },
        2_000,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap();
    let envelope = EnvelopeInput {
        binding: binding(),
        agent: AgentId::from_u128(3),
        node: NodeId::from_u128(4),
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: WorkloadInput {
            argv: vec!["true".to_owned()],
            capability_manifest: None,
            snapshot: SnapshotId::new(Blake3Hash::from_bytes([0x11; 32])),
            wall_clock_budget_ms: budget_ms,
        },
        issued_at_unix_ms: 2_000,
        expires_at_unix_ms: 8_000,
        version: 1,
    }
    .build()
    .unwrap();
    AttemptRequest::sign(&envelope, &IssuerKey::from_seed([7; 32]).unwrap(), None).unwrap()
}

enum Step {
    Reply(TaskLifecycleResponse),
    Eof,
    Fail,
}

type Handler = Box<dyn FnMut(usize, &TaskLifecycleRequest) -> Step + Send>;

struct FakeNode {
    handler: Mutex<Handler>,
    requests: Mutex<Vec<TaskLifecycleRequest>>,
}

impl FakeNode {
    fn new(handler: impl FnMut(usize, &TaskLifecycleRequest) -> Step + Send + 'static) -> Self {
        Self {
            handler: Mutex::new(Box::new(handler)),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn verbs(&self) -> Vec<&'static str> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| match request {
                TaskLifecycleRequest::Create { .. } => "create",
                TaskLifecycleRequest::Admit { .. } => "admit",
                TaskLifecycleRequest::Start { .. } => "start",
                TaskLifecycleRequest::Pause { .. } => "pause",
                TaskLifecycleRequest::Resume { .. } => "resume",
                TaskLifecycleRequest::Stop { .. } => "stop",
                TaskLifecycleRequest::Revoke { .. } => "revoke",
                TaskLifecycleRequest::Inspect { .. } => "inspect",
                TaskLifecycleRequest::Stream { .. } => "stream",
                TaskLifecycleRequest::Seal { .. } => "seal",
            })
            .collect()
    }
}

fn accepted_handshake() -> String {
    serde_json::to_string(&HandshakeResponse::Accepted {
        protocol: ProtocolVersion::new(1, 3),
    })
    .unwrap()
}

impl Transport for FakeNode {
    fn handshake(&self, hello: &str) -> Result<String, TransportError> {
        serde_json::from_str::<HandshakeRequest>(hello).unwrap();
        Ok(accepted_handshake())
    }

    fn exchange(&self, hello: &str, request: &str) -> Result<Exchange, TransportError> {
        serde_json::from_str::<HandshakeRequest>(hello).unwrap();
        let decoded = context().decode_request(request).unwrap();
        let mut requests = self.requests.lock().unwrap();
        let index = requests.len();
        requests.push(decoded.clone());
        drop(requests);
        let step = (self.handler.lock().unwrap())(index, &decoded);
        match step {
            Step::Reply(response) => Ok(Exchange {
                handshake: accepted_handshake(),
                response: Some(serde_json::to_string(&response).unwrap()),
            }),
            Step::Eof => Ok(Exchange {
                handshake: accepted_handshake(),
                response: None,
            }),
            Step::Fail => Err(TransportError::Connect(std::io::Error::other("down"))),
        }
    }
}

fn accepted(request: &TaskLifecycleRequest, state: TaskLifecycleState) -> Step {
    let operation_id = match request {
        TaskLifecycleRequest::Create { operation_id, .. }
        | TaskLifecycleRequest::Admit { operation_id, .. }
        | TaskLifecycleRequest::Start { operation_id, .. }
        | TaskLifecycleRequest::Pause { operation_id, .. }
        | TaskLifecycleRequest::Resume { operation_id, .. }
        | TaskLifecycleRequest::Stop { operation_id, .. }
        | TaskLifecycleRequest::Revoke { operation_id, .. }
        | TaskLifecycleRequest::Seal { operation_id, .. } => *operation_id,
        other => panic!("{other:?} carries no operation id"),
    };
    Step::Reply(context().accepted(operation_id, binding(), state))
}

fn rejected(operation_id: Option<OperationId>, reason: TaskLifecycleRejectionReason) -> Step {
    Step::Reply(context().rejected(operation_id, binding(), reason))
}

fn inspected(state: TaskLifecycleState, outcome: Option<TaskExecutionOutcome>) -> Step {
    Step::Reply(match outcome {
        Some(outcome) => context()
            .inspected_with_outcome(binding(), state, outcome)
            .unwrap(),
        None => context().inspected(binding(), state),
    })
}

fn config() -> RunConfig {
    RunConfig {
        poll_interval: Duration::ZERO,
        max_poll_interval: Duration::ZERO,
        grace: Duration::from_secs(5),
    }
}

fn run(
    node: FakeNode,
    request: &AttemptRequest,
    ids: &OperationIds,
    cancel: &CancelToken,
    config: RunConfig,
) -> (AttemptReport, Vec<AttemptEvent>, FakeNode) {
    let client = Client::connect(node).unwrap();
    let mut events = Vec::new();
    let report = Driver::new(&client, config).run_attempt(request, ids, cancel, &mut |event| {
        events.push(event.clone());
    });
    (report, events, client.into_transport())
}

fn ids_used(report: &AttemptReport) -> Vec<(Verb, u64)> {
    report
        .operations
        .iter()
        .map(|operation| (operation.verb, operation.operation_id.get()))
        .collect()
}

#[test]
fn the_default_operation_id_scheme_is_fixed_and_a_sequence_can_start_anywhere() {
    let default = OperationIds::default();
    assert_eq!(
        [
            default.create.get(),
            default.admit.get(),
            default.start.get(),
            default.stop.get(),
            default.revoke.get(),
            default.seal.get(),
            default.first_intervention.get()
        ],
        [1, 2, 3, 4, 5, 6, 7]
    );
    let from_ten = OperationIds::starting_at(10).unwrap();
    assert_eq!(
        [
            from_ten.create.get(),
            from_ten.admit.get(),
            from_ten.start.get(),
            from_ten.stop.get(),
            from_ten.revoke.get(),
            from_ten.seal.get(),
            from_ten.first_intervention.get()
        ],
        [10, 11, 12, 13, 14, 15, 16]
    );
    assert_eq!(OperationIds::starting_at(1).unwrap(), default);
    assert_eq!(
        OperationIds::starting_at(0).unwrap_err(),
        OperationIdsError::Zero
    );
    assert_eq!(
        OperationIds::starting_at(u64::MAX - 3).unwrap_err(),
        OperationIdsError::Overflow
    );
    let json: OperationIds = serde_json::from_str(r#"{"start_at":10}"#).unwrap();
    assert_eq!(json, from_ten);
    let explicit: OperationIds = serde_json::from_str(
        r#"{"create":1,"admit":2,"start":3,"stop":4,"revoke":5,"seal":6,"first_intervention":7}"#,
    )
    .unwrap();
    assert_eq!(explicit, default);
    assert!(serde_json::from_str::<OperationIds>(r#"{"start_at":0}"#).is_err());
}

#[test]
fn the_happy_path_creates_admits_starts_polls_reads_the_receipt_and_seals() {
    let node = FakeNode::new(|index, request| match (index, request) {
        (0, TaskLifecycleRequest::Create { .. }) => accepted(request, TaskLifecycleState::Created),
        (1, TaskLifecycleRequest::Admit { .. }) => accepted(request, TaskLifecycleState::Ready),
        (2, TaskLifecycleRequest::Start { .. }) => accepted(request, TaskLifecycleState::Running),
        (3, TaskLifecycleRequest::Inspect { .. }) => inspected(TaskLifecycleState::Running, None),
        (4, TaskLifecycleRequest::Inspect { .. }) => inspected(
            TaskLifecycleState::Exited,
            Some(TaskExecutionOutcome::Completed),
        ),
        (5, TaskLifecycleRequest::Seal { .. }) => accepted(request, TaskLifecycleState::Sealed),
        other => panic!("unexpected {other:?}"),
    });
    let request = request(600_000);
    let (report, events, node) = run(
        node,
        &request,
        &OperationIds::default(),
        &CancelToken::default(),
        config(),
    );
    assert_eq!(
        node.verbs(),
        ["create", "admit", "start", "inspect", "inspect", "seal"]
    );
    assert_eq!(report.outcome, AttemptOutcome::Completed);
    assert!(report.outcome_certain);
    assert_eq!(report.receipt, Some(TaskExecutionOutcome::Completed));
    assert_eq!(report.final_state, Some(TaskLifecycleState::Sealed));
    assert!(report.sealed);
    assert!(!report.cancelled);
    assert_eq!(report.transport_error, None);
    assert_eq!(report.evidence_log, None);
    assert_eq!(
        ids_used(&report),
        [
            (Verb::Create, 1),
            (Verb::Admit, 2),
            (Verb::Start, 3),
            (Verb::Seal, 6)
        ]
    );
    assert_eq!(
        events,
        vec![
            AttemptEvent::State {
                verb: Verb::Create,
                operation_id: op(1),
                state: TaskLifecycleState::Created
            },
            AttemptEvent::State {
                verb: Verb::Admit,
                operation_id: op(2),
                state: TaskLifecycleState::Ready
            },
            AttemptEvent::Admitted {
                envelope_json: request.envelope.envelope_json.clone(),
                proof: request.envelope.proof,
            },
            AttemptEvent::State {
                verb: Verb::Start,
                operation_id: op(3),
                state: TaskLifecycleState::Running
            },
            AttemptEvent::Receipt {
                state: TaskLifecycleState::Exited,
                outcome: Some(TaskExecutionOutcome::Completed)
            },
            AttemptEvent::State {
                verb: Verb::Seal,
                operation_id: op(6),
                state: TaskLifecycleState::Sealed
            },
        ]
    );
    let TaskLifecycleRequest::Admit {
        envelope_json,
        proof,
        ..
    } = node.requests.lock().unwrap()[1].clone()
    else {
        panic!("not an admit");
    };
    assert_eq!(envelope_json, request.envelope.envelope_json);
    assert_eq!(proof, request.envelope.proof);
}

#[test]
fn a_refusal_at_admit_ends_the_run_with_nothing_started() {
    let node = FakeNode::new(|index, request| match (index, request) {
        (0, TaskLifecycleRequest::Create { .. }) => accepted(request, TaskLifecycleState::Created),
        (1, TaskLifecycleRequest::Admit { .. }) => {
            rejected(Some(op(2)), TaskLifecycleRejectionReason::AuthorityDenied)
        }
        other => panic!("unexpected {other:?}"),
    });
    let (report, events, node) = run(
        node,
        &request(600_000),
        &OperationIds::default(),
        &CancelToken::default(),
        config(),
    );
    assert_eq!(node.verbs(), ["create", "admit"]);
    assert_eq!(
        report.outcome,
        AttemptOutcome::Refused {
            verb: Verb::Admit,
            reason: TaskLifecycleRejectionReason::AuthorityDenied
        }
    );
    assert!(report.outcome_certain);
    assert_eq!(report.final_state, Some(TaskLifecycleState::Created));
    assert!(!report.sealed);
    assert_eq!(ids_used(&report), [(Verb::Create, 1), (Verb::Admit, 2)]);
    assert_eq!(
        events[1],
        AttemptEvent::Rejected {
            verb: Verb::Admit,
            operation_id: Some(op(2)),
            reason: TaskLifecycleRejectionReason::AuthorityDenied
        }
    );
}

#[test]
fn an_unreachable_node_mid_run_reports_unknown_and_sends_nothing_more() {
    let node = FakeNode::new(|index, request| match (index, request) {
        (0, TaskLifecycleRequest::Create { .. }) => accepted(request, TaskLifecycleState::Created),
        (1, TaskLifecycleRequest::Admit { .. }) => accepted(request, TaskLifecycleState::Ready),
        (2, TaskLifecycleRequest::Start { .. }) => Step::Fail,
        other => panic!("unexpected {other:?}"),
    });
    let (report, _, node) = run(
        node,
        &request(600_000),
        &OperationIds::default(),
        &CancelToken::default(),
        config(),
    );
    assert_eq!(node.verbs(), ["create", "admit", "start"]);
    assert_eq!(report.outcome, AttemptOutcome::Unknown);
    assert!(!report.outcome_certain);
    assert_eq!(report.receipt, None);
    assert_eq!(report.final_state, Some(TaskLifecycleState::Ready));
    assert!(!report.sealed);
    assert!(report.transport_error.is_some());
    assert_eq!(
        ids_used(&report),
        [(Verb::Create, 1), (Verb::Admit, 2), (Verb::Start, 3)]
    );
}

#[test]
fn eof_without_an_answer_is_recovered_by_one_inspect_and_one_replay_of_the_same_id() {
    let node = FakeNode::new(|index, request| match (index, request) {
        (0, TaskLifecycleRequest::Create { .. }) => accepted(request, TaskLifecycleState::Created),
        (1, TaskLifecycleRequest::Admit { .. }) => accepted(request, TaskLifecycleState::Ready),
        (2, TaskLifecycleRequest::Start { .. }) | (6, TaskLifecycleRequest::Seal { .. }) => {
            Step::Eof
        }
        (3, TaskLifecycleRequest::Inspect { .. }) => inspected(TaskLifecycleState::Running, None),
        (4, TaskLifecycleRequest::Start { operation_id, .. }) => {
            assert_eq!(*operation_id, op(3));
            accepted(request, TaskLifecycleState::Running)
        }
        (5, TaskLifecycleRequest::Inspect { .. }) => inspected(
            TaskLifecycleState::Exited,
            Some(TaskExecutionOutcome::Failed),
        ),
        (7, TaskLifecycleRequest::Inspect { .. }) => inspected(
            TaskLifecycleState::Sealed,
            Some(TaskExecutionOutcome::Failed),
        ),
        (8, TaskLifecycleRequest::Seal { operation_id, .. }) => {
            assert_eq!(*operation_id, op(6));
            Step::Eof
        }
        other => panic!("unexpected {other:?}"),
    });
    let (report, events, node) = run(
        node,
        &request(600_000),
        &OperationIds::default(),
        &CancelToken::default(),
        config(),
    );
    assert_eq!(
        node.verbs(),
        [
            "create", "admit", "start", "inspect", "start", "inspect", "seal", "inspect", "seal"
        ]
    );
    assert_eq!(report.outcome, AttemptOutcome::Unknown);
    assert_eq!(report.receipt, Some(TaskExecutionOutcome::Failed));
    assert_eq!(report.final_state, Some(TaskLifecycleState::Sealed));
    assert!(!report.sealed);
    assert!(report.transport_error.is_some());
    assert!(events.contains(&AttemptEvent::Recovering {
        verb: Verb::Start,
        operation_id: op(3)
    }));
}

#[test]
fn cancellation_revokes_rather_than_stops_and_then_seals() {
    let cancel = CancelToken::default();
    let trigger = cancel.clone();
    let node = FakeNode::new(move |index, request| match (index, request) {
        (0, TaskLifecycleRequest::Create { .. }) => accepted(request, TaskLifecycleState::Created),
        (1, TaskLifecycleRequest::Admit { .. }) => accepted(request, TaskLifecycleState::Ready),
        (2, TaskLifecycleRequest::Start { .. }) => accepted(request, TaskLifecycleState::Running),
        (3, TaskLifecycleRequest::Inspect { .. }) => {
            trigger.cancel();
            inspected(TaskLifecycleState::Running, None)
        }
        (4, TaskLifecycleRequest::Revoke { .. }) => accepted(request, TaskLifecycleState::Revoked),
        (5, TaskLifecycleRequest::Inspect { .. }) => inspected(
            TaskLifecycleState::Revoked,
            Some(TaskExecutionOutcome::Failed),
        ),
        (6, TaskLifecycleRequest::Seal { .. }) => accepted(request, TaskLifecycleState::Sealed),
        other => panic!("unexpected {other:?}"),
    });
    let (report, _, node) = run(
        node,
        &request(600_000),
        &OperationIds::default(),
        &cancel,
        config(),
    );
    assert_eq!(
        node.verbs(),
        [
            "create", "admit", "start", "inspect", "revoke", "inspect", "seal"
        ]
    );
    assert_eq!(report.outcome, AttemptOutcome::Failed);
    assert!(report.cancelled);
    assert!(report.sealed);
    assert_eq!(
        ids_used(&report),
        [
            (Verb::Create, 1),
            (Verb::Admit, 2),
            (Verb::Start, 3),
            (Verb::Revoke, 5),
            (Verb::Seal, 6)
        ]
    );
}

#[test]
fn a_cancellation_before_start_revokes_the_ready_task_without_starting_it() {
    let cancel = CancelToken::default();
    cancel.cancel();
    let node = FakeNode::new(|index, request| match (index, request) {
        (0, TaskLifecycleRequest::Create { .. }) => accepted(request, TaskLifecycleState::Created),
        (1, TaskLifecycleRequest::Admit { .. }) => accepted(request, TaskLifecycleState::Ready),
        (2, TaskLifecycleRequest::Revoke { .. }) => accepted(request, TaskLifecycleState::Revoked),
        (3, TaskLifecycleRequest::Inspect { .. }) => inspected(
            TaskLifecycleState::Revoked,
            Some(TaskExecutionOutcome::Failed),
        ),
        (4, TaskLifecycleRequest::Seal { .. }) => accepted(request, TaskLifecycleState::Sealed),
        other => panic!("unexpected {other:?}"),
    });
    let (report, _, node) = run(
        node,
        &request(600_000),
        &OperationIds::default(),
        &cancel,
        config(),
    );
    assert_eq!(
        node.verbs(),
        ["create", "admit", "revoke", "inspect", "seal"]
    );
    assert_eq!(report.outcome, AttemptOutcome::Failed);
    assert!(report.cancelled && report.sealed);
}

#[test]
fn a_workload_still_running_past_its_budget_and_grace_is_revoked() {
    let mut revoked = false;
    let node = FakeNode::new(move |index, request| match (index, request) {
        (0, TaskLifecycleRequest::Create { .. }) => accepted(request, TaskLifecycleState::Created),
        (1, TaskLifecycleRequest::Admit { .. }) => accepted(request, TaskLifecycleState::Ready),
        (2, TaskLifecycleRequest::Start { .. }) => accepted(request, TaskLifecycleState::Running),
        (_, TaskLifecycleRequest::Inspect { .. }) if revoked => inspected(
            TaskLifecycleState::Revoked,
            Some(TaskExecutionOutcome::Unknown),
        ),
        (_, TaskLifecycleRequest::Inspect { .. }) => inspected(TaskLifecycleState::Running, None),
        (_, TaskLifecycleRequest::Revoke { .. }) => {
            revoked = true;
            accepted(request, TaskLifecycleState::Revoked)
        }
        (_, TaskLifecycleRequest::Seal { .. }) => accepted(request, TaskLifecycleState::Sealed),
        other => panic!("unexpected {other:?}"),
    });
    let (report, _, node) = run(
        node,
        &request(1),
        &OperationIds::default(),
        &CancelToken::default(),
        RunConfig {
            poll_interval: Duration::from_millis(1),
            max_poll_interval: Duration::from_millis(2),
            grace: Duration::from_millis(20),
        },
    );
    let verbs = node.verbs();
    assert!(verbs.contains(&"revoke"), "{verbs:?}");
    assert!(!verbs.contains(&"stop"));
    assert_eq!(verbs.last(), Some(&"seal"));
    assert!(report.deadline_exceeded);
    assert_eq!(report.outcome, AttemptOutcome::Unknown);
    assert!(!report.outcome_certain);
    assert!(report.sealed);
}

#[test]
fn an_ambiguous_launch_is_read_as_unknown_and_sealed_without_a_second_start() {
    let node = FakeNode::new(|index, request| match (index, request) {
        (0, TaskLifecycleRequest::Create { .. }) => accepted(request, TaskLifecycleState::Created),
        (1, TaskLifecycleRequest::Admit { .. }) => accepted(request, TaskLifecycleState::Ready),
        (2, TaskLifecycleRequest::Start { .. }) => accepted(request, TaskLifecycleState::Exited),
        (3, TaskLifecycleRequest::Inspect { .. }) => inspected(
            TaskLifecycleState::Exited,
            Some(TaskExecutionOutcome::Unknown),
        ),
        (4, TaskLifecycleRequest::Seal { .. }) => accepted(request, TaskLifecycleState::Sealed),
        other => panic!("unexpected {other:?}"),
    });
    let (report, _, node) = run(
        node,
        &request(600_000),
        &OperationIds::default(),
        &CancelToken::default(),
        config(),
    );
    assert_eq!(
        node.verbs(),
        ["create", "admit", "start", "inspect", "seal"]
    );
    assert_eq!(report.outcome, AttemptOutcome::Unknown);
    assert!(!report.outcome_certain);
    assert!(report.sealed);
}
