//! Cross-system acceptance of `ward-node` result return (#332 stage 2, the result half;
//! node-integration.md §6.6, §7.5 and §9): a real node started with `--output-return`,
//! driven through the real transport by `ward-node-client`, runs real workloads that
//! print and write files, and the control plane receives exactly the bounded content
//! with digests that match the files on the host. The cases prove the bounds and the
//! truncation marks, that the manifest grammar refuses an escaping path at `admit` and
//! that a planted symlink is never followed, that the capability is advertised and
//! honoured only when the operator enabled it, and that a stored result survives a node
//! restart and `seal`. One `#[test]` per case; each case's pass criterion is stated in
//! [`CASES`] and, word for word, in `docs/node-acceptance.md`, and
//! `scripts/acceptance/node.sh` runs these cases beside the main suite. The cases need a
//! working bubblewrap and skip without one, except under `WARD_REQUIRE_ISOLATION=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{
    NODE, envelope_input, imported, isolation, issuer, private_dir, trust_store, ward_node_binary,
};
use ward_events::{
    Blake3Hash, NodeAttemptState, NodeOutputFileStatus, Origin, SandboxPath, SandboxRoot,
    SnapshotId, WardEvent,
};
use ward_node::evidence::{self, VerifiedEvidence};
use ward_node::output::{AttemptOutputStore, RESULT_FILE, output_dir};
use ward_node_client::{
    Applied, AttemptOutcome, AttemptRequest, CancelToken, Client, Driver, EnvelopeInput,
    OperationIds, Resulted, RunConfig, Timeouts, UnixTransport,
};
use ward_node_protocol::{
    AdmissionEnvelopeJson, AttemptOutput, CapabilityManifestBytes, OperationId, OutputCapabilities,
    OutputFileSkip, OutputFileStatus, TaskBinding, TaskExecutionOutcome,
    TaskLifecycleRejectionReason, TaskLifecycleState,
};

/// One acceptance case: the test of that name and the criterion it passes on.
struct Case {
    name: &'static str,
    criterion: &'static str,
}

/// The result-return acceptance cases, in the order `docs/node-acceptance.md` lists them.
const CASES: [Case; 5] = [
    Case {
        name: "output_return_delivers_bounded_stdio_and_files_with_matching_digests",
        criterion: "a workload admitted with an output grant on a node started with --output-return prints to both streams and writes files; the report carries exactly what it printed with dropped 0, each declared file's content and BLAKE3 digest equal to the file in the workspace on the host, a file past files_bytes digest-only with its true size, a missing path and a planted symlink skipped unread; the sealed log records NodeAttemptOutputCollected with the same digests right before NodeAttemptEnded; the result is stored mode 0600 in a 0700 directory beside the workspace and nothing is written into the workspace",
    },
    Case {
        name: "output_return_marks_truncation_and_keeps_digests_right_past_the_budgets",
        criterion: "a workload writing past stdio_bytes on both streams and a file past files_bytes gets exactly the first stdio_bytes of each stream, truncated true and the exact dropped count, the file digest-only with its true size and digest, the evidence record agreeing on every count and digest, and result answering the same bytes after seal",
    },
    Case {
        name: "output_return_refuses_escaping_paths_at_admit_and_follows_nothing",
        criterion: "a signed envelope whose manifest declares ../x or an absolute path is refused authority_denied at admit with no task directory created; a workload that plants a symlink to a host secret at one declared path and a symlink to a directory on another is reported not_a_regular_file for both, the host secret appears nowhere in the result or the log, and the attempt still completes",
    },
    Case {
        name: "output_return_is_advertised_and_honoured_only_when_enabled",
        criterion: "a node started without --output-return carries no output section in its 1.3 capability document, refuses an output grant unsupported_grant with nothing materialised and answers result unsupported_operation; the same node started with it reports output.stdio and output.files true, and an attempt it admitted without the grant has no result (resource_unavailable) while its receipt is unchanged",
    },
    Case {
        name: "output_return_survives_a_node_restart_and_seal",
        criterion: "after SIGKILL of the node and a restart with the flag, result answers the sealed attempt's output byte for byte as before the kill, the evidence log and HEAD still verify with the NodeAttemptOutputCollected record in place, and a client replay of the run with the same operation ids reports the same output without running anything",
    },
];

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
        ward_events::TaskId::from_u128(task),
        ward_events::ExecutionAttemptId::from_u128(attempt),
        ward_events::LeaseId::from_u128(lease),
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

fn output_manifest(stdio_bytes: u64, files: &[&str], files_bytes: u64) -> CapabilityManifestBytes {
    CapabilityManifestBytes::new(output_manifest_bytes(stdio_bytes, files, files_bytes)).unwrap()
}

fn output_manifest_bytes(stdio_bytes: u64, files: &[&str], files_bytes: u64) -> Vec<u8> {
    let list = files
        .iter()
        .map(|path| format!("\"{path}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"network":"offline","output":{{"stdio_bytes":{stdio_bytes},"files":[{list}],"files_bytes":{files_bytes}}}}}"#
    )
    .into_bytes()
}

fn workload(
    binding: TaskBinding,
    snapshot: SnapshotId,
    script: &str,
    manifest: Option<CapabilityManifestBytes>,
) -> EnvelopeInput {
    let mut input = envelope_input(binding, snapshot, &["sh", "-c", script]);
    input.workload.wall_clock_budget_ms = 120_000;
    input.workload.capability_manifest = manifest;
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

fn resulted(
    client: &Client<UnixTransport>,
    binding: TaskBinding,
) -> (TaskLifecycleState, AttemptOutput) {
    match client.result(binding).unwrap() {
        Resulted::Result { state, output } => (state, output),
        Resulted::Rejected { reason } => panic!("result refused: {reason:?}"),
    }
}

fn refused_result(
    client: &Client<UnixTransport>,
    binding: TaskBinding,
) -> TaskLifecycleRejectionReason {
    match client.result(binding).unwrap() {
        Resulted::Rejected { reason } => reason,
        Resulted::Result { state, .. } => panic!("result served in {state:?}"),
    }
}

fn verified(node: &Node, binding: TaskBinding) -> VerifiedEvidence {
    let dir = evidence::evidence_dir(&node.task_root, binding);
    let log = evidence::verify(&dir, binding).unwrap();
    for record in log.records() {
        assert_eq!(record.origin, Origin::Node, "{record:?}");
    }
    log
}

fn file_status<'a>(output: &'a AttemptOutput, path: &str) -> &'a OutputFileStatus {
    &output
        .files()
        .iter()
        .find(|file| file.path.as_str() == path)
        .unwrap_or_else(|| panic!("no file {path} in {output:?}"))
        .status
}

fn host_digest(path: &Path) -> (u64, Blake3Hash) {
    let bytes = std::fs::read(path).unwrap();
    (bytes.len() as u64, Blake3Hash::hash(&bytes))
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// The `NodeAttemptOutputCollected` record of `log`, which must sit right before the
/// `NodeAttemptEnded` record, and agree with `output` on every count, digest and status.
fn assert_collected_record(log: &VerifiedEvidence, output: &AttemptOutput) {
    let position = log
        .records()
        .iter()
        .position(|record| matches!(record.event, WardEvent::NodeAttemptOutputCollected { .. }))
        .expect("an output record");
    assert!(matches!(
        log.records()[position + 1].event,
        WardEvent::NodeAttemptEnded {
            state: NodeAttemptState::Exited,
            ..
        }
    ));
    let WardEvent::NodeAttemptOutputCollected {
        stdout,
        stderr,
        files,
    } = &log.records()[position].event
    else {
        unreachable!()
    };
    assert_eq!(stdout.returned, output.stdout().content().len() as u64);
    assert_eq!(stdout.dropped, output.stdout().dropped());
    assert_eq!(stderr.returned, output.stderr().content().len() as u64);
    assert_eq!(stderr.dropped, output.stderr().dropped());
    assert_eq!(files.len(), output.files().len());
    for (recorded, returned) in files.iter().zip(output.files()) {
        assert_eq!(
            recorded.path,
            SandboxPath::new(SandboxRoot::Work, returned.path.as_str()).unwrap()
        );
        match &returned.status {
            OutputFileStatus::Returned { size, digest, .. } => {
                assert_eq!(
                    (recorded.size, recorded.digest, recorded.status),
                    (*size, Some(*digest), NodeOutputFileStatus::Returned)
                );
            }
            OutputFileStatus::DigestOnly { size, digest } => {
                assert_eq!(
                    (recorded.size, recorded.digest, recorded.status),
                    (*size, Some(*digest), NodeOutputFileStatus::DigestOnly)
                );
            }
            OutputFileStatus::Skipped(skip) => {
                let status = match skip {
                    OutputFileSkip::Missing => NodeOutputFileStatus::Missing,
                    OutputFileSkip::NotARegularFile => NodeOutputFileStatus::NotARegularFile,
                    OutputFileSkip::TooLarge => NodeOutputFileStatus::TooLarge,
                };
                assert_eq!(
                    (recorded.size, recorded.digest, recorded.status),
                    (0, None, status)
                );
            }
        }
    }
}

struct Node {
    child: Child,
    socket: PathBuf,
    task_root: PathBuf,
}

impl Node {
    fn spawn(dir: &Path, output_return: bool) -> Self {
        let socket = dir.join("node.sock");
        let task_root = dir.join("tasks");
        let _ = std::fs::remove_file(&socket);
        let mut command = Command::new(ward_node_binary());
        command
            .arg("--socket")
            .arg(&socket)
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--node-id")
            .arg(NODE.to_string())
            .arg("--trusted-issuers")
            .arg(trust_store(dir))
            .arg("--task-root")
            .arg(&task_root)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if output_return {
            command.arg("--output-return");
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

#[test]
fn every_output_acceptance_case_is_documented() {
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
    assert!(runner.contains("--test acceptance_output"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn output_return_delivers_bounded_stdio_and_files_with_matching_digests() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let returned = binding(0x70, 0x71, 0x72);
    let script = "printf 'hello stdout\\n'; printf 'hello stderr\\n' >&2; \
                  mkdir -p out && printf '{\"ok\":true}' > out/report.json && \
                  head -c 3000 /dev/zero | tr '\\0' b > big.bin && \
                  ln -s /etc/hostname planted && cat src/input.txt > copy.txt";
    let request = signed(
        &node,
        &workload(
            returned,
            snapshot,
            script,
            Some(output_manifest(
                4096,
                &[
                    "out/report.json",
                    "copy.txt",
                    "big.bin",
                    "missing.txt",
                    "planted",
                ],
                2048,
            )),
        ),
    );
    let mut events = Vec::new();
    let report = Driver::new(&client, config()).run_attempt(
        &request,
        &OperationIds::starting_at(1).unwrap(),
        &CancelToken::default(),
        &mut |event| events.push(event.clone()),
    );
    assert_eq!(
        (report.outcome, report.receipt),
        (
            AttemptOutcome::Completed,
            Some(TaskExecutionOutcome::Completed)
        ),
        "{report:?}"
    );
    assert!(report.sealed);
    let output = report.output.as_ref().expect("an output in the report");
    assert_eq!(output.stdout().content(), b"hello stdout\n");
    assert_eq!(output.stdout().dropped(), 0);
    assert_eq!(output.stderr().content(), b"hello stderr\n");
    assert_eq!(output.stderr().dropped(), 0);
    assert!(
        !output.truncated()
            || matches!(
                file_status(output, "big.bin"),
                OutputFileStatus::DigestOnly { .. }
            )
    );

    let workspace = node.workspace(returned);
    for path in ["out/report.json", "copy.txt"] {
        let (size, digest) = host_digest(&workspace.join(path));
        let OutputFileStatus::Returned {
            size: returned_size,
            digest: returned_digest,
            content,
        } = file_status(output, path)
        else {
            panic!("{path} not returned: {output:?}");
        };
        assert_eq!((*returned_size, *returned_digest), (size, digest), "{path}");
        assert_eq!(
            content,
            &std::fs::read(workspace.join(path)).unwrap(),
            "{path}"
        );
    }
    assert_eq!(
        std::str::from_utf8(match file_status(output, "copy.txt") {
            OutputFileStatus::Returned { content, .. } => content,
            other => panic!("{other:?}"),
        })
        .unwrap(),
        "from the snapshot\n"
    );
    let (size, digest) = host_digest(&workspace.join("big.bin"));
    assert_eq!((size, digest), (3000, Blake3Hash::hash(&vec![b'b'; 3000])));
    assert_eq!(
        file_status(output, "big.bin"),
        &OutputFileStatus::DigestOnly { size, digest },
        "past files_bytes: digest only"
    );
    assert_eq!(
        file_status(output, "missing.txt"),
        &OutputFileStatus::Skipped(OutputFileSkip::Missing)
    );
    assert_eq!(
        file_status(output, "planted"),
        &OutputFileStatus::Skipped(OutputFileSkip::NotARegularFile)
    );
    assert!(events.iter().any(|event| matches!(
        event,
        ward_node_client::AttemptEvent::Output { files: 5, .. }
    )));

    let log = verified(&node, returned);
    assert!(log.is_sealed());
    assert_collected_record(&log, output);
    let store_dir = output_dir(&node.task_root, returned);
    assert_eq!(mode(&store_dir), 0o700);
    assert_eq!(mode(&store_dir.join(RESULT_FILE)), 0o600);
    assert_eq!(
        AttemptOutputStore::new(&node.task_root, returned)
            .read()
            .unwrap()
            .as_ref(),
        Some(output)
    );
    assert!(!workspace.join(RESULT_FILE).exists());
    assert!(!workspace.join("result").exists());
    let (state, again) = resulted(&client, returned);
    assert_eq!(state, TaskLifecycleState::Sealed);
    assert_eq!(&again, output);
    pass(
        "output_return_delivers_bounded_stdio_and_files_with_matching_digests",
        started,
    );
}

#[test]
fn output_return_marks_truncation_and_keeps_digests_right_past_the_budgets() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let truncated = binding(0x73, 0x74, 0x75);
    let script = "head -c 10000 /dev/zero | tr '\\0' a; \
                  head -c 5000 /dev/zero | tr '\\0' e >&2; \
                  head -c 4000 /dev/zero | tr '\\0' f > large.bin";
    let request = signed(
        &node,
        &workload(
            truncated,
            snapshot,
            script,
            Some(output_manifest(1000, &["large.bin"], 100)),
        ),
    );
    let report = Driver::new(&client, config()).run_attempt(
        &request,
        &OperationIds::starting_at(1).unwrap(),
        &CancelToken::default(),
        &mut |_| {},
    );
    assert_eq!(report.outcome, AttemptOutcome::Completed, "{report:?}");
    let output = report.output.as_ref().unwrap();
    assert_eq!(output.stdout().content(), &vec![b'a'; 1000]);
    assert_eq!(output.stdout().dropped(), 9000);
    assert!(output.stdout().truncated());
    assert_eq!(output.stderr().content(), &vec![b'e'; 1000]);
    assert_eq!(output.stderr().dropped(), 4000);
    assert!(output.stderr().truncated());
    let (size, digest) = host_digest(&node.workspace(truncated).join("large.bin"));
    assert_eq!(size, 4000);
    assert_eq!(
        file_status(output, "large.bin"),
        &OutputFileStatus::DigestOnly { size, digest }
    );
    assert!(output.truncated());
    let log = verified(&node, truncated);
    assert_collected_record(&log, output);
    let (state, after_seal) = resulted(&client, truncated);
    assert_eq!(state, TaskLifecycleState::Sealed);
    assert_eq!(&after_seal, output);
    pass(
        "output_return_marks_truncation_and_keeps_digests_right_past_the_budgets",
        started,
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn output_return_refuses_escaping_paths_at_admit_and_follows_nothing() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let secret = dir.path().join("host-secret");
    std::fs::write(&secret, b"the host secret\n").unwrap();
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);

    // An escaping path never passes the manifest grammar: the client refuses to build it,
    // and a hand-made envelope carrying it is refused by the node at admit.
    for escaping in ["../x", "/etc/passwd"] {
        assert!(
            CapabilityManifestBytes::new(output_manifest_bytes(16, &[escaping], 16)).is_err(),
            "{escaping}"
        );
    }
    let mut next = 0x76_u128;
    for escaping in ["../x", "/etc/passwd"] {
        let refused = binding(next, next + 1, next + 2);
        next += 3;
        let valid = workload(
            refused,
            snapshot,
            "true",
            Some(output_manifest(16, &["x"], 16)),
        )
        .build()
        .unwrap();
        let json = AdmissionEnvelopeJson::encode(&valid).unwrap();
        let hex = |bytes: &[u8]| {
            use std::fmt::Write as _;
            bytes.iter().fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
        };
        let valid_bytes = output_manifest_bytes(16, &["x"], 16);
        let escaping_bytes = output_manifest_bytes(16, &[escaping], 16);
        let forged = std::str::from_utf8(json.as_bytes())
            .unwrap()
            .replace(&hex(&valid_bytes), &hex(&escaping_bytes))
            .replace(
                &Blake3Hash::hash(&valid_bytes).to_hex(),
                &Blake3Hash::hash(&escaping_bytes).to_hex(),
            );
        assert_ne!(forged.as_bytes(), json.as_bytes());
        let envelope = issuer().sign_json(AdmissionEnvelopeJson::new(forged).unwrap());
        assert_eq!(
            accepted(client.create(refused, op(1))),
            TaskLifecycleState::Created
        );
        assert_eq!(
            rejected(client.admit(refused, op(2), &envelope)),
            TaskLifecycleRejectionReason::AuthorityDenied,
            "{escaping}"
        );
        assert!(!node.task_root.join(refused.task().to_string()).exists());
    }

    // A planted symlink is reported, never followed.
    let planted = binding(0x80, 0x81, 0x82);
    let script = format!(
        "ln -s {} planted && ln -s /tmp dirlink && printf ok > fine.txt",
        secret.display()
    );
    let request = signed(
        &node,
        &workload(
            planted,
            snapshot,
            &script,
            Some(output_manifest(
                64,
                &["planted", "dirlink/x", "fine.txt"],
                1024,
            )),
        ),
    );
    let report = Driver::new(&client, config()).run_attempt(
        &request,
        &OperationIds::starting_at(1).unwrap(),
        &CancelToken::default(),
        &mut |_| {},
    );
    assert_eq!(report.outcome, AttemptOutcome::Completed, "{report:?}");
    let output = report.output.as_ref().unwrap();
    assert!(
        std::fs::symlink_metadata(node.workspace(planted).join("planted"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        file_status(output, "planted"),
        &OutputFileStatus::Skipped(OutputFileSkip::NotARegularFile)
    );
    assert_eq!(
        file_status(output, "dirlink/x"),
        &OutputFileStatus::Skipped(OutputFileSkip::NotARegularFile)
    );
    assert!(matches!(
        file_status(output, "fine.txt"),
        OutputFileStatus::Returned { content, .. } if content == b"ok"
    ));
    let json = serde_json::to_string(output).unwrap();
    assert!(!json.contains("host secret"), "{json}");
    let log_bytes = std::fs::read(
        evidence::evidence_dir(&node.task_root, planted).join(evidence::EVIDENCE_LOG),
    )
    .unwrap();
    assert!(
        !log_bytes
            .windows(b"host secret".len())
            .any(|window| window == b"host secret")
    );
    assert_collected_record(&verified(&node, planted), output);
    pass(
        "output_return_refuses_escaping_paths_at_admit_and_follows_nothing",
        started,
    );
}

#[test]
fn output_return_is_advertised_and_honoured_only_when_enabled() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());

    let plain = Node::spawn(dir.path(), false);
    let client = connect(&plain.socket);
    let capabilities = client.capabilities().unwrap();
    assert_eq!(capabilities.output(), OutputCapabilities::NONE);
    assert!(capabilities.lifecycle().start);
    let refused = binding(0x83, 0x84, 0x85);
    let request = signed(
        &plain,
        &workload(
            refused,
            snapshot,
            "true",
            Some(output_manifest(16, &["x"], 16)),
        ),
    );
    assert_eq!(
        accepted(client.create(refused, op(1))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        rejected(client.admit(refused, op(2), &request.envelope)),
        TaskLifecycleRejectionReason::UnsupportedGrant
    );
    assert!(!plain.task_root.join(refused.task().to_string()).exists());
    assert_eq!(
        refused_result(&client, refused),
        TaskLifecycleRejectionReason::UnsupportedOperation
    );
    drop(client);
    plain.kill();

    let returning = Node::spawn(dir.path(), true);
    let client = connect(&returning.socket);
    let capabilities = client.capabilities().unwrap();
    assert_eq!(
        capabilities.output(),
        OutputCapabilities {
            stdio: true,
            files: true,
        }
    );
    assert!(capabilities.network().offline && !capabilities.network().proxy_allowlist);
    let ungranted = binding(0x86, 0x87, 0x88);
    let report = Driver::new(&client, config()).run_attempt(
        &signed(
            &returning,
            &workload(ungranted, snapshot, "echo quiet", None),
        ),
        &OperationIds::starting_at(1).unwrap(),
        &CancelToken::default(),
        &mut |_| {},
    );
    assert_eq!(report.outcome, AttemptOutcome::Completed, "{report:?}");
    assert_eq!(report.output, None);
    assert_eq!(
        refused_result(&client, ungranted),
        TaskLifecycleRejectionReason::ResourceUnavailable
    );
    assert!(!output_dir(&returning.task_root, ungranted).exists());
    pass(
        "output_return_is_advertised_and_honoured_only_when_enabled",
        started,
    );
}

#[test]
fn output_return_survives_a_node_restart_and_seal() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let durable = binding(0x89, 0x8a, 0x8b);
    let request = signed(
        &node,
        &workload(
            durable,
            snapshot,
            "printf durable; printf 'noted\\n' >&2; printf kept > kept.txt",
            Some(output_manifest(64, &["kept.txt"], 64)),
        ),
    );
    let ids = OperationIds::starting_at(1).unwrap();
    let first = Driver::new(&client, config()).run_attempt(
        &request,
        &ids,
        &CancelToken::default(),
        &mut |_| {},
    );
    assert_eq!(first.outcome, AttemptOutcome::Completed, "{first:?}");
    assert!(first.sealed);
    let output = first.output.clone().expect("an output");
    assert_eq!(output.stdout().content(), b"durable");
    let head_before = first.evidence_head.unwrap();
    drop(client);
    node.kill();

    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let (state, after) = resulted(&client, durable);
    assert_eq!(state, TaskLifecycleState::Sealed);
    assert_eq!(after, output, "the result outlives the node");
    let log = verified(&node, durable);
    assert!(log.is_sealed());
    assert_eq!(log.head().hash, head_before);
    assert_collected_record(&log, &output);

    let replay = Driver::new(&client, config()).run_attempt(
        &request,
        &ids,
        &CancelToken::default(),
        &mut |_| {},
    );
    assert_eq!(replay.outcome, AttemptOutcome::Completed, "{replay:?}");
    assert_eq!(replay.output, Some(output));
    assert_eq!(replay.evidence_head, Some(head_before));
    assert!(
        replay
            .operations
            .iter()
            .all(|operation| !matches!(operation.verb, ward_node_client::Verb::Start)),
        "a replay of a sealed run starts nothing: {replay:?}"
    );
    pass("output_return_survives_a_node_restart_and_seal", started);
}
