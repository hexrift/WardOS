//! Cross-system acceptance of `ward-node` capacity, admission control and resource
//! accounting (#260, the first single-node slice; node-integration.md §5, §7.5 and §8.2): a
//! real node started with `--max-running`, and with `--cgroup-root` where the host
//! delegates a cgroup v2 directory to the test, driven through the real transport by
//! `ward-node-client`, runs real sandboxes concurrently. The cases prove that at least 25
//! sandboxes run at once under CPU pressure while the node answers within a bound, that a
//! `start` past the running bound or below a headroom floor is refused
//! `capacity_exhausted` with nothing materialised and the bound and count are visible, that
//! a resource limit is never accepted on a node that cannot enforce it, and that where the
//! host provides the controllers a workload is held at its pids, memory and CPU limits and
//! what every attempt used is recorded in its task record and its evidence log.
//!
//! One `#[test]` per case; each case's pass criterion is stated in [`CASES`] and, word for
//! word, in `docs/node-acceptance.md`, and `scripts/acceptance/node.sh` runs these cases
//! beside the others. The cases need a working bubblewrap and skip without one, except
//! under `WARD_REQUIRE_ISOLATION=1`. The cgroup case also needs a cgroup v2 directory this
//! process can create a child in (`WARD_NODE_CGROUP_ROOT`, or the host's cgroup2 mount when
//! running as root): without one it prints a SKIP verdict and returns, and it fails instead
//! only under `WARD_REQUIRE_CGROUP=1`, which a host that delegates a cgroup with the `pids`
//! or `memory` controller sets. CI's runner delegates none, so there it skips, loudly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use common::{
    NODE, envelope_input, imported, isolation, issuer, marker, private_dir, processes_with,
    trust_store, wait_until_gone, ward_node_binary,
};
use ward_events::{NodeResourceUsage, Origin, SnapshotId, WardEvent};
use ward_node::evidence::{self, VerifiedEvidence};
use ward_node_client::{Applied, AttemptRequest, Client, Inspection, Timeouts, UnixTransport};
use ward_node_protocol::{
    CapabilityManifest, CapabilityManifestBytes, NetworkGrant, OperationId, ResourceGrant,
    TaskBinding, TaskExecutionOutcome, TaskLifecycleRejectionReason, TaskLifecycleState,
};

/// One acceptance case: the test of that name and the criterion it passes on.
struct Case {
    name: &'static str,
    criterion: &'static str,
}

/// The capacity acceptance cases, in the order `docs/node-acceptance.md` lists them.
const CASES: [Case; 4] = [
    Case {
        name: "capacity_runs_twenty_five_concurrent_sandboxes_within_the_running_bound",
        criterion: "a node started with --max-running 25 runs 25 CPU-burning sandboxes at once, every one inspected running with its process tree present, and reports scheduling.max_running 25 and running 25; while all 25 burn, every inspect and capability request is answered within 2 s; a 26th start is refused capacity_exhausted with the task still ready and no workspace, and the same start is accepted running once one attempt is stopped; every attempt then stops, seals with a verifying log and leaves no process, and running reads 0",
    },
    Case {
        name: "capacity_refuses_a_start_below_the_memory_or_disk_floor",
        criterion: "a node whose --memory-floor or --disk-floor is above what the host has available refuses start capacity_exhausted with the task still ready, nothing materialised and no evidence of a launch, and reports the floor above the available bytes in its scheduling section",
    },
    Case {
        name: "capacity_resource_limits_are_refused_without_a_cgroup_root",
        criterion: "a node started without --cgroup-root carries no resources section in its 1.3 capability document and refuses a manifest with a resources grant unsupported_grant at admit with nothing materialised, while the same node admits and runs an offline manifest",
    },
    Case {
        name: "capacity_cgroup_limits_hold_and_usage_is_recorded",
        criterion: "on a node started with --cgroup-root every attempt's sealed log records NodeAttemptResourceUsage with its CPU time right before NodeAttemptEnded and its task record carries the same usage; with the pids controller a workload forking past pids 8 is held at it (peak at most 8, forks refused counted); with the memory controller a workload allocating past memory_bytes is killed by the limit (outcome failed, oom kills counted, peak at most the limit); with the cpu controller a busy loop limited to 100 cpu_millis uses at most 0.3 s of CPU in 2 s; a limit the node has no controller for is refused unsupported_grant",
    },
];

/// The cases share the host's CPUs; one runs at a time so none measures another's load.
static SERIAL: Mutex<()> = Mutex::new(());

/// How long one `inspect` or capability request may take while the node is under load.
const RESPONSIVE: Duration = Duration::from_secs(2);

const CONCURRENT: u128 = 25;

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

fn skip(name: &str, why: &str) {
    assert!(
        std::env::var_os("WARD_REQUIRE_CGROUP").is_none(),
        "WARD_REQUIRE_CGROUP is set but {name} cannot run: {why}"
    );
    eprintln!("acceptance {name}: SKIP -- {why}");
}

fn op(value: u64) -> OperationId {
    OperationId::new(value).unwrap()
}

fn binding(n: u128) -> TaskBinding {
    TaskBinding::new(
        ward_events::TaskId::from_u128(0x1000 + n),
        ward_events::ExecutionAttemptId::from_u128(0x2000 + n),
        ward_events::LeaseId::from_u128(0x3000 + n),
    )
}

fn connect(socket: &Path) -> Client<UnixTransport> {
    Client::connect(UnixTransport::new(socket, Timeouts::default())).unwrap()
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

fn inspected(client: &Client<UnixTransport>, binding: TaskBinding) -> Inspection {
    client.inspect(binding).unwrap()
}

fn state_of(client: &Client<UnixTransport>, binding: TaskBinding) -> TaskLifecycleState {
    match inspected(client, binding) {
        Inspection::Inspected { state, .. } => state,
        Inspection::Rejected { reason } => panic!("inspect refused: {reason:?}"),
    }
}

fn manifest(resources: Option<ResourceGrant>) -> CapabilityManifestBytes {
    let manifest = CapabilityManifest::new(NetworkGrant::Offline);
    CapabilityManifestBytes::encode(&match resources {
        Some(grant) => manifest.with_resources(grant),
        None => manifest,
    })
    .unwrap()
}

/// Create and admit `binding` to run `argv` for at most `budget_ms`, with `resources`.
fn admitted(
    client: &Client<UnixTransport>,
    node: &Node,
    binding: TaskBinding,
    snapshot: SnapshotId,
    argv: &[&str],
    budget_ms: u64,
    resources: Option<ResourceGrant>,
) -> Applied {
    assert_eq!(
        accepted(client.create(binding, op(1))),
        TaskLifecycleState::Created
    );
    let mut input = envelope_input(binding, snapshot, argv);
    input.workload.wall_clock_budget_ms = budget_ms;
    input.workload.capability_manifest = Some(manifest(resources));
    let request = AttemptRequest::sign(
        &input.build().unwrap(),
        &issuer(),
        Some(node.task_root.clone()),
    )
    .unwrap();
    client.admit(binding, op(2), &request.envelope).unwrap()
}

fn verified(node: &Node, binding: TaskBinding) -> VerifiedEvidence {
    let log = evidence::verify(&evidence::evidence_dir(&node.task_root, binding), binding).unwrap();
    for record in log.records() {
        assert_eq!(record.origin, Origin::Node, "{record:?}");
    }
    log
}

/// The usage record of a sealed log, which must sit right before `NodeAttemptEnded`.
fn recorded_usage(log: &VerifiedEvidence) -> NodeResourceUsage {
    let records = log.records();
    let at = records
        .iter()
        .position(|record| matches!(record.event, WardEvent::NodeAttemptResourceUsage { .. }))
        .expect("the log records the attempt's usage");
    assert!(
        matches!(records[at + 1].event, WardEvent::NodeAttemptEnded { .. }),
        "the usage record sits right before the end record"
    );
    match records[at].event {
        WardEvent::NodeAttemptResourceUsage { usage } => usage,
        _ => unreachable!(),
    }
}

/// The usage the task's durable record carries, read as the node's uid reads it.
fn record_usage(node: &Node, binding: TaskBinding) -> Option<NodeResourceUsage> {
    let record = std::fs::read_to_string(
        node.state_dir
            .join("tasks")
            .join(format!("{}.json", binding.task())),
    )
    .unwrap();
    let record: serde_json::Value = serde_json::from_str(&record).unwrap();
    serde_json::from_value(record.get("usage")?.clone()).ok()
}

fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct Node {
    child: Child,
    socket: PathBuf,
    state_dir: PathBuf,
    task_root: PathBuf,
}

impl Node {
    fn spawn(dir: &Path, extra: &[&str]) -> Self {
        let socket = dir.join("node.sock");
        let task_root = dir.join("tasks");
        let state_dir = dir.join("state");
        let _ = std::fs::remove_file(&socket);
        let mut child = Command::new(ward_node_binary())
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
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
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

/// A fresh child of a cgroup v2 directory this process may write, removed on drop:
/// `WARD_NODE_CGROUP_ROOT`, or the host's cgroup2 mount when this process may create a
/// child there (root). `Err` with the reason when there is none.
struct DelegatedCgroup(PathBuf);

impl DelegatedCgroup {
    fn create(test: &str) -> Result<Self, String> {
        let parent = std::env::var_os("WARD_NODE_CGROUP_ROOT")
            .map(PathBuf::from)
            .or_else(cgroup2_mount)
            .ok_or("this host has no cgroup2 mount and WARD_NODE_CGROUP_ROOT is unset")?;
        let dir = parent.join(format!("ward-acceptance-{}-{test}", std::process::id()));
        std::fs::create_dir(&dir)
            .map(|()| Self(dir))
            .map_err(|error| {
                format!(
                    "no cgroup v2 directory delegated to this test ({}: {error}); set WARD_NODE_CGROUP_ROOT to one",
                    parent.display()
                )
            })
    }
}

impl Drop for DelegatedCgroup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn cgroup2_mount() -> Option<PathBuf> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    mounts.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let (_, path, kind) = (fields.next()?, fields.next()?, fields.next()?);
        (kind == "cgroup2").then(|| PathBuf::from(path))
    })
}

#[test]
fn every_capacity_acceptance_case_is_documented() {
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
    assert!(runner.contains("--test acceptance_capacity"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn capacity_runs_twenty_five_concurrent_sandboxes_within_the_running_bound() {
    if !isolation() {
        return;
    }
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), &["--max-running", "25"]);
    let client = connect(&node.socket);
    let marker = marker("ward-acceptance-cap");
    let burn = ["sh", "-c", "while :; do :; done", marker.as_str()];
    for n in 0..=CONCURRENT {
        assert!(matches!(
            admitted(&client, &node, binding(n), snapshot, &burn, 120_000, None),
            Applied::Accepted {
                state: TaskLifecycleState::Ready
            }
        ));
    }
    let scheduling = client.capabilities().unwrap().scheduling().unwrap();
    assert_eq!((scheduling.max_running, scheduling.running), (25, 0));

    for n in 0..CONCURRENT {
        assert_eq!(
            accepted(client.start(binding(n), op(3))),
            TaskLifecycleState::Running,
            "attempt {n}"
        );
    }
    eventually("not every sandbox's tree came up", || {
        processes_with(&marker) >= 3 * 25
    });

    let mut slowest = Duration::ZERO;
    let mut answered = 0;
    let measured = Instant::now();
    while measured.elapsed() < Duration::from_secs(3) {
        for n in 0..CONCURRENT {
            let asked = Instant::now();
            assert_eq!(state_of(&client, binding(n)), TaskLifecycleState::Running);
            slowest = slowest.max(asked.elapsed());
            answered += 1;
        }
        let asked = Instant::now();
        let scheduling = client.capabilities().unwrap().scheduling().unwrap();
        slowest = slowest.max(asked.elapsed());
        answered += 1;
        assert_eq!((scheduling.max_running, scheduling.running), (25, 25));
    }
    eprintln!(
        "capacity: {answered} requests answered while 25 sandboxes burned CPU on {} CPUs, the slowest in {} ms",
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
        slowest.as_millis()
    );
    assert!(slowest < RESPONSIVE, "the node took {slowest:?} to answer");
    assert!(
        processes_with(&marker) >= 3 * 25,
        "a sandbox's tree is gone"
    );

    let extra = binding(CONCURRENT);
    assert_eq!(
        rejected(client.start(extra, op(3))),
        TaskLifecycleRejectionReason::CapacityExhausted
    );
    assert_eq!(state_of(&client, extra), TaskLifecycleState::Ready);
    assert!(!node.workspace(extra).exists(), "nothing materialised");

    assert_eq!(
        accepted(client.stop(binding(0), op(4))),
        TaskLifecycleState::Stopped
    );
    assert_eq!(
        client.capabilities().unwrap().scheduling().unwrap().running,
        24
    );
    assert_eq!(
        accepted(client.start(extra, op(3))),
        TaskLifecycleState::Running,
        "the refused start, sent again with its operation id once a slot is free"
    );

    for n in 1..=CONCURRENT {
        assert_eq!(
            accepted(client.stop(binding(n), op(4))),
            TaskLifecycleState::Stopped,
            "attempt {n}"
        );
    }
    wait_until_gone(&marker);
    for n in 0..=CONCURRENT {
        assert_eq!(
            accepted(client.seal(binding(n), op(5))),
            TaskLifecycleState::Sealed
        );
        assert!(verified(&node, binding(n)).is_sealed());
        assert!(matches!(
            inspected(&client, binding(n)),
            Inspection::Inspected {
                state: TaskLifecycleState::Sealed,
                outcome: Some(TaskExecutionOutcome::Failed)
            }
        ));
    }
    assert_eq!(
        client.capabilities().unwrap().scheduling().unwrap().running,
        0
    );
    pass(
        "capacity_runs_twenty_five_concurrent_sandboxes_within_the_running_bound",
        started,
    );
}

#[test]
fn capacity_refuses_a_start_below_the_memory_or_disk_floor() {
    if !isolation() {
        return;
    }
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let started = Instant::now();
    let floor = (u64::MAX / 4).to_string();
    for (flag, which) in [("--memory-floor", "memory"), ("--disk-floor", "disk")] {
        let dir = private_dir();
        let snapshot = imported(dir.path());
        let node = Node::spawn(dir.path(), &["--max-running", "4", flag, &floor]);
        let client = connect(&node.socket);
        let scheduling = client.capabilities().unwrap().scheduling().unwrap();
        let (set, available) = match which {
            "memory" => (
                scheduling.memory_floor_bytes,
                scheduling.memory_available_bytes,
            ),
            _ => (scheduling.disk_floor_bytes, scheduling.disk_available_bytes),
        };
        assert_eq!(set, u64::MAX / 4, "{which}");
        assert!(available > 0 && available < set, "{which}: {scheduling:?}");
        let floored = binding(0x40);
        admitted(&client, &node, floored, snapshot, &["true"], 60_000, None);
        assert_eq!(
            rejected(client.start(floored, op(3))),
            TaskLifecycleRejectionReason::CapacityExhausted,
            "{which}"
        );
        assert_eq!(state_of(&client, floored), TaskLifecycleState::Ready);
        assert!(!node.workspace(floored).exists(), "{which}");
        assert!(
            verified(&node, floored)
                .records()
                .iter()
                .all(|record| !matches!(record.event, WardEvent::NodeAttemptLaunched { .. })),
            "{which}"
        );
    }
    pass(
        "capacity_refuses_a_start_below_the_memory_or_disk_floor",
        started,
    );
}

#[test]
fn capacity_resource_limits_are_refused_without_a_cgroup_root() {
    if !isolation() {
        return;
    }
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), &[]);
    let client = connect(&node.socket);
    let capabilities = client.capabilities().unwrap();
    assert_eq!(capabilities.resources(), None);
    assert_eq!(capabilities.scheduling(), None);
    let limited = binding(0x50);
    assert!(matches!(
        admitted(
            &client,
            &node,
            limited,
            snapshot,
            &["true"],
            60_000,
            Some(ResourceGrant::new(None, None, Some(64)).unwrap()),
        ),
        Applied::Rejected {
            reason: TaskLifecycleRejectionReason::UnsupportedGrant
        }
    ));
    assert_eq!(state_of(&client, limited), TaskLifecycleState::Created);
    assert!(!node.task_root.join(limited.task().to_string()).exists());

    let plain = binding(0x51);
    admitted(&client, &node, plain, snapshot, &["true"], 60_000, None);
    accepted(client.start(plain, op(3)));
    eventually("the offline attempt never ended", || {
        state_of(&client, plain) == TaskLifecycleState::Exited
    });
    assert_eq!(
        accepted(client.seal(plain, op(5))),
        TaskLifecycleState::Sealed
    );
    assert!(
        verified(&node, plain)
            .records()
            .iter()
            .all(|record| !matches!(record.event, WardEvent::NodeAttemptResourceUsage { .. })),
        "a node without a cgroup root measures nothing and claims nothing"
    );
    pass(
        "capacity_resource_limits_are_refused_without_a_cgroup_root",
        started,
    );
}

/// Run `argv` to its end under `resources` and seal it; its receipt outcome, the usage its
/// log records and the usage its task record carries.
fn run_limited(
    client: &Client<UnixTransport>,
    node: &Node,
    binding: TaskBinding,
    snapshot: SnapshotId,
    argv: &[&str],
    resources: Option<ResourceGrant>,
) -> (TaskExecutionOutcome, NodeResourceUsage) {
    assert!(matches!(
        admitted(client, node, binding, snapshot, argv, 60_000, resources),
        Applied::Accepted {
            state: TaskLifecycleState::Ready
        }
    ));
    accepted(client.start(binding, op(3)));
    eventually("the limited attempt never ended", || {
        state_of(client, binding) == TaskLifecycleState::Exited
    });
    let Inspection::Inspected {
        outcome: Some(outcome),
        ..
    } = inspected(client, binding)
    else {
        panic!("no receipt")
    };
    assert_eq!(
        accepted(client.seal(binding, op(5))),
        TaskLifecycleState::Sealed
    );
    let usage = recorded_usage(&verified(node, binding));
    assert_eq!(record_usage(node, binding), Some(usage));
    (outcome, usage)
}

#[test]
#[allow(clippy::too_many_lines)]
fn capacity_cgroup_limits_hold_and_usage_is_recorded() {
    const NAME: &str = "capacity_cgroup_limits_hold_and_usage_is_recorded";
    if !isolation() {
        return;
    }
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let started = Instant::now();
    let cgroup = match DelegatedCgroup::create("limits") {
        Ok(cgroup) => cgroup,
        Err(why) => return skip(NAME, &why),
    };
    let dir = private_dir();
    let snapshot = imported(dir.path());
    let root = cgroup.0.to_string_lossy().into_owned();
    let node = Node::spawn(dir.path(), &["--cgroup-root", &root, "--max-running", "4"]);
    let client = connect(&node.socket);
    let enforces = client.capabilities().unwrap().resources().unwrap();
    eprintln!("capacity: the delegated cgroup enforces {enforces:?}");
    if std::env::var_os("WARD_REQUIRE_CGROUP").is_some() {
        assert!(
            enforces.pids || enforces.memory,
            "WARD_REQUIRE_CGROUP is set but the delegated cgroup has neither pids nor memory"
        );
    }

    let (outcome, usage) = run_limited(&client, &node, binding(0x60), snapshot, &["true"], None);
    assert_eq!(outcome, TaskExecutionOutcome::Completed);
    assert!(usage.cpu_usage_usec.is_some(), "{usage:?}");
    assert_eq!(
        (
            usage.cpu_millis_limit,
            usage.memory_limit_bytes,
            usage.pids_limit
        ),
        (None, None, None)
    );

    let mut held = Vec::new();
    if enforces.pids {
        let fork = "for i in $(seq 1 32); do sleep 1 & done 2>/dev/null; wait";
        let (_, usage) = run_limited(
            &client,
            &node,
            binding(0x61),
            snapshot,
            &["sh", "-c", fork],
            Some(ResourceGrant::new(None, None, Some(8)).unwrap()),
        );
        assert_eq!(usage.pids_limit, Some(8));
        assert!(usage.pids_peak.is_none_or(|peak| peak <= 8), "{usage:?}");
        assert!(
            usage.pids_max_events.is_some_and(|refused| refused > 0),
            "{usage:?}"
        );
        held.push("pids");
    }
    if enforces.memory {
        let limit = 32 * 1024 * 1024;
        let (outcome, usage) = run_limited(
            &client,
            &node,
            binding(0x62),
            snapshot,
            &["dd", "if=/dev/zero", "of=/dev/null", "bs=256M", "count=1"],
            Some(ResourceGrant::new(None, Some(limit), None).unwrap()),
        );
        assert_eq!(outcome, TaskExecutionOutcome::Failed);
        assert_eq!(usage.memory_limit_bytes, Some(limit));
        assert!(
            usage.memory_oom_kills.is_some_and(|kills| kills > 0),
            "{usage:?}"
        );
        assert!(
            usage.memory_peak_bytes.is_none_or(|peak| peak <= limit),
            "{usage:?}"
        );
        held.push("memory");
    }
    if enforces.cpu {
        let (_, usage) = run_limited(
            &client,
            &node,
            binding(0x63),
            snapshot,
            &["timeout", "2", "sh", "-c", "while :; do :; done"],
            Some(ResourceGrant::new(Some(100), None, None).unwrap()),
        );
        assert_eq!(usage.cpu_millis_limit, Some(100));
        assert!(
            usage.cpu_usage_usec.is_some_and(|usec| usec <= 300_000),
            "{usage:?}"
        );
        held.push("cpu");
    }
    let missing = [
        (!enforces.cpu).then(|| ResourceGrant::new(Some(100), None, None).unwrap()),
        (!enforces.memory).then(|| ResourceGrant::new(None, Some(1 << 26), None).unwrap()),
        (!enforces.pids).then(|| ResourceGrant::new(None, None, Some(8)).unwrap()),
    ];
    for (n, grant) in missing.into_iter().flatten().enumerate() {
        let refused = binding(0x70 + u128::try_from(n).unwrap());
        assert!(
            matches!(
                admitted(
                    &client,
                    &node,
                    refused,
                    snapshot,
                    &["true"],
                    60_000,
                    Some(grant)
                ),
                Applied::Rejected {
                    reason: TaskLifecycleRejectionReason::UnsupportedGrant
                }
            ),
            "{grant:?}"
        );
    }
    drop(client);
    drop(node);
    eprintln!("capacity: limits proven held by the kernel: {held:?}");
    if !(enforces.pids || enforces.memory) {
        return skip(
            NAME,
            "the delegated cgroup offers neither the pids nor the memory controller, so no limit could be proven held (accounting and refusals were checked)",
        );
    }
    pass(NAME, started);
}
