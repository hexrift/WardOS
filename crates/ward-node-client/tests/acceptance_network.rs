//! Cross-system acceptance of the `ward-node` network allowlist (#332, node-integration.md
//! §7.5 and §9, ADR-0014 on the node path): a real node started with
//! `--network-allowlist`, driven through the real transport by `ward-node-client`, runs a
//! real workload behind the attempt's own egress proxy. The cases prove that exactly the
//! manifest's hosts pass and are recorded, that a non-listed host, a private literal and
//! the metadata endpoint are refused and recorded, that raw TCP, UDP and DNS still have no
//! path out, that the proxy pauses, resumes and stops with the attempt, and that the
//! capability is advertised and honoured only when the operator enabled it. One `#[test]`
//! per case; each case's pass criterion is stated in [`CASES`] and, word for word, in
//! `docs/node-acceptance.md`, and `scripts/acceptance/node.sh` runs these cases beside
//! the main suite. The cases need a working bubblewrap and skip without one, except under
//! `WARD_REQUIRE_ISOLATION=1`; the allowed-host case also needs the host to resolve the
//! allowed name, and skips without that unless isolation is required.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{
    NODE, envelope_input, isolation, issuer, marker, private_dir, processes_with, trust_store,
    wait_until_gone, wait_until_sandboxed, ward_node_binary,
};
use ward_events::{
    DeniedDst, DenyReason, NodeAttemptEnd, NodeAttemptState, NodeIntervention, Origin, SnapshotId,
    WardEvent,
};
use ward_node::egress::{PROXY_SOCKET_FILE, egress_dir};
use ward_node::evidence::{self, VerifiedEvidence};
use ward_node_client::{
    Applied, AttemptOutcome, AttemptRequest, CancelToken, Client, Driver, EnvelopeInput,
    OperationIds, RunConfig, Timeouts, UnixTransport,
};
use ward_node_protocol::{
    CapabilityManifestBytes, OperationId, TaskBinding, TaskExecutionOutcome,
    TaskLifecycleRejectionReason, TaskLifecycleState,
};

/// One acceptance case: the test of that name and the criterion it passes on.
struct Case {
    name: &'static str,
    criterion: &'static str,
}

/// The network acceptance cases, in the order `docs/node-acceptance.md` lists them.
const CASES: [Case; 3] = [
    Case {
        name: "network_allowlist_lets_only_listed_hosts_out_through_the_proxy",
        criterion: "a workload admitted with network.custom reaches the allowlisted host through the proxy socket at /run/ward/proxy.sock named by WARD_PROXY_SOCKET, and is refused 403 for a non-listed host, a private literal, a loopback literal and the metadata endpoint by CONNECT and by forward; raw TCP, UDP and DNS have no path and the sandbox has only lo; the environment is exactly the contract's plus WARD_PROXY_SOCKET; the attempt completes and its sealed log records one NetworkRequested allow and five NetworkDenied with origin node and no ObservationsDropped",
    },
    Case {
        name: "network_allowlist_proxy_pauses_resumes_and_stops_with_the_attempt",
        criterion: "while the attempt is paused its proxy answers 503 paused by ward and records nothing, after resume it decides and records again, and after stop the proxy socket is gone, nothing accepts on it and no workload process is left; the sealed log shows the verdicts around the two interventions in order",
    },
    Case {
        name: "network_allowlist_is_advertised_and_honoured_only_when_enabled",
        criterion: "a node started without --network-allowlist reports network.proxy_allowlist false and refuses a network.custom manifest unsupported_grant with nothing materialised; the same node started with it reports network.offline and network.proxy_allowlist true at 1.3",
    },
];

/// The allowlisted name: an IANA-reserved, stably resolvable public host. The case needs
/// only its resolution and the proxy's verdict, never a reply from it.
const ALLOWED_HOST: &str = "example.com";

const BEATS: &str =
    "import time\nwhile True:\n    open('beats', 'a').write('beat\\n')\n    time.sleep(0.05)\n";

const PROBE: &str = r#"
import errno
import os
import socket
import stat
import sys
import traceback

results_path, allowed = sys.argv[1:3]
rows = []


def record(name, intact, detail=""):
    rows.append((name, "ok" if intact else "HOLE", str(detail).replace("\n", " ")))


def proxy():
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.settimeout(30)
    peer.connect(os.environ["WARD_PROXY_SOCKET"])
    return peer


def status(peer):
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = peer.recv(4096)
        if not chunk:
            break
        head += chunk
    peer.close()
    return head.split(b"\r\n", 1)[0].decode("ascii", "replace")


def connect_via_proxy(target):
    peer = proxy()
    peer.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode())
    return status(peer)


def forward_via_proxy(url, host):
    peer = proxy()
    peer.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (url, host)).encode())
    return status(peer)


def raw_tcp(host, port):
    peer = socket.socket()
    peer.settimeout(3)
    try:
        peer.connect((host, port))
        return True, "connected"
    except OSError as error:
        return False, errno.errorcode.get(error.errno, str(error))
    finally:
        peer.close()


def raw_udp(host, port):
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.settimeout(3)
    try:
        peer.sendto(b"\x00", (host, port))
        return True, "sent"
    except OSError as error:
        return False, errno.errorcode.get(error.errno, str(error))
    finally:
        peer.close()


def main():
    sock = os.environ.get("WARD_PROXY_SOCKET", "")
    record("env.socket", sock == "/run/ward/proxy.sock", sock)
    with open("/proc/self/environ", "rb") as handle:
        keys = sorted(entry.split(b"=", 1)[0].decode() for entry in handle.read().split(b"\0") if entry)
    record("env.keys", set(keys) <= {"HOME", "PATH", "TERM", "PWD", "WARD_PROXY_SOCKET"}, ",".join(keys))
    record("proxy.socket", stat.S_ISSOCK(os.stat(sock).st_mode), sock)

    verdict = connect_via_proxy(allowed + ":443")
    record("proxy.allowed", verdict.startswith("HTTP/1.1 200") or verdict.startswith("HTTP/1.1 502"), verdict)
    for name, target in [
        ("proxy.denied.host", "denied.example:443"),
        ("proxy.denied.private", "10.255.255.1:80"),
        ("proxy.denied.loopback", "127.0.0.1:80"),
        ("proxy.denied.metadata", "169.254.169.254:80"),
    ]:
        verdict = connect_via_proxy(target)
        record(name, verdict.startswith("HTTP/1.1 403"), verdict)
    verdict = forward_via_proxy("http://169.254.169.254/latest/meta-data/", "169.254.169.254")
    record("proxy.denied.metadata_forward", verdict.startswith("HTTP/1.1 403"), verdict)

    reached, detail = raw_tcp("1.1.1.1", 80)
    record("net.raw_tcp", not reached, detail)
    sent, detail = raw_udp("1.1.1.1", 53)
    record("net.raw_udp", not sent, detail)
    try:
        socket.getaddrinfo(allowed, 443)
        record("net.dns", False, "resolved inside the sandbox")
    except OSError as error:
        record("net.dns", True, error)
    with open("/proc/net/dev") as handle:
        names = [line.split(":")[0].strip() for line in handle.readlines()[2:]]
    record("net.interfaces", names == ["lo"], ",".join(names))


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

const PROBES: [&str; 14] = [
    "env.socket",
    "env.keys",
    "proxy.socket",
    "proxy.allowed",
    "proxy.denied.host",
    "proxy.denied.private",
    "proxy.denied.loopback",
    "proxy.denied.metadata",
    "proxy.denied.metadata_forward",
    "net.raw_tcp",
    "net.raw_udp",
    "net.dns",
    "net.interfaces",
    "probe",
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

fn custom_manifest(hosts: &[&str]) -> CapabilityManifestBytes {
    let list = hosts
        .iter()
        .map(|host| format!("\"{host}\""))
        .collect::<Vec<_>>()
        .join(",");
    CapabilityManifestBytes::new(format!(r#"{{"network":{{"custom":[{list}]}}}}"#).into_bytes())
        .unwrap()
}

fn networked_workload(
    binding: TaskBinding,
    snapshot: SnapshotId,
    argv: &[&str],
    budget_ms: u64,
) -> EnvelopeInput {
    let mut input = envelope_input(binding, snapshot, argv);
    input.workload.wall_clock_budget_ms = budget_ms;
    input.workload.capability_manifest = Some(custom_manifest(&[ALLOWED_HOST]));
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

fn verified(node: &Node, binding: TaskBinding) -> VerifiedEvidence {
    let dir = evidence::evidence_dir(&node.task_root, binding);
    let log = evidence::verify(&dir, binding).unwrap();
    for record in log.records() {
        assert_eq!(record.origin, Origin::Node, "{record:?}");
    }
    log
}

fn network_events(log: &VerifiedEvidence) -> Vec<WardEvent> {
    log.records()
        .iter()
        .filter(|record| {
            matches!(
                record.event,
                WardEvent::NetworkRequested { .. }
                    | WardEvent::NetworkDenied { .. }
                    | WardEvent::ObservationsDropped { .. }
            )
        })
        .map(|record| record.event.clone())
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

/// Whether this host resolves the allowed name, which the allowed-host probe needs; a
/// host without name resolution skips that case unless isolation is required.
fn allowed_host_resolves() -> bool {
    if (ALLOWED_HOST, 443).to_socket_addrs().is_ok() {
        return true;
    }
    assert!(
        std::env::var_os("WARD_REQUIRE_ISOLATION").is_none(),
        "WARD_REQUIRE_ISOLATION is set but this host cannot resolve {ALLOWED_HOST}"
    );
    eprintln!("skipping: this host cannot resolve {ALLOWED_HOST}");
    false
}

fn project(dir: &Path) -> SnapshotId {
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
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
    task_root: PathBuf,
}

impl Node {
    fn spawn(dir: &Path, network_allowlist: bool) -> Self {
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
        if network_allowlist {
            command.arg("--network-allowlist");
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

    fn proxy_socket(&self, binding: TaskBinding) -> PathBuf {
        egress_dir(&self.task_root, binding).join(PROXY_SOCKET_FILE)
    }

    /// Ask the attempt's proxy, from the host as the node's uid, for a tunnel to `target`;
    /// the reply's status line, or `None` when nothing accepts on the socket.
    fn ask_proxy(&self, binding: TaskBinding, target: &str) -> Option<String> {
        let dir = File::open(egress_dir(&self.task_root, binding)).ok()?;
        let mut stream = UnixStream::connect(format!(
            "/proc/self/fd/{}/{PROXY_SOCKET_FILE}",
            dir.as_raw_fd()
        ))
        .ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .ok()?;
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
            head.push(byte[0]);
        }
        Some(
            String::from_utf8_lossy(&head)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned(),
        )
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn every_network_acceptance_case_is_documented() {
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
    assert!(runner.contains("--test acceptance_network"));
}

#[test]
fn network_allowlist_lets_only_listed_hosts_out_through_the_proxy() {
    if !isolation() || !allowed_host_resolves() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let probed = binding(0x60, 0x61, 0x62);
    let argv = ["python3", "probe.py", "net-results.txt", ALLOWED_HOST];
    let request = signed(&node, &networked_workload(probed, snapshot, &argv, 120_000));
    let report = Driver::new(&client, config()).run_attempt(
        &request,
        &OperationIds::starting_at(1).unwrap(),
        &CancelToken::default(),
        &mut |_| {},
    );
    let results_path = node.workspace(probed).join("net-results.txt");
    let results = std::fs::read_to_string(&results_path).unwrap_or_default();
    assert_eq!(
        (report.outcome, report.receipt, report.cause),
        (
            AttemptOutcome::Completed,
            Some(TaskExecutionOutcome::Completed),
            Some(NodeAttemptEnd::Exited { code: Some(0) })
        ),
        "the probe found a hole or could not run:\n{results}\n{report:?}"
    );
    assert!(report.sealed);
    assert_every_probe_held(&results);
    assert_allowlisted_log(&verified(&node, probed));
    assert!(!node.proxy_socket(probed).exists());
    pass(
        "network_allowlist_lets_only_listed_hosts_out_through_the_proxy",
        started,
    );
}

fn assert_every_probe_held(results: &str) {
    let rows: Vec<Vec<&str>> = results
        .lines()
        .map(|line| line.split('\t').collect())
        .collect();
    let names: Vec<&str> = rows.iter().map(|row| row[0]).collect();
    for probe in PROBES.iter().filter(|probe| **probe != "probe") {
        assert!(
            names.contains(probe),
            "probe {probe} did not run:\n{results}"
        );
    }
    assert!(
        rows.iter().all(|row| row[1] == "ok"),
        "a probe reported a hole:\n{results}"
    );
    let keys = rows
        .iter()
        .find(|row| row[0] == "env.keys")
        .map(|row| row[2])
        .unwrap();
    eprintln!("network: the workload's environment keys are {keys}");
}

fn assert_allowlisted_log(log: &VerifiedEvidence) {
    assert!(log.is_sealed());
    let events = network_events(log);
    assert_eq!(events.len(), 6, "{events:?}");
    assert!(
        matches!(
            &events[0],
            WardEvent::NetworkRequested { host, port: 443, decision: ward_events::Decision::Allow, .. }
                if host.as_str() == ALLOWED_HOST
        ),
        "{:?}",
        events[0]
    );
    assert!(
        matches!(
            &events[1],
            WardEvent::NetworkDenied { dst: DeniedDst::Host { host, port: 443 }, reason: DenyReason::NotAllowlisted }
                if host.as_str() == "denied.example"
        ),
        "{:?}",
        events[1]
    );
    for event in &events[2..] {
        assert!(
            matches!(
                event,
                WardEvent::NetworkDenied {
                    dst: DeniedDst::Ip { .. },
                    reason: DenyReason::NotAllowlisted
                }
            ),
            "{event:?}"
        );
    }
    let first_network = log
        .records()
        .iter()
        .position(|record| matches!(record.event, WardEvent::NetworkRequested { .. }))
        .unwrap();
    assert!(matches!(
        log.records()[first_network - 1].event,
        WardEvent::NodeAttemptLaunched { .. }
    ));
    assert!(matches!(
        log.records()[first_network + 6].event,
        WardEvent::NodeAttemptEnded {
            state: NodeAttemptState::Exited,
            ..
        }
    ));
}

#[test]
fn network_allowlist_proxy_pauses_resumes_and_stops_with_the_attempt() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());
    let node = Node::spawn(dir.path(), true);
    let client = connect(&node.socket);
    let paused = binding(0x63, 0x64, 0x65);
    let marker = marker("ward-acceptance-net");
    let request = signed(
        &node,
        &networked_workload(
            paused,
            snapshot,
            &["python3", "-c", BEATS, &marker],
            600_000,
        ),
    );
    assert_eq!(
        accepted(client.create(paused, op(1))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        accepted(client.admit(paused, op(2), &request.envelope)),
        TaskLifecycleState::Ready
    );
    assert_eq!(
        accepted(client.start(paused, op(3))),
        TaskLifecycleState::Running
    );
    wait_until_sandboxed(&marker);
    let beats = node.workspace(paused).join("beats");
    eventually("the workload never started beating", || lines(&beats) > 0);
    assert!(node.proxy_socket(paused).exists());
    assert_eq!(
        node.ask_proxy(paused, "denied.example:443").as_deref(),
        Some("HTTP/1.1 403 Forbidden")
    );
    let log_dir = evidence::evidence_dir(&node.task_root, paused);
    let denials = |log: &VerifiedEvidence| network_events(log).len();
    eventually("the first verdict was never recorded", || {
        denials(&evidence::verify(&log_dir, paused).unwrap()) == 1
    });

    assert_eq!(
        accepted(client.pause(paused, op(4))),
        TaskLifecycleState::Paused
    );
    assert_eq!(
        node.ask_proxy(paused, "denied.example:443").as_deref(),
        Some("HTTP/1.1 503 Service Unavailable")
    );
    assert_eq!(
        node.ask_proxy(paused, &format!("{ALLOWED_HOST}:443"))
            .as_deref(),
        Some("HTTP/1.1 503 Service Unavailable")
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(denials(&evidence::verify(&log_dir, paused).unwrap()), 1);
    assert!(processes_with(&marker) >= 3, "the paused tree is gone");

    assert_eq!(
        accepted(client.resume(paused, op(5))),
        TaskLifecycleState::Running
    );
    assert_eq!(
        node.ask_proxy(paused, "10.255.255.1:80").as_deref(),
        Some("HTTP/1.1 403 Forbidden")
    );
    eventually("the verdict after resume was never recorded", || {
        denials(&evidence::verify(&log_dir, paused).unwrap()) == 2
    });

    assert_eq!(
        accepted(client.stop(paused, op(6))),
        TaskLifecycleState::Stopped
    );
    wait_until_gone(&marker);
    assert!(!node.proxy_socket(paused).exists());
    assert_eq!(node.ask_proxy(paused, "denied.example:443"), None);
    assert_eq!(
        accepted(client.seal(paused, op(7))),
        TaskLifecycleState::Sealed
    );
    let log = verified(&node, paused);
    assert!(log.is_sealed());
    assert_eq!(
        shape(&log),
        [
            "admitted", "launched", "denied", "pause", "resume", "denied", "stopped", "sealed"
        ]
    );
    pass(
        "network_allowlist_proxy_pauses_resumes_and_stops_with_the_attempt",
        started,
    );
}

fn shape(log: &VerifiedEvidence) -> Vec<&'static str> {
    log.records()
        .iter()
        .map(|record| match &record.event {
            WardEvent::NodeAttemptAdmitted { .. } => "admitted",
            WardEvent::NodeAttemptLaunched { .. } => "launched",
            WardEvent::NetworkDenied { .. } => "denied",
            WardEvent::NodeAttemptIntervened {
                action: NodeIntervention::Pause,
                ..
            } => "pause",
            WardEvent::NodeAttemptIntervened {
                action: NodeIntervention::Resume,
                ..
            } => "resume",
            WardEvent::NodeAttemptEnded {
                state: NodeAttemptState::Stopped,
                end: NodeAttemptEnd::Killed,
                operation: Some(6),
                ..
            } => "stopped",
            WardEvent::NodeAttemptSealed { operation: 7 } => "sealed",
            other => panic!("unexpected record {other:?}"),
        })
        .collect()
}

#[test]
fn network_allowlist_is_advertised_and_honoured_only_when_enabled() {
    if !isolation() {
        return;
    }
    let started = Instant::now();
    let dir = private_dir();
    let snapshot = project(dir.path());

    let offline = Node::spawn(dir.path(), false);
    let client = connect(&offline.socket);
    let capabilities = client.capabilities().unwrap();
    assert!(capabilities.network().offline);
    assert!(!capabilities.network().proxy_allowlist);
    let refused = binding(0x66, 0x67, 0x68);
    let request = signed(
        &offline,
        &networked_workload(refused, snapshot, &["true"], 60_000),
    );
    assert_eq!(
        accepted(client.create(refused, op(1))),
        TaskLifecycleState::Created
    );
    assert_eq!(
        rejected(client.admit(refused, op(2), &request.envelope)),
        TaskLifecycleRejectionReason::UnsupportedGrant
    );
    assert!(!offline.task_root.join(refused.task().to_string()).exists());
    drop(client);
    offline.kill();

    let enforcing = Node::spawn(dir.path(), true);
    let client = connect(&enforcing.socket);
    let capabilities = client.capabilities().unwrap();
    assert_eq!(
        (
            capabilities.network().offline,
            capabilities.network().proxy_allowlist,
            capabilities.lifecycle().start
        ),
        (true, true, true)
    );
    pass(
        "network_allowlist_is_advertised_and_honoured_only_when_enabled",
        started,
    );
}
