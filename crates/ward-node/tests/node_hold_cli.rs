//! End-to-end approval holds (#415, ADR-0035) over `ward-node`'s real local socket: a node
//! started with `--network-allowlist`, `--action-channel`, `--approval-hold` and
//! `--credentials` admits a manifest whose `hold` names a host and a credential service.
//! The first request the attempt's proxy sees for them opens one approval request each on
//! the action channel, listed with the held capability; the proxy refuses them with a
//! named `403` and never reaches the upstream or injects the credential until the control
//! plane's approval of each is recorded. A denial, an expiry, a stop and a node restart
//! keep them refused; a pause keeps them held; a forged, replayed or misdirected answer
//! releases nothing; a credential the manifest does not hold is unaffected.
//!
//! The fake provider and the fake upstream bind 127.0.0.1 on ephemeral ports. The executing
//! cases need a working bubblewrap and python3 in the sandbox, and skip without them except
//! under `WARD_REQUIRE_ISOLATION=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, DenyReason, ExecutionAttemptId, LeaseId, NodeActionDecision,
    NodeActionRefusal, NodeId, PrincipalId, SessionId, SnapshotId, TaskId, WardEvent,
};
use ward_node::evidence;
use ward_node_protocol::{
    ActionDecision, ActionRejectionReason, AdmissionEnvelopeJson, AdmissionVersion,
    CapabilityDiscoveryContext, CapabilityDiscoveryResponse, CapabilityManifestBytes,
    HandshakeRequest, HandshakeResponse, HeldCapability, IssuerProof, IssuerSignature,
    NodeCapabilities, OperationId, PendingAction, ProtocolVersion, TaskActionsResponse,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskLifecycleContext, TaskLifecycleRejectionReason, TaskLifecycleRequest,
    TaskLifecycleResponse, TaskLifecycleState, TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
};

const NODE: NodeId = NodeId::from_u128(4);
const BROKER_TOKEN: &str = "fake-hold-provider-token";
const LEASED: &str = "hvs.held-leased-token-for-the-upstream";
const ACCESSOR: &str = "held-lease-accessor-handle";

/// The workload: one request on the route of the service the manifest does not hold, then
/// requests on the held route until one is answered with anything but `held for approval`
/// or the paused proxy's `paused by ward` (every distinct answer body goes to `seen.txt`); `forge` first tries to answer its own
/// request through the action channel. Exit 0 once the held route answered `200`; 3, 4 and
/// 5 for a refusal named denied, expired and cancelled.
const WORKLOAD: &str = r#"
import json, os, socket, sys, time

def get(path):
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.settimeout(20)
    peer.connect(os.environ["WARD_PROXY_SOCKET"])
    peer.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer placeholder\r\nConnection: close\r\n\r\n")
    answer = b""
    while True:
        chunk = peer.recv(4096)
        if not chunk:
            break
        answer += chunk
    return answer

def forge(line):
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.settimeout(20)
    peer.connect(os.environ["WARD_ACTION_SOCKET"])
    peer.sendall((json.dumps(line) + "\n").encode())
    got = b""
    while True:
        chunk = peer.recv(4096)
        if not chunk:
            break
        got += chunk
    return len(got)

open("/work/free.txt", "wb").write(get(b"/free/v1/open"))
seen = []
forged = sys.argv[1] == "forge"
while True:
    answer = get(b"/artifacts/v1/data")
    body = answer.split(b"\r\n\r\n", 1)[-1].strip()
    if not seen or seen[-1] != body:
        seen.append(body)
        open("/work/seen.txt", "wb").write(b"\n".join(seen))
    if body not in (b"held for approval", b"paused by ward"):
        break
    if forged:
        forged = False
        got = forge({"request": "answer", "protocol": {"major": 1, "minor": 3}, "operation_id": 1,
                     "binding": {"task": "t", "attempt": "a", "lease": "l"}, "action": 1,
                     "decision": "approved"})
        got += forge({"id": "hold:1", "kind": "approval", "summary": "network localhost", "detail": ""})
        open("/work/forged.txt", "w").write(str(got))
    time.sleep(0.1)
open("/work/answer.txt", "wb").write(answer)
if answer.startswith(b"HTTP/1.1 200"):
    sys.exit(0)
sys.exit({b"approval denied": 3, b"approval expired": 4, b"approval cancelled": 5}.get(body, 6))
"#;

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

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

fn isolation() -> bool {
    ward_sandbox::ci::isolation_ready(ward_launch::available(), "bubblewrap")
}

/// Wait until `done` holds, polling; fail once `what` has not happened within 30 seconds.
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "{what} never happened");
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------------------
// The fake provider and the fake upstream
// ---------------------------------------------------------------------------------------

#[derive(Default)]
struct BaoState {
    issued: usize,
    revoked: Vec<String>,
}

struct FakeBao {
    port: u16,
    state: Arc<Mutex<BaoState>>,
}

impl FakeBao {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(BaoState::default()));
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || serve_bao(stream, &shared));
            }
        });
        Self { port, state }
    }

    fn revoked(&self) -> Vec<String> {
        self.state.lock().unwrap().revoked.clone()
    }
}

fn read_request(stream: &mut TcpStream) -> Option<(String, BTreeMap<String, String>, Vec<u8>)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .and_then(|length| length.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some((line.trim_end().to_owned(), headers, body))
}

fn reply(stream: &mut TcpStream, status: u16, body: &Value) {
    let body = if body.is_null() {
        String::new()
    } else {
        body.to_string()
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn serve_bao(mut stream: TcpStream, state: &Mutex<BaoState>) {
    let Some((line, headers, body)) = read_request(&mut stream) else {
        return;
    };
    if headers.get("x-vault-token").map(String::as_str) != Some(BROKER_TOKEN) {
        return reply(&mut stream, 403, &json!({"errors": ["permission denied"]}));
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if line.starts_with("POST /v1/auth/token/create/") {
        let ttl = body["ttl"]
            .as_str()
            .and_then(|ttl| ttl.trim_end_matches('s').parse::<u64>().ok())
            .unwrap_or(0);
        state.lock().unwrap().issued += 1;
        return reply(
            &mut stream,
            200,
            &json!({"auth": {
                "client_token": LEASED,
                "accessor": ACCESSOR,
                "lease_duration": ttl,
                "token_policies": body["policies"],
            }}),
        );
    }
    if line.starts_with("POST /v1/auth/token/revoke-accessor") {
        let accessor = body["accessor"].as_str().unwrap_or_default().to_owned();
        state.lock().unwrap().revoked.push(accessor);
        return reply(&mut stream, 204, &Value::Null);
    }
    reply(&mut stream, 404, &json!({"errors": []}));
}

struct Upstream {
    port: u16,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&heads);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let Some((line, headers, _)) = read_request(&mut stream) else {
                    continue;
                };
                let head = headers.iter().fold(line, |head, (name, value)| {
                    format!("{head}\n{name}: {value}")
                });
                seen.lock().unwrap().push(head);
                reply(&mut stream, 200, &json!({"artifact": "built"}));
            }
        });
        Self { port, heads }
    }

    /// The heads of the requests that reached the upstream on the held route.
    fn held_heads(&self) -> Vec<String> {
        self.heads
            .lock()
            .unwrap()
            .iter()
            .filter(|head| head.starts_with("GET /v1/data "))
            .cloned()
            .collect()
    }

    fn free_heads(&self) -> Vec<String> {
        self.heads
            .lock()
            .unwrap()
            .iter()
            .filter(|head| head.starts_with("GET /v1/open "))
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------------------

/// `localhost` allowlisted; the `artifacts` and `free` credentials both for it; an approval
/// channel; and the `hold` given (`hosts`, `services`), absent when both are empty.
fn manifest(hosts: &[&str], services: &[&str], wait_secs: u32) -> CapabilityManifestBytes {
    let quoted = |list: &[&str]| {
        list.iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut hold = Vec::new();
    if !hosts.is_empty() {
        hold.push(format!(r#""hosts":[{}]"#, quoted(hosts)));
    }
    if !services.is_empty() {
        hold.push(format!(r#""services":[{}]"#, quoted(services)));
    }
    let hold = if hold.is_empty() {
        String::new()
    } else {
        format!(r#","hold":{{{}}}"#, hold.join(","))
    };
    CapabilityManifestBytes::new(
        format!(
            r#"{{"network":{{"custom":["localhost"]}},"actions":{{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":{wait_secs}}},"credentials":[{{"service":"artifacts","host":"localhost","ttl_secs":600}},{{"service":"free","host":"localhost","ttl_secs":600}}]{hold}}}"#
        )
        .into_bytes(),
    )
    .unwrap()
}

fn signed_admit(
    snapshot: SnapshotId,
    argv: &[&str],
    manifest: CapabilityManifestBytes,
) -> TaskLifecycleRequest {
    let now = now_ms();
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
            issued_at_unix_ms: now - 60_000,
            expires_at_unix_ms: now + 600_000,
            version: LeaseVersion::new(1).unwrap(),
        },
        now,
        EmptyAuthorityPolicy::Reject,
    )
    .unwrap();
    let envelope = TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
        binding: binding(),
        agent: AgentId::from_u128(3),
        node: NODE,
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(argv.iter().map(|arg| (*arg).to_owned()).collect()).unwrap(),
            manifest,
            snapshot,
            120_000,
        )
        .unwrap(),
        issued_at_unix_ms: now - 60_000,
        expires_at_unix_ms: now + 600_000,
        version: AdmissionVersion::new(1).unwrap(),
    })
    .unwrap();
    let json = AdmissionEnvelopeJson::encode(&envelope).unwrap();
    let key_pair = key_pair();
    let proof = IssuerProof::new(
        Blake3Hash::hash(key_pair.public_key().as_ref()),
        IssuerSignature::from_bytes(key_pair.sign(json.as_bytes()).as_ref().try_into().unwrap()),
    );
    context().admit(op(2), binding(), json, proof).unwrap()
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn private_file(path: &Path, text: &str) -> PathBuf {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path.to_path_buf()
}

fn trust_store(dir: &Path) -> PathBuf {
    private_file(
        &dir.join("trusted-issuers"),
        &format!(
            "{} {}\n",
            hex(key_pair().public_key().as_ref()),
            PrincipalId::from_u128(2)
        ),
    )
}

fn credentials_file(dir: &Path, bao: &FakeBao, upstream: &Upstream) -> PathBuf {
    let token = private_file(&dir.join("bao.token"), &format!("{BROKER_TOKEN}\n"));
    let service = |name: &str| {
        format!(
            r#"
[service.{name}]
provider = "bao"
engine = "token"
role = "ward-{name}"
permissions = ["{name}-read"]
max_ttl_secs = 600
upstream = "localhost:{upstream}"
value_prefix = "Bearer "
paths = ["/v1"]
plain_upstream = true
"#,
            upstream = upstream.port,
        )
    };
    private_file(
        &dir.join("credentials.toml"),
        &format!(
            r#"
[provider.bao]
kind = "openbao"
address = "http://127.0.0.1:{bao}"
token_file = "{token}"
insecure_loopback = true
timeout_ms = 2000
max_ttl_secs = 600
{artifacts}{free}"#,
            bao = bao.port,
            token = token.display(),
            artifacts = service("artifacts"),
            free = service("free"),
        ),
    )
}

fn imported(state_dir: &Path, dir: &Path) -> SnapshotId {
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("README"), b"workload\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ward-node"))
        .args(["snapshot", "import", "--state-dir"])
        .arg(state_dir)
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
}

impl Node {
    fn spawn(dir: &Path, credentials: &Path, hold: bool) -> Self {
        let socket = dir.join("node.sock");
        let _ = std::fs::remove_file(&socket);
        let mut command = Command::new(env!("CARGO_BIN_EXE_ward-node"));
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
            .arg(dir.join("tasks"))
            .arg("--network-allowlist")
            .arg("--action-channel")
            .arg("--credentials")
            .arg(credentials)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if hold {
            command.arg("--approval-hold");
        }
        let mut child = command.spawn().unwrap();
        eventually("ward-node binding its socket", || {
            assert!(
                child.try_wait().unwrap().is_none(),
                "ward-node exited before serving"
            );
            UnixStream::connect(&socket).is_ok()
        });
        Self { child, socket }
    }

    fn request(&self, request: &str) -> String {
        let mut client = UnixStream::connect(&self.socket).unwrap();
        let hello = HandshakeRequest::Hello {
            protocol: WARD_NODE_PROTOCOL,
        };
        writeln!(client, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<HandshakeResponse>(line.trim()).unwrap(),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 3)
            }
        );
        writeln!(client, "{request}").unwrap();
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        response.trim().to_owned()
    }

    fn lifecycle(&self, request: &TaskLifecycleRequest) -> TaskLifecycleResponse {
        context()
            .decode_response(&self.request(&serde_json::to_string(request).unwrap()))
            .unwrap()
    }

    fn capabilities(&self) -> NodeCapabilities {
        let discovery = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let CapabilityDiscoveryResponse::Capabilities { capabilities } = discovery
            .decode_response(&self.request(&serde_json::to_string(&discovery.request()).unwrap()))
            .unwrap();
        capabilities
    }

    fn state(&self) -> TaskLifecycleState {
        match self.lifecycle(&context().inspect(binding())) {
            TaskLifecycleResponse::Inspected { state, .. } => state,
            other => panic!("{other:?}"),
        }
    }

    fn pending(&self) -> Vec<PendingAction> {
        let request = serde_json::to_string(&context().actions(binding()).unwrap()).unwrap();
        match context()
            .decode_actions_response(&self.request(&request))
            .unwrap()
        {
            TaskActionsResponse::Actions { pending, .. } => pending,
            other => panic!("{other:?}"),
        }
    }

    /// The listing once it holds `count` requests.
    fn listed(&self, count: usize) -> Vec<PendingAction> {
        eventually("the listing", || self.pending().len() == count);
        self.pending()
    }

    fn answer(&self, operation: u64, action: u32, decision: ActionDecision) -> TaskActionsResponse {
        self.answer_as(binding(), operation, action, decision)
    }

    fn answer_as(
        &self,
        binding: TaskBinding,
        operation: u64,
        action: u32,
        decision: ActionDecision,
    ) -> TaskActionsResponse {
        let request = serde_json::to_string(
            &context()
                .answer(op(operation), binding, action, decision, None)
                .unwrap(),
        )
        .unwrap();
        context()
            .decode_actions_response(&self.request(&request))
            .unwrap()
    }

    fn admit_and_start(&self, snapshot: SnapshotId, mode: &str, manifest: CapabilityManifestBytes) {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding())),
            ctx.accepted(op(1), binding(), TaskLifecycleState::Created)
        );
        assert_eq!(
            self.lifecycle(&signed_admit(
                snapshot,
                &["python3", "-c", WORKLOAD, mode],
                manifest
            )),
            ctx.accepted(op(2), binding(), TaskLifecycleState::Ready)
        );
        assert_eq!(
            self.lifecycle(&ctx.start(op(3), binding())),
            ctx.accepted(op(3), binding(), TaskLifecycleState::Running)
        );
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn workspace(dir: &Path) -> PathBuf {
    dir.join("tasks")
        .join(binding().task().to_string())
        .join(binding().attempt().to_string())
}

fn records(dir: &Path) -> Vec<WardEvent> {
    evidence::verify(
        &evidence::evidence_dir(&dir.join("tasks"), binding()),
        binding(),
    )
    .unwrap()
    .records()
    .iter()
    .map(|record| record.event.clone())
    .collect()
}

fn position(events: &[WardEvent], wanted: impl Fn(&WardEvent) -> bool) -> usize {
    events
        .iter()
        .position(wanted)
        .unwrap_or_else(|| panic!("no such record in {events:?}"))
}

fn answers(events: &[WardEvent]) -> Vec<(u32, NodeActionDecision, Option<u64>)> {
    events
        .iter()
        .filter_map(|event| match event {
            WardEvent::NodeActionAnswered {
                action,
                decision,
                operation,
                ..
            } => Some((*action, *decision, *operation)),
            _ => None,
        })
        .collect()
}

fn refused_by_hold(rule: &'static str) -> impl Fn(&WardEvent) -> bool {
    move |event| {
        matches!(event, WardEvent::NetworkDenied { reason: DenyReason::PolicyDeny { rule: got }, .. }
            if got.as_str() == rule)
    }
}

fn seen(dir: &Path) -> String {
    std::fs::read_to_string(workspace(dir).join("seen.txt")).unwrap_or_default()
}

/// Wait until the workload has been refused `held for approval` and the node lists the
/// `count` requests it opened.
fn held(node: &Node, dir: &Path, count: usize) -> Vec<PendingAction> {
    eventually("the workload being held", || {
        seen(dir).starts_with("held for approval")
    });
    node.listed(count)
}

fn exited(node: &Node) {
    eventually("the attempt's end", || {
        node.state() != TaskLifecycleState::Running
    });
    assert_eq!(node.state(), TaskLifecycleState::Exited);
}

struct Fixture {
    dir: tempfile::TempDir,
    bao: FakeBao,
    upstream: Upstream,
    snapshot: SnapshotId,
    credentials: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = private_dir();
        let (bao, upstream) = (FakeBao::start(), Upstream::start());
        let snapshot = imported(&dir.path().join("state"), dir.path());
        let credentials = credentials_file(dir.path(), &bao, &upstream);
        Self {
            dir,
            bao,
            upstream,
            snapshot,
            credentials,
        }
    }

    fn node(&self, hold: bool) -> Node {
        Node::spawn(self.dir.path(), &self.credentials, hold)
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

// ---------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------

#[test]
fn a_hold_is_advertised_and_admitted_only_by_a_node_started_with_the_flag() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let fixture = Fixture::new();
    let node = fixture.node(false);
    assert!(!node.capabilities().actions().hold);
    assert!(node.capabilities().actions().approval);
    node.lifecycle(&context().create(op(1), binding()));
    assert_eq!(
        node.lifecycle(&signed_admit(
            fixture.snapshot,
            &["true"],
            manifest(&["localhost"], &["artifacts"], 60)
        )),
        context().rejected(
            Some(op(2)),
            binding(),
            TaskLifecycleRejectionReason::UnsupportedGrant
        )
    );
    assert_eq!(node.state(), TaskLifecycleState::Created);
    node.kill();

    let node = fixture.node(true);
    assert!(node.capabilities().actions().hold);
    for outside in [
        br#"{"network":{"custom":["localhost"]},"actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":60},"hold":{"hosts":["elsewhere.example"]}}"#.to_vec(),
        br#"{"network":{"custom":["localhost"]},"hold":{"hosts":["localhost"]}}"#.to_vec(),
        br#"{"network":{"custom":["localhost"]},"actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":60},"hold":{"services":["artifacts"]}}"#.to_vec(),
    ] {
        assert!(
            CapabilityManifestBytes::new(outside).is_err(),
            "a hold on what the manifest does not grant, or without an approval channel, fails decoding"
        );
    }
    assert_eq!(
        node.lifecycle(&signed_admit(
            fixture.snapshot,
            &["true"],
            manifest(&["localhost"], &["artifacts"], 60)
        )),
        context().accepted(op(2), binding(), TaskLifecycleState::Ready)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn approving_each_held_capability_releases_it_and_the_upstream_sees_the_injected_credential() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let fixture = Fixture::new();
    let node = fixture.node(true);
    node.admit_and_start(
        fixture.snapshot,
        "plain",
        manifest(&["localhost"], &["artifacts"], 300),
    );
    let listed = held(&node, fixture.path(), 2);
    assert_eq!(
        (
            listed[0].action(),
            listed[0].id().as_str(),
            listed[0].summary()
        ),
        (1, "hold:1", "network localhost")
    );
    assert_eq!(
        listed[0].hold(),
        Some(&HeldCapability::Host("localhost".to_owned()))
    );
    assert_eq!(
        (
            listed[1].action(),
            listed[1].id().as_str(),
            listed[1].summary()
        ),
        (2, "hold:2", "credential artifacts")
    );
    assert_eq!(
        listed[1].hold(),
        Some(&HeldCapability::Service("artifacts".to_owned()))
    );
    // The held host covers every route to it, the credential the manifest does not hold
    // included; nothing reached the upstream.
    assert!(fixture.upstream.free_heads().is_empty());
    assert!(fixture.upstream.held_heads().is_empty());

    // Approving one releases that one only: the other still holds the route.
    assert_eq!(
        node.answer(10, 2, ActionDecision::Approved),
        context().answered(op(10), binding(), 2, ActionDecision::Approved)
    );
    assert_eq!(node.listed(1)[0].action(), 1);
    assert!(fixture.upstream.held_heads().is_empty());
    assert_eq!(node.state(), TaskLifecycleState::Running);

    assert_eq!(
        node.answer(11, 1, ActionDecision::Approved),
        context().answered(op(11), binding(), 1, ActionDecision::Approved)
    );
    exited(&node);
    let heads = fixture.upstream.held_heads();
    assert!(!heads.is_empty());
    assert!(
        heads
            .iter()
            .all(|head| head.contains(&format!("authorization: Bearer {LEASED}"))),
        "{heads:?}"
    );
    assert_eq!(
        seen(fixture.path()),
        "held for approval\n{\"artifact\":\"built\"}"
    );
    let free = std::fs::read_to_string(workspace(fixture.path()).join("free.txt")).unwrap();
    assert!(free.ends_with("held for approval\n"), "{free}");

    let events = records(fixture.path());
    let requested = position(&events, |event| {
        matches!(event, WardEvent::NodeActionRequested { action: 1, summary, .. }
            if *summary == Blake3Hash::hash(b"network localhost"))
    });
    // A refusal travels the proxy's verdict queue, so its record may follow the answer.
    let refused = position(&events, refused_by_hold("hold:held:1"));
    let approved = position(&events, |event| {
        matches!(
            event,
            WardEvent::NodeActionAnswered {
                action: 1,
                decision: NodeActionDecision::Approved,
                operation: Some(11),
                ..
            }
        )
    });
    let reached = events
        .iter()
        .rposition(|event| {
            matches!(event, WardEvent::NetworkRequested { host, decision: ward_events::Decision::Allow, .. }
                if host.as_str() == "localhost")
        })
        .unwrap();
    let ended = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptEnded { .. })
    });
    assert!(requested < approved && approved < reached && reached < ended);
    assert!(refused < ended);
    assert_eq!(
        answers(&events),
        vec![
            (2, NodeActionDecision::Approved, Some(10)),
            (1, NodeActionDecision::Approved, Some(11)),
        ]
    );
    assert_eq!(
        fixture.bao.revoked().len(),
        2,
        "both leases revoked at the end"
    );
}

#[test]
fn a_denial_keeps_the_held_route_refused_with_a_named_403() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let fixture = Fixture::new();
    let node = fixture.node(true);
    node.admit_and_start(
        fixture.snapshot,
        "plain",
        manifest(&[], &["artifacts"], 300),
    );
    let listed = held(&node, fixture.path(), 1);
    assert_eq!(listed[0].id().as_str(), "hold:1");
    // A credential the manifest does not hold is unaffected: it went through at once.
    assert_eq!(fixture.upstream.free_heads().len(), 1);
    let free = std::fs::read_to_string(workspace(fixture.path()).join("free.txt")).unwrap();
    assert!(free.starts_with("HTTP/1.1 200"), "{free}");
    assert!(fixture.upstream.held_heads().is_empty());
    assert_eq!(
        node.answer(10, 1, ActionDecision::Denied),
        context().answered(op(10), binding(), 1, ActionDecision::Denied)
    );
    exited(&node);
    assert_eq!(seen(fixture.path()), "held for approval\napproval denied");
    let answer = std::fs::read_to_string(workspace(fixture.path()).join("answer.txt")).unwrap();
    assert!(answer.starts_with("HTTP/1.1 403 Forbidden"), "{answer}");
    assert!(fixture.upstream.held_heads().is_empty());
    let events = records(fixture.path());
    assert_eq!(
        answers(&events),
        vec![(1, NodeActionDecision::Denied, Some(10))]
    );
    let denied = position(&events, |event| {
        matches!(
            event,
            WardEvent::NodeActionAnswered {
                decision: NodeActionDecision::Denied,
                ..
            }
        )
    });
    assert!(denied < position(&events, refused_by_hold("hold:denied:1")));
    // A later approval of the same request is too late.
    assert_eq!(
        node.answer(11, 1, ActionDecision::Approved),
        context().actions_rejected(Some(op(11)), binding(), ActionRejectionReason::InvalidState)
    );
}

#[test]
fn an_unanswered_hold_expires_and_stays_refused() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let fixture = Fixture::new();
    let node = fixture.node(true);
    node.admit_and_start(fixture.snapshot, "plain", manifest(&[], &["artifacts"], 2));
    exited(&node);
    assert_eq!(seen(fixture.path()), "held for approval\napproval expired");
    assert!(fixture.upstream.held_heads().is_empty());
    let events = records(fixture.path());
    assert_eq!(
        answers(&events),
        vec![(1, NodeActionDecision::Expired, None)]
    );
    assert!(events.iter().any(refused_by_hold("hold:expired:1")));
}

#[test]
fn stopping_the_attempt_cancels_its_hold_before_the_end_is_recorded() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let fixture = Fixture::new();
    let node = fixture.node(true);
    node.admit_and_start(
        fixture.snapshot,
        "plain",
        manifest(&["localhost"], &[], 300),
    );
    held(&node, fixture.path(), 1);
    assert_eq!(
        node.lifecycle(&context().stop(op(20), binding())),
        context().accepted(op(20), binding(), TaskLifecycleState::Stopped)
    );
    assert!(node.pending().is_empty());
    assert_eq!(
        node.answer(21, 1, ActionDecision::Approved),
        context().actions_rejected(Some(op(21)), binding(), ActionRejectionReason::InvalidState)
    );
    assert!(fixture.upstream.held_heads().is_empty());
    let events = records(fixture.path());
    let cancelled = position(&events, |event| {
        matches!(
            event,
            WardEvent::NodeActionAnswered {
                action: 1,
                decision: NodeActionDecision::Cancelled,
                operation: None,
                ..
            }
        )
    });
    let ended = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptEnded { .. })
    });
    assert!(cancelled < ended);
}

#[test]
fn a_pause_keeps_the_hold_held_past_its_wait_and_an_approval_after_resume_releases_it() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let fixture = Fixture::new();
    let node = fixture.node(true);
    node.admit_and_start(fixture.snapshot, "plain", manifest(&[], &["artifacts"], 12));
    held(&node, fixture.path(), 1);
    assert_eq!(
        node.lifecycle(&context().pause(op(20), binding())),
        context().accepted(op(20), binding(), TaskLifecycleState::Paused)
    );
    let frozen = node.pending()[0].expires_in_ms();
    let paused_at = Instant::now();
    eventually("the wait passing while paused", || {
        let pending = node.pending();
        assert_eq!(pending.len(), 1, "a paused hold stays pending");
        assert_eq!(pending[0].expires_in_ms(), frozen, "its clock stands still");
        paused_at.elapsed() > Duration::from_millis(frozen + 1_000)
    });
    assert_eq!(
        node.lifecycle(&context().resume(op(21), binding())),
        context().accepted(op(21), binding(), TaskLifecycleState::Running)
    );
    assert_eq!(
        node.answer(22, 1, ActionDecision::Approved),
        context().answered(op(22), binding(), 1, ActionDecision::Approved)
    );
    exited(&node);
    assert_eq!(fixture.upstream.held_heads().len(), 1);
    assert_eq!(
        answers(&records(fixture.path())),
        vec![(1, NodeActionDecision::Approved, Some(22))]
    );
}

#[test]
fn a_forged_replayed_or_misdirected_answer_releases_nothing() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let fixture = Fixture::new();
    let node = fixture.node(true);
    node.admit_and_start(
        fixture.snapshot,
        "forge",
        manifest(&["localhost"], &[], 300),
    );
    held(&node, fixture.path(), 1);
    eventually("the workload's forged answers", || {
        workspace(fixture.path()).join("forged.txt").exists()
    });
    assert_eq!(
        std::fs::read_to_string(workspace(fixture.path()).join("forged.txt")).unwrap(),
        "0",
        "a line on the channel shaped as an answer, or under the node's id, gets nothing"
    );
    let other = TaskBinding::new(
        binding().task(),
        binding().attempt(),
        LeaseId::from_u128(99),
    );
    assert_eq!(
        node.answer_as(other, 10, 1, ActionDecision::Approved),
        context().actions_rejected(Some(op(10)), other, ActionRejectionReason::LeaseMismatch)
    );
    assert_eq!(
        node.answer(11, 2, ActionDecision::Approved),
        context().actions_rejected(
            Some(op(11)),
            binding(),
            ActionRejectionReason::UnknownRequest
        )
    );
    assert_eq!(node.listed(1)[0].action(), 1);
    assert!(fixture.upstream.held_heads().is_empty());
    assert_eq!(node.state(), TaskLifecycleState::Running);

    assert_eq!(
        node.answer(12, 1, ActionDecision::Denied),
        context().answered(op(12), binding(), 1, ActionDecision::Denied)
    );
    // A replay of the denial is the denial; the same id approving is stale; another
    // approval is too late. None of them releases anything.
    assert_eq!(
        node.answer(12, 1, ActionDecision::Denied),
        context().answered(op(12), binding(), 1, ActionDecision::Denied)
    );
    exited(&node);
    assert_eq!(
        node.answer(12, 1, ActionDecision::Approved),
        context().actions_rejected(
            Some(op(12)),
            binding(),
            ActionRejectionReason::StaleOperation
        )
    );
    assert_eq!(seen(fixture.path()), "held for approval\napproval denied");
    assert!(fixture.upstream.held_heads().is_empty());
    let events = records(fixture.path());
    assert_eq!(
        answers(&events),
        vec![(1, NodeActionDecision::Denied, Some(12))]
    );
    for reason in [
        NodeActionRefusal::ControlRequest,
        NodeActionRefusal::DuplicateId,
    ] {
        assert!(
            events.iter().any(|event| matches!(event,
                WardEvent::NodeActionRefused { reason: got, .. } if *got == reason)),
            "{reason:?}: {events:?}"
        );
    }
}

#[test]
fn a_restarted_node_keeps_an_approval_recorded_before_the_crash_and_cancels_the_rest() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let fixture = Fixture::new();
    let node = fixture.node(true);
    node.admit_and_start(
        fixture.snapshot,
        "plain",
        manifest(&["localhost"], &["artifacts"], 300),
    );
    held(&node, fixture.path(), 2);
    assert_eq!(
        node.answer(10, 1, ActionDecision::Approved),
        context().answered(op(10), binding(), 1, ActionDecision::Approved)
    );
    node.listed(1);
    node.kill();
    assert!(fixture.upstream.held_heads().is_empty());

    let node = fixture.node(true);
    assert_eq!(node.state(), TaskLifecycleState::Exited);
    assert!(node.pending().is_empty());
    assert_eq!(
        node.answer(11, 2, ActionDecision::Approved),
        context().actions_rejected(Some(op(11)), binding(), ActionRejectionReason::InvalidState)
    );
    let events = records(fixture.path());
    assert_eq!(
        answers(&events),
        vec![
            (1, NodeActionDecision::Approved, Some(10)),
            (2, NodeActionDecision::Cancelled, None),
        ]
    );
    let cancelled = position(&events, |event| {
        matches!(
            event,
            WardEvent::NodeActionAnswered {
                action: 2,
                decision: NodeActionDecision::Cancelled,
                ..
            }
        )
    });
    let recovered = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptRecovered { .. })
    });
    assert!(cancelled < recovered);
    assert!(fixture.upstream.held_heads().is_empty());
    assert_eq!(
        node.lifecycle(&context().seal(op(30), binding())),
        context().accepted(op(30), binding(), TaskLifecycleState::Sealed)
    );
}
