//! End-to-end credentials as node capabilities (#267, ADR-0034) over `ward-node`'s real
//! local socket: a node started with `--network-allowlist` and `--credentials` leases a
//! short-lived token from an in-process fake `OpenBao` for an admitted attempt whose manifest
//! grants it, its egress proxy injects the token into the workload's request to a fake
//! upstream, and the token never reaches the sandbox, the evidence log, the node's state or
//! any answer. The lease is revoked at the provider when the attempt ends, when it is
//! revoked, and when a killed node restarts; a sealed provider fails closed with a recorded
//! denial and a `403` for the workload.
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
    AgentId, Blake3Hash, DelegationId, DenyReason, ExecutionAttemptId, LeaseId, NodeId,
    PrincipalId, RevokeReason, SessionId, SnapshotId, TaskId, WardEvent,
};
use ward_node::credentials::{LEASES_FILE, credentials_dir};
use ward_node::evidence;
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityDiscoveryContext,
    CapabilityDiscoveryResponse, CapabilityManifestBytes, HandshakeRequest, HandshakeResponse,
    IssuerProof, IssuerSignature, NodeCapabilities, OperationId, ProtocolVersion,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskExecutionOutcome, TaskLifecycleContext, TaskLifecycleRejectionReason, TaskLifecycleRequest,
    TaskLifecycleResponse, TaskLifecycleState, TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
};

const NODE: NodeId = NodeId::from_u128(4);
const BROKER_TOKEN: &str = "fake-broker-provider-token";
const LEASED: &str = "hvs.node-leased-token-for-the-upstream";
const ACCESSOR: &str = "node-lease-accessor-handle";

/// The workload: one request for the `artifacts` route through the proxy socket, carrying a
/// placeholder the proxy must replace; what it got back and its environment go to the
/// workspace; with `hold`, it then waits to be ended.
const WORKLOAD: &str = r#"
import os, socket, sys, time
peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
peer.settimeout(20)
peer.connect(os.environ["WARD_PROXY_SOCKET"])
peer.sendall(b"GET /artifacts/v1/data HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer placeholder\r\nConnection: close\r\n\r\n")
answer = b""
while True:
    chunk = peer.recv(4096)
    if not chunk:
        break
    answer += chunk
open("/work/env.txt", "w").write(repr(dict(os.environ)))
open("/work/answer.txt", "wb").write(answer)
if sys.argv[1] == "hold":
    while True:
        time.sleep(0.05)
sys.exit(0 if answer.startswith(b"HTTP/1.1 200") else 3)
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

/// Wait until `done` holds, polling; fail once `what` has not happened within 20 seconds.
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
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
    sealed: bool,
    issued: Vec<Value>,
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

    fn seal(&self) {
        self.state.lock().unwrap().sealed = true;
    }

    fn issued(&self) -> Vec<Value> {
        self.state.lock().unwrap().issued.clone()
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
    if state.lock().unwrap().sealed {
        return reply(&mut stream, 503, &json!({"errors": ["sealed"]}));
    }
    if headers.get("x-vault-token").map(String::as_str) != Some(BROKER_TOKEN) {
        return reply(&mut stream, 403, &json!({"errors": ["permission denied"]}));
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if line.starts_with("POST /v1/auth/token/create/") {
        let ttl = body["ttl"]
            .as_str()
            .and_then(|ttl| ttl.trim_end_matches('s').parse::<u64>().ok())
            .unwrap_or(0);
        state.lock().unwrap().issued.push(body.clone());
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

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------------------

fn manifest(ttl_secs: u32) -> CapabilityManifestBytes {
    CapabilityManifestBytes::new(
        format!(
            r#"{{"network":{{"custom":["localhost"]}},"credentials":[{{"service":"artifacts","host":"localhost","ttl_secs":{ttl_secs}}}]}}"#
        )
        .into_bytes(),
    )
    .unwrap()
}

fn signed_admit(
    snapshot: SnapshotId,
    argv: &[&str],
    manifest: CapabilityManifestBytes,
    version: u64,
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
            30_000,
        )
        .unwrap(),
        issued_at_unix_ms: now - 60_000,
        expires_at_unix_ms: now + 600_000,
        version: AdmissionVersion::new(version).unwrap(),
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

[service.artifacts]
provider = "bao"
engine = "token"
role = "ward-artifacts"
permissions = ["artifacts-read"]
max_ttl_secs = 600
upstream = "localhost:{upstream}"
value_prefix = "Bearer "
paths = ["/v1"]
plain_upstream = true
"#,
            bao = bao.port,
            token = token.display(),
            upstream = upstream.port,
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
    answers: Arc<Mutex<Vec<String>>>,
}

impl Node {
    fn spawn(dir: &Path, credentials: Option<&Path>) -> Self {
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
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(credentials) = credentials {
            command.arg("--credentials").arg(credentials);
        }
        let mut child = command.spawn().unwrap();
        eventually("ward-node binding its socket", || {
            assert!(
                child.try_wait().unwrap().is_none(),
                "ward-node exited before serving"
            );
            UnixStream::connect(&socket).is_ok()
        });
        Self {
            child,
            socket,
            answers: Arc::default(),
        }
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
        self.answers.lock().unwrap().push(response.clone());
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

    fn state(&self) -> TaskLifecycleResponse {
        self.lifecycle(&context().inspect(binding()))
    }

    fn admit_and_start(&self, snapshot: SnapshotId, hold: &str, ttl_secs: u32) {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding())),
            ctx.accepted(op(1), binding(), TaskLifecycleState::Created)
        );
        assert_eq!(
            self.lifecycle(&signed_admit(
                snapshot,
                &["python3", "-c", WORKLOAD, hold],
                manifest(ttl_secs),
                1
            )),
            ctx.accepted(op(2), binding(), TaskLifecycleState::Ready)
        );
        assert_eq!(
            self.lifecycle(&ctx.start(op(3), binding())),
            ctx.accepted(op(3), binding(), TaskLifecycleState::Running)
        );
    }

    fn answers(&self) -> Vec<String> {
        self.answers.lock().unwrap().clone()
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

fn every_byte_under(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        if metadata.is_dir() {
            all.extend(every_byte_under(&path));
        } else if metadata.is_file() {
            all.extend(std::fs::read(&path).unwrap_or_default());
        }
    }
    all
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

fn revoked(reason: RevokeReason) -> impl Fn(&WardEvent) -> bool {
    move |event| {
        matches!(event, WardEvent::CredentialRevoked { service, reason: why }
            if service.as_str() == "artifacts" && *why == reason)
    }
}

// ---------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------

#[test]
fn a_node_without_credentials_neither_advertises_nor_admits_a_credentials_grant() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let dir = private_dir();
    let snapshot = imported(&dir.path().join("state"), dir.path());
    let node = Node::spawn(dir.path(), None);
    let credentials = node.capabilities().credentials();
    assert!(!credentials.proxy_injection && !credentials.scoped_http_gateway);
    node.lifecycle(&context().create(op(1), binding()));
    assert_eq!(
        node.lifecycle(&signed_admit(snapshot, &["true"], manifest(60), 1)),
        context().rejected(
            Some(op(2)),
            binding(),
            TaskLifecycleRejectionReason::UnsupportedGrant
        )
    );
    assert_eq!(
        node.state(),
        context().inspected(binding(), TaskLifecycleState::Created)
    );
}

#[test]
fn a_brokering_node_refuses_a_grant_above_its_ceiling_and_admits_one_within_it() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let dir = private_dir();
    let (bao, upstream) = (FakeBao::start(), Upstream::start());
    let snapshot = imported(&dir.path().join("state"), dir.path());
    let node = Node::spawn(
        dir.path(),
        Some(&credentials_file(dir.path(), &bao, &upstream)),
    );
    let credentials = node.capabilities().credentials();
    assert!(credentials.proxy_injection && credentials.scoped_http_gateway);
    node.lifecycle(&context().create(op(1), binding()));
    assert_eq!(
        node.lifecycle(&signed_admit(snapshot, &["true"], manifest(601), 1)),
        context().rejected(
            Some(op(2)),
            binding(),
            TaskLifecycleRejectionReason::UnsupportedGrant
        )
    );
    let unlisted = CapabilityManifestBytes::new(
        br#"{"network":{"custom":["example.com"]},"credentials":[{"service":"artifacts","host":"localhost","ttl_secs":60}]}"#.to_vec(),
    );
    assert!(
        unlisted.is_err(),
        "a host outside the allowlist fails decoding"
    );
    assert_eq!(
        node.lifecycle(&signed_admit(snapshot, &["true"], manifest(600), 1)),
        context().accepted(op(2), binding(), TaskLifecycleState::Ready)
    );
    assert!(bao.issued().is_empty(), "admission asks no provider");
}

#[test]
fn the_proxy_injects_a_lease_the_sandbox_never_sees_and_the_end_of_the_attempt_revokes_it() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let dir = private_dir();
    let (bao, upstream) = (FakeBao::start(), Upstream::start());
    let snapshot = imported(&dir.path().join("state"), dir.path());
    let node = Node::spawn(
        dir.path(),
        Some(&credentials_file(dir.path(), &bao, &upstream)),
    );
    node.admit_and_start(snapshot, "exit", 600);
    eventually("the attempt's end", || {
        node.state() != context().inspected(binding(), TaskLifecycleState::Running)
    });
    assert_eq!(
        node.state(),
        context()
            .inspected_with_outcome(
                binding(),
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Completed
            )
            .unwrap()
    );

    let heads = upstream.heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(heads[0].starts_with("GET /v1/data HTTP/1.1"), "{heads:?}");
    assert!(
        heads[0].contains(&format!("authorization: Bearer {LEASED}")),
        "{heads:?}"
    );
    assert!(!heads[0].contains("placeholder"), "{heads:?}");
    let issued = bao.issued();
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0]["ttl"], "30s", "the budget bounds the lease");
    assert_eq!(issued[0]["meta"]["ward_audience"], "localhost");
    assert_eq!(
        issued[0]["meta"]["ward_session"],
        binding().attempt().to_string()
    );
    assert_eq!(bao.revoked(), [ACCESSOR]);

    let answer = std::fs::read_to_string(workspace(dir.path()).join("answer.txt")).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(
        std::fs::read_to_string(workspace(dir.path()).join("env.txt"))
            .unwrap()
            .contains("WARD_PROXY_SOCKET")
    );

    let events = records(dir.path());
    let granted = position(&events, |event| {
        matches!(event, WardEvent::CredentialGranted { service, scope, .. }
            if service.as_str() == "artifacts"
                && scope.subject.content().starts_with("issued localhost lease b3:"))
    });
    let launched = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptLaunched { .. })
    });
    let used = position(&events, |event| {
        matches!(event, WardEvent::NetworkRequested { host, decision: ward_events::Decision::Allow, .. }
            if host.as_str() == "localhost")
    });
    let end_revoked = position(&events, revoked(RevokeReason::SessionEnded));
    let ended = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptEnded { .. })
    });
    assert!(granted < launched && launched < used && used < end_revoked && end_revoked < ended);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, WardEvent::CredentialDenied { .. }))
    );

    assert_eq!(
        node.lifecycle(&context().seal(op(4), binding())),
        context().accepted(op(4), binding(), TaskLifecycleState::Sealed)
    );
    assert!(
        !credentials_dir(&dir.path().join("tasks"), binding())
            .join(LEASES_FILE)
            .exists()
    );
    let everything = [
        every_byte_under(&dir.path().join("state")),
        every_byte_under(&dir.path().join("tasks")),
        node.answers().concat().into_bytes(),
    ]
    .concat();
    assert!(!contains(&everything, LEASED), "the leased token leaked");
    assert!(
        !contains(&everything, BROKER_TOKEN),
        "the provider token leaked"
    );
    assert!(
        !contains(&everything, ACCESSOR),
        "the revocation handle outlived its lease"
    );
}

#[test]
fn revoking_the_attempt_withdraws_the_route_and_revokes_the_lease_at_the_provider() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let dir = private_dir();
    let (bao, upstream) = (FakeBao::start(), Upstream::start());
    let snapshot = imported(&dir.path().join("state"), dir.path());
    let node = Node::spawn(
        dir.path(),
        Some(&credentials_file(dir.path(), &bao, &upstream)),
    );
    node.admit_and_start(snapshot, "hold", 60);
    eventually("the workload's answer", || {
        workspace(dir.path()).join("answer.txt").exists()
    });
    assert!(
        credentials_dir(&dir.path().join("tasks"), binding())
            .join(LEASES_FILE)
            .exists(),
        "the handle is kept while the lease lives"
    );
    assert!(bao.revoked().is_empty());
    assert_eq!(
        node.lifecycle(&context().revoke(op(4), binding())),
        context().accepted(op(4), binding(), TaskLifecycleState::Revoked)
    );
    assert_eq!(bao.revoked(), [ACCESSOR]);
    assert!(
        !credentials_dir(&dir.path().join("tasks"), binding())
            .join(LEASES_FILE)
            .exists()
    );
    let events = records(dir.path());
    let user_revoked = position(&events, revoked(RevokeReason::UserRevoked));
    let ended = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptEnded { .. })
    });
    assert!(user_revoked < ended);
    assert_eq!(upstream.heads().len(), 1);
    let everything = [
        every_byte_under(&dir.path().join("state")),
        every_byte_under(&dir.path().join("tasks")),
        node.answers().concat().into_bytes(),
    ]
    .concat();
    assert!(!contains(&everything, LEASED));
}

#[test]
fn a_sealed_provider_fails_closed_with_a_recorded_denial_and_a_refused_request() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let dir = private_dir();
    let (bao, upstream) = (FakeBao::start(), Upstream::start());
    bao.seal();
    let snapshot = imported(&dir.path().join("state"), dir.path());
    let node = Node::spawn(
        dir.path(),
        Some(&credentials_file(dir.path(), &bao, &upstream)),
    );
    node.admit_and_start(snapshot, "exit", 60);
    eventually("the attempt's end", || {
        node.state() != context().inspected(binding(), TaskLifecycleState::Running)
    });
    assert_eq!(
        node.state(),
        context()
            .inspected_with_outcome(
                binding(),
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Failed
            )
            .unwrap()
    );
    let answer = std::fs::read_to_string(workspace(dir.path()).join("answer.txt")).unwrap();
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
    assert!(upstream.heads().is_empty(), "nothing reached the upstream");
    assert!(bao.issued().is_empty() && bao.revoked().is_empty());

    let events = records(dir.path());
    let denied = position(&events, |event| {
        matches!(event, WardEvent::CredentialDenied { service, reason: DenyReason::PolicyDeny { rule }, .. }
            if service.as_str() == "artifacts" && rule.as_str() == "credential-provider:bao:sealed")
    });
    let launched = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptLaunched { .. })
    });
    assert!(denied < launched);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, WardEvent::NetworkDenied { .. })),
        "the refusal is recorded: {events:?}"
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        WardEvent::CredentialGranted { .. } | WardEvent::CredentialRevoked { .. }
    )));
}

#[test]
fn a_restarted_node_revokes_the_lease_a_killed_node_left_before_it_serves() {
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation unavailable");
        return;
    }
    let dir = private_dir();
    let (bao, upstream) = (FakeBao::start(), Upstream::start());
    let snapshot = imported(&dir.path().join("state"), dir.path());
    let credentials = credentials_file(dir.path(), &bao, &upstream);
    let mut node = Node::spawn(dir.path(), Some(&credentials));
    node.admit_and_start(snapshot, "hold", 60);
    eventually("the workload's answer", || {
        workspace(dir.path()).join("answer.txt").exists()
    });
    node.child.kill().unwrap();
    node.child.wait().unwrap();
    assert!(bao.revoked().is_empty(), "a killed node revokes nothing");
    drop(node);

    let restarted = Node::spawn(dir.path(), Some(&credentials));
    assert_eq!(bao.revoked(), [ACCESSOR]);
    assert_eq!(
        restarted.state(),
        context()
            .inspected_with_outcome(
                binding(),
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Unknown
            )
            .unwrap()
    );
    assert!(
        !credentials_dir(&dir.path().join("tasks"), binding())
            .join(LEASES_FILE)
            .exists()
    );
    let events = records(dir.path());
    let recovered_revoked = position(&events, revoked(RevokeReason::SessionEnded));
    let recovered = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptRecovered { .. })
    });
    assert!(recovered_revoked < recovered);
}
