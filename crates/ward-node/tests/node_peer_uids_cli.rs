//! End-to-end `ward-node` socket access for named client uids (#262): the socket's mode
//! and group with and without `--client-group`, the peer-credential gate that closes a
//! connection from an unlisted uid without a response, and the rule that an allowed uid
//! still needs a trusted signature to `admit`.
//!
//! The mode, group and parsing cases run everywhere. The cases that connect as a second
//! uid need root (they switch to `nobody` with `setpriv`) and skip without it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::signature::{Ed25519KeyPair, KeyPair};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId,
};
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityDiscoveryContext, HandshakeRequest,
    HandshakeResponse, IssuerProof, IssuerSignature, OperationId, ProtocolVersion,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskLifecycleContext, TaskLifecycleRejectionReason, TaskLifecycleRequest,
    TaskLifecycleResponse, TaskLifecycleState, TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
};

const NODE: NodeId = NodeId::from_u128(4);
const SECOND_USER: &str = "nobody";
const SECOND_GROUP: &str = "nogroup";
/// A uid no test host assigns to the test process or to `nobody`.
const UNRELATED_UID: u32 = 4_000_001;

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

fn context() -> TaskLifecycleContext {
    TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
}

fn hello() -> String {
    serde_json::to_string(&HandshakeRequest::Hello {
        protocol: WARD_NODE_PROTOCOL,
    })
    .unwrap()
}

/// An `admit` signed by a key no node in this file trusts.
fn untrusted_signed_admit(operation: u64, version: u64) -> TaskLifecycleRequest {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let binding = binding();
    let now = now_ms();
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer: PrincipalId::from_u128(2),
            subject: AgentId::from_u128(3),
            task: binding.task(),
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
        binding,
        agent: AgentId::from_u128(3),
        node: NODE,
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(vec!["/bin/true".to_owned()]).unwrap(),
            ward_node_protocol::CapabilityManifestBytes::new(br#"{"network":"offline"}"#.to_vec())
                .unwrap(),
            SnapshotId::new(Blake3Hash::hash(b"snapshot")),
            600_000,
        )
        .unwrap(),
        issued_at_unix_ms: now - 60_000,
        expires_at_unix_ms: now + 600_000,
        version: AdmissionVersion::new(version).unwrap(),
    })
    .unwrap();
    let json = AdmissionEnvelopeJson::encode(&envelope).unwrap();
    let proof = IssuerProof::new(
        Blake3Hash::hash(key.public_key().as_ref()),
        IssuerSignature::from_bytes(key.sign(json.as_bytes()).as_ref().try_into().unwrap()),
    );
    context()
        .admit(OperationId::new(operation).unwrap(), binding, json, proof)
        .unwrap()
}

struct Node {
    child: Child,
    socket: PathBuf,
}

impl Node {
    fn command(dir: &Path, extra: &[&str]) -> (Command, PathBuf) {
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
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        (command, socket)
    }

    fn spawn(dir: &Path, extra: &[&str]) -> Self {
        let (mut command, socket) = Self::command(dir, extra);
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
        Self { child, socket }
    }

    /// The node refuses to start with `extra`: a failing exit and no socket.
    fn refuses_to_start(dir: &Path, extra: &[&str]) {
        let (mut command, socket) = Self::command(dir, extra);
        let status = command.status().unwrap();
        assert!(!status.success(), "ward-node started with {extra:?}");
        assert!(
            !socket.exists(),
            "ward-node bound {} with {extra:?}",
            socket.display()
        );
    }

    fn mode(&self) -> u32 {
        std::fs::metadata(&self.socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn gid(&self) -> u32 {
        std::fs::metadata(&self.socket).unwrap().gid()
    }

    fn request(&self, request: &str) -> String {
        let mut client = UnixStream::connect(&self.socket).unwrap();
        writeln!(client, "{}", hello()).unwrap();
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

    fn discovers_capabilities(&self) {
        let ctx = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
        let raw = self.request(&serde_json::to_string(&ctx.request()).unwrap());
        ctx.decode_response(&raw).unwrap();
    }

    /// One connection as `SECOND_USER`: `lines` are written at once, then everything the
    /// node sends until it closes the connection, with a closed-before-answer connection
    /// (EOF or a reset) read as no bytes at all.
    fn exchange_as_second_user(&self, lines: &[String]) -> Vec<u8> {
        let mut child = Command::new("setpriv")
            .args([
                &format!("--reuid={SECOND_USER}"),
                &format!("--regid={SECOND_GROUP}"),
                "--clear-groups",
                "python3",
                "-c",
                SECOND_USER_CLIENT,
            ])
            .arg(&self.socket)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        {
            let mut stdin = child.stdin.take().unwrap();
            for line in lines {
                writeln!(stdin, "{line}").unwrap();
            }
        }
        let mut stdout = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        assert!(child.wait().unwrap().success(), "second-user client failed");
        stdout
    }
}

const SECOND_USER_CLIENT: &str = r"
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(30)
s.connect(sys.argv[1])
# The node closes an unlisted peer without reading it, which may happen before
# this send has finished: a broken pipe here is the refusal under test.
try:
    s.sendall(sys.stdin.buffer.read())
except (BrokenPipeError, ConnectionResetError):
    pass
out = b''
try:
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        out += chunk
except ConnectionResetError:
    pass
sys.stdout.buffer.write(out)
";

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// A socket directory shared with `group`: mode 0750, group-owned by `group`.
fn shared_dir(group: u32) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::chown(dir.path(), None, Some(group)).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    dir
}

fn own_uid() -> u32 {
    let probe = tempfile::tempdir().unwrap();
    std::fs::metadata(probe.path()).unwrap().uid()
}

fn own_gid() -> u32 {
    let probe = tempfile::tempdir().unwrap();
    std::fs::metadata(probe.path()).unwrap().gid()
}

fn second_user_gid() -> u32 {
    let output = Command::new("getent")
        .args(["group", SECOND_GROUP])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{SECOND_GROUP} is not a group here"
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .split(':')
        .nth(2)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// Whether this process can connect as a second uid; the reason when it cannot.
fn second_user_available() -> Result<(), &'static str> {
    if own_uid() != 0 {
        return Err("not root: cannot switch to a second uid");
    }
    for tool in ["setpriv", "python3", "getent"] {
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !found {
            return Err("setpriv, python3 and getent are needed to connect as a second uid");
        }
    }
    let known = Command::new("getent")
        .args(["passwd", SECOND_USER])
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !known {
        return Err("no `nobody` user to connect as");
    }
    Ok(())
}

#[test]
fn without_client_flags_the_socket_is_mode_0600_and_the_node_serves_its_own_uid() {
    let dir = private_dir();
    let node = Node::spawn(dir.path(), &[]);
    assert_eq!(node.mode(), 0o600);
    assert_eq!(node.gid(), own_gid());
    node.discovers_capabilities();
}

#[test]
fn with_a_client_group_the_socket_is_mode_0660_owned_by_that_group() {
    let gid = own_gid();
    let dir = shared_dir(gid);
    let unrelated = UNRELATED_UID.to_string();
    let node = Node::spawn(
        dir.path(),
        &[
            "--client-group",
            &gid.to_string(),
            "--client-uid",
            &unrelated,
        ],
    );
    assert_eq!(node.mode(), 0o660);
    assert_eq!(node.gid(), gid);
    node.discovers_capabilities();
}

#[test]
fn a_client_group_needs_a_group_owned_directory_without_other_or_group_write_bits() {
    let gid = own_gid().to_string();
    let unrelated = UNRELATED_UID.to_string();
    let shared = [
        "--client-group",
        gid.as_str(),
        "--client-uid",
        unrelated.as_str(),
    ];

    let private = private_dir();
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
    Node::refuses_to_start(private.path(), &shared);
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    Node::refuses_to_start(private.path(), &shared);

    let dir = shared_dir(own_gid());
    Node::refuses_to_start(dir.path(), &["--client-uid", &unrelated]);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(Node::spawn(dir.path(), &["--client-uid", &unrelated]));
}

#[test]
fn client_flags_are_validated_at_start() {
    let gid = own_gid().to_string();
    let dir = shared_dir(own_gid());
    Node::refuses_to_start(dir.path(), &["--client-group", &gid]);
    Node::refuses_to_start(
        dir.path(),
        &["--client-group", &gid, "--client-uid", "no-such-user-here"],
    );
    Node::refuses_to_start(
        dir.path(),
        &[
            "--client-group",
            &gid,
            "--client-uid",
            "7",
            "--client-uid",
            "7",
        ],
    );
    Node::refuses_to_start(
        dir.path(),
        &["--client-group", "no-such-group-here", "--client-uid", "7"],
    );
}

#[test]
fn a_connection_from_an_unlisted_uid_is_closed_without_a_response() {
    if let Err(reason) = second_user_available() {
        eprintln!("skipping: {reason}");
        return;
    }
    let gid = second_user_gid();
    let dir = shared_dir(gid);
    let node = Node::spawn(
        dir.path(),
        &[
            "--client-group",
            SECOND_GROUP,
            "--client-uid",
            &UNRELATED_UID.to_string(),
        ],
    );
    let ctx = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
    let discovery = serde_json::to_string(&ctx.request()).unwrap();
    for _ in 0..3 {
        let answer = node.exchange_as_second_user(&[hello(), discovery.clone()]);
        assert!(answer.is_empty(), "unlisted uid was answered: {answer:?}");
    }
    node.discovers_capabilities();
}

#[test]
fn a_listed_uid_is_served_and_still_needs_a_trusted_signature_to_admit() {
    let ctx = context();
    let create =
        serde_json::to_string(&ctx.create(OperationId::new(1).unwrap(), binding())).unwrap();
    let admit = serde_json::to_string(&untrusted_signed_admit(2, 1)).unwrap();
    let inspect = serde_json::to_string(&ctx.inspect(binding())).unwrap();
    let refused = ctx.rejected(
        Some(OperationId::new(2).unwrap()),
        binding(),
        TaskLifecycleRejectionReason::AuthorityDenied,
    );

    let own = private_dir();
    let node = Node::spawn(own.path(), &["--client-uid", &UNRELATED_UID.to_string()]);
    node.lifecycle(&ctx.create(OperationId::new(1).unwrap(), binding()));
    assert_eq!(node.lifecycle(&untrusted_signed_admit(2, 1)), refused);
    assert_eq!(
        node.lifecycle(&ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Created)
    );
    drop(node);

    if let Err(reason) = second_user_available() {
        eprintln!("skipping the second-uid half: {reason}");
        return;
    }
    let dir = shared_dir(second_user_gid());
    let node = Node::spawn(
        dir.path(),
        &["--client-group", SECOND_GROUP, "--client-uid", SECOND_USER],
    );
    let answer = |request: &str| -> TaskLifecycleResponse {
        let raw = node.exchange_as_second_user(&[hello(), request.to_owned()]);
        let text = String::from_utf8(raw).unwrap();
        let mut lines = text.lines();
        assert_eq!(
            serde_json::from_str::<HandshakeResponse>(lines.next().unwrap()).unwrap(),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 3)
            }
        );
        ctx.decode_response(lines.next().unwrap()).unwrap()
    };
    answer(&create);
    assert_eq!(answer(&admit), refused);
    assert_eq!(
        answer(&inspect),
        ctx.inspected(binding(), TaskLifecycleState::Created)
    );
}
