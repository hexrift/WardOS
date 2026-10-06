//! End-to-end `ward-node --listen-tls` (#262, ADR-0038): the node protocol over TLS 1.3
//! with a mandatory client certificate, served beside the unchanged Unix socket.
//!
//! A client whose certificate chains to the operator's client CA (and, with
//! `--tls-client-pin`, whose key is pinned) is served exactly what the socket serves. No
//! client certificate, one from another CA, an expired or not-yet-valid one, an unpinned
//! key, a plaintext client, TLS 1.2 and a client without the `ward-node` ALPN are closed
//! without a protocol byte, and each refusal is reported on the node's stderr. A served
//! TLS client still needs a trusted issuer signature to `admit`, and a replayed `admit` is
//! answered without acting twice. Unsafe or inconsistent TLS files stop the node before
//! it binds anything, and a rotated client CA takes effect on restart without losing a
//! task. Every certificate and key is generated here; none is committed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SanType, date_time_ymd,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned, SupportedProtocolVersion,
};
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
const ISSUER: PrincipalId = PrincipalId::from_u128(2);
const TRUSTED_SEED: [u8; 32] = [9; 32];
const UNTRUSTED_SEED: [u8; 32] = [7; 32];
const SERVER_NAME: &str = "node-4.ward.test";
const STARTUP: Duration = Duration::from_secs(20);
static TLS13_ONLY: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
static TLS12_ONLY: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS12];

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

// ---- generated PKI --------------------------------------------------------------------

fn ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

struct Leaf {
    cert_pem: String,
    key_pem: String,
    cert: CertificateDer<'static>,
    key: Vec<u8>,
    spki: Vec<u8>,
}

impl Leaf {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()))
    }

    fn pin(&self) -> String {
        format!(
            "sha256:{}",
            hex(ring::digest::digest(&ring::digest::SHA256, &self.spki).as_ref())
        )
    }
}

#[derive(Clone, Copy)]
enum Validity {
    Current,
    Expired,
    NotYetValid,
}

fn leaf(
    issuer: &CertifiedIssuer<'static, KeyPair>,
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    validity: Validity,
) -> Leaf {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.subject_alt_names = vec![SanType::DnsName(name.try_into().unwrap())];
    params.extended_key_usages = vec![usage];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    match validity {
        Validity::Current => {}
        Validity::Expired => {
            params.not_before = date_time_ymd(2001, 1, 1);
            params.not_after = date_time_ymd(2002, 1, 1);
        }
        Validity::NotYetValid => {
            params.not_before = date_time_ymd(2090, 1, 1);
            params.not_after = date_time_ymd(2091, 1, 1);
        }
    }
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    Leaf {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert: cert.der().clone(),
        key: key.serialize_der(),
        spki: key.subject_public_key_info(),
    }
}

fn client_leaf(issuer: &CertifiedIssuer<'static, KeyPair>, validity: Validity) -> Leaf {
    leaf(
        issuer,
        "control-plane.ward.test",
        ExtendedKeyUsagePurpose::ClientAuth,
        validity,
    )
}

/// The node's TLS files: its server certificate and key from `server_ca`, and the client
/// CA it trusts.
struct NodeTlsFiles {
    cert: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
}

fn write_mode(path: &Path, contents: &str, mode: u32) {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn node_tls_files(
    dir: &Path,
    server_ca: &CertifiedIssuer<'static, KeyPair>,
    client_ca: &CertifiedIssuer<'static, KeyPair>,
) -> NodeTlsFiles {
    let server = leaf(
        server_ca,
        SERVER_NAME,
        ExtendedKeyUsagePurpose::ServerAuth,
        Validity::Current,
    );
    let files = NodeTlsFiles {
        cert: dir.join("node-cert.pem"),
        key: dir.join("node-key.pem"),
        client_ca: dir.join("client-ca.pem"),
    };
    write_mode(&files.cert, &server.cert_pem, 0o644);
    write_mode(&files.key, &server.key_pem, 0o600);
    write_mode(&files.client_ca, &client_ca.pem(), 0o644);
    files
}

impl NodeTlsFiles {
    fn args(&self) -> Vec<String> {
        vec![
            "--listen-tls".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--tls-cert".to_owned(),
            self.cert.display().to_string(),
            "--tls-key".to_owned(),
            self.key.display().to_string(),
            "--tls-client-ca".to_owned(),
            self.client_ca.display().to_string(),
        ]
    }
}

// ---- the node -------------------------------------------------------------------------

struct Node {
    child: Child,
    socket: PathBuf,
    addr: SocketAddr,
    stderr: Receiver<String>,
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn trust_store(dir: &Path) -> PathBuf {
    let key = Ed25519KeyPair::from_seed_unchecked(&TRUSTED_SEED).unwrap();
    let path = dir.join("trusted-issuers");
    write_mode(
        &path,
        &format!("{} {ISSUER}\n", hex(key.public_key().as_ref())),
        0o600,
    );
    path
}

impl Node {
    fn command(dir: &Path, extra: &[String]) -> (Command, PathBuf) {
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
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        (command, socket)
    }

    /// Start the node and wait for it to say where it serves TLS; its stderr lines keep
    /// arriving on `stderr`.
    fn spawn(dir: &Path, extra: &[String]) -> Self {
        let (mut command, socket) = Self::command(dir, extra);
        let mut child = command.spawn().unwrap();
        let (lines, stderr) = channel();
        let pipe = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines() {
                let Ok(line) = line else { break };
                if lines.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + STARTUP;
        let addr = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match stderr.recv_timeout(remaining) {
                Ok(line) => {
                    if let Some(addr) = line
                        .strip_prefix("ward-node: serving the node protocol over mutual TLS on ")
                    {
                        break addr.parse::<SocketAddr>().unwrap();
                    }
                }
                Err(error) => panic!(
                    "ward-node never reported its TLS listener ({error:?}); exited: {:?}",
                    child.try_wait()
                ),
            }
        };
        let deadline = Instant::now() + STARTUP;
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
            addr,
            stderr,
        }
    }

    /// The node refuses to start with `extra`: a failing exit, no socket, and the reason
    /// on stderr, which is returned.
    fn refuses_to_start(dir: &Path, extra: &[String]) -> String {
        let (mut command, socket) = Self::command(dir, extra);
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            !output.status.success(),
            "ward-node started with {extra:?}: {stderr}"
        );
        assert!(
            !socket.exists(),
            "ward-node bound {} with {extra:?}",
            socket.display()
        );
        stderr
    }

    /// The next stderr line containing `needle`, within `timeout`.
    fn reported(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.stderr.recv_timeout(remaining) {
                Ok(line) if line.contains(needle) => return line,
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    panic!("the node never reported {needle:?}")
                }
            }
        }
    }

    /// Both answer lines of one exchange over the Unix socket.
    fn unix_exchange(&self, request: &str) -> Vec<String> {
        let mut client = UnixStream::connect(&self.socket).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        writeln!(client, "{}\n{request}", hello()).unwrap();
        BufReader::new(client)
            .lines()
            .map_while(Result::ok)
            .collect()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- protocol -------------------------------------------------------------------------

fn hello() -> String {
    serde_json::to_string(&HandshakeRequest::Hello {
        protocol: WARD_NODE_PROTOCOL,
    })
    .unwrap()
}

fn context() -> TaskLifecycleContext {
    TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
}

fn discovery() -> String {
    let ctx = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
    serde_json::to_string(&ctx.request()).unwrap()
}

fn binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

fn signed_admit(seed: [u8; 32], operation: u64, version: u64) -> TaskLifecycleRequest {
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let binding = binding();
    let now = now_ms();
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer: ISSUER,
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

// ---- TLS clients ----------------------------------------------------------------------

struct TlsClient {
    roots: RootCertStore,
    identity: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
    versions: &'static [&'static SupportedProtocolVersion],
    alpn: bool,
}

impl TlsClient {
    fn new(server_ca: &CertifiedIssuer<'static, KeyPair>, identity: Option<&Leaf>) -> Self {
        let mut roots = RootCertStore::empty();
        roots.add(server_ca.der().clone()).unwrap();
        Self {
            roots,
            identity: identity.map(|leaf| (leaf.cert.clone(), leaf.key())),
            versions: &TLS13_ONLY,
            alpn: true,
        }
    }

    fn config(&self) -> Arc<ClientConfig> {
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(self.versions)
                .unwrap()
                .with_root_certificates(self.roots.clone());
        let mut config = match &self.identity {
            Some((cert, key)) => builder
                .with_client_auth_cert(vec![cert.clone()], key.clone_key())
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        if self.alpn {
            config.alpn_protocols = vec![b"ward-node".to_vec()];
        }
        Arc::new(config)
    }

    /// Write `lines` at once and read every line the node sends until it closes; a TLS
    /// failure ends the reading like a close, so what came back is all there is.
    fn exchange(&self, addr: SocketAddr, lines: &[String]) -> Vec<String> {
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let connection = ClientConnection::new(
            self.config(),
            ServerName::try_from(SERVER_NAME.to_owned()).unwrap(),
        )
        .unwrap();
        let mut stream = StreamOwned::new(connection, tcp);
        let mut payload = String::new();
        for line in lines {
            payload.push_str(line);
            payload.push('\n');
        }
        if stream.write_all(payload.as_bytes()).is_err() || stream.flush().is_err() {
            return Vec::new();
        }
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        String::from_utf8_lossy(&received)
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn served(&self, node: &Node, request: &str) -> String {
        let lines = self.exchange(node.addr, &[hello(), request.to_owned()]);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(
            serde_json::from_str::<HandshakeResponse>(&lines[0]).unwrap(),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 3)
            }
        );
        lines[1].clone()
    }

    fn lifecycle(&self, node: &Node, request: &TaskLifecycleRequest) -> TaskLifecycleResponse {
        context()
            .decode_response(&self.served(node, &serde_json::to_string(request).unwrap()))
            .unwrap()
    }

    fn refused(&self, node: &Node) {
        let lines = self.exchange(node.addr, &[hello(), discovery()]);
        assert!(
            lines.is_empty(),
            "a refused TLS client was answered: {lines:?}"
        );
    }
}

struct Setup {
    dir: tempfile::TempDir,
    server_ca: CertifiedIssuer<'static, KeyPair>,
    client_ca: CertifiedIssuer<'static, KeyPair>,
    files: NodeTlsFiles,
}

fn setup() -> Setup {
    let dir = private_dir();
    let server_ca = ca("ward test server CA");
    let client_ca = ca("ward test client CA");
    let files = node_tls_files(dir.path(), &server_ca, &client_ca);
    Setup {
        dir,
        server_ca,
        client_ca,
        files,
    }
}

impl Setup {
    fn node(&self, extra: &[String]) -> Node {
        let mut args = self.files.args();
        args.extend_from_slice(extra);
        Node::spawn(self.dir.path(), &args)
    }

    fn client(&self) -> (TlsClient, Leaf) {
        let leaf = client_leaf(&self.client_ca, Validity::Current);
        (TlsClient::new(&self.server_ca, Some(&leaf)), leaf)
    }
}

// ---- served ---------------------------------------------------------------------------

#[test]
fn a_client_with_a_valid_certificate_is_served_exactly_what_the_socket_serves() {
    let setup = setup();
    let node = setup.node(&[]);
    let (client, leaf) = setup.client();

    let over_tls = client.served(&node, &discovery());
    let over_socket = node.unix_exchange(&discovery());
    assert_eq!(over_socket.len(), 2, "{over_socket:?}");
    assert_eq!(over_tls, over_socket[1]);
    let line = node.reported("served a TLS client");
    assert!(line.contains(&leaf.pin()), "{line}");
    assert!(line.contains("127.0.0.1"), "{line}");

    let ctx = context();
    let created = client.lifecycle(&node, &ctx.create(OperationId::new(1).unwrap(), binding()));
    assert_eq!(
        created,
        ctx.accepted(
            OperationId::new(1).unwrap(),
            binding(),
            TaskLifecycleState::Created
        )
    );
    let inspected = node.unix_exchange(&serde_json::to_string(&ctx.inspect(binding())).unwrap());
    assert_eq!(
        ctx.decode_response(&inspected[1]).unwrap(),
        ctx.inspected(binding(), TaskLifecycleState::Created),
        "both transports serve one registry"
    );
}

#[test]
fn a_served_tls_client_still_needs_a_trusted_signature_and_a_replay_never_acts_twice() {
    let setup = setup();
    let node = setup.node(&[]);
    let (client, _) = setup.client();
    let ctx = context();
    let op = |id| OperationId::new(id).unwrap();

    client.lifecycle(&node, &ctx.create(op(1), binding()));
    assert_eq!(
        client.lifecycle(&node, &signed_admit(UNTRUSTED_SEED, 2, 1)),
        ctx.rejected(
            Some(op(2)),
            binding(),
            TaskLifecycleRejectionReason::AuthorityDenied
        ),
        "a TLS identity is not issuer authority"
    );
    assert_eq!(
        client.lifecycle(&node, &ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Created)
    );

    let admit = signed_admit(TRUSTED_SEED, 3, 1);
    let admitted = ctx.accepted(op(3), binding(), TaskLifecycleState::Ready);
    assert_eq!(client.lifecycle(&node, &admit), admitted);
    assert_eq!(
        client.lifecycle(&node, &admit),
        admitted,
        "a replayed admit is answered with the current state"
    );
    for (operation, version) in [(4, 1), (5, 2)] {
        assert_eq!(
            client.lifecycle(&node, &signed_admit(TRUSTED_SEED, operation, version)),
            ctx.rejected(
                Some(op(operation)),
                binding(),
                TaskLifecycleRejectionReason::InvalidState
            ),
            "a second admission of an admitted task is refused"
        );
    }
}

#[test]
fn a_pinned_client_key_is_served_and_another_key_from_the_same_ca_is_refused() {
    let setup = setup();
    let (pinned, leaf) = setup.client();
    let node = setup.node(&["--tls-client-pin".to_owned(), leaf.pin()]);
    pinned.served(&node, &discovery());

    let (other, _) = setup.client();
    other.refused(&node);
    let line = node.reported("refused a TLS connection from 127.0.0.1");
    assert!(line.contains("pin"), "{line}");
}

#[test]
fn a_stalled_tls_handshake_does_not_hold_the_unix_socket() {
    let setup = setup();
    let node = setup.node(&[]);
    let _stalled = TcpStream::connect(node.addr).unwrap();
    let started = Instant::now();
    let lines = node.unix_exchange(&discovery());
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the socket waited {:?} behind an unauthenticated TCP peer",
        started.elapsed()
    );
}

// ---- refused --------------------------------------------------------------------------

#[test]
fn a_client_without_a_certificate_is_closed_unanswered_and_reported() {
    let setup = setup();
    let node = setup.node(&[]);
    TlsClient::new(&setup.server_ca, None).refused(&node);
    let line = node.reported("refused a TLS connection from 127.0.0.1");
    assert!(line.contains("no certificate"), "{line}");
}

#[test]
fn a_client_certificate_from_another_ca_is_refused() {
    let setup = setup();
    let node = setup.node(&[]);
    let stranger = client_leaf(&ca("another CA"), Validity::Current);
    TlsClient::new(&setup.server_ca, Some(&stranger)).refused(&node);
    let line = node.reported("refused a TLS connection from 127.0.0.1");
    assert!(line.contains("UnknownIssuer"), "{line}");
}

#[test]
fn an_expired_client_certificate_is_refused() {
    let setup = setup();
    let node = setup.node(&[]);
    let expired = client_leaf(&setup.client_ca, Validity::Expired);
    TlsClient::new(&setup.server_ca, Some(&expired)).refused(&node);
    let line = node.reported("refused a TLS connection from 127.0.0.1");
    assert!(line.contains("expired"), "{line}");
}

#[test]
fn a_not_yet_valid_client_certificate_is_refused() {
    let setup = setup();
    let node = setup.node(&[]);
    let early = client_leaf(&setup.client_ca, Validity::NotYetValid);
    TlsClient::new(&setup.server_ca, Some(&early)).refused(&node);
    let line = node.reported("refused a TLS connection from 127.0.0.1");
    assert!(line.contains("not valid yet"), "{line}");
}

#[test]
fn a_server_certificate_used_as_a_client_certificate_is_refused() {
    let setup = setup();
    let node = setup.node(&[]);
    let server_only = leaf(
        &setup.client_ca,
        "not-a-client.ward.test",
        ExtendedKeyUsagePurpose::ServerAuth,
        Validity::Current,
    );
    TlsClient::new(&setup.server_ca, Some(&server_only)).refused(&node);
    node.reported("refused a TLS connection from 127.0.0.1");
}

#[test]
fn tls_1_2_is_refused() {
    let setup = setup();
    let node = setup.node(&[]);
    let (mut client, _) = setup.client();
    client.versions = &TLS12_ONLY;
    client.refused(&node);
    node.reported("refused a TLS connection from 127.0.0.1");
}

#[test]
fn a_client_that_does_not_name_the_ward_node_protocol_is_refused() {
    let setup = setup();
    let node = setup.node(&[]);
    let (mut client, _) = setup.client();
    client.alpn = false;
    client.refused(&node);
    let line = node.reported("refused a TLS connection from 127.0.0.1");
    assert!(line.contains("ward-node"), "{line}");
}

#[test]
fn a_plaintext_client_is_closed_without_a_protocol_byte() {
    let setup = setup();
    let node = setup.node(&[]);
    let mut tcp = TcpStream::connect(node.addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let _ = writeln!(tcp, "{}\n{}", hello(), discovery());
    let mut received = Vec::new();
    let _ = tcp.read_to_end(&mut received);
    assert!(
        !String::from_utf8_lossy(&received).contains("accepted"),
        "a plaintext client was answered: {received:?}"
    );
    node.reported("refused a TLS connection from 127.0.0.1");
}

// ---- configuration ----------------------------------------------------------------------

fn with(args: &[String], flag: &str, value: &str) -> Vec<String> {
    let mut args = args.to_vec();
    let at = args.iter().position(|arg| arg == flag).unwrap();
    value.clone_into(&mut args[at + 1]);
    args
}

#[test]
fn unsafe_or_inconsistent_tls_files_stop_the_node_before_it_binds() {
    let setup = setup();
    let dir = setup.dir.path();
    let args = setup.files.args();

    let missing = dir.join("missing.pem").display().to_string();
    for flag in ["--tls-cert", "--tls-key", "--tls-client-ca"] {
        let stderr = Node::refuses_to_start(dir, &with(&args, flag, &missing));
        assert!(stderr.contains("missing.pem"), "{flag}: {stderr}");
    }

    let open_key = dir.join("open-key.pem");
    write_mode(
        &open_key,
        &std::fs::read_to_string(&setup.files.key).unwrap(),
        0o640,
    );
    let stderr = Node::refuses_to_start(
        dir,
        &with(&args, "--tls-key", &open_key.display().to_string()),
    );
    assert!(stderr.contains("too open"), "{stderr}");

    let writable_ca = dir.join("writable-ca.pem");
    write_mode(&writable_ca, &setup.client_ca.pem(), 0o666);
    Node::refuses_to_start(
        dir,
        &with(&args, "--tls-client-ca", &writable_ca.display().to_string()),
    );

    let link = dir.join("linked-key.pem");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&setup.files.key, &link).unwrap();
    Node::refuses_to_start(dir, &with(&args, "--tls-key", &link.display().to_string()));

    let other_key = dir.join("other-key.pem");
    write_mode(
        &other_key,
        &KeyPair::generate().unwrap().serialize_pem(),
        0o600,
    );
    let stderr = Node::refuses_to_start(
        dir,
        &with(&args, "--tls-key", &other_key.display().to_string()),
    );
    assert!(stderr.contains("does not match"), "{stderr}");

    let empty = dir.join("empty.pem");
    write_mode(&empty, "", 0o644);
    for flag in ["--tls-cert", "--tls-key", "--tls-client-ca"] {
        Node::refuses_to_start(dir, &with(&args, flag, &empty.display().to_string()));
    }

    for pin in ["sha256:00", "md5:00", &format!("sha256:{}", "A".repeat(64))] {
        let mut pinned = args.clone();
        pinned.extend(["--tls-client-pin".to_owned(), pin.to_owned()]);
        Node::refuses_to_start(dir, &pinned);
    }
    let pin = format!("sha256:{}", "a".repeat(64));
    let mut twice = args.clone();
    twice.extend([
        "--tls-client-pin".to_owned(),
        pin.clone(),
        "--tls-client-pin".to_owned(),
        pin,
    ]);
    Node::refuses_to_start(dir, &twice);

    Node::refuses_to_start(dir, &args[..6]);
    Node::refuses_to_start(dir, &args[2..]);
}

#[test]
fn a_rotated_client_ca_takes_effect_on_restart_and_no_task_is_lost() {
    let setup = setup();
    let (old_client, _) = setup.client();
    {
        let node = setup.node(&[]);
        old_client.lifecycle(
            &node,
            &context().create(OperationId::new(1).unwrap(), binding()),
        );
    }

    let rotated = ca("ward test client CA, rotated");
    write_mode(&setup.files.client_ca, &rotated.pem(), 0o644);
    let node = setup.node(&[]);
    old_client.refused(&node);
    node.reported("refused a TLS connection from 127.0.0.1");
    let new_client = TlsClient::new(
        &setup.server_ca,
        Some(&client_leaf(&rotated, Validity::Current)),
    );
    assert_eq!(
        new_client.lifecycle(&node, &context().inspect(binding())),
        context().inspected(binding(), TaskLifecycleState::Created)
    );
}
