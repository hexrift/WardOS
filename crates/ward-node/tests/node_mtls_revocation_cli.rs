//! End-to-end client-key revocation and reload without restart for `ward-node
//! --listen-tls` (#262, ADR-0038 §8).
//!
//! `--tls-client-revoked <file>` lists client keys the node refuses even when their
//! certificate chains to the client CA and is pinned. On `SIGHUP` the node reads its
//! certificate, key, client CA and revocation list again, swaps them in only when all of
//! them are usable, and otherwise keeps serving what it had; either way it says so on
//! stderr. The process, and with it the task registry, stays up throughout. Every
//! certificate and key is generated here; none is committed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use ward_events::{ExecutionAttemptId, LeaseId, NodeId, PrincipalId, TaskId};
use ward_node::tls::SpkiPin;
use ward_node_protocol::{
    CapabilityDiscoveryContext, HandshakeRequest, OperationId, ProtocolVersion, TaskBinding,
    TaskLifecycleContext, TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState,
    WARD_NODE_PROTOCOL,
};

const NODE: NodeId = NodeId::from_u128(4);
const ISSUER: PrincipalId = PrincipalId::from_u128(2);
const SERVER_NAME: &str = "node-4.ward.test";
const STARTUP: Duration = Duration::from_secs(20);
const RELOADED: &str = "ward-node: reloaded the TLS configuration: ";
const RELOAD_FAILED: &str =
    "ward-node: reloading the TLS configuration failed; still serving the previous one: ";

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

fn leaf(
    issuer: &CertifiedIssuer<'static, KeyPair>,
    name: &str,
    usage: ExtendedKeyUsagePurpose,
) -> Leaf {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.subject_alt_names = vec![SanType::DnsName(name.try_into().unwrap())];
    params.extended_key_usages = vec![usage];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
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

fn server_leaf(issuer: &CertifiedIssuer<'static, KeyPair>) -> Leaf {
    leaf(issuer, SERVER_NAME, ExtendedKeyUsagePurpose::ServerAuth)
}

fn client_leaf(issuer: &CertifiedIssuer<'static, KeyPair>) -> Leaf {
    leaf(
        issuer,
        "control-plane.ward.test",
        ExtendedKeyUsagePurpose::ClientAuth,
    )
}

fn write_mode(path: &Path, contents: &str, mode: u32) {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn trust_store(dir: &Path) -> PathBuf {
    let key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let path = dir.join("trusted-issuers");
    write_mode(
        &path,
        &format!("{} {ISSUER}\n", hex(key.public_key().as_ref())),
        0o600,
    );
    path
}

// ---- the node -------------------------------------------------------------------------

struct Node {
    child: Child,
    socket: PathBuf,
    addr: SocketAddr,
    stderr: Receiver<String>,
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

    /// The next stderr line containing `needle`.
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

    /// Send `SIGHUP` and return what the node says about the reload: the rest of its
    /// line after the success or failure prefix, and whether it succeeded.
    fn hangup(&mut self) -> (bool, String) {
        kill(
            Pid::from_raw(i32::try_from(self.child.id()).unwrap()),
            Signal::SIGHUP,
        )
        .unwrap();
        let line = self.reported("the TLS configuration");
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "ward-node exited on SIGHUP"
        );
        if let Some(rest) = line.strip_prefix(RELOADED) {
            return (true, rest.to_owned());
        }
        if let Some(rest) = line.strip_prefix(RELOAD_FAILED) {
            return (false, rest.to_owned());
        }
        panic!("unexpected reload report {line:?}")
    }

    fn reloads(&mut self) -> String {
        let (reloaded, line) = self.hangup();
        assert!(reloaded, "the reload failed: {line}");
        line
    }

    fn keeps_the_previous_configuration(&mut self) -> String {
        let (reloaded, line) = self.hangup();
        assert!(!reloaded, "the reload succeeded: {line}");
        line
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

// ---- TLS clients ----------------------------------------------------------------------

struct TlsClient {
    roots: RootCertStore,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

/// What one exchange got: every line before the close, and the key the node presented.
struct Exchanged {
    lines: Vec<String>,
    server_key: Option<SpkiPin>,
}

impl TlsClient {
    fn new(server_ca: &CertifiedIssuer<'static, KeyPair>, identity: &Leaf) -> Self {
        let mut roots = RootCertStore::empty();
        roots.add(server_ca.der().clone()).unwrap();
        Self {
            roots,
            cert: identity.cert.clone(),
            key: identity.key(),
        }
    }

    fn config(&self) -> Arc<ClientConfig> {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(self.roots.clone())
                .with_client_auth_cert(vec![self.cert.clone()], self.key.clone_key())
                .unwrap();
        config.alpn_protocols = vec![b"ward-node".to_vec()];
        Arc::new(config)
    }

    fn exchange(&self, addr: SocketAddr, lines: &[String]) -> Exchanged {
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
        let mut received = Vec::new();
        if stream.write_all(payload.as_bytes()).is_ok() && stream.flush().is_ok() {
            let _ = stream.read_to_end(&mut received);
        }
        Exchanged {
            lines: String::from_utf8_lossy(&received)
                .lines()
                .map(str::to_owned)
                .collect(),
            server_key: stream
                .conn
                .peer_certificates()
                .and_then(<[CertificateDer<'_>]>::first)
                .map(|leaf| SpkiPin::of_certificate(leaf).unwrap()),
        }
    }

    fn served(&self, node: &Node, request: &str) -> Exchanged {
        let exchanged = self.exchange(node.addr, &[hello(), request.to_owned()]);
        assert_eq!(exchanged.lines.len(), 2, "{:?}", exchanged.lines);
        assert!(
            exchanged.lines[0].contains("accepted"),
            "{:?}",
            exchanged.lines
        );
        exchanged
    }

    fn lifecycle(&self, node: &Node, request: &TaskLifecycleRequest) -> TaskLifecycleResponse {
        let exchanged = self.served(node, &serde_json::to_string(request).unwrap());
        context().decode_response(&exchanged.lines[1]).unwrap()
    }

    fn refused(&self, node: &Node) {
        let lines = self.exchange(node.addr, &[hello(), discovery()]).lines;
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
    server: Leaf,
    revoked: PathBuf,
}

fn setup() -> Setup {
    let dir = private_dir();
    let server_ca = ca("ward test server CA");
    let client_ca = ca("ward test client CA");
    let server = server_leaf(&server_ca);
    let setup = Setup {
        revoked: dir.path().join("revoked-clients"),
        dir,
        server_ca,
        client_ca,
        server,
    };
    setup.write_server(&setup.server);
    write_mode(&setup.client_ca_path(), &setup.client_ca.pem(), 0o644);
    setup.revoke(&[]);
    setup
}

impl Setup {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn client_ca_path(&self) -> PathBuf {
        self.path("client-ca.pem")
    }

    fn write_server(&self, server: &Leaf) {
        write_mode(&self.path("node-cert.pem"), &server.cert_pem, 0o644);
        write_mode(&self.path("node-key.pem"), &server.key_pem, 0o600);
    }

    /// Write the revocation list naming `keys`, with the comments an operator keeps.
    fn revoke(&self, keys: &[&Leaf]) {
        let mut list = "# client keys this node refuses\n\n".to_owned();
        for key in keys {
            list.push_str(&key.pin());
            list.push_str("  # control-plane.ward.test\n");
        }
        write_mode(&self.revoked, &list, 0o644);
    }

    fn args(&self) -> Vec<String> {
        [
            "--listen-tls",
            "127.0.0.1:0",
            "--tls-cert",
            &self.path("node-cert.pem").display().to_string(),
            "--tls-key",
            &self.path("node-key.pem").display().to_string(),
            "--tls-client-ca",
            &self.client_ca_path().display().to_string(),
            "--tls-client-revoked",
            &self.revoked.display().to_string(),
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn node(&self, extra: &[String]) -> Node {
        let mut args = self.args();
        args.extend_from_slice(extra);
        Node::spawn(self.dir.path(), &args)
    }

    fn client(&self) -> (TlsClient, Leaf) {
        let leaf = client_leaf(&self.client_ca);
        (TlsClient::new(&self.server_ca, &leaf), leaf)
    }
}

// ---- revocation -----------------------------------------------------------------------

#[test]
fn a_revoked_client_key_is_refused_even_when_pinned_and_another_key_from_the_same_ca_is_served() {
    let setup = setup();
    let (revoked, revoked_leaf) = setup.client();
    let (kept, kept_leaf) = setup.client();
    setup.revoke(&[&revoked_leaf]);
    let node = setup.node(&[
        "--tls-client-pin".to_owned(),
        revoked_leaf.pin(),
        "--tls-client-pin".to_owned(),
        kept_leaf.pin(),
    ]);

    kept.served(&node, &discovery());
    revoked.refused(&node);
    let line = node.reported("refused a TLS connection from 127.0.0.1");
    assert!(line.contains("revoked"), "{line}");
    assert!(line.contains(&revoked_leaf.pin()), "{line}");
}

#[test]
fn revoking_a_key_on_sighup_refuses_it_at_its_next_handshake_and_the_registry_survives() {
    let setup = setup();
    let (revoked, revoked_leaf) = setup.client();
    let (kept, _) = setup.client();
    let mut node = setup.node(&[]);
    let ctx = context();
    let op = OperationId::new(1).unwrap();
    assert_eq!(
        revoked.lifecycle(&node, &ctx.create(op, binding())),
        ctx.accepted(op, binding(), TaskLifecycleState::Created)
    );

    setup.revoke(&[&revoked_leaf]);
    let line = node.reloads();
    assert!(line.contains("revoked client keys 1 (+1, -0)"), "{line}");
    assert!(line.contains("(unchanged)"), "{line}");

    revoked.refused(&node);
    let line = node.reported("refused a TLS connection from 127.0.0.1");
    assert!(line.contains("revoked"), "{line}");
    assert!(line.contains(&revoked_leaf.pin()), "{line}");
    assert_eq!(
        kept.lifecycle(&node, &ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Created),
        "the registry outlives the reload"
    );

    setup.revoke(&[]);
    let line = node.reloads();
    assert!(line.contains("revoked client keys 0 (+0, -1)"), "{line}");
    revoked.served(&node, &discovery());
}

#[test]
fn a_session_authenticated_before_a_revocation_is_not_served_after_it() {
    let setup = setup();
    let (revoked, revoked_leaf) = setup.client();
    let (kept, _) = setup.client();
    let mut node = setup.node(&[]);

    let mut holder = UnixStream::connect(&node.socket).unwrap();
    holder
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    writeln!(holder, "{}", hello()).unwrap();
    let mut accepted = String::new();
    BufReader::new(holder.try_clone().unwrap())
        .read_line(&mut accepted)
        .unwrap();
    assert!(accepted.contains("accepted"), "{accepted}");

    let addr = node.addr;
    let waiting = std::thread::spawn(move || revoked.exchange(addr, &[hello(), discovery()]).lines);
    node.reported(&format!("served a TLS client {}", revoked_leaf.pin()));
    setup.revoke(&[&revoked_leaf]);
    node.reloads();
    drop(holder);

    let lines = waiting.join().unwrap();
    assert!(
        lines.is_empty(),
        "a revoked session was answered: {lines:?}"
    );
    let line = node.reported("refused a TLS connection from 127.0.0.1");
    assert!(line.contains("revoked"), "{line}");
    assert!(line.contains(&revoked_leaf.pin()), "{line}");
    kept.served(&node, &discovery());
}

// ---- reload ---------------------------------------------------------------------------

#[test]
fn an_unusable_reload_keeps_the_whole_previous_configuration_and_says_why() {
    let setup = setup();
    let (client, client_leaf) = setup.client();
    let mut node = setup.node(&[]);
    client.served(&node, &discovery());

    write_mode(
        &setup.revoked,
        &format!("{}\nsha256:00\n", client_leaf.pin()),
        0o644,
    );
    let line = node.keeps_the_previous_configuration();
    assert!(
        line.contains(&setup.revoked.display().to_string()),
        "{line}"
    );
    assert!(line.contains("line 2"), "{line}");
    client.served(&node, &discovery());

    write_mode(&setup.revoked, &client_leaf.pin(), 0o666);
    let line = node.keeps_the_previous_configuration();
    assert!(line.contains("too open"), "{line}");
    client.served(&node, &discovery());

    std::fs::remove_file(&setup.revoked).unwrap();
    let line = node.keeps_the_previous_configuration();
    assert!(line.contains("no such file"), "{line}");
    client.served(&node, &discovery());

    setup.revoke(&[&client_leaf]);
    let rotated = server_leaf(&setup.server_ca);
    write_mode(&setup.path("node-cert.pem"), &rotated.cert_pem, 0o644);
    let line = node.keeps_the_previous_configuration();
    assert!(line.contains("does not match"), "{line}");
    let exchanged = client.served(&node, &discovery());
    assert_eq!(
        exchanged.server_key.unwrap().to_string(),
        setup.server.pin(),
        "neither the half-rotated server key nor the revocation beside it was taken"
    );

    setup.write_server(&rotated);
    let line = node.reloads();
    assert!(line.contains(&rotated.pin()), "{line}");
    assert!(line.contains("revoked client keys 1 (+1, -0)"), "{line}");
    client.refused(&node);
}

#[test]
fn a_rotated_server_key_and_client_ca_are_served_after_sighup_without_a_restart() {
    let setup = setup();
    let (old_client, _) = setup.client();
    let mut node = setup.node(&[]);
    let ctx = context();
    let op = OperationId::new(1).unwrap();
    old_client.lifecycle(&node, &ctx.create(op, binding()));
    assert_eq!(
        old_client
            .served(&node, &discovery())
            .server_key
            .unwrap()
            .to_string(),
        setup.server.pin()
    );

    let server_ca = ca("ward test server CA, rotated");
    let server = server_leaf(&server_ca);
    let client_ca = ca("ward test client CA, rotated");
    setup.write_server(&server);
    write_mode(&setup.client_ca_path(), &client_ca.pem(), 0o644);
    let line = node.reloads();
    assert!(
        line.starts_with(&format!("server key {} (changed)", server.pin())),
        "{line}"
    );
    assert!(
        line.contains("client CA certificates 1 (changed)"),
        "{line}"
    );

    let new_client = TlsClient::new(&server_ca, &client_leaf(&client_ca));
    let exchanged = new_client.served(&node, &discovery());
    assert_eq!(
        exchanged.server_key.unwrap().to_string(),
        server.pin(),
        "the client sees the rotated server key"
    );
    assert_eq!(
        new_client.lifecycle(&node, &ctx.inspect(binding())),
        ctx.inspected(binding(), TaskLifecycleState::Created),
        "the registry outlives the rotation"
    );
    old_client.refused(&node);
}

// ---- configuration --------------------------------------------------------------------

#[test]
fn a_malformed_or_unsafe_revocation_list_stops_the_node_at_start() {
    let setup = setup();
    let dir = setup.dir.path();
    let args = setup.args();
    let at = args
        .iter()
        .position(|arg| arg == "--tls-client-revoked")
        .unwrap()
        + 1;
    let with = |path: &Path| {
        let mut args = args.clone();
        args[at] = path.display().to_string();
        args
    };
    let pin = format!("sha256:{}", "a".repeat(64));

    let malformed = setup.path("malformed");
    for (contents, line) in [
        (format!("{pin}\nsha256:00\n"), "line 2"),
        (format!("# keys\n{}\n", pin.to_uppercase()), "line 2"),
        (format!("{pin} trailing\n"), "line 1"),
        ("md5:00\n".to_owned(), "line 1"),
    ] {
        write_mode(&malformed, &contents, 0o644);
        let stderr = Node::refuses_to_start(dir, &with(&malformed));
        assert!(stderr.contains("malformed"), "{contents:?}: {stderr}");
        assert!(stderr.contains(line), "{contents:?}: {stderr}");
    }

    let stderr = Node::refuses_to_start(dir, &with(&setup.path("missing")));
    assert!(stderr.contains("no such file"), "{stderr}");

    let open = setup.path("open");
    write_mode(&open, &pin, 0o666);
    let stderr = Node::refuses_to_start(dir, &with(&open));
    assert!(stderr.contains("too open"), "{stderr}");

    let link = setup.path("linked");
    std::os::unix::fs::symlink(&setup.revoked, &link).unwrap();
    let stderr = Node::refuses_to_start(dir, &with(&link));
    assert!(stderr.contains("symlink"), "{stderr}");

    let large = setup.path("large");
    write_mode(&large, &format!("{pin}\n").repeat(1_000), 0o644);
    let stderr = Node::refuses_to_start(dir, &with(&large));
    assert!(stderr.contains("larger than"), "{stderr}");

    let binary = setup.path("binary");
    std::fs::write(&binary, [0xff, 0xfe, b'\n']).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o644)).unwrap();
    let stderr = Node::refuses_to_start(dir, &with(&binary));
    assert!(stderr.contains("not UTF-8"), "{stderr}");

    Node::refuses_to_start(
        dir,
        &[
            "--tls-client-revoked".to_owned(),
            setup.revoked.display().to_string(),
        ],
    );
}
