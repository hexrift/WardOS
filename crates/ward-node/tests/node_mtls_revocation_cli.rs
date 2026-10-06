//! End-to-end client-key revocation for `ward-node --listen-tls` (#262, ADR-0038 §8).
//!
//! `--tls-client-revoked <file>` lists client keys the node refuses even when their
//! certificate chains to the client CA and is pinned. Every certificate and key is
//! generated here; none is committed.

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

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use ward_events::{NodeId, PrincipalId};
use ward_node_protocol::{
    CapabilityDiscoveryContext, HandshakeRequest, ProtocolVersion, WARD_NODE_PROTOCOL,
};

const NODE: NodeId = NodeId::from_u128(4);
const ISSUER: PrincipalId = PrincipalId::from_u128(2);
const SERVER_NAME: &str = "node-4.ward.test";
const STARTUP: Duration = Duration::from_secs(20);

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

fn discovery() -> String {
    let ctx = CapabilityDiscoveryContext::new(ProtocolVersion::new(1, 3)).unwrap();
    serde_json::to_string(&ctx.request()).unwrap()
}

// ---- TLS clients ----------------------------------------------------------------------

struct TlsClient {
    roots: RootCertStore,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
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
        let mut received = Vec::new();
        if stream.write_all(payload.as_bytes()).is_ok() && stream.flush().is_ok() {
            let _ = stream.read_to_end(&mut received);
        }
        String::from_utf8_lossy(&received)
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn served(&self, node: &Node, request: &str) {
        let lines = self.exchange(node.addr, &[hello(), request.to_owned()]);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("accepted"), "{lines:?}");
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
