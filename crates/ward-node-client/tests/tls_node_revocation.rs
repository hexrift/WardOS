//! A revoked node key on the client side, against a real `ward-node --listen-tls` (#262,
//! ADR-0038 §9): a client whose revocation list names the node's key refuses the node at
//! the handshake even when that key is pinned and chains to the server CA, a list that
//! does not name it changes nothing, and once the node's operator rotates the node to a
//! fresh key and sends `SIGHUP` the same client reaches it again. The process adapter
//! does the same with `--tls-server-revoked`, and an unusable list is refused before
//! anything is sent. Every certificate and key is generated here; none is committed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use common::{NODE, private_dir, trust_store, ward_node_binary};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
};
use ward_node_client::{
    Client, ClientError, RevokedNodeKeys, Timeouts, TlsSettings, TlsSetupError, TlsTransport,
    TransportError,
};

const SERVER_NAME: &str = "node-4.ward.test";

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
    pin: String,
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
    let digest = ring::digest::digest(&ring::digest::SHA256, &key.subject_public_key_info());
    Leaf {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        pin: digest
            .as_ref()
            .iter()
            .fold(String::from("sha256:"), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            }),
    }
}

fn write_mode(path: &Path, contents: &str, mode: u32) -> PathBuf {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    path.to_owned()
}

/// The server CA and the node's identity from it, the client CA and this client's identity
/// from that, as files in `dir`.
struct Pki {
    server_ca: CertifiedIssuer<'static, KeyPair>,
    client_ca: CertifiedIssuer<'static, KeyPair>,
    server: Leaf,
    server_ca_file: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl Pki {
    fn new(dir: &Path) -> Self {
        let server_ca = ca("ward test server CA");
        let client_ca = ca("ward test client CA");
        let server = leaf(&server_ca, SERVER_NAME, ExtendedKeyUsagePurpose::ServerAuth);
        let client = leaf(
            &client_ca,
            "control-plane.ward.test",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        Self {
            server_ca_file: write_mode(&dir.join("server-ca.pem"), &server_ca.pem(), 0o644),
            client_cert: write_mode(&dir.join("client-cert.pem"), &client.cert_pem, 0o644),
            client_key: write_mode(&dir.join("client-key.pem"), &client.key_pem, 0o600),
            server_ca,
            client_ca,
            server,
        }
    }

    /// Install `server` as the node's identity in `dir`.
    fn install(dir: &Path, server: &Leaf) {
        write_mode(&dir.join("node-cert.pem"), &server.cert_pem, 0o644);
        write_mode(&dir.join("node-key.pem"), &server.key_pem, 0o600);
    }

    fn node_args(&self, dir: &Path) -> Vec<String> {
        Self::install(dir, &self.server);
        let client_ca = write_mode(&dir.join("client-ca.pem"), &self.client_ca.pem(), 0o644);
        [
            "--listen-tls",
            "127.0.0.1:0",
            "--tls-cert",
            &dir.join("node-cert.pem").display().to_string(),
            "--tls-key",
            &dir.join("node-key.pem").display().to_string(),
            "--tls-client-ca",
            &client_ca.display().to_string(),
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn settings(&self, address: &str, pin: Option<&str>) -> TlsSettings {
        TlsSettings {
            address: address.to_owned(),
            server_name: SERVER_NAME.to_owned(),
            server_ca: self.server_ca_file.clone(),
            client_cert: self.client_cert.clone(),
            client_key: self.client_key.clone(),
            server_pin: pin.map(str::to_owned),
        }
    }
}

// ---- the node -------------------------------------------------------------------------

const LISTENING: &str = "ward-node: serving the node protocol over mutual TLS on ";

/// The next stderr line containing `needle`.
fn reported(stderr: &Receiver<String>, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match stderr.recv_timeout(remaining) {
            Ok(line) if line.contains(needle) => return line,
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                panic!("the node never reported {needle:?}")
            }
        }
    }
}

struct Node {
    child: Child,
    address: String,
    stderr: Receiver<String>,
}

impl Node {
    fn spawn(dir: &Path, tls: &[String]) -> Self {
        let socket = dir.join("node.sock");
        let _ = std::fs::remove_file(&socket);
        let mut child = Command::new(ward_node_binary())
            .arg("--socket")
            .arg(&socket)
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--node-id")
            .arg(NODE.to_string())
            .arg("--trusted-issuers")
            .arg(trust_store(dir))
            .args(tls)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
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
        let address = reported(&stderr, LISTENING)
            .split_once(LISTENING)
            .unwrap()
            .1
            .to_owned();
        let mut node = Self {
            child,
            address,
            stderr,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while UnixStream::connect(&socket).is_err() {
            assert!(node.child.try_wait().unwrap().is_none(), "ward-node exited");
            assert!(
                Instant::now() < deadline,
                "ward-node did not bind its socket"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        node
    }

    /// Send `SIGHUP` and wait for the node to report a successful reload.
    fn reload(&self) -> String {
        kill(
            Pid::from_raw(i32::try_from(self.child.id()).unwrap()),
            Signal::SIGHUP,
        )
        .unwrap();
        reported(&self.stderr, "ward-node: reloaded the TLS configuration: ")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn revocation_list(dir: &Path, name: &str, text: &str) -> PathBuf {
    write_mode(&dir.join(name), text, 0o644)
}

fn client(
    settings: &TlsSettings,
    revoked: &RevokedNodeKeys,
) -> Result<Client<TlsTransport>, ClientError> {
    Client::connect(TlsTransport::with_revoked(settings, revoked, Timeouts::default()).unwrap())
}

fn tls_refused(result: Result<Client<TlsTransport>, ClientError>) -> String {
    match result {
        Err(ClientError::Transport(TransportError::Tls(reason))) => reason,
        other => panic!("expected a TLS refusal, got {other:?}"),
    }
}

// ---- tests ----------------------------------------------------------------------------

#[test]
fn a_revoked_node_key_is_refused_even_when_it_is_pinned_and_chains_to_the_server_ca() {
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let node = Node::spawn(dir.path(), &pki.node_args(dir.path()));
    let other = format!("sha256:{}", "e".repeat(64));
    let revoked = RevokedNodeKeys::load(&revocation_list(
        dir.path(),
        "revoked-nodes",
        &format!(
            "# node-4's key leaked\n{other}\n{}  # node-4\n",
            pki.server.pin
        ),
    ))
    .unwrap();
    assert_eq!(revoked.len(), 2);

    for pin in [Some(pki.server.pin.as_str()), None] {
        let reason = tls_refused(client(&pki.settings(&node.address, pin), &revoked));
        assert!(
            reason.contains(&format!("the node's key {} is revoked", pki.server.pin)),
            "{reason}"
        );
    }

    let unrelated = RevokedNodeKeys::load(&revocation_list(
        dir.path(),
        "unrelated",
        &format!("{other}\n"),
    ))
    .unwrap();
    for revoked in [&unrelated, &RevokedNodeKeys::default()] {
        client(&pki.settings(&node.address, Some(&pki.server.pin)), revoked)
            .unwrap()
            .capabilities()
            .unwrap();
    }
}

#[test]
fn a_node_rotated_to_a_fresh_key_after_its_revocation_is_reached_again() {
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let node = Node::spawn(dir.path(), &pki.node_args(dir.path()));
    let revoked = RevokedNodeKeys::load(&revocation_list(
        dir.path(),
        "revoked-nodes",
        &format!("{}\n", pki.server.pin),
    ))
    .unwrap();
    let reason = tls_refused(client(&pki.settings(&node.address, None), &revoked));
    assert!(reason.contains("is revoked"), "{reason}");

    let rotated = leaf(
        &pki.server_ca,
        SERVER_NAME,
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    assert_ne!(rotated.pin, pki.server.pin);
    Pki::install(dir.path(), &rotated);
    let report = node.reload();
    assert!(
        report.contains(&format!("server key {} (changed)", rotated.pin)),
        "{report}"
    );

    client(&pki.settings(&node.address, Some(&rotated.pin)), &revoked)
        .unwrap()
        .capabilities()
        .unwrap();
    let reason = tls_refused(client(
        &pki.settings(&node.address, Some(&pki.server.pin)),
        &revoked,
    ));
    assert!(reason.contains("not the pinned one"), "{reason}");
}

#[test]
fn an_unusable_revocation_list_is_refused_before_anything_is_sent() {
    let dir = private_dir();
    let pin = format!("sha256:{}", "1".repeat(64));
    let malformed = revocation_list(
        dir.path(),
        "malformed",
        &format!("# lost\n{pin}\nsha256:{}\n", "1".repeat(63)),
    );
    let error = RevokedNodeKeys::load(&malformed).unwrap_err();
    assert!(
        matches!(&error, TlsSetupError::Revocation { line: 3, .. }),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("line 3: malformed revoked key"),
        "{error}"
    );

    let writable = write_mode(&dir.path().join("writable"), &pin, 0o666);
    assert!(matches!(
        RevokedNodeKeys::load(&writable),
        Err(TlsSetupError::File { .. })
    ));
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&malformed, &link).unwrap();
    assert!(matches!(
        RevokedNodeKeys::load(&link),
        Err(TlsSetupError::File { .. })
    ));
    assert!(matches!(
        RevokedNodeKeys::load(&dir.path().join("missing")),
        Err(TlsSetupError::File { .. })
    ));
}

// ---- the process adapter ----------------------------------------------------------------

fn adapter(args: &[String]) -> (u8, Vec<serde_json::Value>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ward-node-adapter"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        let _ = writeln!(stdin, r#"{{"cmd":"capabilities"}}"#);
    }
    let output = child.wait_with_output().unwrap();
    let events = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (u8::try_from(output.status.code().unwrap()).unwrap(), events)
}

fn adapter_tls_args(pki: &Pki, address: &str, revoked: &Path) -> Vec<String> {
    [
        "--connect-tls",
        address,
        "--tls-cert",
        &pki.client_cert.display().to_string(),
        "--tls-key",
        &pki.client_key.display().to_string(),
        "--tls-server-ca",
        &pki.server_ca_file.display().to_string(),
        "--tls-server-name",
        SERVER_NAME,
        "--tls-server-pin",
        &pki.server.pin,
        "--tls-server-revoked",
        &revoked.display().to_string(),
    ]
    .map(str::to_owned)
    .to_vec()
}

#[test]
fn the_process_adapter_refuses_a_node_whose_key_its_list_revokes() {
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let node = Node::spawn(dir.path(), &pki.node_args(dir.path()));

    let revoked = revocation_list(dir.path(), "revoked", &format!("{}\n", pki.server.pin));
    let (status, events) = adapter(&adapter_tls_args(&pki, &node.address, &revoked));
    assert_eq!(status, 1, "{events:?}");
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event"], "error");
    let error = events[0]["error"].as_str().unwrap();
    assert!(
        error.contains(&format!("the node's key {} is revoked", pki.server.pin)),
        "{events:?}"
    );

    let unrelated = revocation_list(
        dir.path(),
        "unrelated",
        &format!("# none of ours\nsha256:{}\n", "e".repeat(64)),
    );
    let (status, events) = adapter(&adapter_tls_args(&pki, &node.address, &unrelated));
    assert_eq!(status, 0, "{events:?}");
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event"], "capabilities");

    let malformed = revocation_list(dir.path(), "malformed", "sha256:00\n");
    let (status, events) = adapter(&adapter_tls_args(&pki, &node.address, &malformed));
    assert_eq!(status, 1, "{events:?}");
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(
        events[0]["error"]
            .as_str()
            .unwrap()
            .contains("line 1: malformed revoked key"),
        "{events:?}"
    );

    let socket_only = [
        "--socket".to_owned(),
        dir.path().join("node.sock").display().to_string(),
        "--tls-server-revoked".to_owned(),
        revoked.display().to_string(),
    ];
    assert_eq!(adapter(&socket_only).0, 2);
}
