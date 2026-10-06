//! The client over mutual TLS against a real `ward-node --listen-tls` (#262, ADR-0038):
//! the capability document is the socket's, a whole attempt runs, seals and replays over
//! TLS exactly as over the socket, a superseded `pause` replays `stale_operation`, the
//! client refuses a node whose certificate is not from its server CA, not for the expected
//! name or not the pinned key, a node refuses a client it does not know, and the process
//! adapter speaks the same over `--connect-tls`. The attempt cases need a working
//! bubblewrap and skip without one, except under `WARD_REQUIRE_ISOLATION=1`. Every
//! certificate and key is generated here; none is committed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use common::{
    NODE, binding, envelope, imported, isolation, issuer, marker, private_dir, trust_store,
    wait_until_gone, wait_until_sandboxed, ward_node_binary,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
};
use ward_node_client::{
    Applied, AttemptOutcome, AttemptRequest, CancelToken, Client, ClientError, Driver,
    OperationIds, RunConfig, Timeouts, TlsSettings, TlsSetupError, TlsTransport, TransportError,
    UnixTransport, Verb,
};
use ward_node_protocol::{OperationId, TaskLifecycleRejectionReason, TaskLifecycleState};

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
        pin: format!(
            "sha256:{}",
            digest.as_ref().iter().fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
        ),
    }
}

fn write_mode(path: &Path, contents: &str, mode: u32) -> PathBuf {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    path.to_owned()
}

/// A server CA and a client CA, the node's identity from the first and a client's from
/// the second, as files in `dir`.
struct Pki {
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
            client_ca,
            server,
        }
    }

    fn node_args(&self, dir: &Path) -> Vec<String> {
        let cert = write_mode(&dir.join("node-cert.pem"), &self.server.cert_pem, 0o644);
        let key = write_mode(&dir.join("node-key.pem"), &self.server.key_pem, 0o600);
        let client_ca = write_mode(&dir.join("client-ca.pem"), &self.client_ca.pem(), 0o644);
        [
            "--listen-tls",
            "127.0.0.1:0",
            "--tls-cert",
            &cert.display().to_string(),
            "--tls-key",
            &key.display().to_string(),
            "--tls-client-ca",
            &client_ca.display().to_string(),
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn settings(&self, address: &str) -> TlsSettings {
        TlsSettings {
            address: address.to_owned(),
            server_name: SERVER_NAME.to_owned(),
            server_ca: self.server_ca_file.clone(),
            client_cert: self.client_cert.clone(),
            client_key: self.client_key.clone(),
            server_pin: None,
        }
    }
}

// ---- the node -------------------------------------------------------------------------

struct Node {
    child: Child,
    socket: PathBuf,
    task_root: PathBuf,
    address: String,
    _stderr: Receiver<String>,
}

impl Node {
    fn spawn(dir: &Path, tls: &[String], execute: bool) -> Self {
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
            .args(tls)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if execute {
            command.arg("--task-root").arg(&task_root);
        }
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
        let deadline = Instant::now() + Duration::from_secs(20);
        let address = loop {
            let line = stderr
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| {
                    panic!("ward-node never reported its TLS listener: {error:?}")
                });
            if let Some(address) =
                line.strip_prefix("ward-node: serving the node protocol over mutual TLS on ")
            {
                break address.to_owned();
            }
        };
        while UnixStream::connect(&socket).is_err() {
            assert!(child.try_wait().unwrap().is_none(), "ward-node exited");
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
            address,
            _stderr: stderr,
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tls_client(settings: &TlsSettings) -> Result<Client<TlsTransport>, ClientError> {
    Client::connect(TlsTransport::new(settings, Timeouts::default()).unwrap())
}

fn config() -> RunConfig {
    RunConfig {
        poll_interval: Duration::from_millis(50),
        max_poll_interval: Duration::from_millis(200),
        grace: Duration::from_secs(30),
    }
}

fn tls_refused(result: Result<Client<TlsTransport>, ClientError>) -> String {
    match result {
        Err(ClientError::Transport(TransportError::Tls(reason))) => reason,
        other => panic!("expected a TLS refusal, got {other:?}"),
    }
}

// ---- tests ----------------------------------------------------------------------------

#[test]
fn the_capability_document_over_tls_is_the_sockets() {
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let node = Node::spawn(dir.path(), &pki.node_args(dir.path()), false);
    let over_tls = tls_client(&pki.settings(&node.address)).unwrap();
    let over_socket =
        Client::connect(UnixTransport::new(&node.socket, Timeouts::default())).unwrap();
    assert_eq!(over_tls.protocol(), over_socket.protocol());
    assert_eq!(
        over_tls.capabilities().unwrap(),
        over_socket.capabilities().unwrap()
    );
}

#[test]
fn a_full_attempt_runs_seals_and_replays_over_tls_without_running_twice() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), &pki.node_args(dir.path()), true);
    let marker = marker("ward-node-client-tls-run");
    let script = format!("cat src/input.txt > copy.txt && echo {marker} >> out.txt");
    let request = AttemptRequest::sign(
        &envelope(binding(), snapshot, &["sh", "-c", &script]),
        &issuer(),
        Some(node.task_root.clone()),
    )
    .unwrap();
    let client = tls_client(&pki.settings(&node.address)).unwrap();
    let driver = Driver::new(&client, config());
    let ids = OperationIds::starting_at(100).unwrap();

    let report = driver.run_attempt(&request, &ids, &CancelToken::default(), &mut |_| {});
    assert_eq!(report.outcome, AttemptOutcome::Completed, "{report:?}");
    assert!(report.sealed);
    assert_eq!(report.final_state, Some(TaskLifecycleState::Sealed));
    assert!(report.evidence_head.is_some());
    let verbs: Vec<(Verb, u64)> = report
        .operations
        .iter()
        .map(|operation| (operation.verb, operation.operation_id.get()))
        .collect();
    assert_eq!(
        verbs,
        [
            (Verb::Create, 100),
            (Verb::Admit, 101),
            (Verb::Start, 102),
            (Verb::Seal, 105)
        ]
    );
    let workspace = node
        .task_root
        .join(binding().task().to_string())
        .join(binding().attempt().to_string());
    assert_eq!(
        std::fs::read_to_string(workspace.join("copy.txt")).unwrap(),
        "from the snapshot\n"
    );

    let replay = driver.run_attempt(&request, &ids, &CancelToken::default(), &mut |_| {});
    assert_eq!(replay.outcome, AttemptOutcome::Completed, "{replay:?}");
    assert_eq!(replay.evidence_head, report.evidence_head);
    assert!(replay.operations.iter().all(|operation| {
        operation.state == Some(TaskLifecycleState::Sealed) && operation.reason.is_none()
    }));
    assert_eq!(
        std::fs::read_to_string(workspace.join("out.txt"))
            .unwrap()
            .lines()
            .count(),
        1,
        "the replay over TLS ran nothing"
    );
}

#[test]
fn a_superseded_pause_replays_stale_operation_over_tls() {
    if !isolation() {
        return;
    }
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let snapshot = imported(dir.path());
    let node = Node::spawn(dir.path(), &pki.node_args(dir.path()), true);
    let marker = marker("ward-node-client-tls-pause");
    let script = format!("sleep 600 # {marker}");
    let signed = AttemptRequest::sign(
        &envelope(binding(), snapshot, &["sh", "-c", &script]),
        &issuer(),
        None,
    )
    .unwrap();
    let client = tls_client(&pki.settings(&node.address)).unwrap();
    let op = |id| OperationId::new(id).unwrap();
    let accepted = |applied: Applied| match applied {
        Applied::Accepted { state } => state,
        Applied::Rejected { reason } => panic!("refused: {reason:?}"),
    };
    accepted(client.create(binding(), op(1)).unwrap());
    accepted(client.admit(binding(), op(2), &signed.envelope).unwrap());
    assert_eq!(
        accepted(client.start(binding(), op(3)).unwrap()),
        TaskLifecycleState::Running
    );
    wait_until_sandboxed(&marker);
    for (pause, resume) in [(7, 8), (9, 10)] {
        assert_eq!(
            accepted(client.pause(binding(), op(pause)).unwrap()),
            TaskLifecycleState::Paused
        );
        assert_eq!(
            accepted(client.resume(binding(), op(resume)).unwrap()),
            TaskLifecycleState::Running
        );
    }
    assert_eq!(
        client.pause(binding(), op(7)).unwrap(),
        Applied::Rejected {
            reason: TaskLifecycleRejectionReason::StaleOperation
        }
    );
    assert_eq!(
        accepted(client.revoke(binding(), op(11)).unwrap()),
        TaskLifecycleState::Revoked
    );
    wait_until_gone(&marker);
}

#[test]
fn the_client_refuses_a_node_it_cannot_authenticate() {
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let node = Node::spawn(dir.path(), &pki.node_args(dir.path()), false);

    let mut stranger = pki.settings(&node.address);
    stranger.server_ca = write_mode(
        &dir.path().join("other-ca.pem"),
        &ca("an impersonator's CA").pem(),
        0o644,
    );
    let reason = tls_refused(tls_client(&stranger));
    assert!(reason.contains("UnknownIssuer"), "{reason}");

    let mut misnamed = pki.settings(&node.address);
    misnamed.server_name = "another-node.ward.test".to_owned();
    let reason = tls_refused(tls_client(&misnamed));
    assert!(reason.contains("not valid for name"), "{reason}");

    let mut pinned = pki.settings(&node.address);
    pinned.server_pin = Some(format!("sha256:{}", "0".repeat(64)));
    let reason = tls_refused(tls_client(&pinned));
    assert!(reason.contains("pinned"), "{reason}");

    pinned.server_pin = Some(pki.server.pin.clone());
    tls_client(&pinned).unwrap().capabilities().unwrap();
}

#[test]
fn a_node_refuses_a_client_its_ca_did_not_certify() {
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let node = Node::spawn(dir.path(), &pki.node_args(dir.path()), false);
    let outsider = leaf(
        &ca("an outsider's CA"),
        "control-plane.ward.test",
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let mut settings = pki.settings(&node.address);
    settings.client_cert = write_mode(&dir.path().join("outsider.pem"), &outsider.cert_pem, 0o644);
    settings.client_key = write_mode(
        &dir.path().join("outsider-key.pem"),
        &outsider.key_pem,
        0o600,
    );
    match tls_client(&settings) {
        Err(ClientError::Transport(
            TransportError::Tls(_) | TransportError::ClosedWithoutResponse,
        )) => {}
        other => panic!("an outsider was served: {other:?}"),
    }
}

#[test]
fn unusable_client_files_are_refused_before_anything_is_sent() {
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let settings = pki.settings("127.0.0.1:9");
    let refused = |settings: &TlsSettings| {
        TlsTransport::new(settings, Timeouts::default()).expect_err("unusable settings")
    };

    std::fs::set_permissions(&pki.client_key, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(refused(&settings), TlsSetupError::File { .. }));
    std::fs::set_permissions(&pki.client_key, std::fs::Permissions::from_mode(0o400)).unwrap();
    TlsTransport::new(&settings, Timeouts::default()).unwrap();

    let mut other = settings.clone();
    other.client_key = write_mode(
        &dir.path().join("not-a-key.pem"),
        &pki.server.cert_pem,
        0o600,
    );
    assert!(matches!(refused(&other), TlsSetupError::File { .. }));

    let mut other = settings.clone();
    other.server_ca = dir.path().join("missing.pem");
    assert!(matches!(refused(&other), TlsSetupError::File { .. }));

    let mut other = settings.clone();
    other.server_name = "not a name".to_owned();
    assert!(matches!(refused(&other), TlsSetupError::ServerName(_)));

    let mut other = settings;
    other.server_pin = Some("sha256:00".to_owned());
    assert!(matches!(refused(&other), TlsSetupError::Pin(_)));
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

fn adapter_tls_args(pki: &Pki, address: &str) -> Vec<String> {
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
    ]
    .map(str::to_owned)
    .to_vec()
}

#[test]
fn the_process_adapter_speaks_to_a_node_over_tls() {
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    let node = Node::spawn(dir.path(), &pki.node_args(dir.path()), false);
    let over_socket = adapter(&["--socket".to_owned(), node.socket.display().to_string()]);

    let mut args = adapter_tls_args(&pki, &node.address);
    args.extend(["--tls-server-pin".to_owned(), pki.server.pin.clone()]);
    let (status, events) = adapter(&args);
    assert_eq!(status, 0, "{events:?}");
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event"], "capabilities");
    assert_eq!(events, over_socket.1);

    let mut wrong = adapter_tls_args(&pki, &node.address);
    wrong.extend([
        "--tls-server-pin".to_owned(),
        format!("sha256:{}", "f".repeat(64)),
    ]);
    let (status, events) = adapter(&wrong);
    assert_eq!(status, 1);
    assert_eq!(events[0]["event"], "error");
    assert!(
        events[0]["error"].as_str().unwrap().contains("TLS"),
        "{events:?}"
    );
}

#[test]
fn the_process_adapter_refuses_unusable_tls_flags() {
    let dir = private_dir();
    let pki = Pki::new(dir.path());
    std::fs::set_permissions(&pki.client_key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (status, events) = adapter(&adapter_tls_args(&pki, "127.0.0.1:9"));
    assert_eq!(status, 1);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event"], "error");
    assert!(
        events[0]["error"]
            .as_str()
            .unwrap()
            .contains("client-key.pem"),
        "{events:?}"
    );

    let mut both = adapter_tls_args(&pki, "127.0.0.1:9");
    both.extend(["--socket".to_owned(), "/nonexistent".to_owned()]);
    assert_eq!(adapter(&both).0, 2);
    assert_eq!(adapter(&adapter_tls_args(&pki, "127.0.0.1:9")[..8]).0, 2);
    assert_eq!(adapter(&[]).0, 2);
}
