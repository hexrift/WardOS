//! Capsule backend conformance (#263, ADR-0039): one signed manifest, the same authority on
//! every backend.
//!
//! The acceptance of #263 against the real `ward-node` binary. A node started with
//! `--container-runtime` runs attempts on two backends: bubblewrap at `sandbox` and an OCI
//! container driven by `runc` at `container`. The same manifest runs on both, once without
//! a floor (bubblewrap) and once with `isolation.minimum` `container` (runc), the same
//! probe in each: it reads its workspace and a host secret, writes its workspace, a host
//! path, `/usr` and the trust roots, its private `/tmp` and home, asks its proxy for an
//! allowlisted and an unlisted host, connects directly and resolves a name, and reports its
//! environment. The probe's report, the returned output and the node's evidence records
//! must be identical apart from the backend that ran it, as must a budget kill and a stop.
//! Only the container's own guarantees differ, and must hold: no capability, `no_new_privs`
//! and a seccomp filter.
//!
//! Placement is explicit: a `container` floor on a node without a runtime is refused
//! `unsupported_grant`; a manifest without a floor runs on runc only on a node whose
//! operator said `--place-stronger`, which its capability document advertises, and its
//! record then names runc.
//!
//! The cases need bubblewrap and python3, and skip without them except under
//! `WARD_REQUIRE_ISOLATION=1`. Those that run a container also need `/usr/bin/runc` able to
//! run one as the test's user, and skip without it except under `WARD_REQUIRE_CONTAINER=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId,
    SnapshotId, TaskId,
};
use ward_node::evidence;
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifestBytes, HandshakeRequest,
    HandshakeResponse, IssuerProof, IssuerSignature, OperationId, ProtocolVersion,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskExecutionOutcome, TaskLifecycleContext, TaskLifecycleRejectionReason, TaskLifecycleRequest,
    TaskLifecycleResponse, TaskLifecycleState, TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
};

/// Serialises every test body of this binary: writing the snapshot's files and spawning
/// processes from another thread at the same time can make an exec fail with `ETXTBSY`.
static SERIAL: Mutex<()> = Mutex::new(());

const NODE: NodeId = NodeId::from_u128(263);
const RUNC: &str = "/usr/bin/runc";
const HOST_SECRET: &str = "host-secret-263-never-in-a-capsule";
const NODE_CANARY: &str = "node-canary-263-never-in-a-capsule";
const BROKER_TOKEN: &str = "fake-broker-token-for-263";
const LEASED: &str = "hvs.node-leased-token-263";

/// The manifest every attempt runs under, without a floor: an allowlist of `localhost`,
/// where the node brokers the credential of one service, and of a reserved name the
/// proxy allows and then cannot resolve; the probe's report returned with its stdio.
const MANIFEST: &str = r#"{"network":{"custom":["localhost","allowed.example"]},"output":{"stdio_bytes":4096,"files":["report.txt"],"files_bytes":65536},"credentials":[{"service":"svc","host":"localhost","ttl_secs":60}]}"#;

/// The same manifest requiring an OCI container.
const CONTAINER_MANIFEST: &str = r#"{"network":{"custom":["localhost","allowed.example"]},"output":{"stdio_bytes":4096,"files":["report.txt"],"files_bytes":65536},"credentials":[{"service":"svc","host":"localhost","ttl_secs":60}],"isolation":{"minimum":"container"}}"#;

/// The probe: one `PROBE <step> <result>` line per step and one `ENV <json>` line in
/// `/work/report.txt`, the process's own hardening in `/work/status.txt`, and one line on
/// each of stdout and stderr.
const PROBE: &str = r#"
import errno, json, os, socket, sys

def refused(e):
    return "refused " + errno.errorcode.get(e.errno, str(e.errno))

def read(path):
    with open(path) as f:
        return "read " + f.read().strip()

def write(path):
    with open(path, "w") as f:
        f.write("written by the probe\n")
    return "written"

def listdir(path):
    return "listed " + ",".join(sorted(os.listdir(path)))

def proxy(head):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(os.environ["WARD_PROXY_SOCKET"])
    s.sendall(head.encode())
    data = b""
    while b"\r\n" not in data:
        chunk = s.recv(256)
        if not chunk:
            break
        data += chunk
    s.close()
    return "status " + data.split(b"\r\n")[0].decode().split(" ")[1]

def connect_proxy(host, port):
    return proxy("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port))

def route():
    return proxy("GET /svc/v1/data HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer placeholder\r\nConnection: close\r\n\r\n")

def direct(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((addr, port))
        return "connected"
    finally:
        s.close()

def resolve(host):
    try:
        socket.getaddrinfo(host, 443)
        return "resolved"
    except socket.gaierror:
        return "refused unresolved"

args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
port = int(args["--port"])
steps = [
    ("read-workspace", lambda: read("/work/input.txt")),
    ("write-workspace", lambda: write("/work/inside.txt")),
    ("read-host-secret", lambda: read(args["--secret"])),
    ("write-host-path", lambda: write(args["--outside"])),
    ("read-node-state", lambda: listdir(args["--state"])),
    ("write-system", lambda: write("/usr/ward-escape")),
    ("write-trust-roots", lambda: write("/etc/ssl/ward-escape")),
    ("write-tmp", lambda: write("/tmp/scratch")),
    ("write-home", lambda: write(os.environ["HOME"] + "/scratch")),
    ("proxy-credential-route", route),
    ("proxy-allowlisted", lambda: connect_proxy("allowed.example", 443)),
    ("proxy-loopback", lambda: connect_proxy("localhost", port)),
    ("proxy-unlisted", lambda: connect_proxy("blocked.example", 443)),
    ("direct-connect", lambda: direct("192.0.2.1", 443)),
    ("direct-loopback", lambda: direct("127.0.0.1", port)),
    ("dns", lambda: resolve("blocked.example")),
]
lines = []
for name, step in steps:
    try:
        result = step()
    except OSError as e:
        result = refused(e)
    lines.append("PROBE %s %s" % (name, result))
lines.append("ENV " + json.dumps(dict(os.environ), sort_keys=True))
with open("/work/report.txt", "w") as f:
    f.write("\n".join(lines) + "\n")
with open("/proc/self/status") as f:
    status = [line.strip() for line in f if line.split(":")[0] in ("CapEff", "CapBnd", "NoNewPrivs", "Seccomp")]
with open("/work/status.txt", "w") as f:
    f.write("\n".join(status) + "\n")
print("probe stdout")
print("probe stderr", file=sys.stderr)
"#;

fn bubblewrap() -> bool {
    ward_sandbox::ci::isolation_ready(ward_launch::available(), "bubblewrap")
        && ward_sandbox::ci::isolation_ready(Path::new("/usr/bin/python3").exists(), "python3")
}

fn container() -> bool {
    bubblewrap()
        && ward_sandbox::ci::container_ready(
            runc_runs(),
            "runc at /usr/bin/runc running a container as this user",
        )
}

/// Whether `/usr/bin/runc` runs a minimal container (a read-only `/usr`, its own user
/// namespace mapping only this user) on this host, independently of the node.
fn runc_runs() -> bool {
    if !Path::new(RUNC).is_file() {
        return false;
    }
    let dir = tempfile::tempdir().unwrap();
    let rootfs = dir.path().join("rootfs");
    std::fs::create_dir(&rootfs).unwrap();
    let meta = std::fs::metadata(dir.path()).unwrap();
    let bind = |path: &str| json!({"destination": path, "type": "bind", "source": path, "options": ["rbind", "ro"]});
    let mut mounts = vec![json!({"destination": "/proc", "type": "proc", "source": "proc"})];
    mounts.extend(
        ["/usr", "/bin", "/lib", "/lib64"]
            .into_iter()
            .filter(|path| Path::new(path).exists())
            .map(bind),
    );
    let namespaces: Vec<Value> = ["user", "mount", "pid", "ipc", "uts", "network"]
        .into_iter()
        .map(|kind| json!({"type": kind}))
        .collect();
    let config = json!({
        "ociVersion": "1.2.1",
        "root": {"path": "rootfs", "readonly": true},
        "process": {"user": {"uid": 0, "gid": 0}, "args": ["/bin/true"], "cwd": "/",
            "env": ["PATH=/usr/bin:/bin"], "noNewPrivileges": true},
        "mounts": mounts,
        "linux": {
            "namespaces": namespaces,
            "uidMappings": [{"containerID": 0, "hostID": meta.uid(), "size": 1}],
            "gidMappings": [{"containerID": 0, "hostID": meta.gid(), "size": 1}],
        },
    });
    std::fs::write(dir.path().join("config.json"), config.to_string()).unwrap();
    Command::new(RUNC)
        .arg("--root")
        .arg(dir.path().join("state"))
        .args(["run", "--bundle"])
        .arg(dir.path())
        .arg(format!("ward-probe-{}", std::process::id()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[63; 32]).unwrap()
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

fn task_binding(task: u128) -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(task),
        ExecutionAttemptId::from_u128(task + 1000),
        LeaseId::from_u128(task + 2000),
    )
}

fn op(value: u64) -> OperationId {
    OperationId::new(value).unwrap()
}

fn context() -> TaskLifecycleContext {
    TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
}

/// Wait until `done` holds, polling; fail once `what` has not happened within 30 seconds.
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "{what} never happened");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn trust_store(dir: &Path) -> PathBuf {
    let path = dir.join("trusted-issuers");
    std::fs::write(
        &path,
        format!(
            "{} {}\n",
            hex(key_pair().public_key().as_ref()),
            PrincipalId::from_u128(2)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// The project every attempt starts from: an input file and the probe.
fn imported(dir: &Path) -> SnapshotId {
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("input.txt"), b"from the snapshot\n").unwrap();
    std::fs::write(project.join("probe.py"), PROBE).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ward-node"))
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

/// The signed `admit` of `argv` under `manifest` for `binding`, its budget `budget_ms`.
fn signed_admit(
    binding: TaskBinding,
    snapshot: SnapshotId,
    manifest: &str,
    argv: &[String],
    budget_ms: u64,
) -> TaskLifecycleRequest {
    let now = now_ms();
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(binding.task().as_u128() + 3000),
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
            WorkloadArgv::new(argv.to_vec()).unwrap(),
            CapabilityManifestBytes::new(manifest.as_bytes().to_vec()).unwrap(),
            snapshot,
            budget_ms,
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
    context().admit(op(2), binding, json, proof).unwrap()
}

struct Node {
    child: Child,
    socket: PathBuf,
    root: PathBuf,
    state: PathBuf,
}

impl Node {
    /// An executing node with an allowlist and output return, and `flags`; its own
    /// environment holds a canary that must reach no attempt.
    fn spawn(dir: &Path, flags: &[&str]) -> Self {
        let mut child = Self::command(dir, flags).spawn().unwrap();
        let socket = dir.join("node.sock");
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
            root: dir.join("tasks"),
            state: dir.join("state"),
        }
    }

    fn command(dir: &Path, flags: &[&str]) -> Command {
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
            .args(["--network-allowlist", "--output-return", "--credentials"])
            .arg(dir.join("credentials.toml"))
            .args(flags)
            .env("WARD_NODE_CANARY", NODE_CANARY)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
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

    /// The `isolation` section of the capability document, as the node wrote it.
    fn isolation(&self) -> Value {
        let answer: Value = serde_json::from_str(
            &self.request(r#"{"request":"capabilities","protocol":{"major":1,"minor":3}}"#),
        )
        .unwrap();
        answer["capabilities"]["isolation"].clone()
    }

    fn admit(&self, binding: TaskBinding, admit: &TaskLifecycleRequest) -> TaskLifecycleResponse {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding)),
            ctx.accepted(op(1), binding, TaskLifecycleState::Created)
        );
        self.lifecycle(admit)
    }

    /// Admit and start one attempt.
    fn start(&self, binding: TaskBinding, admit: &TaskLifecycleRequest) {
        let ctx = context();
        assert_eq!(
            self.admit(binding, admit),
            ctx.accepted(op(2), binding, TaskLifecycleState::Ready)
        );
        assert_eq!(
            self.lifecycle(&ctx.start(op(3), binding)),
            ctx.accepted(op(3), binding, TaskLifecycleState::Running)
        );
    }

    /// Wait for the end of a started attempt; its inspected outcome.
    fn ended(&self, binding: TaskBinding) -> TaskLifecycleResponse {
        let ctx = context();
        let running = ctx.inspected(binding, TaskLifecycleState::Running);
        let mut state = running;
        eventually("the attempt's end", || {
            state = self.lifecycle(&ctx.inspect(binding));
            state != running
        });
        state
    }

    /// The `result` of an ended attempt, without its binding.
    fn result(&self, binding: TaskBinding) -> Value {
        let request = context().result(binding).unwrap();
        let mut answer: Value =
            serde_json::from_str(&self.request(&serde_json::to_string(&request).unwrap())).unwrap();
        answer.as_object_mut().unwrap().remove("binding");
        answer
    }

    fn workspace(&self, binding: TaskBinding) -> PathBuf {
        self.root
            .join(binding.task().to_string())
            .join(binding.attempt().to_string())
    }

    /// The OCI bundle a runc attempt runs from, beside its workspace.
    fn bundle(&self, binding: TaskBinding) -> PathBuf {
        self.root
            .join(binding.task().to_string())
            .join(format!("{}.capsule", binding.attempt()))
    }

    /// The capsule the attempt's durable task record names.
    fn capsule(&self, binding: TaskBinding) -> Value {
        let record: Value = serde_json::from_slice(
            &std::fs::read(
                self.state
                    .join("tasks")
                    .join(format!("{}.json", binding.task())),
            )
            .unwrap(),
        )
        .unwrap();
        record["capsule"].clone()
    }

    /// The attempt's evidence records, each event without what differs between two
    /// attempts of the same manifest: their ids, the envelope digest, host pids and the
    /// requesting process.
    fn evidence(&self, binding: TaskBinding) -> Vec<Value> {
        evidence::verify(&evidence::evidence_dir(&self.root, binding), binding)
            .unwrap()
            .records()
            .iter()
            .map(|record| {
                let mut event = serde_json::to_value(&record.event).unwrap();
                strip(&mut event);
                json!({"origin": format!("{:?}", record.origin), "event": event})
            })
            .collect()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn strip(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for key in ["task", "attempt", "lease", "envelope", "host_pid", "by"] {
                map.remove(key);
            }
            map.values_mut().for_each(strip);
        }
        Value::Array(items) => items.iter_mut().for_each(strip),
        _ => {}
    }
}

/// Read one HTTP request head and its body from `stream`.
/// A request's line, its headers (names lowercased) and its body.
type Request = (String, Vec<(String, String)>, Vec<u8>);

fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, length)| length.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some((line.trim_end().to_owned(), headers, body))
}

fn reply(mut stream: TcpStream, status: u16, body: &Value) {
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

/// Serve every connection to a fresh loopback listener with `answer`; its port.
fn serve(answer: impl Fn(TcpStream) + Send + Sync + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answer = Arc::new(answer);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let answer = Arc::clone(&answer);
            std::thread::spawn(move || answer(stream));
        }
    });
    port
}

/// The credential provider the node leases from: every lease is [`LEASED`].
fn provider() -> u16 {
    serve(|stream| {
        let Some((line, headers, body)) = read_request(&stream) else {
            return;
        };
        if !headers.contains(&("x-vault-token".to_owned(), BROKER_TOKEN.to_owned())) {
            return reply(stream, 403, &json!({"errors": ["permission denied"]}));
        }
        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        if line.starts_with("POST /v1/auth/token/create/") {
            let ttl = body["ttl"]
                .as_str()
                .and_then(|ttl| ttl.trim_end_matches('s').parse::<u64>().ok())
                .unwrap_or(0);
            return reply(
                stream,
                200,
                &json!({"auth": {"client_token": LEASED, "accessor": "accessor-263",
                    "lease_duration": ttl, "token_policies": body["policies"]}}),
            );
        }
        if line.starts_with("POST /v1/auth/token/revoke-accessor") {
            return reply(stream, 204, &Value::Null);
        }
        reply(stream, 404, &json!({"errors": []}));
    })
}

/// The service's upstream: records the request line and authorization of every request.
fn upstream(seen: &Arc<Mutex<Vec<String>>>) -> u16 {
    let seen = Arc::clone(seen);
    serve(move |stream| {
        let Some((line, headers, _)) = read_request(&stream) else {
            return;
        };
        let authorization = headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map_or("", |(_, value)| value.as_str());
        seen.lock()
            .unwrap()
            .push(format!("{line} | {authorization}"));
        reply(stream, 200, &json!({"data": []}));
    })
}

/// The operator's credentials file in `dir`: the service `svc` at the upstream, its lease
/// injected as a bearer token.
fn credentials(dir: &Path, provider: u16, upstream: u16) {
    let token = dir.join("bao.token");
    std::fs::write(&token, format!("{BROKER_TOKEN}\n")).unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = dir.join("credentials.toml");
    std::fs::write(
        &file,
        format!(
            r#"
[provider.bao]
kind = "openbao"
address = "http://127.0.0.1:{provider}"
token_file = "{token}"
insecure_loopback = true
timeout_ms = 2000
max_ttl_secs = 600

[service.svc]
provider = "bao"
engine = "token"
role = "ward-svc"
permissions = ["svc-read"]
max_ttl_secs = 600
upstream = "localhost:{upstream}"
header = "authorization"
value_prefix = "Bearer "
paths = ["/v1"]
plain_upstream = true
"#,
            token = token.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A node's directory with its snapshot imported and its credentials file written: the
/// requests the service's upstream saw, and the port of a loopback listener.
struct Bench {
    dir: tempfile::TempDir,
    snapshot: SnapshotId,
    seen: Arc<Mutex<Vec<String>>>,
    port: u16,
}

impl Bench {
    fn new() -> Self {
        let dir = private_dir();
        let snapshot = imported(dir.path());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let port = upstream(&seen);
        credentials(dir.path(), provider(), port);
        Self {
            dir,
            snapshot,
            seen,
            port,
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

/// What one attempt of the probe observed and returned.
#[derive(Debug)]
struct Probe {
    outcome: TaskLifecycleResponse,
    report: String,
    status: String,
    result: Value,
    evidence: Vec<Value>,
    capsule: Value,
}

struct Targets {
    _host: tempfile::TempDir,
    secret: PathBuf,
    outside: PathBuf,
}

impl Targets {
    fn new() -> Self {
        let host = tempfile::tempdir().unwrap();
        let secret = host.path().join("id_token");
        std::fs::write(&secret, HOST_SECRET).unwrap();
        let outside = host.path().join("escape.txt");
        Self {
            _host: host,
            secret,
            outside,
        }
    }
}

fn probe(
    node: &Node,
    task: u128,
    snapshot: SnapshotId,
    manifest: &str,
    targets: &Targets,
    port: u16,
) -> Probe {
    let binding = task_binding(task);
    let argv: Vec<String> = [
        "python3",
        "/work/probe.py",
        "--secret",
        &targets.secret.display().to_string(),
        "--outside",
        &targets.outside.display().to_string(),
        "--state",
        &node.state.display().to_string(),
        "--port",
        &port.to_string(),
    ]
    .map(str::to_owned)
    .into();
    node.start(
        binding,
        &signed_admit(binding, snapshot, manifest, &argv, 60_000),
    );
    let outcome = node.ended(binding);
    let workspace = node.workspace(binding);
    let read = |name: &str| {
        std::fs::read_to_string(workspace.join(name))
            .unwrap_or_else(|error| panic!("task {task}: no {name} ({error}); {outcome:?}"))
    };
    Probe {
        report: read("report.txt"),
        status: read("status.txt"),
        result: node.result(binding),
        evidence: node.evidence(binding),
        capsule: node.capsule(binding),
        outcome,
    }
}

fn completed(binding: TaskBinding) -> TaskLifecycleResponse {
    context()
        .inspected_with_outcome(
            binding,
            TaskLifecycleState::Exited,
            TaskExecutionOutcome::Completed,
        )
        .unwrap()
}

fn report_line<'a>(report: &'a str, prefix: &str) -> &'a str {
    report
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("no {prefix}line in {report}"))
}

/// What the probe must observe on every backend, step by step.
const STEPS: [&str; 16] = [
    "read-workspace read from the snapshot",
    "write-workspace written",
    "read-host-secret refused ENOENT",
    "write-host-path refused ENOENT",
    "read-node-state refused ENOENT",
    "write-system refused EROFS",
    "write-trust-roots refused EROFS",
    "write-tmp written",
    "write-home written",
    "proxy-credential-route status 200",
    "proxy-allowlisted status 403",
    "proxy-loopback status 403",
    "proxy-unlisted status 403",
    "direct-connect refused ENETUNREACH",
    "direct-loopback refused ECONNREFUSED",
    "dns refused unresolved",
];

/// The names in the probe's environment, but for `LC_CTYPE`, which python sets itself.
fn environment(report: &str) -> Vec<String> {
    let env: Value = serde_json::from_str(report_line(report, "ENV ")).unwrap();
    env.as_object()
        .unwrap()
        .keys()
        .filter(|name| *name != "LC_CTYPE")
        .cloned()
        .collect()
}

/// What a container always has and bubblewrap only under the shim: no capability,
/// `no_new_privs` and a seccomp filter.
#[track_caller]
fn assert_hardened(status: &str) {
    for line in [
        "CapEff:\t0000000000000000",
        "CapBnd:\t0000000000000000",
        "NoNewPrivs:\t1",
        "Seccomp:\t2",
    ] {
        assert!(
            status.lines().any(|seen| seen == line),
            "the container guarantees {line:?}: {status}"
        );
    }
}

/// The acceptance of #263: the same manifest runs on bubblewrap and on runc with the same
/// writable paths, environment, network, refusals, output and evidence.
#[test]
fn one_manifest_runs_with_the_same_authority_on_bubblewrap_and_on_runc() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !container() {
        eprintln!("skipping: bubblewrap, python3 or a runnable runc unavailable");
        return;
    }
    let bench = Bench::new();
    let snapshot = bench.snapshot;
    let node = Node::spawn(bench.path(), &["--container-runtime", RUNC]);
    let isolation = node.isolation();
    assert_eq!(
        isolation,
        json!({"namespaces": {"sandbox": true, "user_namespace": true},
            "backends": {"container": true, "microvm": false, "vm": false}}),
        "a node with a container runtime offers sandbox and container and places nothing \
         stronger than asked"
    );
    let targets = Targets::new();
    let port = bench.port;

    let sandboxed = probe(&node, 101, snapshot, MANIFEST, &targets, port);
    let contained = probe(&node, 102, snapshot, CONTAINER_MANIFEST, &targets, port);

    assert_eq!(sandboxed.outcome, completed(task_binding(101)));
    assert_eq!(contained.outcome, completed(task_binding(102)));
    assert_eq!(
        sandboxed.capsule,
        json!({"backend": "bubblewrap", "isolation": "sandbox"})
    );
    assert_eq!(
        contained.capsule,
        json!({"backend": "runc", "isolation": "container"})
    );

    let steps: Vec<&str> = sandboxed
        .report
        .lines()
        .filter_map(|line| line.strip_prefix("PROBE "))
        .collect();
    assert_eq!(steps, STEPS, "{}", sandboxed.report);
    assert_eq!(
        contained.report, sandboxed.report,
        "the same steps, refusals and environment on both backends"
    );
    assert_eq!(
        environment(&contained.report),
        ["HOME", "PATH", "PWD", "TERM", "WARD_PROXY_SOCKET"],
        "the node's variables and nothing of the host"
    );
    for report in [&sandboxed.report, &contained.report] {
        for secret in [NODE_CANARY, HOST_SECRET, LEASED, BROKER_TOKEN] {
            assert!(!report.contains(secret), "{secret} reached a capsule");
        }
    }
    assert_eq!(
        bench.seen(),
        ["GET /v1/data HTTP/1.1 | Bearer hvs.node-leased-token-263"; 2],
        "the upstream saw the node's lease, injected by its proxy, from each backend"
    );
    assert!(!targets.outside.exists(), "nothing escaped to the host");
    for workspace in [
        node.workspace(task_binding(101)),
        node.workspace(task_binding(102)),
    ] {
        assert_eq!(
            std::fs::read_to_string(workspace.join("inside.txt")).unwrap(),
            "written by the probe\n"
        );
        assert!(!workspace.join("scratch").exists());
    }
    assert!(
        !node.bundle(task_binding(102)).exists(),
        "the container is deleted and its bundle removed once it is reaped"
    );

    assert_eq!(
        contained.result, sandboxed.result,
        "the same returned output"
    );
    assert_eq!(sandboxed.result["state"], "exited");
    assert_eq!(
        sandboxed.result["output"]["stdout"]["content_base64"],
        "cHJvYmUgc3Rkb3V0Cg=="
    );
    assert_eq!(
        sandboxed.result["output"]["stderr"]["content_base64"],
        "cHJvYmUgc3RkZXJyCg=="
    );
    assert_eq!(
        contained.evidence, sandboxed.evidence,
        "the same evidence records apart from ids, digests and pids"
    );
    assert!(
        contained
            .evidence
            .iter()
            .any(|record| record["event"].get("NetworkRequested").is_some()),
        "{:?}",
        contained.evidence
    );

    assert_hardened(&contained.status);
}

fn marker() -> String {
    format!(
        "ward-capsule-263-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn processes_with(marker: &str) -> usize {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().parse::<u32>().is_ok())
        .filter_map(|entry| std::fs::read(entry.path().join("cmdline")).ok())
        .filter(|cmdline| {
            cmdline
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        })
        .count()
}

/// A budget kill and a stop end the attempt the same way on both backends, and leave no
/// process of it behind.
#[test]
fn a_budget_and_a_stop_end_an_attempt_alike_on_both_backends() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !container() {
        eprintln!("skipping: bubblewrap, python3 or a runnable runc unavailable");
        return;
    }
    let bench = Bench::new();
    let snapshot = bench.snapshot;
    let node = Node::spawn(bench.path(), &["--container-runtime", RUNC]);
    let ctx = context();
    let mut ends = Vec::new();
    for (task, manifest) in [(201, MANIFEST), (202, CONTAINER_MANIFEST)] {
        let marker = marker();
        let script = format!("touch /work/started; sleep 300; echo {marker}");
        let binding = task_binding(task);
        let started = Instant::now();
        node.start(
            binding,
            &signed_admit(
                binding,
                snapshot,
                manifest,
                &["sh".into(), "-c".into(), script],
                1_500,
            ),
        );
        assert_eq!(
            node.ended(binding),
            ctx.inspected_with_outcome(
                binding,
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Failed
            )
            .unwrap()
        );
        assert!(started.elapsed() < Duration::from_secs(20));
        assert!(node.workspace(binding).join("started").exists());
        eventually("the killed workload's processes gone", || {
            processes_with(&marker) == 0
        });
        ends.push(node.evidence(binding));
    }
    for (task, manifest) in [(203, MANIFEST), (204, CONTAINER_MANIFEST)] {
        let marker = marker();
        let script = format!("touch /work/started; sleep 300; echo {marker}");
        let binding = task_binding(task);
        node.start(
            binding,
            &signed_admit(
                binding,
                snapshot,
                manifest,
                &["sh".into(), "-c".into(), script],
                600_000,
            ),
        );
        eventually("the workload running", || {
            node.workspace(binding).join("started").exists()
        });
        assert_eq!(
            node.lifecycle(&ctx.stop(op(4), binding)),
            ctx.accepted(op(4), binding, TaskLifecycleState::Stopped)
        );
        eventually("the stopped workload's processes gone", || {
            processes_with(&marker) == 0
        });
        ends.push(node.evidence(binding));
    }
    for task in [202, 204] {
        assert!(!node.bundle(task_binding(task)).exists(), "{task}");
    }
    assert_eq!(ends[1], ends[0], "a budget kill is recorded alike");
    assert_eq!(ends[3], ends[2], "a stop is recorded alike");
    assert_eq!(
        node.capsule(task_binding(202)),
        json!({"backend": "runc", "isolation": "container"})
    );
    assert_eq!(
        node.capsule(task_binding(204)),
        json!({"backend": "runc", "isolation": "container"})
    );
}

/// A node without a container runtime refuses a `container` floor and never runs an
/// unmarked manifest anywhere but bubblewrap; `--place-stronger` needs the runtime.
#[test]
fn a_container_floor_is_refused_by_a_node_without_a_container_runtime() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !bubblewrap() {
        eprintln!("skipping: bubblewrap or python3 unavailable");
        return;
    }
    let bench = Bench::new();
    let snapshot = bench.snapshot;
    let refused = Node::command(bench.path(), &["--place-stronger"])
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--container-runtime"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let node = Node::spawn(bench.path(), &[]);
    assert_eq!(
        node.isolation()["backends"],
        json!({"container": false, "microvm": false, "vm": false})
    );
    let binding = task_binding(301);
    let argv = ["true".to_owned()];
    assert_eq!(
        node.admit(
            binding,
            &signed_admit(binding, snapshot, CONTAINER_MANIFEST, &argv, 60_000)
        ),
        context().rejected(
            Some(op(2)),
            binding,
            TaskLifecycleRejectionReason::UnsupportedGrant
        )
    );
    assert!(
        !node
            .root
            .join(binding.task().to_string())
            .join(binding.attempt().to_string())
            .exists()
    );
    assert_eq!(
        node.lifecycle(&signed_admit(binding, snapshot, MANIFEST, &argv, 60_000)),
        context().accepted(op(2), binding, TaskLifecycleState::Ready)
    );
    assert_eq!(
        node.lifecycle(&context().start(op(3), binding)),
        context().accepted(op(3), binding, TaskLifecycleState::Running)
    );
    assert_eq!(node.ended(binding), completed(binding));
    assert_eq!(
        node.capsule(binding),
        json!({"backend": "bubblewrap", "isolation": "sandbox"})
    );
}

/// The operator's runtime is verified at start: a node refuses to serve with a runtime
/// that is not an absolute path to the operator's own `runc`.
#[test]
fn a_node_refuses_a_container_runtime_it_cannot_trust() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !bubblewrap() {
        eprintln!("skipping: bubblewrap or python3 unavailable");
        return;
    }
    let dir = private_dir();
    let writable = dir.path().join("runc-writable");
    std::fs::copy("/bin/true", &writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    let impostor = dir.path().join("runc-impostor");
    std::fs::copy("/bin/true", &impostor).unwrap();
    std::fs::set_permissions(&impostor, std::fs::Permissions::from_mode(0o755)).unwrap();
    for (runtime, refusal) in [
        ("runc", "not an absolute path"),
        ("/nonexistent/runc", "No such file"),
        ("/usr/bin", "not a regular file"),
        (writable.to_str().unwrap(), "writable by group or others"),
        (impostor.to_str().unwrap(), "does not answer as runc"),
    ] {
        let output = Node::command(dir.path(), &["--container-runtime", runtime])
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{runtime}");
        assert!(stderr.contains(refusal), "{runtime}: {stderr}");
    }
}

/// Stronger placement is the operator's: with `--place-stronger` an unmarked manifest runs
/// on runc, the document says so and the record names runc; without it, never.
#[test]
fn an_unmarked_manifest_runs_on_runc_only_when_the_operator_places_stronger() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !container() {
        eprintln!("skipping: bubblewrap, python3 or a runnable runc unavailable");
        return;
    }
    let argv = [
        "sh".to_owned(),
        "-c".to_owned(),
        "cat input.txt > copy.txt".to_owned(),
    ];
    for (task, flags, backend) in [
        (401, &["--container-runtime", RUNC][..], "bubblewrap"),
        (
            402,
            &["--container-runtime", RUNC, "--place-stronger"][..],
            "runc",
        ),
    ] {
        let bench = Bench::new();
        let snapshot = bench.snapshot;
        let node = Node::spawn(bench.path(), flags);
        let isolation = node.isolation();
        assert_eq!(isolation["backends"]["container"], true);
        assert_eq!(
            isolation.get("stronger_placement"),
            (backend == "runc").then_some(&Value::Bool(true)),
            "{isolation}"
        );
        let binding = task_binding(task);
        node.start(
            binding,
            &signed_admit(binding, snapshot, MANIFEST, &argv, 60_000),
        );
        assert_eq!(node.ended(binding), completed(binding));
        assert_eq!(
            std::fs::read(node.workspace(binding).join("copy.txt")).unwrap(),
            b"from the snapshot\n"
        );
        let level = if backend == "runc" {
            "container"
        } else {
            "sandbox"
        };
        assert_eq!(
            node.capsule(binding),
            json!({"backend": backend, "isolation": level}),
            "{flags:?}"
        );
    }
}

/// `pause` and `resume` on a runc attempt are the cgroup freezer's when the node runs as
/// root, and refused `unsupported_operation` without root, where the container has no
/// cgroup; a paused container still dies at its budget.
#[test]
fn a_runc_attempt_pauses_only_where_it_has_a_freezer() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !container() {
        eprintln!("skipping: bubblewrap, python3 or a runnable runc unavailable");
        return;
    }
    let bench = Bench::new();
    let node = Node::spawn(bench.path(), &["--container-runtime", RUNC]);
    let ctx = context();
    let binding = task_binding(501);
    let marker = marker();
    let script = format!("while :; do date +%s%N > /work/tick; sleep 0.05; done; echo {marker}");
    node.start(
        binding,
        &signed_admit(
            binding,
            bench.snapshot,
            CONTAINER_MANIFEST,
            &["sh".into(), "-c".into(), script],
            8_000,
        ),
    );
    let tick = node.workspace(binding).join("tick");
    eventually("the workload ticking", || tick.exists());
    let root = std::fs::metadata(bench.path()).unwrap().uid() == 0;
    let paused = node.lifecycle(&ctx.pause(op(4), binding));
    if !root {
        assert_eq!(
            paused,
            ctx.rejected(
                Some(op(4)),
                binding,
                TaskLifecycleRejectionReason::UnsupportedOperation
            ),
            "a rootless container has no freezer"
        );
        assert_eq!(
            node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Running)
        );
        assert_eq!(
            node.lifecycle(&ctx.stop(op(5), binding)),
            ctx.accepted(op(5), binding, TaskLifecycleState::Stopped)
        );
        eventually("the workload gone", || processes_with(&marker) == 0);
        return;
    }
    assert_eq!(
        paused,
        ctx.accepted(op(4), binding, TaskLifecycleState::Paused)
    );
    let frozen = std::fs::read(&tick).unwrap();
    let mut still = 0;
    eventually("the frozen workload not ticking over a dozen polls", || {
        assert_eq!(
            std::fs::read(&tick).unwrap(),
            frozen,
            "a paused container ran"
        );
        still += 1;
        still > 12
    });
    assert_eq!(
        node.lifecycle(&ctx.resume(op(5), binding)),
        ctx.accepted(op(5), binding, TaskLifecycleState::Running)
    );
    eventually("the resumed workload ticking", || {
        std::fs::read(&tick).unwrap() != frozen
    });
    assert_eq!(
        node.lifecycle(&ctx.pause(op(6), binding)),
        ctx.accepted(op(6), binding, TaskLifecycleState::Paused)
    );
    let paused = ctx.inspected(binding, TaskLifecycleState::Paused);
    let mut state = paused;
    eventually("the paused attempt's end at its budget", || {
        state = node.lifecycle(&ctx.inspect(binding));
        state != paused
    });
    assert_eq!(
        state,
        ctx.inspected_with_outcome(
            binding,
            TaskLifecycleState::Exited,
            TaskExecutionOutcome::Failed
        )
        .unwrap(),
        "the budget kills a paused container"
    );
    eventually("the killed workload gone", || processes_with(&marker) == 0);
    assert!(!node.bundle(binding).exists());
}

/// A runc attempt dies with its node, as a bubblewrap one does: a node killed outright
/// leaves no process of its container behind.
#[test]
fn a_runc_attempt_dies_with_its_node() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !container() {
        eprintln!("skipping: bubblewrap, python3 or a runnable runc unavailable");
        return;
    }
    let bench = Bench::new();
    let mut node = Node::spawn(bench.path(), &["--container-runtime", RUNC]);
    let binding = task_binding(601);
    let marker = marker();
    let script = format!("touch /work/started; sleep 300; echo {marker}");
    node.start(
        binding,
        &signed_admit(
            binding,
            bench.snapshot,
            CONTAINER_MANIFEST,
            &["sh".into(), "-c".into(), script],
            600_000,
        ),
    );
    eventually("the workload running", || {
        node.workspace(binding).join("started").exists()
    });
    assert_eq!(processes_with(&marker), 1);
    node.child.kill().unwrap();
    node.child.wait().unwrap();
    eventually("the container gone with its node", || {
        processes_with(&marker) == 0
    });
    drop(node);
    let node = Node::spawn(bench.path(), &["--container-runtime", RUNC]);
    assert_eq!(
        node.lifecycle(&context().inspect(binding)),
        context()
            .inspected_with_outcome(
                binding,
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Unknown
            )
            .unwrap()
    );
    assert_eq!(
        node.capsule(binding),
        json!({"backend": "runc", "isolation": "container"})
    );
    assert!(
        !node.bundle(binding).exists(),
        "the restarted node deletes the container its predecessor left"
    );
}
