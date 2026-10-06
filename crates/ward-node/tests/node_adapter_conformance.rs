//! Node adapter conformance (#279, ADR-0036, `docs/agent-integration.md` §10.9).
//!
//! The acceptance of #279 against the real `ward-node` binary: the same signed capability
//! manifest, byte for byte, runs through three materially different agent adapters —
//! Claude Code (hooks `full`), Codex (hooks `none`) and the generic process adapter (no
//! hooks, no provider) — named by the admitted workload, and the node enforces exactly
//! the same authority for each. Every attempt runs the same hostile probe: it reads a host
//! secret, the node's own state, its own evidence log and its own credential leases,
//! writes outside the workspace and into `/usr`, asks the attempt's proxy for an unlisted
//! host, a model provider's API and a private address, connects directly and resolves a
//! name, and uses the two credential routes the manifest grants. The refusals must be
//! identical step for step, the node's enforcement records identical record for record,
//! no variable of the node's environment (where model keys sit) may reach the sandbox,
//! and the upstream must see only the node's leased credential, injected by its proxy.
//! Only the semantic picture differs, and exactly as each adapter's capability document
//! says: Claude Code's hook lines become agent-origin claims, Codex and the generic
//! adapter add none, and each attempt records one `agent_adapter` binding as metadata.
//!
//! The runtimes are fakes, as in `ward-daemon`'s `adapter_conformance.rs`: the Claude Code
//! fake reads the settings the node seeds and, with no `ward-agent` shim in the sandbox,
//! writes the line `ward-agent hook` would to `$WARD_SOCKET`; the Codex fake checks the
//! environment its adapter sets. The fake provider and upstream bind 127.0.0.1. Requires
//! bubblewrap and python3; skips without them except under `WARD_REQUIRE_ISOLATION=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
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
    AgentId, Blake3Hash, ClaimKind, DelegationId, EventRecord, ExecutionAttemptId, LeaseId, NodeId,
    Origin, PrincipalId, SessionId, SnapshotId, TaskId, WardEvent,
};
use ward_node::evidence;
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifestBytes, HandshakeRequest,
    HandshakeResponse, IssuerProof, IssuerSignature, OperationId, ProtocolVersion,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskExecutionOutcome, TaskLifecycleContext, TaskLifecycleRejectionReason, TaskLifecycleRequest,
    TaskLifecycleResponse, TaskLifecycleState, TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
};

/// Serialises writing the fake executables with every process spawn in this binary: a
/// fork while another thread holds a just-written executable open for writing makes its
/// exec fail with `ETXTBSY`. Every test body runs under it.
static SERIAL: Mutex<()> = Mutex::new(());

const NODE: NodeId = NodeId::from_u128(36);
const BROKER_TOKEN: &str = "fake-broker-token-for-279";
const LEASED: &str = "hvs.node-leased-provider-token-279";
const ACCESSOR: &str = "node-lease-accessor-279";
const ANTHROPIC_CANARY: &str = "anthropic-canary-279-never-in-a-node-sandbox";
const OPENAI_CANARY: &str = "openai-canary-279-never-in-a-node-sandbox";
const GITHUB_CANARY: &str = "github-canary-279-never-in-a-node-sandbox";
const HOST_SECRET: &str = "host-secret-279-node";

/// The one capability manifest every adapter runs under: the attempt's proxy allows
/// `localhost` only, and the node brokers one credential for each model provider there.
const MANIFEST: &str = r#"{"network":{"custom":["localhost"]},"credentials":[{"service":"anthropic","host":"localhost","ttl_secs":60},{"service":"openai","host":"localhost","ttl_secs":60}]}"#;

/// The probe every fake runs: the same steps, in the same order, each reported as one
/// `PROBE <step> <result>` line in `/work/report.txt`, then one `ENV <json>` line with its
/// environment and one `INIT <json>` line with the names in the environment of the
/// sandbox's PID 1. `hook(event, tool, summary)` is the adapter's hook layer; a step a
/// hook refuses is reported `skipped`.
const PROBE: &str = r#"
import errno, json, os, socket

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

def proxy():
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(os.environ["WARD_PROXY_SOCKET"])
    return s

def status(s):
    data = b""
    while b"\r\n" not in data:
        chunk = s.recv(256)
        if not chunk:
            break
        data += chunk
    s.close()
    return "status " + data.split(b"\r\n")[0].decode().split(" ")[1]

def proxy_connect(host):
    s = proxy()
    s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (host, host)).encode())
    return status(s)

def route(service, header):
    s = proxy()
    s.sendall(("GET /%s/v1/models HTTP/1.1\r\nHost: localhost\r\n%s: placeholder\r\nConnection: close\r\n\r\n" % (service, header)).encode())
    return status(s)

def direct_connect(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((addr, 443))
        return "connected"
    finally:
        s.close()

def resolve(host):
    try:
        socket.getaddrinfo(host, 443)
        return "resolved"
    except socket.gaierror:
        return "refused unresolved"

def run(args, hook):
    host = dict(zip(args[::2], args[1::2]))
    steps = [
        ("read-workspace", "Read", "/work/README.md", lambda: read("/work/README.md")),
        ("write-workspace", "Write", "/work/inside.txt", lambda: write("/work/inside.txt")),
        ("read-host-secret", "Read", host["--secret"], lambda: read(host["--secret"])),
        ("read-node-state", "Read", host["--state"], lambda: listdir(host["--state"])),
        ("read-own-evidence", "Read", host["--evidence"], lambda: listdir(host["--evidence"])),
        ("read-own-leases", "Read", host["--leases"], lambda: listdir(host["--leases"])),
        ("write-host-path", "Write", host["--outside"], lambda: write(host["--outside"])),
        ("write-system", "Write", "/usr/ward-escape", lambda: write("/usr/ward-escape")),
        ("proxy-blocked-host", "WebFetch", "https://blocked.example/", lambda: proxy_connect("blocked.example")),
        ("proxy-provider-api", "WebFetch", "https://api.anthropic.com/", lambda: proxy_connect("api.anthropic.com")),
        ("proxy-other-provider", "WebFetch", "https://api.openai.com/", lambda: proxy_connect("api.openai.com")),
        ("proxy-private-address", "WebFetch", "https://10.0.0.1/", lambda: proxy_connect("10.0.0.1")),
        ("direct-connect", "Bash", "connect 192.0.2.1:443", lambda: direct_connect("192.0.2.1")),
        ("dns-blocked-host", "Bash", "resolve blocked.example", lambda: resolve("blocked.example")),
        ("route-anthropic", "WebFetch", "/anthropic/v1/models", lambda: route("anthropic", "x-api-key")),
        ("route-openai", "WebFetch", "/openai/v1/models", lambda: route("openai", "authorization")),
    ]
    lines = []
    hook("SessionStart", None, None)
    for name, tool, summary, step in steps:
        if hook("PreToolUse", tool, summary) == "deny":
            lines.append("PROBE %s skipped" % name)
            continue
        try:
            result = step()
        except OSError as e:
            result = refused(e)
        lines.append("PROBE %s %s" % (name, result))
        hook("PostToolUse", tool, summary)
    hook("PermissionRequest", "Bash", "connect 192.0.2.1:443")
    hook("Stop", None, None)
    lines.append("ENV " + json.dumps(dict(os.environ), sort_keys=True))
    try:
        with open("/proc/1/environ", "rb") as f:
            init = [kv.split(b"=", 1)[0].decode() for kv in f.read().split(b"\0") if kv]
    except OSError as e:
        init = [refused(e)]
    lines.append("INIT " + json.dumps(sorted(init)))
    with open("/work/report.txt", "w") as f:
        f.write("\n".join(lines) + "\n")
"#;

/// Claude Code as the node launches it: the hooks are whatever the seeded settings file
/// wires; with no `ward-agent` shim in the sandbox each is the line `ward-agent hook`
/// would write to `$WARD_SOCKET`.
const CLAUDE: &str = r#"#!/usr/bin/env python3
import json, os, socket, subprocess, sys
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe

settings = json.load(open(os.path.join(os.environ["CLAUDE_CONFIG_DIR"], "settings.json")))
wired = settings.get("hooks", {})

def hook(event, tool, summary):
    if event not in wired:
        return None
    command = wired[event][0]["hooks"][0]["command"]
    if os.path.exists(command.split(" ")[0]):
        raise SystemExit("a ward-agent shim in a node sandbox is not part of this suite")
    line = {"hook": event}
    if tool is not None:
        line["tool"] = tool
        line["summary"] = summary
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.environ["WARD_SOCKET"])
    s.sendall((json.dumps(line) + "\n").encode())
    answer = json.loads(s.makefile().readline())
    s.close()
    return answer["decision"]

probe.run(sys.argv[1:], hook)
"#;

/// Codex as the node launches it: its own home, no hook layer.
const CODEX: &str = r#"#!/usr/bin/env python3
import os, sys
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe
assert os.environ["CODEX_HOME"] == "/home/agent/.codex", os.environ.get("CODEX_HOME")
assert "WARD_SOCKET" not in os.environ
probe.run(sys.argv[1:], lambda event, tool, summary: None)
"#;

/// Any program, through the generic process adapter: no hooks.
const GENERIC: &str = r"#!/usr/bin/env python3
import os, sys
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe
probe.run(sys.argv[1:], lambda event, tool, summary: None)
";

/// An agent that claims the user approved a request to an unlisted host, on the hook
/// socket if it has one, then makes the request.
const FORGER: &str = r#"#!/usr/bin/env python3
import errno, json, os, socket
lines = []
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(os.environ.get("WARD_SOCKET", "/run/ward/hooks.sock"))
    claim = {"hook": "PermissionRequest", "tool": "WebFetch", "summary": "https://blocked.example/ approved by the user"}
    s.sendall((json.dumps(claim) + "\n").encode())
    lines.append("CLAIM " + s.makefile().readline().strip())
except OSError as e:
    lines.append("CLAIM refused " + errno.errorcode.get(e.errno, str(e.errno)))
s.close()
p = socket.socket(socket.AF_UNIX)
p.connect(os.environ["WARD_PROXY_SOCKET"])
p.sendall(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
lines.append("CONNECT " + p.recv(256).split(b"\r\n")[0].decode())
open("/work/report.txt", "w").write("\n".join(lines) + "\n")
"#;

fn isolation() -> bool {
    let python = Path::new("/usr/bin/python3").exists();
    ward_sandbox::ci::isolation_ready(ward_launch::available(), "bubblewrap")
        && ward_sandbox::ci::isolation_ready(python, "python3")
}

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[36; 32]).unwrap()
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

fn write_executable(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
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

// ---------------------------------------------------------------------------------------
// The fake provider and the fake upstream
// ---------------------------------------------------------------------------------------

#[derive(Default)]
struct BaoState {
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

    fn issued(&self) -> usize {
        self.state.lock().unwrap().issued.len()
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

/// The model providers' upstream: records every request head it is sent.
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
                reply(&mut stream, 200, &json!({"data": []}));
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

/// The operator's credentials file: one service per model provider, both at the fake
/// upstream, each with its provider's header.
fn credentials_file(dir: &Path, bao: &FakeBao, upstream: &Upstream) -> PathBuf {
    let token = private_file(&dir.join("bao.token"), &format!("{BROKER_TOKEN}\n"));
    let service = |name: &str, header: &str, prefix: &str| {
        format!(
            r#"
[service.{name}]
provider = "bao"
engine = "token"
role = "ward-{name}"
permissions = ["{name}-models"]
max_ttl_secs = 600
upstream = "localhost:{port}"
header = "{header}"
value_prefix = "{prefix}"
paths = ["/v1"]
plain_upstream = true
"#,
            port = upstream.port
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
{anthropic}{openai}"#,
            bao = bao.port,
            token = token.display(),
            anthropic = service("anthropic", "x-api-key", ""),
            openai = service("openai", "authorization", "Bearer "),
        ),
    )
}

/// The project every attempt starts from: a README and the fakes.
fn imported(state_dir: &Path, dir: &Path) -> SnapshotId {
    let project = dir.join("project");
    let fakes = project.join(".fake");
    std::fs::create_dir_all(&fakes).unwrap();
    std::fs::write(project.join("README.md"), "conformance\n").unwrap();
    std::fs::write(fakes.join("probe.py"), PROBE).unwrap();
    for (name, content) in [
        ("claude", CLAUDE),
        ("codex", CODEX),
        ("acme-agent", GENERIC),
        ("forger", FORGER),
    ] {
        write_executable(&fakes.join(name), content);
    }
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
    root: PathBuf,
    state: PathBuf,
}

impl Node {
    /// A node hosting `adapters`, its own environment holding model and forge keys.
    fn spawn(dir: &Path, credentials: &Path, adapters: &[&str]) -> Self {
        let socket = dir.join("node.sock");
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
            .arg("--credentials")
            .arg(credentials)
            .env("ANTHROPIC_API_KEY", ANTHROPIC_CANARY)
            .env("OPENAI_API_KEY", OPENAI_CANARY)
            .env("GITHUB_TOKEN", GITHUB_CANARY)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for adapter in adapters {
            command.arg("--agent-adapter").arg(adapter);
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
            root: dir.join("tasks"),
            state: dir.join("state"),
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
        response.trim().to_owned()
    }

    fn lifecycle(&self, request: &TaskLifecycleRequest) -> TaskLifecycleResponse {
        context()
            .decode_response(&self.request(&serde_json::to_string(request).unwrap()))
            .unwrap()
    }

    /// The capability document, as the node wrote it.
    fn capabilities(&self) -> Value {
        let answer: Value = serde_json::from_str(
            &self.request(r#"{"request":"capabilities","protocol":{"major":1,"minor":3}}"#),
        )
        .unwrap();
        answer["capabilities"].clone()
    }

    fn admit(&self, binding: TaskBinding, admit: &TaskLifecycleRequest) -> TaskLifecycleResponse {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding)),
            ctx.accepted(op(1), binding, TaskLifecycleState::Created)
        );
        self.lifecycle(admit)
    }

    /// Admit, start and wait for the end of one attempt; its outcome.
    fn run(&self, binding: TaskBinding, admit: &TaskLifecycleRequest) -> TaskLifecycleResponse {
        let ctx = context();
        assert_eq!(
            self.admit(binding, admit),
            ctx.accepted(op(2), binding, TaskLifecycleState::Ready)
        );
        assert_eq!(
            self.lifecycle(&ctx.start(op(3), binding)),
            ctx.accepted(op(3), binding, TaskLifecycleState::Running)
        );
        let running = ctx.inspected(binding, TaskLifecycleState::Running);
        let mut state = running;
        eventually("the attempt's end", || {
            state = self.lifecycle(&ctx.inspect(binding));
            state != running
        });
        state
    }

    fn workspace(&self, binding: TaskBinding) -> PathBuf {
        self.root
            .join(binding.task().to_string())
            .join(binding.attempt().to_string())
    }

    fn records(&self, binding: TaskBinding) -> Vec<EventRecord> {
        evidence::verify(&evidence::evidence_dir(&self.root, binding), binding)
            .unwrap()
            .records()
            .to_vec()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The signed `admit` of `argv` under [`MANIFEST`] for `binding`, the workload naming
/// `adapter` when given (`{"id": …}` beside the argv, ADR-0036), its version 1.
fn signed_admit(
    binding: TaskBinding,
    snapshot: SnapshotId,
    argv: &[String],
    adapter: Option<&Value>,
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
            CapabilityManifestBytes::new(MANIFEST.as_bytes().to_vec()).unwrap(),
            snapshot,
            30_000,
        )
        .unwrap(),
        issued_at_unix_ms: now - 60_000,
        expires_at_unix_ms: now + 600_000,
        version: AdmissionVersion::new(1).unwrap(),
    })
    .unwrap();
    let mut wire: Value =
        serde_json::from_slice(AdmissionEnvelopeJson::encode(&envelope).unwrap().as_bytes())
            .unwrap();
    if let Some(adapter) = adapter {
        wire["workload"]["adapter"] = adapter.clone();
    }
    let json = AdmissionEnvelopeJson::new(serde_json::to_string(&wire).unwrap()).unwrap();
    let key_pair = key_pair();
    let proof = IssuerProof::new(
        Blake3Hash::hash(key_pair.public_key().as_ref()),
        IssuerSignature::from_bytes(key_pair.sign(json.as_bytes()).as_ref().try_into().unwrap()),
    );
    context().admit(op(2), binding, json, proof).unwrap()
}

// ---------------------------------------------------------------------------------------
// The adapters under test
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Under {
    Claude,
    Codex,
    Generic,
}

impl Under {
    const ALL: [Self; 3] = [Self::Claude, Self::Codex, Self::Generic];

    const fn id(self) -> &'static str {
        match self {
            Self::Claude => "claude-code",
            Self::Codex => "codex",
            Self::Generic => "process",
        }
    }

    const fn program(self) -> &'static str {
        match self {
            Self::Claude => "/work/.fake/claude",
            Self::Codex => "/work/.fake/codex",
            Self::Generic => "/work/.fake/acme-agent",
        }
    }

    const fn task(self) -> u128 {
        match self {
            Self::Claude => 101,
            Self::Codex => 102,
            Self::Generic => 103,
        }
    }

    /// The variables the adapter's launch sets, beside what the node sets for every
    /// attempt: its configuration, and the hook socket for an adapter with hooks.
    fn launch_env(self) -> &'static [&'static str] {
        match self {
            Self::Claude => &[
                "CLAUDE_CONFIG_DIR",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
                "DISABLE_TELEMETRY",
                "DISABLE_ERROR_REPORTING",
                "ENABLE_CLAUDEAI_MCP_SERVERS",
                "CLAUDE_CODE_DISABLE_ARTIFACT",
                "WARD_SOCKET",
            ],
            Self::Codex => &["CODEX_HOME"],
            Self::Generic => &[],
        }
    }

    /// The binding the node must record: the document's id, runtime and events, the
    /// adapter's provider and the model its command line requests.
    fn binding(self) -> Value {
        let all = json!([
            "SessionStart",
            "PreToolUse",
            "PostToolUse",
            "PermissionRequest",
            "Stop"
        ]);
        match self {
            Self::Claude => json!({"agent_adapter": {"contract": "1.0", "adapter": "claude-code",
                "runtime": {"product": "Claude Code", "version": "2.1.263"}, "hooks": "full",
                "events": all, "provider": "anthropic", "model": "fake-model"}}),
            Self::Codex => json!({"agent_adapter": {"contract": "1.0", "adapter": "codex",
                "runtime": {"product": "OpenAI Codex CLI", "version": "0.153.4"}, "hooks": "none",
                "events": [], "provider": "openai", "model": "fake-model"}}),
            Self::Generic => json!({"agent_adapter": {"contract": "1.0", "adapter": "process",
                "runtime": {"product": "acme-agent", "version": null}, "hooks": "none",
                "events": [], "provider": null, "model": null}}),
        }
    }
}

/// One adapter's attempt.
struct Run {
    under: Under,
    probe: Vec<String>,
    env: BTreeMap<String, String>,
    init_env: Vec<String>,
    report: String,
    outcome: TaskLifecycleResponse,
    records: Vec<EventRecord>,
    manifest: Value,
}

/// Host paths the probe aims at.
struct Targets {
    _secrets: tempfile::TempDir,
    secret: PathBuf,
    outside: PathBuf,
}

impl Targets {
    fn new() -> Self {
        let secrets = tempfile::tempdir().unwrap();
        let secret = secrets.path().join("id_token");
        std::fs::write(&secret, HOST_SECRET).unwrap();
        let outside = secrets.path().join("escape.txt");
        Self {
            _secrets: secrets,
            secret,
            outside,
        }
    }
}

fn argv(under: Under, node: &Node, targets: &Targets, binding: TaskBinding) -> Vec<String> {
    let task_dir = node.root.join(binding.task().to_string());
    let attempt = binding.attempt().to_string();
    [
        under.program().to_owned(),
        "--model".to_owned(),
        "fake-model".to_owned(),
        "--secret".to_owned(),
        targets.secret.display().to_string(),
        "--state".to_owned(),
        node.state.display().to_string(),
        "--evidence".to_owned(),
        task_dir
            .join(format!("{attempt}.evidence"))
            .display()
            .to_string(),
        "--leases".to_owned(),
        task_dir
            .join(format!("{attempt}.credentials"))
            .display()
            .to_string(),
        "--outside".to_owned(),
        targets.outside.display().to_string(),
    ]
    .into()
}

fn run(under: Under, node: &Node, snapshot: SnapshotId, targets: &Targets) -> Run {
    let binding = task_binding(under.task());
    let argv = argv(under, node, targets, binding);
    let admit = signed_admit(binding, snapshot, &argv, Some(&json!({"id": under.id()})));
    let TaskLifecycleRequest::Admit { envelope_json, .. } = &admit else {
        panic!("an admit request")
    };
    let envelope: Value = serde_json::from_slice(envelope_json.as_bytes()).unwrap();
    let outcome = node.run(binding, &admit);
    let report_path = node.workspace(binding).join("report.txt");
    let report = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|error| panic!("{under:?}: no report ({error}); outcome {outcome:?}"));
    let line = |prefix: &str| {
        report
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap_or_else(|| panic!("{under:?}: no {prefix}line in {report}"))
            .to_owned()
    };
    Run {
        under,
        probe: report
            .lines()
            .filter_map(|line| line.strip_prefix("PROBE "))
            .map(str::to_owned)
            .collect(),
        env: serde_json::from_str(&line("ENV ")).unwrap(),
        init_env: serde_json::from_str(&line("INIT ")).unwrap(),
        report: report.clone(),
        outcome,
        records: node.records(binding),
        manifest: envelope["workload"]["capability_manifest"].clone(),
    }
}

/// What the node enforced, normalised for comparison: every enforcement-fact record about
/// the network and credentials, and the kinds of its lifecycle records, without pids,
/// times or lease lifetimes.
fn enforcement(records: &[EventRecord]) -> Vec<String> {
    records
        .iter()
        .filter(|record| record.origin.is_enforcement_fact())
        .map(|record| match &record.event {
            WardEvent::NetworkRequested {
                host,
                port,
                decision,
                rule,
                ..
            } => format!("net {host}:{port} {decision:?} {rule:?}"),
            WardEvent::NetworkDenied { dst, reason } => format!("deny {dst:?} {reason:?}"),
            WardEvent::CredentialGranted {
                service,
                scope,
                delivery,
                ..
            } => format!("granted {service:?} {scope:?} {delivery:?}"),
            WardEvent::CredentialDenied {
                service, reason, ..
            } => format!("cred-denied {service:?} {reason:?}"),
            WardEvent::CredentialRevoked { service, reason } => {
                format!("revoked {service:?} {reason:?}")
            }
            other => format!("{:?}", other.kind()),
        })
        .collect()
}

/// The agent-origin records: the binding payloads, then the hook events by name.
fn claims(records: &[EventRecord]) -> (Vec<Value>, Vec<String>) {
    let mut bindings = Vec::new();
    let mut hooks = Vec::new();
    for record in records
        .iter()
        .filter(|record| record.origin == Origin::Agent)
    {
        let WardEvent::AgentClaim { kind, payload } = &record.event else {
            panic!("agent-origin record that is not a claim: {record:?}")
        };
        let text = payload.content();
        match serde_json::from_str::<Value>(text) {
            Ok(binding) if binding.get("agent_adapter").is_some() => {
                assert_eq!(*kind, ClaimKind::Note);
                bindings.push(binding);
            }
            _ => hooks.push(text.split(' ').next().unwrap_or_default().to_owned()),
        }
    }
    (bindings, hooks)
}

/// A node hosting every shipped adapter, its fakes, and the provider it brokers from.
struct Bench {
    dir: tempfile::TempDir,
    bao: FakeBao,
    upstream: Upstream,
    snapshot: SnapshotId,
    node: Node,
}

impl Bench {
    fn new(adapters: &[&str]) -> Self {
        let dir = private_dir();
        let (bao, upstream) = (FakeBao::start(), Upstream::start());
        let snapshot = imported(&dir.path().join("state"), dir.path());
        let credentials = credentials_file(dir.path(), &bao, &upstream);
        let node = Node::spawn(dir.path(), &credentials, adapters);
        Self {
            dir,
            bao,
            upstream,
            snapshot,
            node,
        }
    }
}

// ---------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------

/// The acceptance of #279 on a node: the same signed manifest, the same refusals and
/// enforcement records, the node's leased credential as the only one, a different
/// semantic picture, for every adapter.
#[test]
fn every_adapter_runs_the_same_signed_manifest_under_identical_node_authority() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation or python3 unavailable");
        return;
    }
    let bench = Bench::new(&["claude-code", "codex", "process"]);
    let targets = Targets::new();
    let runs: Vec<Run> = Under::ALL
        .into_iter()
        .map(|under| run(under, &bench.node, bench.snapshot, &targets))
        .collect();

    let generic = &runs[2];
    assert_probe_is_refused(&generic.probe);
    for run in &runs {
        assert_same_authority(run, generic);
        assert_no_host_environment(run);
        assert_declared_semantics(run);
    }
    assert!(!targets.outside.exists(), "nothing was written outside");
    assert_only_the_brokered_credential(&bench, &runs);
}

/// The probe itself: the workspace is usable, the granted routes work, everything else
/// is refused.
fn assert_probe_is_refused(probe: &[String]) {
    let expected = [
        "read-workspace read conformance",
        "write-workspace written",
        "read-host-secret refused ENOENT",
        "read-node-state refused ENOENT",
        "read-own-evidence refused ENOENT",
        "read-own-leases refused ENOENT",
        "write-host-path refused ENOENT",
    ];
    assert_eq!(&probe[..expected.len()], &expected, "{probe:#?}");
    let by_step: BTreeMap<&str, &str> = probe.iter().filter_map(|l| l.split_once(' ')).collect();
    assert!(
        by_step["write-system"].starts_with("refused "),
        "{by_step:?}"
    );
    for step in [
        "proxy-blocked-host",
        "proxy-provider-api",
        "proxy-other-provider",
        "proxy-private-address",
    ] {
        assert_eq!(by_step[step], "status 403", "{step}: {by_step:?}");
    }
    assert!(
        by_step["direct-connect"].starts_with("refused "),
        "{by_step:?}"
    );
    assert_eq!(by_step["dns-blocked-host"], "refused unresolved");
    assert_eq!(by_step["route-anthropic"], "status 200", "{by_step:?}");
    assert_eq!(by_step["route-openai"], "status 200", "{by_step:?}");
    assert_eq!(probe.len(), 16, "{probe:#?}");
}

/// The same signed manifest, the same refusals step for step and record for record, and
/// the same receipt.
fn assert_same_authority(run: &Run, reference: &Run) {
    let under = run.under;
    assert_eq!(
        run.manifest, reference.manifest,
        "{under:?}: the manifest bytes"
    );
    assert_eq!(run.probe, reference.probe, "{under:?}");
    assert_eq!(
        enforcement(&run.records),
        enforcement(&reference.records),
        "{under:?}"
    );
    let binding = task_binding(under.task());
    assert_eq!(
        run.outcome,
        context()
            .inspected_with_outcome(
                binding,
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Completed
            )
            .unwrap(),
        "{under:?}: {}",
        run.report
    );
}

/// Nothing of the node's environment in the sandbox: the agent sees what the node sets
/// for every attempt and its adapter's own configuration, and the sandbox's PID 1 holds
/// nothing at all. No key, no token, no leased value.
fn assert_no_host_environment(run: &Run) {
    let under = run.under;
    let node_set = ["HOME", "PATH", "TERM", "WARD_PROXY_SOCKET"];
    for (name, value) in &run.env {
        let python_coercion = name == "LC_CTYPE" && value.eq_ignore_ascii_case("c.utf-8");
        let workdir = name == "PWD" && value == "/work";
        assert!(
            python_coercion
                || workdir
                || node_set.contains(&name.as_str())
                || under.launch_env().contains(&name.as_str()),
            "{under:?}: {name} reached the sandbox"
        );
    }
    for name in under.launch_env() {
        assert!(run.env.contains_key(*name), "{under:?}: {name} is not set");
    }
    for secret in [
        ANTHROPIC_CANARY,
        OPENAI_CANARY,
        GITHUB_CANARY,
        HOST_SECRET,
        LEASED,
        BROKER_TOKEN,
    ] {
        assert!(
            !run.report.contains(secret),
            "{under:?}: {secret} reached the sandbox"
        );
    }
    assert_eq!(
        run.init_env,
        Vec::<String>::new(),
        "{under:?}: PID 1's environment"
    );
}

/// What differs: one binding per attempt naming the adapter, and the semantic events,
/// exactly as the document declares them.
fn assert_declared_semantics(run: &Run) {
    let under = run.under;
    let (bindings, hooks) = claims(&run.records);
    assert_eq!(
        bindings,
        [under.binding()],
        "{under:?}: one binding per attempt"
    );
    let launched = run
        .records
        .iter()
        .position(|record| matches!(record.event, WardEvent::NodeAttemptLaunched { .. }))
        .unwrap();
    assert_eq!(
        run.records[launched + 1].origin,
        Origin::Agent,
        "{under:?}: the binding follows the launch record"
    );
    match under {
        Under::Claude => {
            let mut seen = hooks.clone();
            seen.sort();
            seen.dedup();
            assert_eq!(
                seen,
                [
                    "PermissionRequest",
                    "PostToolUse",
                    "PreToolUse",
                    "SessionStart",
                    "Stop"
                ],
                "{hooks:?}"
            );
            assert_eq!(hooks.len(), 1 + 16 * 2 + 1 + 1, "{hooks:?}");
        }
        Under::Codex | Under::Generic => assert!(hooks.is_empty(), "{under:?}: {hooks:?}"),
    }
}

/// The only credential is the node's lease, injected by its proxy into the route the
/// manifest grants: the same two routes for every adapter, whatever its provider, every
/// lease revoked when its attempt ended, and no key of the node's ever sent.
fn assert_only_the_brokered_credential(bench: &Bench, runs: &[Run]) {
    let heads = bench.upstream.heads();
    assert_eq!(heads.len(), 2 * runs.len(), "{heads:#?}");
    for pair in heads.chunks(2) {
        assert!(pair[0].starts_with("GET /v1/models HTTP/1.1"), "{heads:#?}");
        assert!(
            pair[0].contains(&format!("x-api-key: {LEASED}")),
            "{heads:#?}"
        );
        assert!(
            pair[1].contains(&format!("authorization: Bearer {LEASED}")),
            "{heads:#?}"
        );
    }
    for head in &heads {
        assert!(!head.contains("placeholder"), "{head}");
        for canary in [ANTHROPIC_CANARY, OPENAI_CANARY, GITHUB_CANARY] {
            assert!(!head.contains(canary), "{head}");
        }
    }
    assert_eq!(bench.bao.issued(), 2 * runs.len());
    assert_eq!(bench.bao.revoked(), vec![ACCESSOR; 2 * runs.len()]);
    let _ = bench.dir.path();
}

/// A hook answer is steering, and a claim is a claim: Claude Code's hook socket answers a
/// forged approval `allow` and records it as an agent-origin claim, a hookless adapter has
/// no hook socket at all, and the node's proxy refuses the request for both, recording
/// the same denial.
#[test]
fn a_forged_approval_grants_nothing_with_or_without_hooks() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation or python3 unavailable");
        return;
    }
    let bench = Bench::new(&["claude-code", "codex"]);
    let mut denials = Vec::new();
    for (task, adapter) in [(201, "claude-code"), (202, "codex")] {
        let binding = task_binding(task);
        let admit = signed_admit(
            binding,
            bench.snapshot,
            &["/work/.fake/forger".to_owned()],
            Some(&json!({"id": adapter})),
        );
        bench.node.run(binding, &admit);
        let report = std::fs::read_to_string(bench.node.workspace(binding).join("report.txt"))
            .unwrap_or_else(|error| panic!("{adapter}: no report: {error}"));
        let records = bench.node.records(binding);
        let (bindings, hooks) = claims(&records);
        assert_eq!(bindings.len(), 1, "{adapter}");
        if adapter == "claude-code" {
            assert!(report.contains(r#"CLAIM {"decision":"allow""#), "{report}");
            assert_eq!(
                hooks,
                ["PermissionRequest"],
                "the forged line is only a claim"
            );
        } else {
            assert!(report.contains("CLAIM refused ENOENT"), "{report}");
            assert!(hooks.is_empty(), "{hooks:?}");
        }
        assert!(
            report.contains("CONNECT HTTP/1.1 403"),
            "{adapter}: {report}"
        );
        denials.push(
            enforcement(&records)
                .into_iter()
                .filter(|line| line.contains("blocked.example"))
                .collect::<Vec<_>>(),
        );
    }
    assert!(!denials[0].is_empty(), "the proxy recorded the refusal");
    assert_eq!(
        denials[0], denials[1],
        "the same refusal, recorded the same"
    );
}

/// A node advertises exactly the adapters its operator hosts, refuses any other
/// `unsupported_grant` before the version is consumed, and refuses an adapter outside the
/// grammar as it refuses any malformed envelope; a node that hosts none says nothing new.
#[test]
fn a_node_hosts_only_the_adapters_its_operator_named() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation or python3 unavailable");
        return;
    }
    let ctx = context();
    let bench = Bench::new(&["codex"]);
    let document = bench.node.capabilities();
    assert_eq!(
        document["adapters"],
        json!({"contract": "1.0", "hosted": ["codex"]}),
        "{document}"
    );
    let program = || vec!["/work/.fake/codex".to_owned()];
    for (task, adapter, argv, reason) in [
        (
            301,
            json!({"id": "claude-code"}),
            program(),
            TaskLifecycleRejectionReason::UnsupportedGrant,
        ),
        (
            302,
            json!({"id": "gemini-cli"}),
            program(),
            TaskLifecycleRejectionReason::UnsupportedGrant,
        ),
        (
            303,
            json!({"id": "Codex"}),
            program(),
            TaskLifecycleRejectionReason::AuthorityDenied,
        ),
        (
            304,
            json!({"id": "codex", "network": "unrestricted"}),
            program(),
            TaskLifecycleRejectionReason::AuthorityDenied,
        ),
        (
            305,
            json!({"id": "codex"}),
            vec![".fake/codex".to_owned()],
            TaskLifecycleRejectionReason::AuthorityDenied,
        ),
        (
            306,
            json!("codex"),
            program(),
            TaskLifecycleRejectionReason::AuthorityDenied,
        ),
    ] {
        let binding = task_binding(task);
        assert_eq!(
            bench.node.admit(
                binding,
                &signed_admit(binding, bench.snapshot, &argv, Some(&adapter))
            ),
            ctx.rejected(Some(op(2)), binding, reason),
            "{adapter}"
        );
        assert_eq!(
            bench.node.lifecycle(&ctx.inspect(binding)),
            ctx.inspected(binding, TaskLifecycleState::Created)
        );
    }
    let hosted = task_binding(301);
    assert_eq!(
        bench.node.lifecycle(&signed_admit(
            hosted,
            bench.snapshot,
            &program(),
            Some(&json!({"id": "codex"}))
        )),
        ctx.accepted(op(2), hosted, TaskLifecycleState::Ready),
        "a refused adapter consumed no version"
    );
}

/// A node started without `--agent-adapter` emits the earlier capability document and
/// refuses every workload naming an adapter, while a workload naming none runs as before.
#[test]
fn a_node_hosting_no_adapter_says_nothing_new_and_refuses_one() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        eprintln!("skipping: bubblewrap isolation or python3 unavailable");
        return;
    }
    let ctx = context();
    let program = || vec!["/work/.fake/codex".to_owned()];
    let plain = Bench::new(&[]);
    assert!(plain.node.capabilities().get("adapters").is_none());
    let binding = task_binding(401);
    assert_eq!(
        plain.node.admit(
            binding,
            &signed_admit(
                binding,
                plain.snapshot,
                &program(),
                Some(&json!({"id": "codex"}))
            )
        ),
        ctx.rejected(
            Some(op(2)),
            binding,
            TaskLifecycleRejectionReason::UnsupportedGrant
        )
    );
    let unnamed = task_binding(402);
    assert_eq!(
        plain.node.admit(
            unnamed,
            &signed_admit(unnamed, plain.snapshot, &program(), None)
        ),
        ctx.accepted(op(2), unnamed, TaskLifecycleState::Ready),
        "a workload that names no adapter runs as before"
    );
}
