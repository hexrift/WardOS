//! A real agent runtime's shape on a node (#424, ADR-0037): the `ward-agent` shim and the
//! in-sandbox loopback relay of a hosted adapter, against the real `ward-node` binary.
//!
//! A node started with `--agent-shim <file>` runs every attempt of a hosted adapter under
//! the shim, bound read-only at `/run/ward/ward-agent`: the adapter's command hooks run it
//! as `ward-agent hook` against the attempt's hook socket, and its relay listens on
//! `127.0.0.1:3128` inside the attempt's network namespace, forwarding to the attempt's
//! egress proxy. The adapter's provider base URL points at the relay only when the
//! manifest grants the credentials service named after that provider.
//!
//! The runtime is a fake that behaves like the real one: it reads its base URL and key
//! from the environment the adapter's launch gets, speaks HTTP to it, and runs every hook
//! its seeded settings file wires as a shell command with Claude Code's hook input on
//! stdin. The fake provider and the fake model upstream are plain HTTP on 127.0.0.1, as
//! the `test-loopback` build allows. The shim is the `ward-agent` binary of this build
//! (`WARD_AGENT_BIN`, or beside the test's target directory, which `cargo test
//! --workspace` builds). Requires bubblewrap, python3 and that shim; skips without them
//! except under `WARD_REQUIRE_ISOLATION=1`.

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
    ActionDecision, AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifestBytes,
    HandshakeRequest, HandshakeResponse, IssuerProof, IssuerSignature, OperationId, PendingAction,
    ProtocolVersion, TaskActionsResponse, TaskAdmissionAuthority, TaskAdmissionEnvelope,
    TaskAdmissionEnvelopeInput, TaskBinding, TaskExecutionOutcome, TaskLifecycleContext,
    TaskLifecycleRequest, TaskLifecycleResponse, TaskLifecycleState, TaskWorkload,
    WARD_NODE_PROTOCOL, WorkloadArgv,
};

/// Serialises writing executables with every process spawn in this binary: a fork while
/// another thread holds a just-written executable open for writing makes its exec fail
/// with `ETXTBSY`. Every test body runs under it.
static SERIAL: Mutex<()> = Mutex::new(());

const NODE: NodeId = NodeId::from_u128(424);
const BROKER_TOKEN: &str = "fake-broker-token-for-424";
const LEASED: &str = "hvs.node-leased-model-token-424";
const ACCESSOR: &str = "node-lease-accessor-424";
const ANTHROPIC_CANARY: &str = "anthropic-canary-424-never-in-a-node-sandbox";
const HOST_ONLY: (&str, &str) = ("NODE_HOST_ONLY_424", "host-only-value-424");
const RELAY: &str = "http://127.0.0.1:3128";

/// The model API is a `POST`, so the operator's service grants `write`.
const GRANTED: &str = r#"{"network":{"custom":["localhost"]},"credentials":[{"service":"anthropic","host":"localhost","ttl_secs":60}]}"#;
const UNGRANTED: &str = r#"{"network":{"custom":["localhost"]}}"#;
const HELD: &str = r#"{"network":{"custom":["localhost"]},"actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":300},"credentials":[{"service":"anthropic","host":"localhost","ttl_secs":60}],"hold":{"services":["anthropic"]}}"#;

/// The runtime: `agent --provider <anthropic|openai> --mode <turn|held>`. A turn runs the
/// wired hooks around one model request on its base URL, tries to replace the shim, and
/// asks the relay for what the manifest does not grant; `held` retries the model request
/// while the proxy answers `held for approval`. Everything goes to `/work/report.txt`.
const AGENT: &str = r##"#!/usr/bin/env python3
import errno, hashlib, http.client, json, os, socket, subprocess, sys, time, urllib.parse
sys.dont_write_bytecode = True

args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
provider = args["--provider"]
base_env, key_env, path = {
    "anthropic": ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "/v1/messages"),
    "openai": ("OPENAI_BASE_URL", "OPENAI_API_KEY", "/chat/completions"),
}[provider]
lines = []

config = os.environ.get("CLAUDE_CONFIG_DIR")
wired = json.load(open(os.path.join(config, "settings.json")))["hooks"] if config else {}

def hook(event, tool=None, tool_input=None):
    payload = {"hook_event_name": event, "session_id": "fake-session", "cwd": "/work"}
    if tool is not None:
        payload["tool_name"] = tool
        payload["tool_input"] = tool_input
    for group in wired.get(event, []):
        for entry in group["hooks"]:
            done = subprocess.run(entry["command"], shell=True, input=json.dumps(payload).encode(),
                                  capture_output=True, timeout=60)
            lines.append("HOOK %s %d %s" % (event, done.returncode, done.stdout.decode().strip()))

def model():
    base = os.environ.get(base_env)
    if base is None:
        return "none"
    url = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(url.hostname, url.port, timeout=20)
    body = json.dumps({"model": "fake-model", "max_tokens": 8, "messages": [{"role": "user", "content": "ping"}]})
    key = os.environ.get(key_env, "")
    headers = {"x-api-key": key} if provider == "anthropic" else {"authorization": "Bearer " + key}
    headers["content-type"] = "application/json"
    conn.request("POST", url.path + path, body=body, headers=headers)
    answer = conn.getresponse()
    return "%d %s" % (answer.status, answer.read().decode().strip())

def relay(head):
    s = socket.create_connection(("127.0.0.1", 3128), timeout=20)
    s.sendall(head.encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    status = data.split(b"\r\n")[0].decode().split(" ")[1]
    return "%s %s" % (status, data.split(b"\r\n\r\n", 1)[-1].decode().strip())

def attempt(name, step):
    try:
        step()
        lines.append("REPLACE %s done" % name)
    except OSError as e:
        lines.append("REPLACE %s refused %s" % (name, errno.errorcode.get(e.errno, str(e.errno))))

if args["--mode"] == "held":
    seen = []
    while True:
        answer = model()
        if not seen or seen[-1] != answer:
            seen.append(answer)
        if not answer.startswith("403 held for approval"):
            break
        time.sleep(0.05)
    lines.extend("SEEN " + s for s in seen)
else:
    hook("SessionStart")
    attempt("write", lambda: open("/run/ward/ward-agent", "wb").write(b"#!/bin/sh\n"))
    attempt("create-beside", lambda: open("/run/ward/ward-agent.new", "wb").write(b"#!/bin/sh\n"))
    attempt("rename", lambda: os.rename("/run/ward/ward-agent", "/run/ward/ward-agent.old"))
    attempt("unlink", lambda: os.unlink("/run/ward/ward-agent"))
    attempt("chmod", lambda: os.chmod("/run/ward/ward-agent", 0o777))
    with open("/run/ward/ward-agent", "rb") as f:
        lines.append("SHIM " + hashlib.sha256(f.read()).hexdigest())
    hook("PreToolUse", "Bash", {"command": "ask the model"})
    lines.append("MODEL " + model())
    hook("PostToolUse", "Bash", {"command": "ask the model"})
    lines.append("RELAY-CONNECT " + relay("CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n"))
    lines.append("RELAY-FORWARD " + relay("GET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\nConnection: close\r\n\r\n"))
    if base_env not in os.environ:
        lines.append("RELAY-ROUTE " + relay("POST /%s%s HTTP/1.1\r\nHost: 127.0.0.1:3128\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" % (provider, path)))
    hook("PermissionRequest", "WebFetch", {"url": "https://blocked.example/"})
    hook("Stop")
lines.append("ENV " + json.dumps(dict(os.environ), sort_keys=True))
try:
    with open("/proc/1/environ", "rb") as f:
        init = [kv.split(b"=", 1)[0].decode() for kv in f.read().split(b"\0") if kv]
except OSError as e:
    init = ["refused " + errno.errorcode.get(e.errno, str(e.errno))]
lines.append("INIT " + json.dumps(sorted(init)))
with open("/work/report.txt", "w") as f:
    f.write("\n".join(lines) + "\n")
"##;

fn shim() -> Option<PathBuf> {
    let path = std::env::var_os("WARD_AGENT_BIN").map_or_else(
        || {
            let exe = std::env::current_exe().unwrap();
            exe.parent().unwrap().parent().unwrap().join("ward-agent")
        },
        PathBuf::from,
    );
    path.is_file().then_some(path)
}

fn isolation() -> bool {
    ward_sandbox::ci::isolation_ready(ward_launch::available(), "bubblewrap")
        && ward_sandbox::ci::isolation_ready(Path::new("/usr/bin/python3").exists(), "python3")
        && ward_sandbox::ci::isolation_ready(
            shim().is_some(),
            "the ward-agent shim of this build (cargo build -p ward-agent, or WARD_AGENT_BIN)",
        )
}

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap()
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

fn write_file(path: &Path, content: &str, mode: u32) -> PathBuf {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    path.to_path_buf()
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn sha256(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

// ---------------------------------------------------------------------------------------
// The fake provider and the fake model upstream
// ---------------------------------------------------------------------------------------

struct FakeBao {
    port: u16,
    revoked: Arc<Mutex<Vec<String>>>,
}

impl FakeBao {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::clone(&revoked);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || serve_bao(stream, &shared));
            }
        });
        Self { port, revoked }
    }

    fn revoked(&self) -> Vec<String> {
        self.revoked.lock().unwrap().clone()
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

fn serve_bao(mut stream: TcpStream, revoked: &Mutex<Vec<String>>) {
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
        revoked.lock().unwrap().push(accessor);
        return reply(&mut stream, 204, &Value::Null);
    }
    reply(&mut stream, 404, &json!({"errors": []}));
}

/// The model API: records every request head and body it is sent and answers one message.
struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let Some((line, headers, body)) = read_request(&mut stream) else {
                    continue;
                };
                let head = headers.iter().fold(line, |head, (name, value)| {
                    format!("{head}\n{name}: {value}")
                });
                shared
                    .lock()
                    .unwrap()
                    .push(format!("{head}\n\n{}", String::from_utf8_lossy(&body)));
                reply(
                    &mut stream,
                    200,
                    &json!({"type": "message", "role": "assistant",
                        "content": [{"type": "text", "text": "pong"}]}),
                );
            }
        });
        Self { port, seen }
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------------------

struct Bench {
    dir: tempfile::TempDir,
    bao: FakeBao,
    upstream: Upstream,
    snapshot: SnapshotId,
    credentials: PathBuf,
}

impl Bench {
    fn new() -> Self {
        let dir = private_dir();
        let (bao, upstream) = (FakeBao::start(), Upstream::start());
        let project = dir.path().join("project");
        std::fs::create_dir_all(project.join(".fake")).unwrap();
        std::fs::write(project.join("README.md"), "relay\n").unwrap();
        write_file(&project.join(".fake/agent"), AGENT, 0o755);
        let output = Command::new(env!("CARGO_BIN_EXE_ward-node"))
            .args(["snapshot", "import", "--state-dir"])
            .arg(dir.path().join("state"))
            .arg(&project)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let snapshot = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let token = write_file(
            &dir.path().join("bao.token"),
            &format!("{BROKER_TOKEN}\n"),
            0o600,
        );
        let credentials = write_file(
            &dir.path().join("credentials.toml"),
            &format!(
                r#"
[provider.bao]
kind = "openbao"
address = "http://127.0.0.1:{bao}"
token_file = "{token}"
insecure_loopback = true
timeout_ms = 2000
max_ttl_secs = 600

[service.anthropic]
provider = "bao"
engine = "token"
role = "ward-anthropic"
permissions = ["anthropic-messages", "write"]
max_ttl_secs = 600
upstream = "localhost:{upstream}"
header = "x-api-key"
value_prefix = ""
paths = ["/v1/messages"]
plain_upstream = true
"#,
                bao = bao.port,
                token = token.display(),
                upstream = upstream.port,
            ),
            0o600,
        );
        Self {
            dir,
            bao,
            upstream,
            snapshot,
            credentials,
        }
    }

    fn trust_store(&self) -> PathBuf {
        write_file(
            &self.dir.path().join("trusted-issuers"),
            &format!(
                "{} {}\n",
                hex(key_pair().public_key().as_ref()),
                PrincipalId::from_u128(2)
            ),
            0o600,
        )
    }

    /// The node's command line, its own environment holding a model key and a variable
    /// that must never reach a sandbox.
    fn command(&self, extra: &[&std::ffi::OsStr]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ward-node"));
        command
            .arg("--socket")
            .arg(self.dir.path().join("node.sock"))
            .arg("--state-dir")
            .arg(self.dir.path().join("state"))
            .arg("--node-id")
            .arg(NODE.to_string())
            .arg("--trusted-issuers")
            .arg(self.trust_store())
            .arg("--task-root")
            .arg(self.dir.path().join("tasks"))
            .args(extra)
            .env("ANTHROPIC_API_KEY", ANTHROPIC_CANARY)
            .env(HOST_ONLY.0, HOST_ONLY.1);
        command
    }

    /// A node brokering the model credential, holding on request, hosting Claude Code and
    /// Codex under the shim.
    fn node(&self, shim: &Path) -> Node {
        let credentials = self.credentials.clone();
        let mut command = self.command(&[
            "--network-allowlist".as_ref(),
            "--credentials".as_ref(),
            credentials.as_os_str(),
            "--action-channel".as_ref(),
            "--approval-hold".as_ref(),
            "--agent-adapter".as_ref(),
            "claude-code".as_ref(),
            "--agent-adapter".as_ref(),
            "codex".as_ref(),
            "--agent-shim".as_ref(),
            shim.as_os_str(),
        ]);
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let socket = self.dir.path().join("node.sock");
        let mut child = command.spawn().unwrap();
        eventually("ward-node binding its socket", || {
            assert!(
                child.try_wait().unwrap().is_none(),
                "ward-node exited before serving"
            );
            UnixStream::connect(&socket).is_ok()
        });
        Node {
            child,
            socket,
            root: self.dir.path().join("tasks"),
        }
    }

    /// The node's refusal to start with `extra`: its exit status and stderr.
    fn refusal(&self, extra: &[&std::ffi::OsStr]) -> String {
        let output = self
            .command(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();
        assert!(!output.status.success(), "the node started with {extra:?}");
        assert!(
            !self.dir.path().join("node.sock").exists(),
            "the node served"
        );
        String::from_utf8_lossy(&output.stderr).into_owned()
    }
}

struct Node {
    child: Child,
    socket: PathBuf,
    root: PathBuf,
}

impl Node {
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

    fn capabilities(&self) -> Value {
        let answer: Value = serde_json::from_str(
            &self.request(r#"{"request":"capabilities","protocol":{"major":1,"minor":3}}"#),
        )
        .unwrap();
        answer["capabilities"].clone()
    }

    fn start(&self, binding: TaskBinding, admit: &TaskLifecycleRequest) {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding)),
            ctx.accepted(op(1), binding, TaskLifecycleState::Created)
        );
        assert_eq!(
            self.lifecycle(admit),
            ctx.accepted(op(2), binding, TaskLifecycleState::Ready)
        );
        assert_eq!(
            self.lifecycle(&ctx.start(op(3), binding)),
            ctx.accepted(op(3), binding, TaskLifecycleState::Running)
        );
    }

    fn ended(&self, binding: TaskBinding) -> TaskLifecycleResponse {
        let running = context().inspected(binding, TaskLifecycleState::Running);
        let mut state = running;
        eventually("the attempt's end", || {
            state = self.lifecycle(&context().inspect(binding));
            state != running
        });
        state
    }

    fn pending(&self, binding: TaskBinding) -> Vec<PendingAction> {
        let request = serde_json::to_string(&context().actions(binding).unwrap()).unwrap();
        match context()
            .decode_actions_response(&self.request(&request))
            .unwrap()
        {
            TaskActionsResponse::Actions { pending, .. } => pending,
            other => panic!("{other:?}"),
        }
    }

    fn approve(&self, binding: TaskBinding, action: u32) -> TaskActionsResponse {
        let request = serde_json::to_string(
            &context()
                .answer(op(10), binding, action, ActionDecision::Approved, None)
                .unwrap(),
        )
        .unwrap();
        context()
            .decode_actions_response(&self.request(&request))
            .unwrap()
    }

    fn workspace(&self, binding: TaskBinding) -> PathBuf {
        self.root
            .join(binding.task().to_string())
            .join(binding.attempt().to_string())
    }

    fn report(&self, binding: TaskBinding) -> Report {
        let text = std::fs::read_to_string(self.workspace(binding).join("report.txt"))
            .unwrap_or_else(|error| panic!("no report: {error}"));
        Report(text)
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

/// What the runtime wrote.
struct Report(String);

impl Report {
    fn line(&self, prefix: &str) -> &str {
        self.0
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap_or_else(|| panic!("no {prefix}line in {}", self.0))
    }

    fn lines(&self, prefix: &str) -> Vec<&str> {
        self.0
            .lines()
            .filter_map(|line| line.strip_prefix(prefix))
            .collect()
    }

    fn env(&self) -> BTreeMap<String, String> {
        serde_json::from_str(self.line("ENV ")).unwrap()
    }

    /// The runtime saw nothing of the node's environment, no lease and no provider token,
    /// and PID 1 holds no environment at all, or one the hardened runtime cannot read.
    fn assert_no_host_environment(&self) {
        let env = self.env();
        assert!(!env.contains_key(HOST_ONLY.0), "{env:?}");
        for secret in [
            ANTHROPIC_CANARY,
            HOST_ONLY.1,
            LEASED,
            BROKER_TOKEN,
            ACCESSOR,
        ] {
            assert!(!self.0.contains(secret), "{secret} reached the sandbox");
        }
        let init: Vec<String> = serde_json::from_str(self.line("INIT ")).unwrap();
        assert!(
            init.is_empty() || init == ["refused EACCES"],
            "PID 1's environment: {init:?}"
        );
    }
}

/// The signed `admit` of the runtime as `adapter` under `manifest` for `binding`.
fn signed_admit(
    binding: TaskBinding,
    snapshot: SnapshotId,
    manifest: &str,
    adapter: &str,
    args: &[&str],
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
    let command: Vec<String> = std::iter::once("/work/.fake/agent")
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect();
    let envelope = TaskAdmissionEnvelope::new(TaskAdmissionEnvelopeInput {
        binding,
        agent: AgentId::from_u128(3),
        node: NODE,
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: TaskWorkload::new(
            WorkloadArgv::new(command).unwrap(),
            CapabilityManifestBytes::new(manifest.as_bytes().to_vec()).unwrap(),
            snapshot,
            60_000,
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
    wire["workload"]["adapter"] = json!({ "id": adapter });
    let json = AdmissionEnvelopeJson::new(serde_json::to_string(&wire).unwrap()).unwrap();
    let key_pair = key_pair();
    let proof = IssuerProof::new(
        Blake3Hash::hash(key_pair.public_key().as_ref()),
        IssuerSignature::from_bytes(key_pair.sign(json.as_bytes()).as_ref().try_into().unwrap()),
    );
    context().admit(op(2), binding, json, proof).unwrap()
}

/// The agent-origin hook claims, as recorded.
fn hook_claims(records: &[EventRecord]) -> Vec<(ClaimKind, String)> {
    records
        .iter()
        .filter(|record| record.origin == Origin::Agent)
        .filter_map(|record| match &record.event {
            WardEvent::AgentClaim { kind, payload }
                if !payload.content().starts_with("{\"agent_adapter\"") =>
            {
                Some((*kind, payload.content().to_owned()))
            }
            WardEvent::AgentClaim { .. } => None,
            other => panic!("agent-origin record that is not a claim: {other:?}"),
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------

/// A model round trip: the base URL is the relay, the proxy injects the lease the runtime
/// never sees, the hooks run the bound shim and are recorded as agent claims, and the
/// workload can neither replace the shim nor reach anything else through the relay.
#[test]
#[allow(clippy::too_many_lines)]
fn a_runtime_completes_a_model_round_trip_through_the_relay_and_its_hooks_run_the_bound_shim() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        return;
    }
    let shim = shim().unwrap();
    let digest = sha256(&std::fs::read(&shim).unwrap());
    let bench = Bench::new();
    let node = bench.node(&shim);
    assert_eq!(
        node.capabilities()["adapters"],
        json!({"contract": "1.0", "hosted": ["claude-code", "codex"]}),
        "the shim changes nothing a control plane reads"
    );
    let binding = task_binding(1);
    node.start(
        binding,
        &signed_admit(
            binding,
            bench.snapshot,
            GRANTED,
            "claude-code",
            &["-p", "ping", "--provider", "anthropic", "--mode", "turn"],
        ),
    );
    assert_eq!(
        node.ended(binding),
        context()
            .inspected_with_outcome(
                binding,
                TaskLifecycleState::Exited,
                TaskExecutionOutcome::Completed
            )
            .unwrap()
    );
    let report = node.report(binding);

    assert_eq!(
        report.line("MODEL "),
        r#"200 {"content":[{"text":"pong","type":"text"}],"role":"assistant","type":"message"}"#
    );
    let env = report.env();
    assert_eq!(env["ANTHROPIC_BASE_URL"], format!("{RELAY}/anthropic"));
    assert_eq!(env["ANTHROPIC_API_KEY"], "ward-gateway");
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        assert_eq!(env[name], RELAY, "{name}");
    }
    let seen = bench.upstream.seen();
    let [request] = seen.as_slice() else {
        panic!("one model request upstream: {seen:?}")
    };
    assert!(
        request.starts_with("POST /v1/messages HTTP/1.1\n"),
        "{request}"
    );
    assert!(
        request.contains(&format!("\nx-api-key: {LEASED}\n")),
        "{request}"
    );
    assert!(!request.contains("ward-gateway"), "{request}");
    assert!(request.ends_with(r#""content": "ping"}]}"#), "{request}");
    report.assert_no_host_environment();

    // The relay adds nothing the manifest does not grant.
    assert_eq!(
        report.line("RELAY-CONNECT "),
        "403 destination not permitted by session policy"
    );
    assert_eq!(
        report.line("RELAY-FORWARD "),
        "403 destination not permitted by session policy"
    );
    assert!(report.lines("RELAY-ROUTE ").is_empty());

    // The shim is the node's, read-only, and the hooks still run it afterwards.
    assert_eq!(report.line("SHIM "), digest);
    assert_eq!(sha256(&std::fs::read(&shim).unwrap()), digest);
    for replace in report.lines("REPLACE ") {
        assert!(
            replace.contains(" refused "),
            "the workload replaced the shim: {replace}"
        );
    }
    assert_eq!(report.lines("REPLACE ").len(), 5);
    assert_eq!(
        report.lines("HOOK "),
        [
            "SessionStart 0 ",
            "PreToolUse 0 ",
            "PostToolUse 0 ",
            "PermissionRequest 0 ",
            "Stop 0 "
        ]
    );
    assert_eq!(
        hook_claims(&node.records(binding)),
        [
            (ClaimKind::Note, "SessionStart".to_owned()),
            (
                ClaimKind::ToolUse,
                "PreToolUse Bash ask the model → allow".to_owned()
            ),
            (
                ClaimKind::ToolUse,
                "PostToolUse Bash ask the model".to_owned()
            ),
            (
                ClaimKind::ToolUse,
                "PermissionRequest WebFetch https://blocked.example/ → allow".to_owned()
            ),
            (ClaimKind::Note, "Stop".to_owned()),
        ]
    );
    assert_eq!(bench.bao.revoked(), [ACCESSOR], "the lease is revoked");
}

/// No credentials grant for the adapter's provider: no base URL, no placeholder and no
/// route, for the runtime of that provider and for one of another provider under a grant
/// that is not its own.
#[test]
fn without_a_grant_for_its_provider_a_runtime_gets_no_base_url_and_no_route() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        return;
    }
    let bench = Bench::new();
    let node = bench.node(&shim().unwrap());
    for (task, manifest, adapter, provider) in [
        (2, UNGRANTED, "claude-code", "anthropic"),
        (3, GRANTED, "codex", "openai"),
    ] {
        let binding = task_binding(task);
        node.start(
            binding,
            &signed_admit(
                binding,
                bench.snapshot,
                manifest,
                adapter,
                &["--provider", provider, "--mode", "turn"],
            ),
        );
        node.ended(binding);
        let report = node.report(binding);
        let env = report.env();
        assert_eq!(report.line("MODEL "), "none", "{adapter}");
        for name in [
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_API_KEY",
            "OPENAI_BASE_URL",
            "OPENAI_API_KEY",
        ] {
            assert!(!env.contains_key(name), "{adapter}: {name} is set");
        }
        assert_eq!(env["HTTPS_PROXY"], RELAY, "{adapter}: the relay still runs");
        assert_eq!(
            report.line("RELAY-ROUTE "),
            "400 proxy requires an absolute http:// URI",
            "{adapter}: a route the manifest does not grant"
        );
        assert_eq!(
            report.line("RELAY-CONNECT "),
            "403 destination not permitted by session policy"
        );
        report.assert_no_host_environment();
    }
    assert!(
        bench.upstream.seen().is_empty(),
        "nothing reached the model API"
    );
}

/// A held credential is refused through the relay until the control plane approves the
/// request the node opened, and only then reaches the upstream.
#[test]
fn the_relay_reaches_a_held_credential_only_after_the_approval() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        return;
    }
    let bench = Bench::new();
    let node = bench.node(&shim().unwrap());
    let binding = task_binding(4);
    node.start(
        binding,
        &signed_admit(
            binding,
            bench.snapshot,
            HELD,
            "claude-code",
            &["--provider", "anthropic", "--mode", "held"],
        ),
    );
    let mut pending = Vec::new();
    eventually("the hold's request", || {
        pending = node.pending(binding);
        !pending.is_empty()
    });
    assert_eq!(
        (pending[0].id().as_str(), pending[0].summary()),
        ("hold:1", "credential anthropic")
    );
    assert!(
        bench.upstream.seen().is_empty(),
        "nothing reached the model API before the approval"
    );
    assert_eq!(
        node.approve(binding, pending[0].action()),
        context().answered(
            op(10),
            binding,
            pending[0].action(),
            ActionDecision::Approved
        )
    );
    node.ended(binding);
    let report = node.report(binding);
    let seen = report.lines("SEEN ");
    assert_eq!(seen.first().copied(), Some("403 held for approval"));
    assert!(seen.last().unwrap().starts_with("200 "), "{seen:?}");
    let upstream = bench.upstream.seen();
    assert_eq!(upstream.len(), 1, "{upstream:?}");
    assert!(upstream[0].contains(&format!("\nx-api-key: {LEASED}\n")));
    report.assert_no_host_environment();
}

/// The operator names the shim; the node verifies it and refuses to start with anything
/// else, never looking for one of its own.
#[test]
fn a_node_refuses_a_shim_it_cannot_verify() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        return;
    }
    let shim = shim().unwrap();
    let bench = Bench::new();
    let dir = bench.dir.path();
    let link = dir.join("linked-shim");
    std::os::unix::fs::symlink(&shim, &link).unwrap();
    let writable = dir.join("writable-shim");
    std::fs::copy(&shim, &writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o775)).unwrap();
    let plain = dir.join("plain");
    std::fs::copy(&shim, &plain).unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    let impostor = write_file(
        &dir.join("impostor"),
        "#!/bin/sh\necho 'usage: impostor --rw DIR'\n",
        0o755,
    );
    let adapter: [&std::ffi::OsStr; 2] = ["--agent-adapter".as_ref(), "claude-code".as_ref()];
    for (path, reason) in [
        (PathBuf::from("ward-agent"), "not an absolute path"),
        (dir.join("missing"), "No such file"),
        (link, "not a regular file"),
        (writable, "writable by group or others"),
        (plain, "not executable"),
        (impostor, "not a ward-agent shim"),
    ] {
        let mut args = adapter.to_vec();
        args.extend(["--agent-shim".as_ref(), path.as_os_str()]);
        let stderr = bench.refusal(&args);
        assert!(
            stderr.contains("agent shim") && stderr.contains(reason),
            "{path:?}: {stderr}"
        );
    }
    let stderr = bench.refusal(&["--agent-shim".as_ref(), shim.as_os_str()]);
    assert!(stderr.contains("--agent-adapter"), "{stderr}");
}
