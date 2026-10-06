//! A Git capability end to end on a node (#267, ADR-0034, ADR-0037): a plain workload — a
//! shell script running the stock `git` client, no agent adapter — clones and pushes over
//! smart HTTP with a short-lived token the node leases and its egress proxy injects, and
//! the token never enters the sandbox.
//!
//! A node started with `--network-allowlist`, `--credentials` and `--agent-shim` runs an
//! attempt that has an egress proxy under the operator's `ward-agent` shim, whose relay
//! listens on `127.0.0.1:3128` inside the attempt's network namespace with `HTTP_PROXY`
//! naming it. The workload clones the gateway URL `http://127.0.0.1:3128/git/<repo>.git`;
//! the proxy forwards it to the service's upstream with `Authorization: Bearer <lease>`.
//! The lease is revoked at the provider when the attempt ends, so a later attempt of the
//! same task has nothing to clone with: a fresh grant the provider refuses fails closed
//! with the proxy's named `403`, and the revoked token itself is refused upstream. A host
//! outside the allowlist is refused through the relay, and a sealed provider fails the
//! clone closed. A node without the shim, and an offline attempt on a node with one, run
//! as before: no relay, no proxy variables, no shim.
//!
//! The fake `OpenBao` issues `hvs.git-acceptance-<n>` and tracks which tokens are live; the
//! fake Git server runs `git http-backend` as a CGI over a bare repository and serves only
//! a request carrying a live token, recording every `Authorization` it is sent. Both are
//! plain HTTP on 127.0.0.1, as the `test-loopback` build allows. The shim is the
//! `ward-agent` binary of this build (`WARD_AGENT_BIN`, or beside the test's target
//! directory). Requires bubblewrap, git, python3 and that shim; skips without them except
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
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, Blake3Hash, DelegationId, DeniedDst, DenyReason, ExecutionAttemptId, LeaseId, NodeId,
    PrincipalId, RevokeReason, SessionId, SnapshotId, TaskId, WardEvent,
};
use ward_node::credentials::{LEASES_FILE, credentials_dir};
use ward_node::evidence;
use ward_node_protocol::{
    AdmissionEnvelopeJson, AdmissionVersion, CapabilityManifestBytes, HandshakeRequest,
    HandshakeResponse, IssuerProof, IssuerSignature, OperationId, ProtocolVersion,
    TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskAdmissionEnvelopeInput, TaskBinding,
    TaskExecutionOutcome, TaskLifecycleContext, TaskLifecycleRequest, TaskLifecycleResponse,
    TaskLifecycleState, TaskWorkload, WARD_NODE_PROTOCOL, WorkloadArgv,
};

/// Serialises writing files with every process spawn in this binary: a fork while another
/// thread holds a just-written executable open for writing makes its exec fail with
/// `ETXTBSY`. Every test body runs under it.
static SERIAL: Mutex<()> = Mutex::new(());

const NODE: NodeId = NodeId::from_u128(267);
const BROKER_TOKEN: &str = "fake-broker-token-for-267";
const TOKEN_PREFIX: &str = "hvs.git-acceptance-";
const ACCESSOR_PREFIX: &str = "git-accessor-";
const REPO: &str = "acme/widgets.git";

const GRANTED: &str = r#"{"network":{"custom":["localhost"]},"credentials":[{"service":"git","host":"localhost","ttl_secs":60}]}"#;
const OFFLINE: &str = r#"{"network":"offline"}"#;

/// The workload, `sh -c WORKLOAD sh <clone|push>`: the stock `git` client against the
/// gateway URL on the relay, a push in `push` mode, a clone of a host the manifest does not
/// list, one plain request for the route to read the proxy's answer, and everything it
/// could keep afterwards written to the workspace.
const WORKLOAD: &str = r#"
set -u
mode=$1
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=agent GIT_AUTHOR_EMAIL=agent@example.invalid
export GIT_COMMITTER_NAME=agent GIT_COMMITTER_EMAIL=agent@example.invalid
report=/work/report.txt
step() {
  name=$1; shift
  if "$@" >"/work/$name.log" 2>&1; then echo "$name ok" >>"$report"; else echo "$name failed" >>"$report"; return 1; fi
}
grep '^Seccomp:' /proc/self/status | tr -s '\t ' ' ' >>"$report"
if [ -e /work/clone ]; then echo "kept clone" >>"$report"; else echo "kept nothing" >>"$report"; fi
status=0
step clone git clone -q http://127.0.0.1:3128/git/acme/widgets.git /work/clone || status=1
if [ "$mode" = push ] && [ "$status" = 0 ]; then
  echo "built by the attempt" >/work/clone/BUILT
  step add git -C /work/clone add BUILT || status=1
  step commit git -C /work/clone commit -q -m built || status=1
  step push git -C /work/clone push -q origin HEAD:main || status=1
fi
step blocked git ls-remote https://blocked.example/acme/widgets.git
python3 -c '
import http.client
try:
    c = http.client.HTTPConnection("127.0.0.1", 3128, timeout=20)
    c.request("GET", "/git/acme/widgets.git/info/refs?service=git-upload-pack")
    r = c.getresponse()
    body = r.read()
    print("probe %d %s" % (r.status, "refs" if r.status == 200 else body.decode(errors="replace").strip()))
except OSError as e:
    print("probe unreachable %s" % e.__class__.__name__)
' >>"$report"
env | sort >/work/env.txt
cat /home/agent/.git-credentials /home/agent/.gitconfig >/work/kept.txt 2>&1
git -C /work/clone config --list >>/work/kept.txt 2>&1
exit $status
"#;

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

fn git_http_backend() -> bool {
    Command::new("git")
        .arg("--exec-path")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| {
            Path::new(String::from_utf8_lossy(&output.stdout).trim())
                .join("git-http-backend")
                .is_file()
        })
}

fn isolation() -> bool {
    ward_sandbox::ci::isolation_ready(ward_launch::available(), "bubblewrap")
        && ward_sandbox::ci::isolation_ready(Path::new("/usr/bin/python3").exists(), "python3")
        && ward_sandbox::ci::isolation_ready(git_http_backend(), "git with git-http-backend")
        && ward_sandbox::ci::isolation_ready(
            shim().is_some(),
            "the ward-agent shim of this build (cargo build -p ward-agent, or WARD_AGENT_BIN)",
        )
}

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[67; 32]).unwrap()
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

fn attempt_binding(task: u128, attempt: u128) -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(task),
        ExecutionAttemptId::from_u128(task * 100 + attempt),
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

/// `git` on the host, never reading the user's or the system's configuration.
fn host_git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "seed")
        .env("GIT_AUTHOR_EMAIL", "seed@example.invalid")
        .env("GIT_COMMITTER_NAME", "seed")
        .env("GIT_COMMITTER_EMAIL", "seed@example.invalid")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

// ---------------------------------------------------------------------------------------
// The fake provider and the fake Git server
// ---------------------------------------------------------------------------------------

#[derive(Default)]
struct BaoState {
    sealed: bool,
    refusing: bool,
    issued: Vec<Value>,
    live: BTreeMap<String, String>,
    revoked: Vec<String>,
}

#[derive(Clone)]
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

    fn lock(&self) -> std::sync::MutexGuard<'_, BaoState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn seal(&self) {
        self.lock().sealed = true;
    }

    /// The operator withdraws the role at the provider: every new token is refused.
    fn refuse_role(&self) {
        self.lock().refusing = true;
    }

    fn issued(&self) -> Vec<Value> {
        self.lock().issued.clone()
    }

    fn revoked(&self) -> Vec<String> {
        self.lock().revoked.clone()
    }

    fn live(&self) -> Vec<String> {
        self.lock().live.values().cloned().collect()
    }

    fn is_live(&self, token: &str) -> bool {
        self.lock().live.values().any(|live| live == token)
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
    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|coding| coding.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).ok()?;
            let size = usize::from_str_radix(size.trim().split(';').next()?, 16).ok()?;
            let mut chunk = vec![0; size + 2];
            reader.read_exact(&mut chunk).ok()?;
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else {
        let length = headers
            .get("content-length")
            .and_then(|length| length.parse().ok())
            .unwrap_or(0);
        body.resize(length, 0);
        reader.read_exact(&mut body).ok()?;
    }
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
    let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
    if state.sealed {
        return reply(&mut stream, 503, &json!({"errors": ["sealed"]}));
    }
    if headers.get("x-vault-token").map(String::as_str) != Some(BROKER_TOKEN) {
        return reply(&mut stream, 403, &json!({"errors": ["permission denied"]}));
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if line.starts_with("POST /v1/auth/token/create/") {
        if state.refusing {
            return reply(&mut stream, 403, &json!({"errors": ["permission denied"]}));
        }
        let ttl = body["ttl"]
            .as_str()
            .and_then(|ttl| ttl.trim_end_matches('s').parse::<u64>().ok())
            .unwrap_or(0);
        state.issued.push(body.clone());
        let n = state.issued.len();
        let (token, accessor) = (
            format!("{TOKEN_PREFIX}{n}"),
            format!("{ACCESSOR_PREFIX}{n}"),
        );
        state.live.insert(accessor.clone(), token.clone());
        return reply(
            &mut stream,
            200,
            &json!({"auth": {
                "client_token": token,
                "accessor": accessor,
                "lease_duration": ttl,
                "token_policies": body["policies"],
            }}),
        );
    }
    if line.starts_with("POST /v1/auth/token/revoke-accessor") {
        let accessor = body["accessor"].as_str().unwrap_or_default().to_owned();
        state.live.remove(&accessor);
        state.revoked.push(accessor);
        return reply(&mut stream, 204, &Value::Null);
    }
    reply(&mut stream, 404, &json!({"errors": []}));
}

/// A Git smart-HTTP server over the bare repositories under `root`, serving only requests
/// that carry a token the provider holds live, and recording the `Authorization` of every
/// request it is sent (`-` for none).
struct GitServer {
    port: u16,
    root: PathBuf,
    seen: Arc<Mutex<Vec<String>>>,
}

impl GitServer {
    fn start(root: &Path, bao: &FakeBao) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (shared, bao, repos) = (Arc::clone(&seen), bao.clone(), root.to_path_buf());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let (shared, bao, repos) = (Arc::clone(&shared), bao.clone(), repos.clone());
                std::thread::spawn(move || serve_git(stream, &repos, &bao, &shared));
            }
        });
        Self {
            port,
            root: root.to_path_buf(),
            seen,
        }
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    fn file(&self, rev: &str) -> String {
        host_git(&self.root.join(REPO), &["show", rev])
    }
}

fn serve_git(mut stream: TcpStream, root: &Path, bao: &FakeBao, seen: &Mutex<Vec<String>>) {
    let Some((line, headers, body)) = read_request(&mut stream) else {
        return;
    };
    let authorization = headers.get("authorization").cloned();
    seen.lock()
        .unwrap()
        .push(authorization.clone().unwrap_or_else(|| "-".to_owned()));
    let authorised = authorization
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| bao.is_live(token));
    if !authorised {
        let _ = write!(
            stream,
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"git\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        return;
    }
    let mut parts = line.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let header = |name: &str| headers.get(name).cloned().unwrap_or_default();
    let mut cgi = Command::new("git")
        .arg("http-backend")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_PROJECT_ROOT", root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REMOTE_USER", "agent")
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("REQUEST_METHOD", method)
        .env("PATH_INFO", path)
        .env("QUERY_STRING", query)
        .env("CONTENT_TYPE", header("content-type"))
        .env("CONTENT_LENGTH", body.len().to_string())
        .env("HTTP_CONTENT_ENCODING", header("content-encoding"))
        .env("HTTP_GIT_PROTOCOL", header("git-protocol"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = cgi.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(&body);
    });
    let output = cgi.wait_with_output().unwrap();
    feeder.join().unwrap();
    let out = output.stdout;
    let split = out
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| (at, at + 4))
        .or_else(|| {
            out.windows(2)
                .position(|window| window == b"\n\n")
                .map(|at| (at, at + 2))
        })
        .unwrap_or((0, 0));
    let mut status = "200 OK".to_owned();
    let mut response = String::new();
    for cgi_header in String::from_utf8_lossy(&out[..split.0]).lines() {
        match cgi_header.split_once(':') {
            Some((name, value)) if name.eq_ignore_ascii_case("status") => {
                value.trim().clone_into(&mut status);
            }
            Some(_) => {
                let _ = write!(response, "{}\r\n", cgi_header.trim_end());
            }
            None => {}
        }
    }
    let content = &out[split.1..];
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\n{response}Content-Length: {}\r\nConnection: close\r\n\r\n",
        content.len()
    );
    let _ = stream.write_all(content);
}

// ---------------------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------------------

struct Bench {
    dir: tempfile::TempDir,
    bao: FakeBao,
    git: GitServer,
    snapshot: SnapshotId,
    credentials: PathBuf,
}

impl Bench {
    fn new() -> Self {
        let dir = private_dir();
        let bao = FakeBao::start();
        let seed = dir.path().join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        host_git(&seed, &["init", "-q", "--template=", "-b", "main"]);
        std::fs::write(seed.join("README"), "widgets\n").unwrap();
        host_git(&seed, &["add", "README"]);
        host_git(&seed, &["commit", "-q", "-m", "seed"]);
        let repos = dir.path().join("repos");
        std::fs::create_dir_all(repos.join("acme")).unwrap();
        host_git(
            dir.path(),
            &[
                "clone",
                "-q",
                "--bare",
                "--template=",
                &seed.display().to_string(),
                &repos.join(REPO).display().to_string(),
            ],
        );
        let git = GitServer::start(&repos, &bao);

        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("README"),
            "a task that needs the widgets repo\n",
        )
        .unwrap();
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

[service.git]
provider = "bao"
engine = "token"
role = "ward-git-widgets"
permissions = ["widgets-push", "write"]
max_ttl_secs = 600
upstream = "localhost:{git}"
header = "authorization"
value_prefix = "Bearer "
paths = ["/{REPO}"]
plain_upstream = true
"#,
                bao = bao.port,
                token = token.display(),
                git = git.port,
            ),
            0o600,
        );
        Self {
            dir,
            bao,
            git,
            snapshot,
            credentials,
        }
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("tasks")
    }

    /// A node brokering the Git service, under the operator's shim when `shim` names one.
    fn node(&self, shim: Option<&Path>) -> Node {
        let socket = self.dir.path().join("node.sock");
        let _ = std::fs::remove_file(&socket);
        let trust = write_file(
            &self.dir.path().join("trusted-issuers"),
            &format!(
                "{} {}\n",
                hex(key_pair().public_key().as_ref()),
                PrincipalId::from_u128(2)
            ),
            0o600,
        );
        let mut command = Command::new(env!("CARGO_BIN_EXE_ward-node"));
        command
            .arg("--socket")
            .arg(&socket)
            .arg("--state-dir")
            .arg(self.dir.path().join("state"))
            .arg("--node-id")
            .arg(NODE.to_string())
            .arg("--trusted-issuers")
            .arg(trust)
            .arg("--task-root")
            .arg(self.root())
            .arg("--network-allowlist")
            .arg("--credentials")
            .arg(&self.credentials)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(shim) = shim {
            command.arg("--agent-shim").arg(shim);
        }
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
            root: self.root(),
            answers: Arc::default(),
        }
    }

    /// Every byte the node keeps: its state, its task root and every answer it gave.
    fn everything(&self, node: &Node) -> Vec<u8> {
        [
            every_byte_under(&self.dir.path().join("state")),
            every_byte_under(&self.root()),
            node.answers.lock().unwrap().concat().into_bytes(),
        ]
        .concat()
    }
}

struct Node {
    child: Child,
    socket: PathBuf,
    root: PathBuf,
    answers: Arc<Mutex<Vec<String>>>,
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
        self.answers.lock().unwrap().push(response.clone());
        response.trim().to_owned()
    }

    fn lifecycle(&self, request: &TaskLifecycleRequest) -> TaskLifecycleResponse {
        context()
            .decode_response(&self.request(&serde_json::to_string(request).unwrap()))
            .unwrap()
    }

    /// Create, admit (at `version`) and start `binding` running the workload in `mode`.
    fn start(&self, bench: &Bench, binding: TaskBinding, manifest: &str, mode: &str, version: u64) {
        let ctx = context();
        assert_eq!(
            self.lifecycle(&ctx.create(op(1), binding)),
            ctx.accepted(op(1), binding, TaskLifecycleState::Created)
        );
        assert_eq!(
            self.lifecycle(&signed_admit(
                binding,
                bench.snapshot,
                manifest,
                &["sh", "-c", WORKLOAD, "sh", mode],
                version
            )),
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

    fn workspace(&self, binding: TaskBinding) -> PathBuf {
        self.root
            .join(binding.task().to_string())
            .join(binding.attempt().to_string())
    }

    fn report(&self, binding: TaskBinding) -> Report {
        let workspace = self.workspace(binding);
        let read = |name: &str| std::fs::read_to_string(workspace.join(name)).unwrap_or_default();
        Report {
            lines: read("report.txt"),
            env: read("env.txt"),
            logs: ["clone", "push", "blocked"]
                .into_iter()
                .map(|step| (step, read(&format!("{step}.log"))))
                .collect(),
        }
    }

    fn records(&self, binding: TaskBinding) -> Vec<WardEvent> {
        evidence::verify(&evidence::evidence_dir(&self.root, binding), binding)
            .unwrap()
            .records()
            .iter()
            .map(|record| record.event.clone())
            .collect()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What the workload wrote: its report, its environment and its step logs.
struct Report {
    lines: String,
    env: String,
    logs: BTreeMap<&'static str, String>,
}

impl Report {
    fn has(&self, line: &str) -> bool {
        self.lines.lines().any(|found| found == line)
    }

    fn assert_has(&self, line: &str) {
        assert!(
            self.has(line),
            "no {line:?} in\n{}\n{:?}",
            self.lines,
            self.logs
        );
    }

    fn env(&self, name: &str) -> Option<&str> {
        self.env
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
    }
}

fn signed_admit(
    binding: TaskBinding,
    snapshot: SnapshotId,
    manifest: &str,
    argv: &[&str],
    version: u64,
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
                CapabilityName::new("repo.write").unwrap(),
                ResourceRef::new("repo:acme/widgets").unwrap(),
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
            WorkloadArgv::new(argv.iter().map(|arg| (*arg).to_owned()).collect()).unwrap(),
            CapabilityManifestBytes::new(manifest.as_bytes().to_vec()).unwrap(),
            snapshot,
            60_000,
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
    context().admit(op(2), binding, json, proof).unwrap()
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

fn position(events: &[WardEvent], wanted: impl Fn(&WardEvent) -> bool) -> usize {
    events
        .iter()
        .position(wanted)
        .unwrap_or_else(|| panic!("no such record in {events:?}"))
}

fn outcome(binding: TaskBinding, outcome: TaskExecutionOutcome) -> TaskLifecycleResponse {
    context()
        .inspected_with_outcome(binding, TaskLifecycleState::Exited, outcome)
        .unwrap()
}

fn denied_by_provider(state: &'static str) -> impl Fn(&WardEvent) -> bool {
    move |event| {
        matches!(event, WardEvent::CredentialDenied { service, reason: DenyReason::PolicyDeny { rule }, .. }
            if service.as_str() == "git" && rule.as_str() == format!("credential-provider:bao:{state}"))
    }
}

fn blocked_refused(event: &WardEvent) -> bool {
    matches!(event, WardEvent::NetworkDenied { dst: DeniedDst::Host { host, .. }, reason: DenyReason::NotAllowlisted }
        if host.as_str() == "blocked.example")
}

/// The revoked token, presented to the Git server by someone who somehow kept it.
fn replayed(git: &GitServer, token: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", git.port)).unwrap();
    write!(
        stream,
        "GET /{REPO}/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer.lines().next().unwrap_or_default().to_owned()
}

// ---------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------

/// Attempt 1 clones and pushes with the leased token the proxy injects; the token is in
/// no byte the sandbox, the log, the state or an answer holds, and it is revoked at the
/// provider when the attempt ends. Attempt 2 of the same task, whose fresh grant the
/// provider refuses, has nothing to clone with, and the revoked token is refused upstream.
#[test]
#[allow(clippy::too_many_lines)]
fn a_task_clones_and_pushes_with_a_leased_token_and_its_next_attempt_cannot() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        return;
    }
    let bench = Bench::new();
    let node = bench.node(Some(&shim().unwrap()));
    let first = attempt_binding(1, 1);
    node.start(&bench, first, GRANTED, "push", 1);
    assert_eq!(
        node.ended(first),
        outcome(first, TaskExecutionOutcome::Completed),
        "{}",
        node.report(first).lines
    );
    let report = node.report(first);
    for line in [
        "Seccomp: 2",
        "kept nothing",
        "clone ok",
        "add ok",
        "commit ok",
        "push ok",
        "blocked failed",
        "probe 200 refs",
    ] {
        report.assert_has(line);
    }
    assert!(report.logs["blocked"].contains("403"), "{:?}", report.logs);
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        assert_eq!(report.env(name), Some("http://127.0.0.1:3128"), "{name}");
    }
    assert_eq!(report.env("NO_PROXY"), Some("localhost,127.0.0.1"));
    assert_eq!(
        report.env("WARD_PROXY_SOCKET"),
        Some("/run/ward/proxy.sock")
    );
    assert_eq!(bench.git.file("main:BUILT"), "built by the attempt\n");

    let token = format!("{TOKEN_PREFIX}1");
    let seen = bench.git.seen();
    assert!(seen.len() >= 5, "{seen:?}");
    assert!(
        seen.iter().all(|auth| *auth == format!("Bearer {token}")),
        "every request upstream carried the lease and only it: {seen:?}"
    );
    let issued = bench.bao.issued();
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0]["meta"]["ward_audience"], "localhost");
    assert_eq!(
        issued[0]["meta"]["ward_session"],
        first.attempt().to_string()
    );
    assert_eq!(bench.bao.revoked(), [format!("{ACCESSOR_PREFIX}1")]);
    assert!(
        bench.bao.live().is_empty(),
        "the lease outlived its attempt"
    );

    let events = node.records(first);
    let granted = position(&events, |event| {
        matches!(event, WardEvent::CredentialGranted { service, scope, .. }
            if service.as_str() == "git"
                && scope.subject.content().starts_with("issued localhost lease b3:"))
    });
    let launched = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptLaunched { .. })
    });
    let used = position(&events, |event| {
        matches!(event, WardEvent::NetworkRequested { host, decision: ward_events::Decision::Allow, .. }
            if host.as_str() == "localhost")
    });
    let refused = position(&events, blocked_refused);
    let revoked = position(&events, |event| {
        matches!(event, WardEvent::CredentialRevoked { service, reason: RevokeReason::SessionEnded }
            if service.as_str() == "git")
    });
    let ended = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptEnded { .. })
    });
    assert!(granted < launched && launched < used && used < revoked && revoked < ended);
    assert!(launched < refused && refused < ended);
    assert!(
        !credentials_dir(&bench.root(), first)
            .join(LEASES_FILE)
            .exists()
    );
    let everything = bench.everything(&node);
    assert!(
        contains(&everything, "built by the attempt"),
        "the scan reads the workspace"
    );
    for secret in [token.as_str(), BROKER_TOKEN, ACCESSOR_PREFIX] {
        assert!(!contains(&everything, secret), "{secret} leaked");
    }

    bench.bao.refuse_role();
    let second = attempt_binding(1, 2);
    node.start(&bench, second, GRANTED, "clone", 2);
    assert_eq!(
        node.ended(second),
        outcome(second, TaskExecutionOutcome::Failed)
    );
    let report = node.report(second);
    for line in [
        "Seccomp: 2",
        "kept nothing",
        "clone failed",
        "probe 403 credential lease expired",
    ] {
        report.assert_has(line);
    }
    assert!(report.logs["clone"].contains("403"), "{:?}", report.logs);
    assert_eq!(
        bench.git.seen().len(),
        seen.len(),
        "nothing reached the server"
    );
    assert_eq!(bench.bao.issued().len(), 1);
    let events = node.records(second);
    let denied = position(&events, denied_by_provider("auth-rejected"));
    let launched = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptLaunched { .. })
    });
    assert!(denied < launched);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, WardEvent::CredentialGranted { .. }))
    );
    assert!(
        replayed(&bench.git, &token).starts_with("HTTP/1.1 401"),
        "the revoked token still opens the repository"
    );
    let everything = bench.everything(&node);
    assert!(!contains(&everything, &token), "the token leaked");
}

/// A provider that cannot serve fails the clone closed with the proxy's named `403` and a
/// recorded denial; a host outside the allowlist is refused through the relay.
#[test]
fn a_sealed_provider_fails_the_clone_closed_and_an_unlisted_host_is_refused() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        return;
    }
    let bench = Bench::new();
    bench.bao.seal();
    let node = bench.node(Some(&shim().unwrap()));
    let binding = attempt_binding(2, 1);
    node.start(&bench, binding, GRANTED, "clone", 1);
    assert_eq!(
        node.ended(binding),
        outcome(binding, TaskExecutionOutcome::Failed)
    );
    let report = node.report(binding);
    for line in [
        "clone failed",
        "blocked failed",
        "probe 403 credential lease expired",
    ] {
        report.assert_has(line);
    }
    assert!(report.logs["clone"].contains("403"), "{:?}", report.logs);
    assert!(report.logs["blocked"].contains("403"), "{:?}", report.logs);
    assert!(bench.git.seen().is_empty(), "nothing reached the server");
    assert!(bench.bao.issued().is_empty() && bench.bao.revoked().is_empty());
    let events = node.records(binding);
    let denied = position(&events, denied_by_provider("sealed"));
    let launched = position(&events, |event| {
        matches!(event, WardEvent::NodeAttemptLaunched { .. })
    });
    assert!(denied < launched);
    position(&events, blocked_refused);
    assert!(!events.iter().any(|event| matches!(
        event,
        WardEvent::CredentialGranted { .. } | WardEvent::CredentialRevoked { .. }
    )));
}

/// Where no relay is asked for, nothing changes: a node without the shim runs an
/// allowlisted plain workload with only its proxy socket, and a node with one runs an
/// offline plain workload outside it.
#[test]
fn without_the_shim_or_a_proxy_a_plain_workload_runs_as_before() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !isolation() {
        return;
    }
    let bench = Bench::new();
    let node = bench.node(None);
    let binding = attempt_binding(3, 1);
    node.start(&bench, binding, GRANTED, "clone", 1);
    assert_eq!(
        node.ended(binding),
        outcome(binding, TaskExecutionOutcome::Failed)
    );
    let report = node.report(binding);
    for line in [
        "Seccomp: 0",
        "clone failed",
        "probe unreachable ConnectionRefusedError",
    ] {
        report.assert_has(line);
    }
    assert_eq!(
        report.env("WARD_PROXY_SOCKET"),
        Some("/run/ward/proxy.sock")
    );
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "NO_PROXY"] {
        assert_eq!(report.env(name), None, "{name}");
    }
    assert!(bench.git.seen().is_empty());
    assert_eq!(bench.bao.revoked(), [format!("{ACCESSOR_PREFIX}1")]);
    drop(node);

    let node = bench.node(Some(&shim().unwrap()));
    let binding = attempt_binding(4, 1);
    node.start(&bench, binding, OFFLINE, "clone", 1);
    assert_eq!(
        node.ended(binding),
        outcome(binding, TaskExecutionOutcome::Failed)
    );
    let report = node.report(binding);
    for line in [
        "Seccomp: 0",
        "clone failed",
        "probe unreachable ConnectionRefusedError",
    ] {
        report.assert_has(line);
    }
    for name in ["WARD_PROXY_SOCKET", "HTTP_PROXY", "NO_PROXY"] {
        assert_eq!(report.env(name), None, "{name}");
    }
    assert!(bench.git.seen().is_empty());
    assert_eq!(
        bench.bao.issued().len(),
        1,
        "the offline attempt leased nothing"
    );
}
