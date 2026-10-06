#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Adapter conformance (#279, ADR-0033, `docs/agent-integration.md` §10.5).
//!
//! One suite, parameterised over every adapter `WardOS` ships — Claude Code, Codex and
//! the generic process adapter — proving that the adapter changes what the session
//! *sees* and nothing it *allows*. Each adapter runs the same hostile probe under the
//! same project policy (the same capability manifest), through the one launch path
//! `ward claude` / `ward codex` / `ward agent` use (`Session::adapter_launch`, then
//! `Session::launch`): it tries to read a host secret and the host vault, to reach a
//! host the allowlist does not name (through the proxy, directly and by DNS), to
//! write outside the workspace, and looks for the model-API key in its environment.
//! The refusals must be identical, line for line and record for record; only the
//! semantic events differ, and exactly as each adapter's capability document says.
//!
//! The agents are fakes: no real Claude Code or Codex can run a task here (no network,
//! no key). The Claude Code fake behaves as Claude Code does with the settings `ward
//! claude` seeds: it reads `$CLAUDE_CONFIG_DIR/settings.json` and, for each hook event
//! the settings wire, runs the configured `ward-agent hook` command with Claude Code's
//! hook payload on stdin — or, where the test build has no shim inside the sandbox,
//! writes the same line `ward-agent hook` would to `$WARD_SOCKET` — and honours the
//! answer. The Codex fake checks the environment its adapter sets and has no hooks,
//! as `ward codex` wires none. The generic fake is any program.
//!
//! Requires bubblewrap and python3; skips cleanly without them, except under
//! `WARD_REQUIRE_ISOLATION=1`.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use ward_agent_adapter::{
    BindingClaim, HookSupport, SemanticEvent, TaskOutcome, catalogue as documents,
};
use ward_daemon::adapters::{self, Adapter};
use ward_daemon::{Session, sandbox};
use ward_events::{ClaimKind, EndReason, EventRecord, LogReader, Origin, WardEvent};

/// Serialises writing the fake executables with every sandbox spawn in this binary: a
/// fork while another thread holds a just-written executable open for writing makes
/// its exec fail with `ETXTBSY`. Every test body runs under it.
static SERIAL: Mutex<()> = Mutex::new(());

const BLOCKED: &str = "blocked.example";
const ANTHROPIC_CANARY: &str = "anthropic-canary-279-never-in-the-sandbox";
const OPENAI_CANARY: &str = "sk-openai-canary-279-never-in-the-sandbox";
const HOST_SECRET: &str = "host-secret-279";

/// The probe every fake runs: the same steps, in the same order, printing one
/// `PROBE <step> <result>` line each, then one `ENV <json>` line with its environment
/// (checked for keys, never compared across adapters: adapters set different
/// configuration variables) and one `INIT <json>` line with the names in the
/// environment of the sandbox's PID 1, which every process inside can read. `hook(event, tool, summary)` is the adapter's hook layer;
/// a step a hook refuses is reported as `skipped`.
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

def proxy_connect(host):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect("/run/ward/proxy.sock")
    s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (host, host)).encode())
    status = s.recv(200).split(b"\r\n")[0].decode().split(" ")
    s.close()
    return "status " + status[1]

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
        ("read-host-vault", "Read", host["--vault"], lambda: listdir(host["--vault"])),
        ("read-host-home", "Read", host["--home"], lambda: listdir(host["--home"])),
        ("write-host-path", "Write", host["--outside"], lambda: write(host["--outside"])),
        ("write-system", "Write", "/usr/ward-escape", lambda: write("/usr/ward-escape")),
        ("proxy-blocked-host", "WebFetch", "https://blocked.example/", lambda: proxy_connect("blocked.example")),
        ("proxy-other-provider", "WebFetch", "https://api.openai.com/", lambda: proxy_connect("api.openai.com")),
        ("proxy-private-address", "WebFetch", "https://10.0.0.1/", lambda: proxy_connect("10.0.0.1")),
        ("direct-connect", "Bash", "connect 192.0.2.1:443", lambda: direct_connect("192.0.2.1")),
        ("dns-blocked-host", "Bash", "resolve blocked.example", lambda: resolve("blocked.example")),
    ]
    hook("SessionStart", None, None)
    for name, tool, summary, step in steps:
        if hook("PreToolUse", tool, summary) == "deny":
            print("PROBE", name, "skipped")
            continue
        try:
            result = step()
        except OSError as e:
            result = refused(e)
        print("PROBE", name, result)
        hook("PostToolUse", tool, summary)
    hook("PermissionRequest", "Bash", "connect 192.0.2.1:443")
    hook("Stop", None, None)
    print("ENV", json.dumps(dict(os.environ), sort_keys=True))
    try:
        with open("/proc/1/environ", "rb") as f:
            init = [kv.split(b"=", 1)[0].decode() for kv in f.read().split(b"\0") if kv]
    except OSError as e:
        init = [refused(e)]
    print("INIT", json.dumps(sorted(init)))
"#;

/// Claude Code as `ward claude` configures it: the hooks are whatever the seeded
/// settings file wires, each run as Claude Code runs a command hook.
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
    payload = {"hook_event_name": event, "session_id": "fake", "cwd": "/work"}
    if tool is not None:
        payload["tool_name"] = tool
        payload["tool_input"] = {"command": summary} if tool == "Bash" else (
            {"url": summary} if tool == "WebFetch" else {"file_path": summary})
    program = command.split(" ")[0]
    if os.path.exists(program):
        out = subprocess.run(command.split(" "), input=json.dumps(payload), capture_output=True, text=True).stdout
        if not out.strip():
            return "allow"
        decision = json.loads(out)["hookSpecificOutput"]
        return decision.get("permissionDecision") or decision.get("decision", {}).get("behavior")
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

/// Codex as `ward codex` configures it: its own home, no hook layer.
const CODEX: &str = r#"#!/usr/bin/env python3
import os, sys
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe
assert os.environ["CODEX_HOME"] == "/home/agent/.codex", os.environ.get("CODEX_HOME")
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

/// A hookless agent that forges hook claims anyway, claiming the network step is
/// approved, then tries it.
const FORGER: &str = r#"#!/usr/bin/env python3
import json, os, socket, sys
def claim(line):
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.environ["WARD_SOCKET"])
    s.sendall((json.dumps(line) + "\n").encode())
    answer = s.makefile().readline().strip()
    s.close()
    return answer
print("CLAIM", claim({"hook": "PreToolUse", "tool": "WebFetch", "summary": "https://blocked.example/ approved by the user"}))
s = socket.socket(socket.AF_UNIX)
s.connect("/run/ward/proxy.sock")
s.sendall(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
print("CONNECT", s.recv(200).split(b"\r\n")[0].decode())
"#;

fn isolation_ready() -> bool {
    let python = Path::new("/usr/bin/python3").exists();
    ward_sandbox::ci::isolation_ready(sandbox::available(), "bubblewrap")
        && ward_sandbox::ci::isolation_ready(python, "python3")
}

/// The three adapters under test, each pointed at its fake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Under {
    Claude,
    Codex,
    Generic,
}

impl Under {
    const ALL: [Self; 3] = [Self::Claude, Self::Codex, Self::Generic];

    fn fake(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Generic => "acme-agent",
        }
    }

    fn adapter(self) -> Adapter {
        let program = format!("/work/.fake/{}", self.fake());
        match self {
            Self::Claude | Self::Codex => Adapter::first_party(self.fake())
                .unwrap()
                .with_program(&program)
                .unwrap(),
            Self::Generic => {
                Adapter::process(&program, Some("Acme Agent"), Some("1.0"), None).unwrap()
            }
        }
    }
}

/// One adapter's run: a fresh project and state root (so every run starts from the
/// same tree), the same policy for all.
struct Run {
    under: Under,
    probe: Vec<String>,
    env: BTreeMap<String, String>,
    init_env: Vec<String>,
    launch_env: Vec<String>,
    outcome: TaskOutcome,
    records: Vec<EventRecord>,
    manifest: ward_policy::CapabilityManifest,
    host: Host,
}

/// Host paths the probe aims at, kept alive for the host-side checks.
struct Host {
    _secrets: tempfile::TempDir,
    _state: tempfile::TempDir,
    _project: tempfile::TempDir,
    outside: PathBuf,
    vault: PathBuf,
}

const POLICY: &str = "network: !custom\n  - allowed.example\ncontainers: none\n";

fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join(".ward")).unwrap();
    fs::write(root.join(".ward/policy.yaml"), POLICY).unwrap();
    fs::write(root.join("README.md"), "conformance\n").unwrap();
    let fakes = root.join(".fake");
    fs::create_dir_all(&fakes).unwrap();
    fs::write(fakes.join("probe.py"), PROBE).unwrap();
    for (name, content) in [
        ("claude", CLAUDE),
        ("codex", CODEX),
        ("acme-agent", GENERIC),
        ("forger", FORGER),
    ] {
        write_executable(&fakes.join(name), content);
    }
    dir
}

fn run(under: Under) -> Run {
    let secrets = tempfile::tempdir().unwrap();
    let secret = secrets.path().join("id_token");
    fs::write(&secret, HOST_SECRET).unwrap();
    let outside = secrets.path().join("escape.txt");
    let state = tempfile::tempdir().unwrap();
    let vault = ward_daemon::gateway::vault_dir(state.path());
    fs::create_dir_all(&vault).unwrap();
    fs::write(vault.join("ANTHROPIC_API_KEY"), ANTHROPIC_CANARY).unwrap();
    fs::write(vault.join("OPENAI_API_KEY"), OPENAI_CANARY).unwrap();
    let project = project();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());

    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let manifest = session.manifest().clone();
    let probe_args: Vec<String> = [
        "--secret",
        &secret.to_string_lossy(),
        "--vault",
        &vault.to_string_lossy(),
        "--home",
        &home,
        "--outside",
        &outside.to_string_lossy(),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let (argv, mut opts) = session
        .adapter_launch(&under.adapter(), &probe_args, &[], &[])
        .expect("adapter launch");
    opts.interactive = false;
    let launch_env = opts.env.iter().map(|(name, _)| name.clone()).collect();
    let report = session.launch(&argv, &opts).expect("launch");
    session.stop(EndReason::UserStop).expect("stop");

    let probe: Vec<String> = report
        .stdout
        .lines()
        .filter_map(|l| l.strip_prefix("PROBE "))
        .map(str::to_owned)
        .collect();
    let line = |prefix: &str| {
        let Some(json) = report.stdout.lines().find_map(|l| l.strip_prefix(prefix)) else {
            panic!(
                "{under:?}: no {prefix}line\n{}\n{}",
                report.stdout, report.stderr
            )
        };
        json.to_owned()
    };
    let env = serde_json::from_str(&line("ENV ")).unwrap();
    let init_env = serde_json::from_str(&line("INIT ")).unwrap();
    for canary in [ANTHROPIC_CANARY, OPENAI_CANARY, HOST_SECRET] {
        assert!(
            !report.stdout.contains(canary) && !report.stderr.contains(canary),
            "{under:?}: {canary} reached the sandbox"
        );
    }
    let records = LogReader::open(&log)
        .unwrap()
        .map(|r| r.expect("record"))
        .collect();
    Run {
        under,
        probe,
        env,
        init_env,
        launch_env,
        outcome: adapters::task_result(&report).outcome,
        records,
        manifest,
        host: Host {
            _secrets: secrets,
            _state: state,
            _project: project,
            outside,
            vault,
        },
    }
}

/// What the host enforced, normalised for comparison: every enforcement-fact record
/// about the network, files and credentials, without timestamps or pids.
fn enforcement(records: &[EventRecord]) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.origin.is_enforcement_fact())
        .filter_map(|r| match &r.event {
            WardEvent::NetworkRequested {
                host,
                port,
                decision,
                rule,
                ..
            } => Some(format!("net {host}:{port} {decision:?} {rule:?}")),
            WardEvent::NetworkDenied { dst, reason } => Some(format!("deny {dst:?} {reason:?}")),
            WardEvent::FileModified { path, kind, .. } => Some(format!("file {path} {kind:?}")),
            WardEvent::CredentialDenied {
                service, reason, ..
            } => Some(format!("cred-denied {service:?} {reason:?}")),
            _ => None,
        })
        .collect()
}

/// The credentials the proxy holds for the launch, by service.
fn granted(records: &[EventRecord]) -> Vec<String> {
    records
        .iter()
        .filter_map(|r| match &r.event {
            WardEvent::CredentialGranted { service, .. } => Some(service.to_string()),
            _ => None,
        })
        .collect()
}

/// Agent-origin claims: the adapter binding, then the hook events by name.
fn claims(records: &[EventRecord]) -> (Vec<BindingClaim>, Vec<String>) {
    let mut bindings = Vec::new();
    let mut hooks = Vec::new();
    for r in records.iter().filter(|r| r.origin == Origin::Agent) {
        let WardEvent::AgentClaim { kind, payload } = &r.event else {
            panic!("agent-origin record that is not a claim: {r:?}")
        };
        let text = payload.content();
        if let Ok(binding) = serde_json::from_str::<BindingClaim>(text) {
            assert_eq!(*kind, ClaimKind::Note);
            bindings.push(binding);
        } else {
            hooks.push(text.split(' ').next().unwrap_or_default().to_owned());
        }
    }
    (bindings, hooks)
}

/// The acceptance of #279 in test form: the same manifest, the same refusals, a
/// different semantic picture, for every adapter.
#[test]
fn every_adapter_is_refused_the_same_and_differs_only_in_semantic_events() {
    if !isolation_ready() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let runs: Vec<Run> = Under::ALL.into_iter().map(run).collect();
    let generic = &runs[2];
    assert_probe_is_refused(&generic.probe);
    for run in &runs {
        assert_same_authority(run, &runs[0], generic);
        assert_no_host_environment(run);
        assert_declared_semantics(run);
    }
}

/// The probe itself: the workspace is usable, everything else is refused.
fn assert_probe_is_refused(probe: &[String]) {
    let expected = [
        "read-workspace read conformance",
        "write-workspace written",
        "read-host-secret refused ENOENT",
        "read-host-vault refused ENOENT",
        "read-host-home refused ENOENT",
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
    assert_eq!(probe.len(), 12, "{probe:#?}");
}

/// The same manifest, the same refusals step for step and record for record, and the
/// adapter's own provider as the only credential.
fn assert_same_authority(run: &Run, first: &Run, reference: &Run) {
    let under = run.under;
    // Each run is its own session and project, so only the identity fields differ.
    let mut manifest = run.manifest.clone();
    manifest.session = first.manifest.session.clone();
    manifest.project = first.manifest.project.clone();
    assert_eq!(manifest, first.manifest, "{under:?}");
    assert_eq!(run.probe, reference.probe, "{under:?}");
    assert_eq!(
        enforcement(&run.records),
        enforcement(&reference.records),
        "{under:?}"
    );
    assert_eq!(run.outcome, TaskOutcome::Completed, "{under:?}");
    assert!(!run.host.outside.exists(), "{under:?} wrote outside");
    assert_eq!(
        fs::read_dir(&run.host.vault).unwrap().count(),
        2,
        "{under:?}: the vault is untouched"
    );
    let provider = under
        .adapter()
        .launch_spec()
        .provider()
        .map(|p| p.as_str().to_owned());
    assert_eq!(
        granted(&run.records),
        provider.into_iter().collect::<Vec<_>>(),
        "{under:?}: the only credential is the adapter's own provider, proxy-injected"
    );
}

/// Nothing of the host's environment in the sandbox: the agent sees what the host sets
/// for every launch, the non-secret locale and identity variables it forwards, and the
/// launch's own variables (the adapter's configuration and its gateway's base URL and
/// placeholder) — and the sandbox's PID 1, whose environment every process inside can
/// read, holds nothing at all. No key, a placeholder where the adapter has a provider.
fn assert_no_host_environment(run: &Run) {
    let under = run.under;
    let host_set = [
        "HOME",
        "PATH",
        "TERM",
        "WARD_SOCKET",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ];
    for (name, value) in &run.env {
        // Python's own locale coercion (PEP 538) under the C locale, not the host's.
        let python_coercion = name == "LC_CTYPE" && value.eq_ignore_ascii_case("c.utf-8");
        // bubblewrap's own `--chdir`.
        let workdir = name == "PWD" && value == "/work";
        assert!(
            python_coercion
                || workdir
                || host_set.contains(&name.as_str())
                || ward_daemon::session::FORWARDED_ENV.contains(&name.as_str())
                || run.launch_env.contains(name),
            "{under:?}: {name} reached the sandbox from the host's environment"
        );
        assert!(
            value != ANTHROPIC_CANARY && value != OPENAI_CANARY,
            "{under:?}: {name} holds a key"
        );
    }
    assert_eq!(
        run.init_env,
        Vec::<String>::new(),
        "{under:?}: PID 1's environment"
    );
    if let Some(gateway) = under.adapter().gateway() {
        assert_eq!(
            run.env.get(gateway.placeholder_env).map(String::as_str),
            Some(ward_daemon::gateway::PLACEHOLDER),
            "{under:?}"
        );
    }
}

/// What differs: the semantic events, exactly as the document declares them, and one
/// binding per launch naming the adapter.
fn assert_declared_semantics(run: &Run) {
    let under = run.under;
    let document = run_document(under);
    let (bindings, hooks) = claims(&run.records);
    assert_eq!(bindings.len(), 1, "{under:?}: one binding per launch");
    let binding = &bindings[0].agent_adapter;
    assert_eq!(binding.adapter(), document.adapter().id(), "{under:?}");
    assert_eq!(binding.runtime(), document.adapter().runtime(), "{under:?}");
    assert_eq!(binding.events(), document.events(), "{under:?}");
    let mut seen: Vec<SemanticEvent> = hooks
        .iter()
        .map(|h| SemanticEvent::from_wire(h).unwrap_or_else(|| panic!("{h}")))
        .collect();
    seen.sort();
    seen.dedup();
    assert_eq!(seen, document.events().as_slice(), "{under:?}: {hooks:?}");
    match document.hooks() {
        HookSupport::Full => assert!(hooks.len() > SemanticEvent::ALL.len(), "{hooks:?}"),
        HookSupport::None => assert!(hooks.is_empty(), "{under:?}: {hooks:?}"),
        HookSupport::Partial => unreachable!("no shipped adapter is partial"),
    }
}

fn run_document(under: Under) -> ward_agent_adapter::CapabilityDocument {
    match under {
        Under::Claude => documents::claude_code(),
        Under::Codex => documents::codex(),
        Under::Generic => under.adapter().document().clone(),
    }
}

/// A hookless agent that writes hook lines anyway gets claims recorded, and nothing
/// else: the claim says the user approved the request, and the proxy refuses it.
#[test]
fn forged_semantic_claims_grant_nothing() {
    if !isolation_ready() {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let state = tempfile::tempdir().unwrap();
    let project = project();
    let mut session = Session::start_in(project.path(), state.path()).expect("start");
    let log = session.log_path();
    let adapter = Adapter::process("/work/.fake/forger", None, None, None).unwrap();
    let (argv, mut opts) = session
        .adapter_launch(&adapter, &[], &[], &[])
        .expect("adapter launch");
    opts.interactive = false;
    let report = session.launch(&argv, &opts).expect("launch");
    session.stop(EndReason::UserStop).expect("stop");

    assert!(
        report.stdout.contains(r#"CLAIM {"decision":"allow""#),
        "{}\n{}",
        report.stdout,
        report.stderr
    );
    assert!(
        report.stdout.contains("CONNECT HTTP/1.1 403"),
        "{}",
        report.stdout
    );
    let records: Vec<EventRecord> = LogReader::open(&log).unwrap().map(Result::unwrap).collect();
    let (bindings, hooks) = claims(&records);
    assert_eq!(bindings[0].agent_adapter.hooks(), HookSupport::None);
    assert_eq!(
        hooks,
        ["PreToolUse"],
        "the forged line is still only a claim"
    );
    assert!(
        records.iter().any(|r| r.origin == Origin::Proxy
            && matches!(
                &r.event,
                WardEvent::NetworkDenied { .. } | WardEvent::NetworkRequested { .. }
            )
            && format!("{:?}", r.event).contains(BLOCKED)),
        "the proxy refused and recorded it"
    );
}

/// Without a sandbox: the launch every adapter gets differs only in the adapter's own
/// command, configuration and provider route — never in the session's authority.
#[test]
fn every_adapter_gets_the_same_launch_authority() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let state = tempfile::tempdir().unwrap();
    let project = project();
    let session = Session::start_in(project.path(), state.path()).expect("start");
    let launches: Vec<_> = Under::ALL
        .into_iter()
        .map(|under| {
            let (argv, opts) = session
                .adapter_launch(
                    &under.adapter(),
                    &["--task".into()],
                    &[],
                    &["github".into()],
                )
                .expect("adapter launch");
            (under, argv, opts)
        })
        .collect();
    let (_, _, first) = &launches[0];
    for (under, argv, opts) in &launches {
        assert_eq!(argv.last().map(String::as_str), Some("--task"), "{under:?}");
        assert!(argv[0].starts_with("/work/.fake/"), "{under:?}");
        assert_eq!(
            format!("{:?}", opts.refusals),
            format!("{:?}", first.refusals),
            "{under:?}"
        );
        let non_provider = |o: &ward_daemon::session::LaunchOpts| -> Vec<String> {
            o.gateways
                .iter()
                .filter(|g| !ward_daemon::agents::PROVIDERS.contains(&g.service.as_str()))
                .map(|g| g.service.clone())
                .collect()
        };
        assert_eq!(non_provider(opts), non_provider(first), "{under:?}");
        for (name, _) in &opts.env {
            assert!(
                !ward_agent_adapter::launch::is_reserved_env(name),
                "{under:?}: {name} (proxy settings, HOME, PATH and WARD_* are the host's)"
            );
        }
        assert_eq!(opts.interactive, first.interactive, "{under:?}");
        assert!(
            opts.adapter.is_some(),
            "{under:?}: the launch carries its binding"
        );
    }
    drop(session);
}
