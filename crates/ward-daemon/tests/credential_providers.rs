#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #267 end to end against a small in-process fake Vault/OpenBao: a token
//! lease issued for a session, renewed within its bounds and refused past its
//! maximum, injected by the egress proxy without the sandbox ever seeing it,
//! revoked at the provider when its grant is revoked and when the session
//! stops, a provider outage failing closed with a named state — and the
//! leased bytes absent from the event log, the sandbox and every answer.
//!
//! The fake binds 127.0.0.1 on an ephemeral port and is torn down when the
//! test drops it. The sandboxed tests need bubblewrap and python3.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};
use ward_daemon::control::{RemoteSink, Request, Response};
use ward_daemon::credentials::config::Registry;
use ward_daemon::credentials::{
    BindingViolation, CredentialProvider, DegradedState, Health, ProviderError, Revocation,
    issue_bound, renew_within_bounds,
};
use ward_daemon::session::LaunchOpts;
use ward_daemon::{Session, daemon, sandbox};
use ward_events::{DenyReason, EndReason, LogReader, WardEvent};

const BROKER_TOKEN: &str = "fake-broker-root-token";

// ---------------------------------------------------------------------------
// The fake provider
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Up,
    Sealed,
    /// Accept, read, never answer (until the fake is dropped).
    Hang,
}

#[derive(Clone, Debug)]
struct Issued {
    token: String,
    accessor: String,
    role: String,
    ttl: String,
    max: String,
    policies: Vec<String>,
    meta: Value,
}

struct FakeState {
    mode: Mode,
    next: u32,
    issued: Vec<Issued>,
    revoked: Vec<String>,
    renewals: Vec<(String, String)>,
    widen_on_renew: bool,
    kv: BTreeMap<String, Value>,
    calls: Vec<String>,
    stop: bool,
}

struct FakeVault {
    port: u16,
    state: Arc<(Mutex<FakeState>, Condvar)>,
    accept: Option<JoinHandle<()>>,
}

impl FakeVault {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new((
            Mutex::new(FakeState {
                mode: Mode::Up,
                next: 0,
                issued: Vec::new(),
                revoked: Vec::new(),
                renewals: Vec::new(),
                widen_on_renew: false,
                kv: BTreeMap::new(),
                calls: Vec::new(),
                stop: false,
            }),
            Condvar::new(),
        ));
        let shared = Arc::clone(&state);
        let accept = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if shared.0.lock().unwrap().stop {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || serve(stream, &shared));
            }
        });
        Self {
            port,
            state,
            accept: Some(accept),
        }
    }

    fn address(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn with<T>(&self, f: impl FnOnce(&mut FakeState) -> T) -> T {
        f(&mut self.state.0.lock().unwrap())
    }

    fn issued(&self) -> Vec<Issued> {
        self.with(|s| s.issued.clone())
    }

    fn revoked(&self) -> Vec<String> {
        self.with(|s| s.revoked.clone())
    }
}

impl Drop for FakeVault {
    fn drop(&mut self) {
        self.with(|s| s.stop = true);
        self.state.1.notify_all();
        // Wake the accept loop so it sees the stop and returns.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, Option<String>, Vec<u8>)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).ok()? != 1 {
            return None;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, path) = (first.next()?.to_owned(), first.next()?.to_owned());
    let mut token = None;
    let mut length = 0;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.to_ascii_lowercase().as_str() {
                "x-vault-token" => token = Some(value.trim().to_owned()),
                "content-length" => length = value.trim().parse().ok()?,
                _ => {}
            }
        }
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).ok()?;
    Some((method, path, token, body))
}

fn reply(stream: &mut TcpStream, status: u16, body: &Value) {
    let text = if status == 204 {
        String::new()
    } else {
        body.to_string()
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{text}",
        text.len()
    );
}

fn serve(mut stream: TcpStream, shared: &Arc<(Mutex<FakeState>, Condvar)>) {
    let Some((method, path, token, body)) = read_request(&mut stream) else {
        return;
    };
    let (lock, changed) = &**shared;
    let mut s = lock.lock().unwrap();
    s.calls.push(format!("{method} {path}"));
    match s.mode {
        Mode::Hang => {
            while !s.stop {
                s = changed.wait(s).unwrap();
            }
            return;
        }
        Mode::Sealed => return reply(&mut stream, 503, &json!({"errors": ["sealed"]})),
        Mode::Up => {}
    }
    if path == "/v1/sys/health" {
        return reply(&mut stream, 200, &json!({"sealed": false}));
    }
    if token.as_deref() != Some(BROKER_TOKEN) {
        return reply(&mut stream, 403, &json!({"errors": ["permission denied"]}));
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if path == "/v1/auth/token/lookup-self" {
        return reply(&mut stream, 200, &json!({"data": {"policies": ["broker"]}}));
    }
    if let Some(role) = path.strip_prefix("/v1/auth/token/create/") {
        s.next += 1;
        let n = s.next;
        let issued = Issued {
            token: format!("fake-lease-token-{n}-{}", std::process::id()),
            accessor: format!("fake-accessor-{n}-{}", std::process::id()),
            role: role.to_owned(),
            ttl: body["ttl"].as_str().unwrap_or_default().to_owned(),
            max: body["explicit_max_ttl"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            policies: body["policies"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|p| p.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            meta: body["meta"].clone(),
        };
        let ttl: u64 = issued.ttl.trim_end_matches('s').parse().unwrap_or(0);
        let answer = json!({"auth": {
            "client_token": issued.token,
            "accessor": issued.accessor,
            "policies": issued.policies,
            "token_policies": issued.policies,
            "lease_duration": ttl,
            "renewable": true,
        }});
        s.issued.push(issued);
        return reply(&mut stream, 200, &answer);
    }
    if path == "/v1/auth/token/renew" {
        let token = body["token"].as_str().unwrap_or_default().to_owned();
        let increment = body["increment"].as_str().unwrap_or_default().to_owned();
        let Some(found) = s.issued.iter().find(|i| i.token == token).cloned() else {
            return reply(&mut stream, 400, &json!({"errors": ["invalid token"]}));
        };
        if s.revoked.contains(&found.accessor) {
            return reply(&mut stream, 400, &json!({"errors": ["invalid token"]}));
        }
        s.renewals.push((found.accessor.clone(), increment.clone()));
        let mut policies = found.policies.clone();
        if s.widen_on_renew {
            policies.push("admin".into());
        }
        // A generous provider: an hour, whatever was asked. The broker's
        // rules are what hold the lease to its maximum.
        return reply(
            &mut stream,
            200,
            &json!({"auth": {"lease_duration": 3600, "token_policies": policies}}),
        );
    }
    if path == "/v1/auth/token/revoke-accessor" {
        let accessor = body["accessor"].as_str().unwrap_or_default().to_owned();
        let known = s.issued.iter().any(|i| i.accessor == accessor);
        if !known || s.revoked.contains(&accessor) {
            return reply(&mut stream, 400, &json!({"errors": ["invalid accessor"]}));
        }
        s.revoked.push(accessor);
        drop(s);
        changed.notify_all();
        return reply(&mut stream, 204, &Value::Null);
    }
    if let Some(rest) = path.strip_prefix("/v1/secret/data/") {
        return match s.kv.get(rest) {
            Some(data) => reply(&mut stream, 200, &json!({"data": {"data": data}})),
            None => reply(&mut stream, 404, &json!({"errors": []})),
        };
    }
    reply(&mut stream, 404, &json!({"errors": []}));
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The broker's provider token, 0600, outside the state directory.
fn token_file(dir: &Path) -> PathBuf {
    let path = dir.join("bao.token");
    fs::write(&path, format!("{BROKER_TOKEN}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

struct Service<'a> {
    rule: &'a str,
    ttl: u64,
    max: u64,
    upstream_port: u16,
    timeout_ms: u64,
}

impl Default for Service<'_> {
    fn default() -> Self {
        Self {
            rule: "allow",
            ttl: 120,
            max: 300,
            upstream_port: 443,
            timeout_ms: 2000,
        }
    }
}

fn write_config(state: &Path, address: &str, token: &Path, s: &Service<'_>) {
    let text = format!(
        r#"
[provider.bao]
kind = "openbao"
address = "{address}"
token_file = "{token}"
insecure_loopback = true
timeout_ms = {timeout}
max_ttl_secs = 600

[service.artifacts]
provider = "bao"
engine = "token"
role = "ward-artifacts"
rule = "{rule}"
permissions = ["artifacts-read"]
ttl_secs = {ttl}
max_ttl_secs = {max}
upstream = "127.0.0.1:{port}"
prefix = "/artifacts"
value_prefix = "Bearer "
paths = ["/v1/repos/acme"]
base_url_env = "ARTIFACTS_URL"

[service.registry]
provider = "bao"
engine = "kv"
mount = "secret"
path = "ci/registry"
field = "token"
rule = "ask"
ttl_secs = 60
upstream = "registry.example:443"
prefix = "/registry"
"#,
        token = token.display(),
        timeout = s.timeout_ms,
        rule = s.rule,
        ttl = s.ttl,
        max = s.max,
        port = s.upstream_port,
    );
    fs::create_dir_all(state).unwrap();
    fs::write(state.join("credentials.toml"), text).unwrap();
}

fn scratch_project(policy: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".ward")).unwrap();
    fs::write(dir.path().join("README.md"), "demo\n").unwrap();
    fs::write(dir.path().join(".ward/policy.yaml"), policy).unwrap();
    dir
}

const LOCAL_POLICY: &str = "network: localhost_only\ncontainers: none\n";

fn artifacts_provider(
    state: &Path,
    session: &str,
) -> (
    Arc<dyn CredentialProvider>,
    ward_daemon::credentials::LeaseRequest,
) {
    let registry = Registry::load(state).unwrap();
    let perms = ["artifacts-read".to_owned()].into();
    registry.request_for("artifacts", session, &perms).unwrap()
}

/// Every file under `dir`, recursively, as raw bytes.
fn every_file(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            out.extend(every_file(&path));
        } else if meta.is_file()
            && let Ok(bytes) = fs::read(&path)
        {
            out.push((path, bytes));
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

fn assert_absent(dir: &Path, secrets: &[&str]) {
    for (path, bytes) in every_file(dir) {
        for secret in secrets {
            assert!(
                !contains(&bytes, secret),
                "{} holds a leased secret",
                path.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The interface against the fake: issue, renew, revoke, outage
// ---------------------------------------------------------------------------

#[test]
fn a_token_lease_is_bound_renewed_within_its_max_and_revoked_at_the_provider() {
    let vault = FakeVault::start();
    let state = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    write_config(
        state.path(),
        &vault.address(),
        &token_file(keys.path()),
        &Service::default(),
    );
    let (provider, request) = artifacts_provider(state.path(), "sess_bound");
    assert_eq!(provider.health(), Health::Healthy);

    let lease = issue_bound(&*provider, &request).unwrap();
    let issued = vault.issued();
    assert_eq!(issued.len(), 1);
    let fake = &issued[0];
    // What the provider was asked for: the role, the TTL and the max the
    // service names, the policies the policy granted, and the binding.
    assert_eq!(fake.role, "ward-artifacts");
    assert_eq!((fake.ttl.as_str(), fake.max.as_str()), ("120s", "300s"));
    assert_eq!(fake.policies, ["artifacts-read"]);
    assert_eq!(fake.meta["ward_session"], "sess_bound");
    assert_eq!(fake.meta["ward_service"], "artifacts");
    assert_eq!(fake.meta["ward_audience"], "127.0.0.1");
    assert_eq!(lease.ttl(), Duration::from_secs(120));
    assert_eq!(
        lease
            .max_expires_at
            .duration_since(lease.issued_at)
            .unwrap(),
        Duration::from_secs(300)
    );
    assert!(lease.revocable);
    let debug = format!("{lease:?}");
    assert!(
        !debug.contains(&fake.token) && !debug.contains(&fake.accessor),
        "{debug}"
    );

    // Renewal: the fake offers an hour, the lease reaches its max and no more.
    let renewed = renew_within_bounds(&*provider, &lease, SystemTime::now()).unwrap();
    assert_eq!(renewed.expires_at, lease.max_expires_at);
    assert_eq!(vault.with(|s| s.renewals.len()), 1);
    // At the max: refused, and the provider is not even asked.
    assert_eq!(
        renew_within_bounds(&*provider, &renewed, SystemTime::now()).unwrap_err(),
        ProviderError::Binding(BindingViolation::PastMaxTtl)
    );
    assert_eq!(vault.with(|s| s.renewals.len()), 1);

    // A provider that answers a renewal with more policies is refused.
    vault.with(|s| s.widen_on_renew = true);
    assert_eq!(
        renew_within_bounds(&*provider, &lease, SystemTime::now()).unwrap_err(),
        ProviderError::Binding(BindingViolation::ScopeWidened)
    );

    // Revocation is pushed to the provider and confirmed; once more is still
    // a confirmed end state ("invalid accessor": the token is gone).
    assert_eq!(provider.revoke(&lease), Ok(Revocation::Confirmed));
    assert_eq!(vault.revoked(), std::slice::from_ref(&fake.accessor));
    assert_eq!(provider.revoke(&lease), Ok(Revocation::Confirmed));
}

#[test]
fn a_kv_secret_is_a_client_side_lease_the_provider_cannot_revoke() {
    let vault = FakeVault::start();
    vault.with(|s| {
        s.kv.insert(
            "ci/registry".into(),
            json!({"token": "fake-kv-static-value"}),
        );
    });
    let state = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    write_config(
        state.path(),
        &vault.address(),
        &token_file(keys.path()),
        &Service::default(),
    );
    let registry = Registry::load(state.path()).unwrap();
    let (provider, request) = registry
        .request_for(
            "registry",
            "sess_kv",
            &std::collections::BTreeSet::default(),
        )
        .unwrap();
    let lease = issue_bound(&*provider, &request).unwrap();
    assert!(!lease.revocable);
    assert_eq!(lease.ttl(), Duration::from_secs(60));
    assert_eq!(provider.revoke(&lease), Ok(Revocation::NotRevocable));
    assert!(vault.revoked().is_empty());
    // A missing secret is not found, not an empty credential.
    vault.with(|s| s.kv.clear());
    assert!(matches!(
        issue_bound(&*provider, &request),
        Err(ProviderError::NotFound(_))
    ));
}

#[test]
fn a_provider_outage_fails_closed_with_a_named_state() {
    let keys = tempfile::tempdir().unwrap();
    let token = token_file(keys.path());

    // Nothing listening: unreachable.
    let gone = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://127.0.0.1:{}", gone.local_addr().unwrap().port());
    drop(gone);
    let state = tempfile::tempdir().unwrap();
    write_config(state.path(), &address, &token, &Service::default());
    let (provider, request) = artifacts_provider(state.path(), "sess_down");
    let err = issue_bound(&*provider, &request).unwrap_err();
    assert_eq!(err.state_name(), "unreachable");
    assert_eq!(
        provider.health(),
        Health::Degraded(DegradedState::Unreachable)
    );
    let check = ward_daemon::doctor::credential_providers(state.path());
    assert_eq!(check.status, ward_daemon::doctor::Status::Warn);
    assert!(
        check.detail.contains("bao degraded (unreachable)"),
        "{}",
        check.detail
    );
    assert!(!check.detail.contains(BROKER_TOKEN));

    // Accepting and never answering: timed out within the configured bound.
    let vault = FakeVault::start();
    vault.with(|s| s.mode = Mode::Hang);
    let state = tempfile::tempdir().unwrap();
    write_config(
        state.path(),
        &vault.address(),
        &token,
        &Service {
            timeout_ms: 300,
            ..Service::default()
        },
    );
    let (provider, request) = artifacts_provider(state.path(), "sess_hang");
    let started = Instant::now();
    let err = issue_bound(&*provider, &request).unwrap_err();
    assert_eq!(err.state_name(), "timed-out");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    drop(vault);

    // Sealed.
    let vault = FakeVault::start();
    vault.with(|s| s.mode = Mode::Sealed);
    let state = tempfile::tempdir().unwrap();
    write_config(state.path(), &vault.address(), &token, &Service::default());
    let (provider, request) = artifacts_provider(state.path(), "sess_sealed");
    assert_eq!(
        issue_bound(&*provider, &request).unwrap_err().state_name(),
        "sealed"
    );
    assert_eq!(provider.health(), Health::Degraded(DegradedState::Sealed));
    assert!(vault.issued().is_empty());
}

#[test]
fn a_launch_against_a_degraded_provider_gets_no_credential_and_a_named_refusal() {
    let keys = tempfile::tempdir().unwrap();
    let gone = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://127.0.0.1:{}", gone.local_addr().unwrap().port());
    drop(gone);
    let state = tempfile::tempdir().unwrap();
    write_config(
        state.path(),
        &address,
        &token_file(keys.path()),
        &Service::default(),
    );
    let project = scratch_project(LOCAL_POLICY);
    let session = Session::start_in(project.path(), state.path()).unwrap();
    let grants = session.provider_gateways(&[]).unwrap();
    assert!(grants.gateways.is_empty(), "fail closed: no gateway");
    let rules: Vec<String> = grants
        .refusals
        .iter()
        .map(|r| match r {
            WardEvent::CredentialDenied {
                service,
                reason: DenyReason::PolicyDeny { rule },
                ..
            } => format!("{} {}", service.as_str(), rule.as_str()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(rules, ["artifacts credential-provider:bao:unreachable"]);
    assert!(
        grants
            .notes
            .iter()
            .any(|n| n.contains("artifacts: provider bao unreachable; no credential granted")),
        "{:?}",
        grants.notes
    );
    // The `ask` service was not asked for: no lease, and the note says how.
    assert!(
        grants
            .notes
            .iter()
            .any(|n| n.contains("pass --grant registry")),
        "{:?}",
        grants.notes
    );
}

#[test]
fn policy_decides_before_any_provider_is_asked() {
    let vault = FakeVault::start();
    let keys = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    write_config(
        state.path(),
        &vault.address(),
        &token_file(keys.path()),
        &Service::default(),
    );
    // The project narrows the host's `allow` to `deny`.
    let project = scratch_project(&format!("{LOCAL_POLICY}credentials:\n  artifacts: deny\n"));
    let session = Session::start_in(project.path(), state.path()).unwrap();
    let grants = session
        .provider_gateways(&["artifacts".to_owned()])
        .unwrap();
    assert!(grants.gateways.is_empty());
    assert!(matches!(
        &grants.refusals[..],
        [WardEvent::CredentialDenied { reason: DenyReason::PolicyDeny { rule }, .. }]
            if rule.as_str() == "credentials.artifacts"
    ));
    // A project cannot introduce a provider service the host did not.
    let project = scratch_project(&format!(
        "{LOCAL_POLICY}credentials:\n  invented: !allow {{permissions: [x]}}\n"
    ));
    let session = Session::start_in(project.path(), state.path()).unwrap();
    let grants = session.provider_gateways(&["invented".to_owned()]).unwrap();
    assert_eq!(
        grants.gateways.len(),
        1,
        "only the host's artifacts service"
    );
    assert!(vault.issued().iter().all(|i| i.role == "ward-artifacts"));
    assert_eq!(vault.issued().len(), 1);
    // A lease that is never launched is not left alive at the provider.
    assert!(vault.revoked().is_empty());
    drop(grants);
    assert_eq!(vault.revoked(), [vault.issued()[0].accessor.clone()]);
}

// ---------------------------------------------------------------------------
// Through a real sandbox, a real proxy and a real daemon
// ---------------------------------------------------------------------------

fn sandbox_ready() -> bool {
    ward_sandbox::ci::isolation_ready(sandbox::available(), "bubblewrap")
        && ward_sandbox::ci::isolation_ready(Path::new("/usr/bin/python3").exists(), "python3")
}

/// A loopback upstream that answers 200 and keeps every request head.
fn spawn_upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let log = heads.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).into_owned());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, heads)
}

fn serve_session(
    project: &Path,
    state: &Path,
) -> (String, PathBuf, JoinHandle<ward_daemon::Result<()>>) {
    let up = Session::start_in(project, state).expect("up");
    let id = up.id().to_owned();
    let log = up.log_path();
    up.persist_current().expect("persist");
    drop(up);
    let (state_path, serve_id) = (state.to_path_buf(), id.clone());
    let served = std::thread::spawn(move || daemon::serve(&state_path, &serve_id));
    assert!(daemon::wait_until(daemon::STARTUP_TIMEOUT, || {
        daemon::serving(state, &id)
    }));
    (id, log, served)
}

/// The leased gateway with a plain loopback upstream (the test build's proxy).
fn leased_opts(session: &Session) -> LaunchOpts {
    let grants = session.provider_gateways(&[]).unwrap();
    assert!(grants.refusals.is_empty(), "{:?}", grants.refusals);
    assert_eq!(grants.gateways.len(), 1, "{:?}", grants.notes);
    let gateway = grants
        .gateways
        .into_iter()
        .next()
        .unwrap()
        .map_route(|r| r.plain_upstream(true));
    LaunchOpts {
        env: gateway.env.clone(),
        gateways: vec![gateway],
        ..LaunchOpts::default()
    }
}

const SCRIPT: &str = r"
import json, os, socket, time
base = os.environ['ARTIFACTS_URL']
with open('env.json', 'w') as f:
    json.dump(dict(os.environ), f)

def req(path):
    s = socket.socket(socket.AF_UNIX)
    s.connect('/run/ward/proxy.sock')
    p = base.split('3128', 1)[1] + path
    s.sendall(('GET ' + p + ' HTTP/1.1\r\nHost: 127.0.0.1:3128\r\n'
               'Authorization: Bearer placeholder\r\nConnection: close\r\n\r\n').encode())
    return s.recv(200).split(b'\r\n')[0].decode()

first = req('/v1/repos/acme/items') + '|' + req('/v1/repos/other/items')
with open('first.tmp', 'w') as f:
    f.write(first)
os.replace('first.tmp', 'first.txt')
deadline = time.time() + 20
while not os.path.exists('go.txt') and time.time() < deadline:
    time.sleep(0.05)
open('second.txt', 'w').write(req('/v1/repos/acme/items'))
";

#[test]
#[allow(clippy::too_many_lines)]
fn a_lease_is_injected_by_the_proxy_never_seen_by_the_sandbox_and_revoked_with_its_grant() {
    if !sandbox_ready() {
        return;
    }
    let vault = FakeVault::start();
    let (upstream_port, heads) = spawn_upstream();
    let keys = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    write_config(
        state.path(),
        &vault.address(),
        &token_file(keys.path()),
        &Service {
            upstream_port,
            ..Service::default()
        },
    );
    let project = scratch_project(LOCAL_POLICY);
    let (session_id, log, served) = serve_session(project.path(), state.path());
    let socket = daemon::socket_path(state.path(), &session_id);

    let mut run = Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap();
    let opts = leased_opts(&run);
    let issued = vault.issued();
    assert_eq!(issued.len(), 1);
    let (token, accessor) = (issued[0].token.clone(), issued[0].accessor.clone());
    assert_eq!(issued[0].meta["ward_session"], session_id.as_str());
    let argv: Vec<String> = ["python3", "-c", SCRIPT]
        .iter()
        .map(ToString::to_string)
        .collect();
    let launch = std::thread::spawn(move || run.launch(&argv, &opts));

    let first = project.path().join("first.txt");
    assert!(
        daemon::wait_until(Duration::from_secs(20), || first.exists()),
        "the sandboxed requests complete"
    );
    // In scope: injected. Outside the resource scope: refused at the proxy.
    assert_eq!(
        fs::read_to_string(&first).unwrap(),
        "HTTP/1.1 200 OK|HTTP/1.1 403 Forbidden"
    );
    let upstream = heads.lock().unwrap().clone();
    assert_eq!(
        upstream.len(),
        1,
        "the out-of-scope request never left: {upstream:?}"
    );
    assert!(
        upstream[0].starts_with("GET /v1/repos/acme/items HTTP/1.1"),
        "{upstream:?}"
    );
    assert!(
        upstream[0].contains(&format!("authorization: Bearer {token}")),
        "{upstream:?}"
    );
    assert!(!upstream[0].contains("placeholder"), "{upstream:?}");

    // `ward session revoke`: the proxy withdraws the route, the lease is
    // revoked at the provider, and the grant's history says so.
    let mut sink = RemoteSink::connect(&socket).expect("control connection");
    let id = match sink.call(&Request::Grants).unwrap() {
        Response::Grants(g) if g.len() == 1 => g[0].id,
        other => panic!("{other:?}"),
    };
    match sink.call(&Request::Revoke { id }).unwrap() {
        Response::Revoked(outcome) => assert!(
            matches!(
                outcome,
                ward_daemon::approvals::RevokeOutcome::Withdrawn
                    | ward_daemon::approvals::RevokeOutcome::WithdrawnInFlight(_)
            ),
            "{outcome:?}"
        ),
        other => panic!("{other:?}"),
    }
    assert!(
        daemon::wait_until(Duration::from_secs(10), || vault.revoked()
            == [accessor.clone()]),
        "the provider records the revocation: {:?}",
        vault.revoked()
    );
    let history = |sink: &mut RemoteSink| match sink.call(&Request::GrantHistory).unwrap() {
        Response::GrantHistory(h) => h,
        other => panic!("{other:?}"),
    };
    assert!(
        daemon::wait_until(Duration::from_secs(10), || {
            history(&mut sink).iter().any(|g| {
                g.id == id
                    && g.scope
                        .ends_with("provider bao: revoked at the provider (grant revoked)")
            })
        }),
        "{:?}",
        history(&mut sink)
    );

    fs::write(project.path().join("go.txt"), "").unwrap();
    let report = launch.join().unwrap().expect("launch");
    let second = fs::read_to_string(project.path().join("second.txt")).unwrap();
    assert!(
        second.starts_with("HTTP/1.1 403"),
        "after the revoke: {second}"
    );
    assert_eq!(heads.lock().unwrap().len(), 1, "never sent again");

    // The sandbox never held it: not in its environment, not in its output.
    let env = fs::read_to_string(project.path().join("env.json")).unwrap();
    assert!(env.contains("ARTIFACTS_URL"), "{env}");
    for secret in [&token, &accessor] {
        assert!(!env.contains(secret.as_str()));
        assert!(!report.stdout.contains(secret.as_str()));
        assert!(!report.stderr.contains(secret.as_str()));
    }
    // Nor any answer the daemon gives about it.
    let answers = format!(
        "{:?} {:?}",
        history(&mut sink),
        sink.call(&Request::Grants).unwrap()
    );
    assert!(
        !answers.contains(&token) && !answers.contains(&accessor),
        "{answers}"
    );
    drop(sink);

    Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .unwrap();
    served.join().unwrap().unwrap();

    // The grant is in the log, minus the secret; the secret is nowhere in
    // the log, the state directory or the worktree.
    let records: Vec<_> = LogReader::open(&log)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(records.iter().any(|r| matches!(
        &r.event,
        WardEvent::CredentialGranted { service, expires, .. }
            if service.as_str() == "artifacts" && *expires <= Duration::from_secs(120)
    )));
    assert_absent(state.path(), &[&token, &accessor, BROKER_TOKEN]);
    assert_absent(project.path(), &[&token, &accessor, BROKER_TOKEN]);
    assert!(!contains(&fs::read(&log).unwrap(), &token));
}

#[test]
fn stopping_the_session_revokes_its_lease_at_the_provider() {
    if !sandbox_ready() {
        return;
    }
    let vault = FakeVault::start();
    let (upstream_port, _heads) = spawn_upstream();
    let keys = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    write_config(
        state.path(),
        &vault.address(),
        &token_file(keys.path()),
        &Service {
            upstream_port,
            ..Service::default()
        },
    );
    let project = scratch_project(LOCAL_POLICY);
    let (_id, log, served) = serve_session(project.path(), state.path());

    let mut run = Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap();
    let opts = leased_opts(&run);
    let issued = vault.issued();
    let (token, accessor) = (issued[0].token.clone(), issued[0].accessor.clone());
    let argv: Vec<String> = ["python3", "-c", SCRIPT]
        .iter()
        .map(ToString::to_string)
        .collect();
    // The launch's own end cannot be recorded once the stop has sealed the
    // log: whatever it answers, it returns.
    let launch = std::thread::spawn(move || {
        let _ = run.launch(&argv, &opts);
    });
    let first = project.path().join("first.txt");
    assert!(
        daemon::wait_until(Duration::from_secs(20), || first.exists()),
        "the sandbox is running"
    );
    assert!(vault.revoked().is_empty(), "nothing revoked while it runs");

    Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap()
        .stop(EndReason::UserStop)
        .expect("stop");
    launch.join().unwrap();
    served.join().unwrap().unwrap();

    // The launch ended with the stop, and its lease with it — at the provider.
    assert_eq!(vault.revoked(), std::slice::from_ref(&accessor));
    assert!(
        !project.path().join("second.txt").exists(),
        "stopped before go"
    );
    assert!(!contains(&fs::read(&log).unwrap(), &token));
    assert_absent(state.path(), &[&token, &accessor, BROKER_TOKEN]);
}

#[test]
fn a_launch_that_ends_revokes_its_lease_and_retires_its_grant_with_the_outcome() {
    if !sandbox_ready() {
        return;
    }
    let vault = FakeVault::start();
    let (upstream_port, heads) = spawn_upstream();
    let keys = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    write_config(
        state.path(),
        &vault.address(),
        &token_file(keys.path()),
        &Service {
            upstream_port,
            ..Service::default()
        },
    );
    let project = scratch_project(LOCAL_POLICY);
    let (session_id, _log, served) = serve_session(project.path(), state.path());
    let socket = daemon::socket_path(state.path(), &session_id);

    let mut run = Session::open_current(project.path(), state.path())
        .unwrap()
        .unwrap();
    let opts = leased_opts(&run);
    let accessor = vault.issued()[0].accessor.clone();
    // One request, then the command exits on its own.
    let script = SCRIPT.replace("deadline = time.time() + 20", "deadline = time.time()");
    let argv: Vec<String> = vec!["python3".into(), "-c".into(), script];
    let report = run.launch(&argv, &opts).expect("launch");
    assert_eq!(report.code, Some(0), "{}", report.stderr);
    assert_eq!(
        heads.lock().unwrap().len(),
        2,
        "both requests in scope reached it"
    );

    // The launch's end revoked the lease at the provider before its terminal
    // record, and the grant is retired with that outcome.
    assert_eq!(vault.revoked(), [accessor]);
    let mut sink = RemoteSink::connect(&socket).unwrap();
    assert!(matches!(sink.call(&Request::Grants).unwrap(), Response::Grants(g) if g.is_empty()));
    match sink.call(&Request::GrantHistory).unwrap() {
        Response::GrantHistory(h) => {
            assert_eq!(h.len(), 1, "{h:?}");
            assert_eq!(
                h[0].revoke_state,
                ward_daemon::approvals::RevokeState::Revoked
            );
            assert!(
                h[0].scope
                    .ends_with("provider bao: revoked at the provider (launch ended)"),
                "{}",
                h[0].line()
            );
        }
        other => panic!("{other:?}"),
    }
    drop(sink);
    run.stop(EndReason::UserStop).unwrap();
    served.join().unwrap().unwrap();
}
