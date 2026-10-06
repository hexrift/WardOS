#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ward_authority::{
    AuthorityLease, AuthorityLeaseInput, CapabilityGrant, CapabilityName, EmptyAuthorityPolicy,
    GrantSet, LeaseVersion, ResourceRef, UntrustedAuthorityLease,
};
use ward_events::{
    AgentId, DelegationId, ExecutionAttemptId, LeaseId, NodeId, PrincipalId, SessionId, SnapshotId,
    TaskId,
};
use ward_node_client::{EnvelopeInput, IssuerKey, WorkloadInput};
use ward_node_protocol::{TaskAdmissionAuthority, TaskAdmissionEnvelope, TaskBinding};

pub const NODE: NodeId = NodeId::from_u128(4);
pub const ISSUER: PrincipalId = PrincipalId::from_u128(2);
pub const SEED: [u8; 32] = [7; 32];

pub fn issuer() -> IssuerKey {
    IssuerKey::from_seed(SEED).unwrap()
}

pub fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

pub fn binding() -> TaskBinding {
    TaskBinding::new(
        TaskId::from_u128(7),
        ExecutionAttemptId::from_u128(8),
        LeaseId::from_u128(9),
    )
}

pub fn isolation() -> bool {
    ward_sandbox::ci::isolation_ready(ward_launch::available(), "bubblewrap")
}

pub fn envelope_input(binding: TaskBinding, snapshot: SnapshotId, argv: &[&str]) -> EnvelopeInput {
    let now = now_ms();
    let lease = AuthorityLease::root(
        AuthorityLeaseInput {
            id: binding.lease(),
            delegation_id: DelegationId::from_u128(6),
            issuer: ISSUER,
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
    EnvelopeInput {
        binding,
        agent: AgentId::from_u128(3),
        node: NODE,
        session: SessionId::from_u128(5),
        authority: TaskAdmissionAuthority::new(UntrustedAuthorityLease::from(&lease), Vec::new())
            .unwrap(),
        workload: WorkloadInput {
            argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
            capability_manifest: None,
            snapshot,
            wall_clock_budget_ms: 600_000,
        },
        issued_at_unix_ms: now - 60_000,
        expires_at_unix_ms: now + 600_000,
        version: 1,
    }
}

pub fn envelope(
    binding: TaskBinding,
    snapshot: SnapshotId,
    argv: &[&str],
) -> TaskAdmissionEnvelope {
    envelope_input(binding, snapshot, argv).build().unwrap()
}

pub fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

pub fn trust_store(dir: &Path) -> PathBuf {
    let path = dir.join("trusted-issuers");
    std::fs::write(&path, format!("{}\n", issuer().trust_store_line(ISSUER))).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

pub fn seed_file(dir: &Path) -> PathBuf {
    let path = dir.join("issuer.seed");
    std::fs::write(&path, SEED).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// The shipped `ward-node`, never one built with `test-loopback`: `WARD_NODE_BIN` when
/// set, otherwise a build into `<target>/node-shipped`, a target directory no feature
/// build writes. A workspace test run leaves a `test-loopback` build in
/// `<target>/<profile>`, so that one is never taken.
pub fn ward_node_binary() -> PathBuf {
    static SHIPPED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    SHIPPED
        .get_or_init(|| {
            let binary = std::env::var_os("WARD_NODE_BIN")
                .map_or_else(build_shipped_ward_node, PathBuf::from);
            assert_shipped(&binary);
            binary
        })
        .clone()
}

fn build_shipped_ward_node() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap();
    let profile = profile_dir.file_name().unwrap();
    let target = profile_dir.parent().unwrap().join("node-shipped");
    let mut build = Command::new(env!("CARGO"));
    build
        .args([
            "build",
            "-p",
            "ward-node",
            "--bin",
            "ward-node",
            "--target-dir",
        ])
        .arg(&target);
    if profile == "release" {
        build.arg("--release");
    }
    assert!(
        build.status().unwrap().success(),
        "building the shipped ward-node failed"
    );
    target.join(profile).join("ward-node")
}

fn assert_shipped(binary: &Path) {
    let version = Command::new(binary).arg("--version").output().unwrap();
    let version = String::from_utf8_lossy(&version.stdout);
    assert!(
        !version.contains("(test-loopback)"),
        "{} is a test-loopback build of ward-node ({}); the acceptance proves the shipped build",
        binary.display(),
        version.trim()
    );
}

pub fn imported(dir: &Path) -> SnapshotId {
    let project = dir.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/input.txt"), b"from the snapshot\n").unwrap();
    let output = Command::new(ward_node_binary())
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

pub struct Node {
    child: Child,
    pub socket: PathBuf,
    pub task_root: PathBuf,
}

impl Node {
    pub fn spawn(dir: &Path) -> Self {
        let socket = dir.join("node.sock");
        let task_root = dir.join("tasks");
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
            .arg("--task-root")
            .arg(&task_root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
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
            task_root,
        }
    }

    pub fn workspace(&self, binding: TaskBinding) -> PathBuf {
        self.task_root
            .join(binding.task().to_string())
            .join(binding.attempt().to_string())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn marker(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

pub fn processes_with(marker: &str) -> usize {
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

pub fn wait_until_sandboxed(marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while processes_with(marker) < 3 {
        assert!(Instant::now() < deadline, "the workload never started");
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn wait_until_gone(marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while processes_with(marker) > 0 {
        assert!(
            Instant::now() < deadline,
            "a workload process outlived its revocation"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
