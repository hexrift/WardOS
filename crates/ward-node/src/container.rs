//! The OCI container backend: `runc` at level `container` (#263, ADR-0039 §2).
//!
//! A node started with `--container-runtime <file>` runs every attempt placed at
//! `container` ([`crate::capsule::CapsulePlacement`]) in a container the operator's `runc`
//! creates, from the same [`LaunchRequest`] the bubblewrap backend runs: the request is
//! turned into the very [`ward_launch::Launch`] bubblewrap would be given, and its
//! [`ward_launch::SandboxPlan`] (environment, mounts, working directory, hostname, command
//! line) into an OCI bundle beside the attempt's workspace (`<attempt>.capsule/`, mode
//! 0700). The five bindings are therefore bubblewrap's, from the request and nothing else:
//!
//! * storage: the workspace bound writable at `/work`, the system directories read-only,
//!   private `/tmp`, `/home`, `/run`, `/home/agent` and `/env`; the root filesystem is an
//!   empty directory of the bundle, mounted read-only;
//! * network: a network namespace of its own holding only loopback and, for a manifest
//!   naming an allowlist, the attempt's egress proxy socket at
//!   [`ward_launch::PROXY_SOCKET`];
//! * devices: `runc`'s minimal `/dev`;
//! * credentials: never inside; the proxy injects them;
//! * the verifier: not reachable.
//!
//! On top the container always has what bubblewrap only has under the `ward-agent` shim:
//! no capability in any set, `no_new_privs` and the baseline seccomp profile of
//! [`ward_sandbox::seccomp::Profile::baseline`], with masked and read-only `/proc` paths.
//! Its own user namespace maps exactly one id, the node's own user, to root inside: as
//! root the container's root is the host's root without a capability, and rootless it is
//! the node's user.
//!
//! `runc run` is spawned through `setpriv --pdeathsig KILL` from the attempt's reaper
//! thread and the container's first process is `setpriv --pdeathsig KILL` too, so the
//! container dies with `runc` and `runc` with the node, as bubblewrap's
//! `--die-with-parent` does. A stop or the budget kills `runc` and the container's init
//! (`runc kill`), and the container is deleted (`runc delete --force`) and its bundle
//! removed once it is reaped, whatever ended it.
//!
//! As root `runc` puts the container in cgroups of its own, and `pause` and `resume` are
//! `runc pause` and `runc resume` (the cgroup freezer), confirmed by `runc state`, with
//! the egress proxy paused for as long as the container is. Rootless, `runc` gets no
//! cgroup here, so the backend declares `pause` and `resume` unserved
//! ([`CapsuleBackendDescriptor::RUNC_ROOTLESS`]) and the node refuses them for its
//! attempts. Neither mode enforces a manifest's `resources` limits; such a manifest is
//! never placed on it.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, getegid, geteuid};
use serde_json::{Value, json};
use thiserror::Error;
use ward_launch::{SandboxMount, SandboxPlan};
use ward_sandbox::seccomp::Profile;

use crate::capsule::{CapsuleBackend, CapsuleBackendDescriptor};
use crate::egress::AttemptEgress;
use crate::execution::{
    FreezeUnconfirmed, LaunchRequest, RunningWorkload, SpawnError, StopSignal, TaskLauncher,
    WorkloadEnd, WorkloadExit, WorkloadFreezer, WorkloadProcess, capsule_launch, captured,
    current_boot, end_survivor_tree, start_egress,
};

/// Where `setpriv` is, on the host and, through the read-only `/usr`, in every container.
pub const SETPRIV: &str = "/usr/bin/setpriv";

/// The suffix of an attempt's bundle directory, beside its workspace.
const CAPSULE_SUFFIX: &str = ".capsule";

/// How long verifying the runtime waits for its probe container.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one `runc` control command (`kill`, `pause`, `state`, …) may take.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// The namespaces of every container: all of bubblewrap's, the cgroup one included.
const NAMESPACES: [&str; 7] = ["user", "mount", "pid", "ipc", "uts", "network", "cgroup"];

/// Paths of `/proc` the container cannot read.
const MASKED: [&str; 9] = [
    "/proc/acpi",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
];

/// Paths of `/proc` the container can only read.
const READ_ONLY_PROC: [&str; 5] = [
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];

/// Why the node refuses a container runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeRefusal {
    /// The path is relative.
    NotAbsolute,
    /// The path cannot be inspected.
    Unreadable(String),
    /// A symlink, a directory or anything but a regular file.
    NotAFile,
    /// Group or others may write it.
    Writable,
    /// The owner may not execute it.
    NotExecutable,
    /// Owned by neither root nor the node's user.
    Owner,
    /// Its `--version` does not name `runc`.
    NotRunc,
    /// [`SETPRIV`] is missing.
    NoSetpriv,
    /// It could not run a container on this host.
    CannotRun,
}

impl std::fmt::Display for RuntimeRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsolute => formatter.write_str("not an absolute path"),
            Self::Unreadable(error) => formatter.write_str(error),
            Self::NotAFile => formatter.write_str("not a regular file"),
            Self::Writable => formatter.write_str("writable by group or others"),
            Self::NotExecutable => formatter.write_str("not executable"),
            Self::Owner => formatter.write_str("owned by neither root nor the node's user"),
            Self::NotRunc => formatter.write_str("does not answer as runc"),
            Self::NoSetpriv => write!(formatter, "needs {SETPRIV} (util-linux)"),
            Self::CannotRun => formatter.write_str("cannot run a container on this host"),
        }
    }
}

/// A container runtime the node refuses to start with.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("container runtime {}: {refusal}", path.display())]
pub struct RuntimeError {
    /// The path the operator named.
    pub path: PathBuf,
    /// Why it is refused.
    pub refusal: RuntimeRefusal,
}

/// The operator's verified `runc`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerRuntime {
    path: PathBuf,
    rootless: bool,
}

impl ContainerRuntime {
    /// Verify the runtime at `path`: an absolute path to a regular, executable file owned
    /// by root or the node's user and writable by no one else, whose `--version` names
    /// `runc`, with [`SETPRIV`] present, and that runs one container built as an attempt's
    /// would be over a scratch workspace under `scratch`, which must exist.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] naming the path and the [`RuntimeRefusal`].
    pub fn verify(path: &Path, scratch: &Path) -> Result<Self, RuntimeError> {
        let refuse = |refusal| RuntimeError {
            path: path.to_path_buf(),
            refusal,
        };
        if !path.is_absolute() {
            return Err(refuse(RuntimeRefusal::NotAbsolute));
        }
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| refuse(RuntimeRefusal::Unreadable(error.to_string())))?;
        if !metadata.file_type().is_file() {
            return Err(refuse(RuntimeRefusal::NotAFile));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(refuse(RuntimeRefusal::Writable));
        }
        if metadata.mode() & 0o100 == 0 {
            return Err(refuse(RuntimeRefusal::NotExecutable));
        }
        if metadata.uid() != 0 && metadata.uid() != geteuid().as_raw() {
            return Err(refuse(RuntimeRefusal::Owner));
        }
        let version = Command::new(path)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| refuse(RuntimeRefusal::NotRunc))?;
        if !version.status.success() || !version.stdout.starts_with(b"runc version ") {
            return Err(refuse(RuntimeRefusal::NotRunc));
        }
        if !Path::new(SETPRIV).is_file() {
            return Err(refuse(RuntimeRefusal::NoSetpriv));
        }
        let runtime = Self {
            path: path.to_path_buf(),
            rootless: !geteuid().is_root(),
        };
        if !runtime.runs_a_container(scratch) {
            return Err(refuse(RuntimeRefusal::CannotRun));
        }
        Ok(runtime)
    }

    /// The runtime's host path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the node runs it without root, so with no cgroup and no freezer.
    #[must_use]
    pub const fn rootless(&self) -> bool {
        self.rootless
    }

    fn runs_a_container(&self, scratch: &Path) -> bool {
        let dir = scratch.join(format!(".ward-container-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let workspace = dir.join("work");
        let ran = std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&workspace)
            .is_ok()
            && self.runs_in(&workspace);
        let _ = std::fs::remove_dir_all(&dir);
        ran
    }

    fn runs_in(&self, workspace: &Path) -> bool {
        let Some(bundle) = capsule_dir_beside(workspace) else {
            return false;
        };
        let launch = ward_launch::Launch::new(workspace, vec!["true".into()])
            .clear_env()
            .budget(PROBE_TIMEOUT);
        let Ok(bundle) = Bundle::create(&bundle, &launch.plan(workspace)) else {
            return false;
        };
        let ran = launch
            .spawn_runtime(self.run(&bundle))
            .and_then(ward_launch::RunningLaunch::wait)
            .is_ok_and(|outcome| outcome.code == Some(0) && !outcome.timed_out);
        self.remove(&bundle);
        ran
    }

    /// `runc run` of `bundle` in the foreground, under `setpriv --pdeathsig KILL`.
    fn run(&self, bundle: &Bundle) -> Command {
        let mut command = Command::new(SETPRIV);
        command
            .args(["--pdeathsig", "KILL", "--"])
            .arg(&self.path)
            .arg("--root")
            .arg(bundle.state())
            .arg("--log")
            .arg(bundle.dir.join("runc.log"))
            .args(["run", "--bundle"])
            .arg(&bundle.dir)
            .arg(&bundle.id)
            .stdin(Stdio::null());
        command
    }

    /// Run `runc <verb> <id> <signal…>` against `bundle`'s state to its end, bounded.
    fn control(&self, bundle: &Bundle, verb: &[&str], after: &[&str]) -> Option<Output> {
        let mut child = Command::new(&self.path)
            .env_clear()
            .arg("--root")
            .arg(bundle.state())
            .args(verb)
            .arg(&bundle.id)
            .args(after)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return child.wait_with_output().ok(),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }

    /// Whether `runc <verb>` succeeded and `runc state` then reports `status`.
    fn reaches(&self, bundle: &Bundle, verb: &str, status: &str) -> bool {
        self.control(bundle, &[verb], &[])
            .is_some_and(|output| output.status.success())
            && self
                .control(bundle, &["state"], &[])
                .and_then(|output| serde_json::from_slice::<Value>(&output.stdout).ok())
                .is_some_and(|state| state["status"] == status)
    }

    /// Kill every process of the container. As root `runc kill --all` freezes its cgroup,
    /// signals each process and thaws it, so a paused container dies at once without
    /// running again, and nothing is left behind if its init is already gone. Rootless
    /// there is no cgroup and no freezer: killing the init ends its PID namespace.
    fn kill(&self, bundle: &Bundle) {
        let all = if self.rootless {
            &["kill"][..]
        } else {
            &["kill", "--all"][..]
        };
        let _ = self.control(bundle, all, &["KILL"]);
    }

    /// Delete the container, killing whatever of it is left, and remove its bundle.
    fn remove(&self, bundle: &Bundle) {
        let _ = self.control(bundle, &["delete", "--force"], &[]);
        let _ = std::fs::remove_dir_all(&bundle.dir);
    }
}

/// An attempt's OCI bundle: its directory, the container id and its `runc` state.
#[derive(Clone, Debug)]
struct Bundle {
    dir: PathBuf,
    id: String,
}

impl Bundle {
    /// Write the bundle of `plan` at `dir` (mode 0700): an empty root filesystem and the
    /// container's `config.json`.
    fn create(dir: &Path, plan: &SandboxPlan) -> std::io::Result<Self> {
        let bundle = Self::at(dir)
            .ok_or_else(|| std::io::Error::other("an attempt's bundle needs its attempt's name"))?;
        if plan.host_network {
            return Err(std::io::Error::other(
                "a container never shares the host network",
            ));
        }
        std::fs::DirBuilder::new().mode(0o700).create(dir)?;
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(dir.join("rootfs"))?;
        let config = oci_config(plan, geteuid().as_raw(), getegid().as_raw());
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("config.json"))?;
        std::io::Write::write_all(&mut file, config.to_string().as_bytes())?;
        Ok(bundle)
    }

    /// The bundle at `dir`, `<attempt>.capsule`, whose container is `ward-<attempt>`.
    fn at(dir: &Path) -> Option<Self> {
        let id = dir
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(CAPSULE_SUFFIX))
            .filter(|attempt| {
                attempt.starts_with(|first: char| first.is_ascii_alphanumeric())
                    && attempt
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
            })
            .map(|attempt| format!("ward-{attempt}"))?;
        Some(Self {
            dir: dir.to_path_buf(),
            id,
        })
    }

    fn state(&self) -> PathBuf {
        self.dir.join("state")
    }
}

/// The bundle directory of the attempt whose workspace is `workspace`: a sibling named
/// `<attempt>.capsule`.
#[must_use]
pub fn capsule_dir_beside(workspace: &Path) -> Option<PathBuf> {
    let attempt = workspace.file_name()?.to_str()?;
    Some(workspace.with_file_name(format!("{attempt}{CAPSULE_SUFFIX}")))
}

/// The OCI configuration of a container running `plan`, its user namespace mapping root
/// inside to `uid` and `gid` only.
fn oci_config(plan: &SandboxPlan, uid: u32, gid: u32) -> Value {
    let mut mounts = vec![
        json!({"destination": "/proc", "type": "proc", "source": "proc",
            "options": ["nosuid", "noexec", "nodev"]}),
        json!({"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}),
        json!({"destination": "/dev/pts", "type": "devpts", "source": "devpts",
            "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]}),
        json!({"destination": "/dev/shm", "type": "tmpfs", "source": "shm",
            "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]}),
    ];
    mounts.extend(plan.mounts.iter().map(|mount| match mount {
        SandboxMount::ReadOnly { host, path } => json!({"destination": path, "type": "bind",
            "source": host, "options": ["rbind", "ro", "nosuid", "nodev"]}),
        SandboxMount::Writable { host, path } => json!({"destination": path, "type": "bind",
            "source": host, "options": ["rbind", "rw", "nosuid", "nodev"]}),
        SandboxMount::Private { path } => json!({"destination": path, "type": "tmpfs",
            "source": "tmpfs", "options": ["nosuid", "nodev", "mode=755"]}),
    }));
    let mut args = vec![
        SETPRIV.to_owned(),
        "--pdeathsig".into(),
        "KILL".into(),
        "--".into(),
    ];
    args.extend(plan.command.iter().cloned());
    let none: [&str; 0] = [];
    let namespaces: Vec<Value> = NAMESPACES
        .iter()
        .map(|kind| json!({"type": kind}))
        .collect();
    let env: Vec<String> = plan
        .env
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    json!({
        "ociVersion": "1.0.2",
        "hostname": plan.hostname,
        "root": {"path": "rootfs", "readonly": true},
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": args,
            "env": env,
            "cwd": plan.cwd,
            "capabilities": {"bounding": none, "effective": none, "inheritable": none,
                "permitted": none, "ambient": none},
            "noNewPrivileges": true,
        },
        "mounts": mounts,
        "linux": {
            "namespaces": namespaces,
            "uidMappings": [{"containerID": 0, "hostID": uid, "size": 1}],
            "gidMappings": [{"containerID": 0, "hostID": gid, "size": 1}],
            "maskedPaths": MASKED,
            "readonlyPaths": READ_ONLY_PROC,
            "seccomp": Profile::baseline(),
        },
    })
}

/// The `runc` backend at `container`.
#[derive(Clone, Debug)]
pub struct RuncLauncher {
    runtime: Arc<ContainerRuntime>,
}

impl RuncLauncher {
    /// Run attempts in containers of the verified `runtime`.
    #[must_use]
    pub const fn new(runtime: Arc<ContainerRuntime>) -> Self {
        Self { runtime }
    }
}

impl CapsuleBackend for RuncLauncher {
    fn descriptor(&self) -> CapsuleBackendDescriptor {
        if self.runtime.rootless() {
            CapsuleBackendDescriptor::RUNC_ROOTLESS
        } else {
            CapsuleBackendDescriptor::RUNC
        }
    }
}

impl TaskLauncher for RuncLauncher {
    fn launch(&self, request: &LaunchRequest) -> Result<Box<dyn RunningWorkload>, SpawnError> {
        if request.resources().is_some() {
            return Err(SpawnError::Refused);
        }
        let workspace = request
            .workspace()
            .canonicalize()
            .map_err(|_| SpawnError::Refused)?;
        let dir = capsule_dir_beside(&workspace).ok_or(SpawnError::Refused)?;
        let egress = start_egress(request)?;
        let launch = capsule_launch(request, egress.as_deref().map(AttemptEgress::socket));
        let bundle = Bundle::create(&dir, &launch.plan(&workspace)).map_err(|_| {
            let _ = std::fs::remove_dir_all(&dir);
            SpawnError::Refused
        })?;
        let container = Container {
            runtime: Arc::clone(&self.runtime),
            bundle,
            ended: AtomicBool::new(false),
        };
        let launch = launch
            .spawn_runtime(self.runtime.run(&container.bundle))
            .map_err(|_| SpawnError::Refused)?;
        let deadline = Instant::now()
            .checked_add(request.budget())
            .ok_or(SpawnError::Ambiguous)?;
        Ok(Box::new(RuncWorkload {
            launch,
            container: Arc::new(container),
            egress,
            deadline,
            pausable: !self.runtime.rootless(),
        }))
    }

    fn end_survivor(&self, process: &WorkloadProcess) {
        end_survivor_tree(process);
    }

    fn end_survivor_beside(&self, workspace: &Path) {
        if let Some(bundle) = capsule_dir_beside(workspace)
            .filter(|dir| dir.is_dir())
            .and_then(|dir| Bundle::at(&dir))
        {
            self.runtime.kill(&bundle);
            self.runtime.remove(&bundle);
        }
    }
}

/// A created container: deleted with its bundle once its workload is reaped, or when the
/// last holder drops it.
#[derive(Debug)]
struct Container {
    runtime: Arc<ContainerRuntime>,
    bundle: Bundle,
    ended: AtomicBool,
}

impl Container {
    /// Kill `runc` (the process `runc`, so its parent sees it killed) and the container's
    /// init.
    fn kill(&self, runc: u32) {
        if let Ok(pid) = i32::try_from(runc) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
        self.runtime.kill(&self.bundle);
    }

    fn end(&self) {
        if !self.ended.swap(true, Ordering::SeqCst) {
            self.runtime.kill(&self.bundle);
            self.runtime.remove(&self.bundle);
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        self.end();
    }
}

struct RuncWorkload {
    launch: ward_launch::RunningLaunch,
    container: Arc<Container>,
    egress: Option<Arc<AttemptEgress>>,
    deadline: Instant,
    pausable: bool,
}

impl RunningWorkload for RuncWorkload {
    fn pid(&self) -> u32 {
        self.launch.id()
    }

    fn process(&self) -> Option<WorkloadProcess> {
        let root = self.launch.tree_root()?;
        Some(WorkloadProcess::new(
            root.pid(),
            root.start_time(),
            current_boot()?,
        ))
    }

    fn freezer(&self) -> Arc<dyn WorkloadFreezer> {
        Arc::new(RuncFreezer {
            container: Arc::clone(&self.container),
            pausable: self.pausable,
            frozen: Mutex::new(false),
            egress: self.egress.clone(),
        })
    }

    fn egress(&self) -> Option<Arc<AttemptEgress>> {
        self.egress.clone()
    }

    fn wait(self: Box<Self>, stop: &StopSignal, on_tick: &mut dyn FnMut()) -> WorkloadEnd {
        let Self {
            launch,
            container,
            deadline,
            ..
        } = *self;
        let runc = launch.id();
        let budget = std::cell::Cell::new(false);
        let outcome = launch.wait_observed_stoppable(on_tick, &|| {
            let over = Instant::now() >= deadline;
            if !over && !stop.is_requested() {
                return false;
            }
            budget.set(over);
            container.kill(runc);
            true
        });
        container.end();
        let Ok(outcome) = outcome else {
            return WorkloadEnd::default();
        };
        let exit = if outcome.stopped && budget.get() {
            WorkloadExit::BudgetExceeded
        } else if outcome.stopped {
            WorkloadExit::Stopped
        } else {
            WorkloadExit::Exited { code: outcome.code }
        };
        WorkloadEnd {
            exit,
            stdio: captured(&outcome),
            usage: None,
        }
    }
}

/// Freezes a container with `runc pause`, its egress proxy paused for as long as it is;
/// refuses everything for a rootless container, which has no freezer.
#[derive(Debug)]
struct RuncFreezer {
    container: Arc<Container>,
    pausable: bool,
    frozen: Mutex<bool>,
    egress: Option<Arc<AttemptEgress>>,
}

impl RuncFreezer {
    fn pause_egress(&self, paused: bool) {
        if let Some(egress) = &self.egress {
            egress.set_paused(paused);
        }
    }

    fn reached(&self, verb: &str, status: &str) -> bool {
        let Container {
            runtime,
            bundle,
            ended,
        } = &*self.container;
        !ended.load(Ordering::SeqCst) && runtime.reaches(bundle, verb, status)
    }
}

impl WorkloadFreezer for RuncFreezer {
    fn freeze(&self) -> Result<(), FreezeUnconfirmed> {
        if !self.pausable {
            return Err(FreezeUnconfirmed);
        }
        let mut frozen = self.frozen.lock().map_err(|_| FreezeUnconfirmed)?;
        self.pause_egress(true);
        if !self.reached("pause", "paused") {
            let _ = self.reached("resume", "running");
            self.pause_egress(false);
            return Err(FreezeUnconfirmed);
        }
        *frozen = true;
        Ok(())
    }

    fn thaw(&self) -> Result<(), FreezeUnconfirmed> {
        let mut frozen = self.frozen.lock().map_err(|_| FreezeUnconfirmed)?;
        if !*frozen {
            self.pause_egress(false);
            return Ok(());
        }
        if !self.reached("resume", "running") {
            return Err(FreezeUnconfirmed);
        }
        *frozen = false;
        self.pause_egress(false);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;

    use ward_launch::Launch;

    use super::*;

    fn plan() -> SandboxPlan {
        Launch::new("/tmp", vec!["python3".into(), "probe.py".into()])
            .clear_env()
            .egress("/host/a.egress/proxy.sock")
            .env("WARD_PROXY_SOCKET", ward_launch::PROXY_SOCKET)
            .plan(Path::new("/host/tasks/t/a"))
    }

    #[test]
    fn a_container_runs_the_plan_with_nothing_more_than_bubblewrap_and_no_privilege() {
        let plan = plan();
        let config = oci_config(&plan, 1001, 1002);
        assert_eq!(config["hostname"], plan.hostname);
        assert_eq!(config["root"], json!({"path": "rootfs", "readonly": true}));
        let process = &config["process"];
        assert_eq!(process["cwd"], "/work");
        assert_eq!(process["user"], json!({"uid": 0, "gid": 0}));
        assert_eq!(process["noNewPrivileges"], true);
        assert_eq!(process["terminal"], false);
        for set in [
            "bounding",
            "effective",
            "inheritable",
            "permitted",
            "ambient",
        ] {
            assert_eq!(process["capabilities"][set], json!([]), "{set}");
        }
        let mut args = vec![SETPRIV, "--pdeathsig", "KILL", "--"];
        args.extend(plan.command.iter().map(String::as_str));
        assert_eq!(process["args"], json!(args));
        let env: Vec<String> = plan
            .env
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        assert_eq!(process["env"], json!(env));
        assert!(env.contains(&"WARD_PROXY_SOCKET=/run/ward/proxy.sock".to_owned()));

        let linux = &config["linux"];
        assert_eq!(
            linux["namespaces"],
            json!(NAMESPACES.map(|kind| json!({"type": kind})))
        );
        assert_eq!(
            linux["uidMappings"],
            json!([{"containerID": 0, "hostID": 1001, "size": 1}])
        );
        assert_eq!(
            linux["gidMappings"],
            json!([{"containerID": 0, "hostID": 1002, "size": 1}])
        );
        assert_eq!(
            linux["seccomp"],
            serde_json::to_value(Profile::baseline()).unwrap()
        );
        assert!(linux.get("resources").is_none());

        let mounts = config["mounts"].as_array().unwrap();
        let destinations: Vec<&str> = mounts
            .iter()
            .map(|mount| mount["destination"].as_str().unwrap())
            .collect();
        assert_eq!(destinations[..4], ["/proc", "/dev", "/dev/pts", "/dev/shm"]);
        assert_eq!(mounts.len(), 4 + plan.mounts.len());
        for (mount, planned) in mounts[4..].iter().zip(&plan.mounts) {
            let (source, path, kind, access) = match planned {
                SandboxMount::ReadOnly { host, path } => (json!(host), path, "bind", "ro"),
                SandboxMount::Writable { host, path } => (json!(host), path, "bind", "rw"),
                SandboxMount::Private { path } => (json!("tmpfs"), path, "tmpfs", "mode=755"),
            };
            assert_eq!(mount["destination"], json!(path));
            assert_eq!(mount["source"], source);
            assert_eq!(mount["type"], kind);
            assert!(
                mount["options"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(access)),
                "{mount}"
            );
        }
        let writable: Vec<&Value> = mounts
            .iter()
            .filter(|mount| mount["options"].as_array().unwrap().contains(&json!("rw")))
            .collect();
        assert_eq!(
            writable,
            [
                &json!({"destination": "/work", "type": "bind", "source": "/host/tasks/t/a",
                    "options": ["rbind", "rw", "nosuid", "nodev"]}),
                &json!({"destination": "/run/ward/proxy.sock", "type": "bind",
                    "source": "/host/a.egress/proxy.sock",
                    "options": ["rbind", "rw", "nosuid", "nodev"]}),
            ],
            "the workspace and the proxy socket are the only writable host paths"
        );
    }

    #[test]
    fn a_bundle_sits_beside_its_workspace_and_names_its_container_after_the_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("exec_01ABC");
        assert_eq!(
            capsule_dir_beside(&workspace).unwrap(),
            dir.path().join("exec_01ABC.capsule")
        );
        let bundle = Bundle::create(&capsule_dir_beside(&workspace).unwrap(), &plan()).unwrap();
        assert_eq!(bundle.id, "ward-exec_01ABC");
        assert_eq!(bundle.state(), dir.path().join("exec_01ABC.capsule/state"));
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&bundle.dir), 0o700);
        assert_eq!(mode(&bundle.dir.join("config.json")), 0o600);
        assert!(
            std::fs::read_dir(bundle.dir.join("rootfs"))
                .unwrap()
                .next()
                .is_none()
        );
        let written: Value =
            serde_json::from_slice(&std::fs::read(bundle.dir.join("config.json")).unwrap())
                .unwrap();
        assert_eq!(
            written,
            oci_config(&plan(), geteuid().as_raw(), getegid().as_raw())
        );
        assert!(
            Bundle::create(&bundle.dir, &plan()).is_err(),
            "a bundle is never reused"
        );

        for refused in ["exec_01ABC", ".capsule", "a b.capsule", "a/..capsule"] {
            assert!(Bundle::at(&dir.path().join(refused)).is_none(), "{refused}");
        }
        let shared = Launch::new("/tmp", vec!["true".into()])
            .host_network()
            .plan(Path::new("/tmp"));
        assert!(Bundle::create(&dir.path().join("other.capsule"), &shared).is_err());
        assert!(!dir.path().join("other.capsule").exists());
    }

    #[test]
    fn the_operators_runtime_is_refused_unless_it_is_a_trustworthy_runc() {
        let dir = tempfile::tempdir().unwrap();
        let refusal = |path: &Path| ContainerRuntime::verify(path, dir.path()).unwrap_err();
        assert_eq!(
            refusal(Path::new("runc")).refusal,
            RuntimeRefusal::NotAbsolute
        );
        assert!(matches!(
            refusal(&dir.path().join("missing")).refusal,
            RuntimeRefusal::Unreadable(_)
        ));
        assert_eq!(refusal(dir.path()).refusal, RuntimeRefusal::NotAFile);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink("/bin/true", &link).unwrap();
        assert_eq!(refusal(&link).refusal, RuntimeRefusal::NotAFile);
        let copy = |name: &str, mode: u32| {
            let path = dir.path().join(name);
            std::fs::copy("/bin/true", &path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        assert_eq!(
            refusal(&copy("writable", 0o775)).refusal,
            RuntimeRefusal::Writable
        );
        assert_eq!(
            refusal(&copy("plain", 0o644)).refusal,
            RuntimeRefusal::NotExecutable
        );
        let impostor = copy("impostor", 0o755);
        let error = refusal(&impostor);
        assert_eq!(error.refusal, RuntimeRefusal::NotRunc);
        assert_eq!(
            error.to_string(),
            format!(
                "container runtime {}: does not answer as runc",
                impostor.display()
            )
        );
        assert_eq!(
            RuntimeRefusal::NoSetpriv.to_string(),
            "needs /usr/bin/setpriv (util-linux)"
        );
        assert_eq!(
            RuntimeRefusal::Owner.to_string(),
            "owned by neither root nor the node's user"
        );
        assert_eq!(
            RuntimeRefusal::CannotRun.to_string(),
            "cannot run a container on this host"
        );
    }

    #[test]
    fn a_runc_that_runs_a_container_here_is_verified_and_leaves_nothing_behind() {
        let runc = Path::new("/usr/bin/runc");
        let dir = tempfile::tempdir().unwrap();
        let verified = runc.is_file()
            && Path::new(SETPRIV).is_file()
            && ContainerRuntime::verify(runc, dir.path()).is_ok();
        if !ward_sandbox::ci::container_ready(verified, "runc running a container as this user") {
            return;
        }
        let runtime = ContainerRuntime::verify(runc, dir.path()).unwrap();
        assert_eq!(runtime.path(), runc);
        assert_eq!(runtime.rootless(), !geteuid().is_root());
        assert_eq!(
            RuncLauncher::new(Arc::new(runtime)).descriptor(),
            if geteuid().is_root() {
                CapsuleBackendDescriptor::RUNC
            } else {
                CapsuleBackendDescriptor::RUNC_ROOTLESS
            }
        );
        assert!(
            std::fs::read_dir(dir.path()).unwrap().next().is_none(),
            "the probe container and its bundle are gone"
        );
    }
}
