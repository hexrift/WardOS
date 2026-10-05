//! Per-attempt cgroups (#260): resource limits and accounting on an attempt's whole
//! process tree.
//!
//! A node started with a cgroup root (`ward-node --cgroup-root <dir>`) runs every attempt
//! in a cgroup of its own, `<dir>/<attempt>`, created before the spawn and removed once the
//! workload has been reaped. The directory must be on a cgroup v2 filesystem and writable
//! by the node's uid: a subtree the operator delegated to the node (for systemd,
//! `Delegate=yes` with the node's own process in a sub-cgroup, `DelegateSubgroup=`), with
//! no process of its own. At start the node enables, in the root's
//! `cgroup.subtree_control`, those of the `cpu`, `memory` and `pids` controllers the root
//! offers ([`CgroupRoot::enforces`]); the capability document reports exactly those
//! (`resources`), and a manifest asking for a limit whose controller is missing is refused
//! `unsupported_grant` at `admit`. The node also kills and removes every attempt cgroup a
//! previous run left behind, so no workload outlives a node restart in its cgroup.
//!
//! The launch moves itself into the attempt's cgroup before `bwrap` is executed
//! (`ward_launch::Launch::cgroup`), so bubblewrap and every process of the sandbox are
//! created inside it; the sandbox has no cgroup filesystem and cannot leave. Limits are
//! written before the spawn, in the kernel's spelling ([`limit_writes`]): `cpu.max`,
//! `memory.max` with `memory.swap.max` `0` (where the kernel accounts swap) and
//! `memory.oom.group` `1` (the whole tree is killed together when it passes the limit),
//! and `pids.max`. A limit that cannot be written refuses the spawn with nothing run.
//!
//! When the workload has been reaped the node kills whatever is still in the cgroup
//! (`cgroup.kill`, or `SIGKILL` to each member on a kernel without it), reads the kernel's
//! counters ([`read_usage`]: `cpu.stat`, `memory.peak`, `pids.peak`, `memory.events`,
//! `pids.events`) and removes the cgroup. The counters are the attempt's accounting,
//! recorded in its task record and evidence log.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use ward_events::{ExecutionAttemptId, NodeResourceUsage};
use ward_node_protocol::{NodeCapacity, ResourceCapabilities, ResourceGrant};

use crate::execution::{
    LaunchRequest, RunningWorkload, SandboxLauncher, SpawnError, StopSignal, TaskLauncher,
    WorkloadEnd, WorkloadFreezer, WorkloadProcess,
};

/// How long releasing an attempt's cgroup waits for its last process to be gone.
const RELEASE_SETTLE: Duration = Duration::from_secs(2);

/// The controllers the node can enforce limits through, as the kernel names them.
const CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

/// Why a cgroup root or an attempt's cgroup is unusable.
#[derive(Debug, Error)]
pub enum CgroupError {
    /// The directory is not on a cgroup v2 filesystem.
    #[error("{0} is not a cgroup v2 directory")]
    NotCgroup2(PathBuf),
    /// A controller the root offers could not be enabled for the node's attempts.
    #[error("cannot enable the {controller} controller under {dir}: {source}")]
    Delegation {
        /// The cgroup root.
        dir: PathBuf,
        /// The controller.
        controller: &'static str,
        /// Why.
        source: std::io::Error,
    },
    /// Cgroup filesystem I/O failed.
    #[error("cgroup {path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
}

impl CgroupError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// What a node enforces on an attempt's process tree and the host ceilings it holds
/// grants to: set on a node that runs attempts in cgroups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceEnforcement {
    enforces: ResourceCapabilities,
    capacity: NodeCapacity,
}

impl ResourceEnforcement {
    /// Enforce the limits `enforces` names, up to the host's `capacity`.
    #[must_use]
    pub const fn new(enforces: ResourceCapabilities, capacity: NodeCapacity) -> Self {
        Self { enforces, capacity }
    }

    /// Which limits the node enforces.
    #[must_use]
    pub const fn enforces(&self) -> ResourceCapabilities {
        self.enforces
    }

    /// Whether the node honours `grant`: every limit it names enforced, within the host's
    /// ceilings.
    #[must_use]
    pub fn honours(&self, grant: &ResourceGrant) -> bool {
        self.enforces.enforces(grant) && grant.within_ceilings(self.capacity)
    }
}

/// The cgroup v2 directory the node runs its attempts under.
#[derive(Debug)]
pub struct CgroupRoot {
    dir: PathBuf,
    enforces: ResourceCapabilities,
}

impl CgroupRoot {
    /// Open `dir` as the node's cgroup root: refuse anything but a cgroup v2 directory,
    /// enable the `cpu`, `memory` and `pids` controllers it offers for the attempts under
    /// it, and kill and remove every attempt cgroup a previous run left there.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupError::NotCgroup2`] for a directory on another filesystem,
    /// [`CgroupError::Delegation`] when an offered controller cannot be enabled (the
    /// directory holds processes of its own, or is not writable), and
    /// [`CgroupError::Io`] when it cannot be read or no cgroup can be created under it.
    pub fn open(dir: &Path) -> Result<Self, CgroupError> {
        let statfs = nix::sys::statfs::statfs(dir)
            .map_err(|errno| CgroupError::io(dir, std::io::Error::from(errno)))?;
        if statfs.filesystem_type() != nix::sys::statfs::CGROUP2_SUPER_MAGIC {
            return Err(CgroupError::NotCgroup2(dir.to_path_buf()));
        }
        let offered = read_words(&dir.join("cgroup.controllers"))
            .ok_or_else(|| CgroupError::io(dir, std::io::ErrorKind::NotFound.into()))?;
        let subtree = dir.join("cgroup.subtree_control");
        for controller in CONTROLLERS {
            if offered.iter().any(|word| word == controller) {
                std::fs::write(&subtree, format!("+{controller}")).map_err(|source| {
                    CgroupError::Delegation {
                        dir: dir.to_path_buf(),
                        controller,
                        source,
                    }
                })?;
            }
        }
        let enabled = read_words(&subtree).unwrap_or_default();
        let has = |controller: &str| enabled.iter().any(|word| word == controller);
        let root = Self {
            dir: dir.to_path_buf(),
            enforces: ResourceCapabilities {
                cpu: has("cpu"),
                memory: has("memory"),
                pids: has("pids"),
            },
        };
        root.sweep()?;
        let probe = dir.join(format!("ward-node-probe-{}", std::process::id()));
        std::fs::create_dir(&probe).map_err(|error| CgroupError::io(&probe, error))?;
        std::fs::remove_dir(&probe).map_err(|error| CgroupError::io(&probe, error))?;
        Ok(root)
    }

    /// The root directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Which limits the node can enforce under this root.
    #[must_use]
    pub const fn enforces(&self) -> ResourceCapabilities {
        self.enforces
    }

    /// Kill and remove every attempt cgroup (named `exec_…`) under the root: what a previous
    /// run of the node left behind.
    fn sweep(&self) -> Result<(), CgroupError> {
        let entries =
            std::fs::read_dir(&self.dir).map_err(|error| CgroupError::io(&self.dir, error))?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let is_attempt = name
                .to_str()
                .is_some_and(|name| name.parse::<ExecutionAttemptId>().is_ok());
            if is_attempt && entry.path().is_dir() {
                release(&entry.path());
            }
        }
        Ok(())
    }

    /// Create the cgroup of the attempt whose workspace is `workspace` (named after the
    /// attempt id) and write the limits `grant` names into it.
    fn create(
        &self,
        workspace: &Path,
        grant: Option<&ResourceGrant>,
    ) -> Result<AttemptCgroup, CgroupError> {
        let name = workspace
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| name.parse::<ExecutionAttemptId>().is_ok())
            .ok_or_else(|| CgroupError::io(workspace, std::io::ErrorKind::InvalidInput.into()))?;
        let dir = self.dir.join(name);
        if dir.exists() {
            release(&dir);
        }
        std::fs::create_dir(&dir).map_err(|error| CgroupError::io(&dir, error))?;
        let cgroup = AttemptCgroup {
            dir,
            grant: grant.copied(),
        };
        if let Some(grant) = grant {
            for (file, value) in limit_writes(grant) {
                let path = cgroup.dir.join(file);
                write_existing(&path, &value).map_err(|error| CgroupError::io(&path, error))?;
            }
            if grant.memory_bytes().is_some() {
                for (file, value) in [("memory.swap.max", "0"), ("memory.oom.group", "1")] {
                    let path = cgroup.dir.join(file);
                    if path.exists() {
                        write_existing(&path, value)
                            .map_err(|error| CgroupError::io(&path, error))?;
                    }
                }
            }
        }
        Ok(cgroup)
    }
}

/// One attempt's cgroup, removed (with anything still in it killed) when dropped.
#[derive(Debug)]
struct AttemptCgroup {
    dir: PathBuf,
    grant: Option<ResourceGrant>,
}

impl AttemptCgroup {
    /// Kill whatever is still in the cgroup, then read what the tree used.
    fn finish(&self) -> NodeResourceUsage {
        kill_members(&self.dir);
        settle(&self.dir);
        read_usage(&self.dir, self.grant.as_ref())
    }
}

impl Drop for AttemptCgroup {
    fn drop(&mut self) {
        release(&self.dir);
    }
}

/// The files and values that set the limits `grant` names, in the kernel's spelling:
/// `cpu.max` as quota and period in microseconds (a 100 ms period, stretched to one second
/// when the quota would fall below the kernel's 1 ms minimum), `memory.max` in bytes and
/// `pids.max` as a count.
#[must_use]
pub fn limit_writes(grant: &ResourceGrant) -> Vec<(&'static str, String)> {
    let mut writes = Vec::new();
    if let Some(cpu_millis) = grant.cpu_millis() {
        let (quota, period) = if cpu_millis >= 10 {
            (cpu_millis.saturating_mul(100), 100_000)
        } else {
            (cpu_millis.saturating_mul(1000), 1_000_000)
        };
        writes.push(("cpu.max", format!("{quota} {period}")));
    }
    if let Some(memory) = grant.memory_bytes() {
        writes.push(("memory.max", memory.to_string()));
    }
    if let Some(pids) = grant.pids() {
        writes.push(("pids.max", pids.to_string()));
    }
    writes
}

/// What the tree in cgroup `dir` used, from the kernel's counters, beside the limits
/// `grant` set. A counter the kernel does not provide reads `None`.
#[must_use]
pub fn read_usage(dir: &Path, grant: Option<&ResourceGrant>) -> NodeResourceUsage {
    let read = |file: &str| std::fs::read_to_string(dir.join(file)).ok();
    let number = |file: &str| read(file).and_then(|text| text.trim().parse::<u64>().ok());
    let keyed = |file: &str, key: &str| {
        read(file).and_then(|text| {
            text.lines().find_map(|line| {
                let (name, value) = line.split_once(' ')?;
                (name == key).then(|| value.trim().parse::<u64>().ok())?
            })
        })
    };
    NodeResourceUsage {
        cpu_millis_limit: grant.and_then(ResourceGrant::cpu_millis),
        memory_limit_bytes: grant.and_then(ResourceGrant::memory_bytes),
        pids_limit: grant.and_then(ResourceGrant::pids),
        cpu_usage_usec: keyed("cpu.stat", "usage_usec"),
        memory_peak_bytes: number("memory.peak"),
        pids_peak: number("pids.peak"),
        memory_oom_kills: keyed("memory.events", "oom_kill"),
        pids_max_events: keyed("pids.events", "max"),
    }
}

fn read_words(path: &Path) -> Option<Vec<String>> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.split_whitespace().map(str::to_owned).collect())
}

/// Write `value` to an existing cgroup file; never creates one.
fn write_existing(path: &Path, value: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .write_all(value.as_bytes())
}

/// Kill every process in cgroup `dir`: `cgroup.kill` where the kernel has it, otherwise
/// `SIGKILL` to each member listed in `cgroup.procs`.
fn kill_members(dir: &Path) {
    if write_existing(&dir.join("cgroup.kill"), "1").is_ok() {
        return;
    }
    for pid in members(dir) {
        if let Ok(pid) = i32::try_from(pid) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
}

fn members(dir: &Path) -> Vec<u32> {
    std::fs::read_to_string(dir.join("cgroup.procs"))
        .map(|text| {
            text.lines()
                .filter_map(|line| line.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Wait, a bounded time, until cgroup `dir` holds no process, killing late arrivals.
fn settle(dir: &Path) {
    let deadline = Instant::now() + RELEASE_SETTLE;
    while !members(dir).is_empty() && Instant::now() < deadline {
        kill_members(dir);
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Kill everything in cgroup `dir` and remove it; best effort, bounded.
fn release(dir: &Path) {
    kill_members(dir);
    settle(dir);
    let deadline = Instant::now() + RELEASE_SETTLE;
    while std::fs::remove_dir(dir).is_err() && dir.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The bubblewrap launcher, running every attempt in a cgroup of its own under a
/// [`CgroupRoot`] and measuring it once reaped.
#[derive(Clone, Debug)]
pub struct CgroupLauncher {
    root: Arc<CgroupRoot>,
}

impl CgroupLauncher {
    /// Launch under `root`.
    #[must_use]
    pub const fn new(root: Arc<CgroupRoot>) -> Self {
        Self { root }
    }
}

impl TaskLauncher for CgroupLauncher {
    fn launch(&self, request: &LaunchRequest) -> Result<Box<dyn RunningWorkload>, SpawnError> {
        let cgroup = self
            .root
            .create(request.workspace(), request.resources())
            .map_err(|_| SpawnError::Refused)?;
        let workload = SandboxLauncher::launch_in(request, Some(&cgroup.dir))?;
        Ok(Box::new(CgroupWorkload { workload, cgroup }))
    }

    fn end_survivor(&self, process: &WorkloadProcess) {
        SandboxLauncher.end_survivor(process);
    }
}

/// A sandboxed workload and the cgroup it runs in.
struct CgroupWorkload {
    workload: Box<dyn RunningWorkload>,
    cgroup: AttemptCgroup,
}

impl RunningWorkload for CgroupWorkload {
    fn pid(&self) -> u32 {
        self.workload.pid()
    }

    fn process(&self) -> Option<WorkloadProcess> {
        self.workload.process()
    }

    fn freezer(&self) -> Arc<dyn WorkloadFreezer> {
        self.workload.freezer()
    }

    fn egress(&self) -> Option<Arc<crate::egress::AttemptEgress>> {
        self.workload.egress()
    }

    fn wait(self: Box<Self>, stop: &StopSignal, on_tick: &mut dyn FnMut()) -> WorkloadEnd {
        let Self { workload, cgroup } = *self;
        let mut end = workload.wait(stop, on_tick);
        end.usage = Some(cgroup.finish());
        drop(cgroup);
        end
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use ward_node_protocol::{ResourceCapabilities, ResourceGrant};

    use super::*;
    use crate::execution::{LaunchRequest, StopSignal, TaskLauncher, WorkloadExit};

    #[test]
    fn limits_are_written_in_the_kernel_spelling() {
        let grant = ResourceGrant::new(Some(250), Some(64 * 1024 * 1024), Some(32)).unwrap();
        assert_eq!(
            limit_writes(&grant),
            vec![
                ("cpu.max", "25000 100000".to_owned()),
                ("memory.max", "67108864".to_owned()),
                ("pids.max", "32".to_owned()),
            ]
        );
        assert_eq!(
            limit_writes(&ResourceGrant::new(Some(5), None, None).unwrap()),
            vec![("cpu.max", "5000 1000000".to_owned())],
            "below the kernel's 1 ms quota the period stretches to one second"
        );
        assert_eq!(
            limit_writes(&ResourceGrant::new(Some(4000), None, None).unwrap()),
            vec![("cpu.max", "400000 100000".to_owned())]
        );
    }

    #[test]
    fn usage_is_read_from_the_kernel_counters_and_missing_ones_are_none() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, text: &str| std::fs::write(dir.path().join(name), text).unwrap();
        write(
            "cpu.stat",
            "usage_usec 1234567\nuser_usec 1000000\nsystem_usec 234567\n",
        );
        write("memory.peak", "52428800\n");
        write("pids.peak", "17\n");
        write(
            "memory.events",
            "low 0\nhigh 0\nmax 12\noom 1\noom_kill 1\noom_group_kill 1\n",
        );
        write("pids.events", "max 3\n");
        let limits = ResourceGrant::new(None, Some(64 * 1024 * 1024), Some(16)).unwrap();
        assert_eq!(
            read_usage(dir.path(), Some(&limits)),
            NodeResourceUsage {
                cpu_millis_limit: None,
                memory_limit_bytes: Some(64 * 1024 * 1024),
                pids_limit: Some(16),
                cpu_usage_usec: Some(1_234_567),
                memory_peak_bytes: Some(52_428_800),
                pids_peak: Some(17),
                memory_oom_kills: Some(1),
                pids_max_events: Some(3),
            }
        );
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(read_usage(empty.path(), None), NodeResourceUsage::default());
    }

    #[test]
    fn a_directory_that_is_not_cgroup2_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            CgroupRoot::open(dir.path()),
            Err(CgroupError::NotCgroup2(_))
        ));
        assert!(CgroupRoot::open(Path::new("/nonexistent/ward-cgroup")).is_err());
    }

    /// A writable cgroup v2 directory to run real attempts under: `WARD_NODE_CGROUP_ROOT`,
    /// or a fresh child of the host's cgroup2 mount when this process may create one (root,
    /// or a delegated subtree). `None`, with the reason printed, when there is none.
    fn delegated_cgroup(test: &str) -> Option<PathBuf> {
        let parent = std::env::var_os("WARD_NODE_CGROUP_ROOT")
            .map(PathBuf::from)
            .or_else(cgroup2_mount)?;
        let dir = parent.join(format!("ward-node-unit-{}-{test}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => Some(dir),
            Err(error) => {
                eprintln!("skipping {test}: no writable cgroup v2 directory ({error})");
                None
            }
        }
    }

    fn cgroup2_mount() -> Option<PathBuf> {
        let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
        mounts.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            let (_, path, kind) = (fields.next()?, fields.next()?, fields.next()?);
            (kind == "cgroup2").then(|| PathBuf::from(path))
        })
    }

    #[test]
    fn a_real_attempt_runs_in_its_own_cgroup_is_measured_and_its_cgroup_removed() {
        if !ward_launch::available() {
            return;
        }
        let Some(dir) = delegated_cgroup("measured") else {
            return;
        };
        let root = CgroupRoot::open(&dir).unwrap();
        let work = tempfile::tempdir().unwrap();
        let workspace = work
            .path()
            .join(ward_events::ExecutionAttemptId::from_u128(0x5eed).to_string());
        std::fs::create_dir(&workspace).unwrap();
        let launcher = CgroupLauncher::new(std::sync::Arc::new(root));
        let request = LaunchRequest::new(
            workspace.clone(),
            vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done; cat /proc/self/cgroup > seen"
                    .to_owned(),
            ],
            Duration::from_secs(30),
        );
        let workload = launcher.launch(&request).unwrap();
        let attempt_cgroup = dir.join(workspace.file_name().unwrap());
        assert!(attempt_cgroup.is_dir());
        let end = workload.wait(&StopSignal::default(), &mut || {});
        assert_eq!(end.exit, WorkloadExit::Exited { code: Some(0) });
        let usage = end.usage.expect("an attempt run in a cgroup is measured");
        assert!(
            usage.cpu_usage_usec.is_some_and(|usec| usec > 0),
            "{usage:?}"
        );
        assert_eq!(usage.memory_limit_bytes, None);
        assert!(
            !attempt_cgroup.exists(),
            "the attempt's cgroup is removed once reaped"
        );
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn a_pids_limit_holds_the_whole_tree_at_its_bound() {
        if !ward_launch::available() {
            return;
        }
        let Some(dir) = delegated_cgroup("pids") else {
            return;
        };
        let root = CgroupRoot::open(&dir).unwrap();
        if !root.enforces().pids {
            eprintln!(
                "skipping a_pids_limit_holds_the_whole_tree_at_its_bound: no pids controller"
            );
            let _ = std::fs::remove_dir(&dir);
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let workspace = work
            .path()
            .join(ward_events::ExecutionAttemptId::from_u128(0x919).to_string());
        std::fs::create_dir(&workspace).unwrap();
        let launcher = CgroupLauncher::new(std::sync::Arc::new(root));
        let request = LaunchRequest::new(
            workspace,
            vec![
                "sh".to_owned(),
                "-c".to_owned(),
                "for i in $(seq 1 64); do sleep 5 & done 2>/dev/null; wait".to_owned(),
            ],
            Duration::from_secs(30),
        )
        .with_resources(ResourceGrant::new(None, None, Some(8)).unwrap());
        let end = launcher
            .launch(&request)
            .unwrap()
            .wait(&StopSignal::default(), &mut || {});
        let usage = end.usage.unwrap();
        assert_eq!(usage.pids_limit, Some(8));
        assert!(usage.pids_peak.is_none_or(|peak| peak <= 8), "{usage:?}");
        assert!(
            usage.pids_max_events.is_some_and(|hits| hits > 0),
            "{usage:?}"
        );
        let _ = ResourceCapabilities::default();
        let _ = std::fs::remove_dir(&dir);
    }
}
