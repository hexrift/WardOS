//! Node-owned execution of admitted tasks (ADR-0030 §3–§6).
//!
//! The registry ([`crate::task`]) never spawns a process itself. It asks a
//! [`TaskLauncher`] for one, on a node-owned reaper thread per attempt that then waits on
//! the returned [`RunningWorkload`] and records how it ended. The port keeps the state
//! machine testable without a sandbox; [`SandboxLauncher`] is the real implementation over
//! the bubblewrap primitive in `ward-launch`.
//!
//! A launch is built only from node-owned state: the workspace the node allocated under
//! its task root ([`crate::workspace`]), the admitted envelope's argv, its mandatory
//! wall-clock budget, the host allowlist its manifest names, if any, and the output grant
//! its manifest carries, if any ([`LaunchRequest::output`]): the launcher then keeps
//! exactly the first `stdio_bytes` of each stream raw ([`WorkloadEnd::stdio`]) for the
//! reaper to return ([`crate::output`]), and still drains the rest. The sandbox's
//! network namespace always holds only loopback. An offline manifest binds no egress
//! socket. A `custom` manifest, which `admit` ([`crate::admit`]) accepts only on a node
//! built [`NodeExecution::with_network_allowlist`], binds the attempt's own egress proxy
//! ([`crate::egress`]) at [`ward_launch::PROXY_SOCKET`], named in
//! [`crate::egress::PROXY_SOCKET_ENV`], with a policy of exactly the manifest's hosts; the
//! node never runs a workload under less, or more, than its manifest asked for.
//!
//! `pause` and `resume` act on the running workload through its [`WorkloadFreezer`], which
//! the reaper hands back with the spawned pid. The sandbox freezer first pauses the
//! attempt's egress proxy, if there is one, so no new connection is served while the tree
//! is stopped, then stops the tree rooted at the outer `bwrap`'s host pid with `SIGSTOP`,
//! children first, and reports it frozen only once the settle check in
//! `ward_launch::freeze` confirms every process stopped (or ended, or held in vfork wait on
//! a stopped child) within [`DEFAULT_FREEZE_SETTLE`]; otherwise it continues the tree and
//! the proxy again and refuses. Resuming sends `SIGCONT`, parents first, confirms nothing
//! is still stopped, and then resumes the proxy. There is no cgroup freezer, also on a node
//! whose launcher runs attempts in cgroups ([`crate::cgroup::CgroupLauncher`]): those
//! cgroups carry limits and accounting only. The budget clock keeps running while a workload is
//! paused (ADR-0030 §3: the budget is always enforced), and `SIGKILL` ends a stopped
//! process as it is, so a paused workload can still be stopped or killed at its budget.
//!
//! Each spawned workload reports the host process it runs as ([`WorkloadProcess`]): its
//! pid, the start time `/proc` gives it and the boot it started in. The registry records it
//! durably, and after a node restart asks the launcher to end any survivor
//! ([`TaskLauncher::end_survivor`]). The sandbox launcher kills, with `SIGKILL`, the tree
//! still rooted at a process with exactly that identity, stopped processes included, and
//! never signals a pid that now names another process or one from an earlier boot. The
//! egress proxy runs on threads of the node process and ends with it, so a restart leaves
//! no proxy behind; a socket file left in the attempt's egress directory is inert.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ward_events::NodeResourceUsage;
use ward_launch::freeze::{FrozenTree, TreeRoot, freeze_tree, kill_tree, thaw_tree};
use ward_launch::{ACTION_SOCKET, Launch, PROXY_SOCKET, RunningLaunch};
use ward_node_protocol::{HostAllowlist, MAX_OUTPUT_STDIO_BYTES, OutputGrant, ResourceGrant};
use ward_snapshot::SnapshotStore;

use crate::actions::ACTION_SOCKET_ENV;
use crate::cgroup::ResourceEnforcement;
use crate::egress::{AttemptEgress, PROXY_SOCKET_ENV, egress_dir_beside};
use crate::output::{CapturedStdio, CapturedStream};
use crate::scheduling::SchedulingLimits;
use crate::workspace::TaskRoot;

/// Default bound on how long `stop` waits for the reaper to confirm the kill and reap.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default bound on how long `start` waits for the launcher to report a spawn.
pub const DEFAULT_SPAWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Default bound on how long `pause` waits for a freeze, and `resume` for a thaw, to be
/// confirmed.
pub const DEFAULT_FREEZE_SETTLE: Duration = ward_launch::freeze::FREEZE_SETTLE;

/// Bound on how long ending a survivor of a node restart waits for its tree to die.
pub const DEFAULT_SURVIVOR_SETTLE: Duration = ward_launch::freeze::FREEZE_SETTLE;

/// Where the host's boot id is read: it changes at every boot.
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// Bytes of each workload output stream the sandbox launcher retains (a head and a tail)
/// before discarding it. Output is drained so a chatty workload never blocks on a pipe.
pub const OUTPUT_CAPTURE_BYTES: usize = 64 * 1024;

/// One workload launch, built only from node-owned state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchRequest {
    workspace: PathBuf,
    argv: Vec<String>,
    budget: Duration,
    allowlist: Option<HostAllowlist>,
    output: Option<OutputGrant>,
    resources: Option<ResourceGrant>,
    action_socket: Option<PathBuf>,
}

impl LaunchRequest {
    /// A launch of `argv` over the node-allocated `workspace`, killed at `budget`, offline.
    #[must_use]
    pub const fn new(workspace: PathBuf, argv: Vec<String>, budget: Duration) -> Self {
        Self {
            workspace,
            argv,
            budget,
            allowlist: None,
            output: None,
            resources: None,
            action_socket: None,
        }
    }

    /// The same launch behind an egress proxy allowing exactly `allowlist`.
    #[must_use]
    pub fn with_allowlist(mut self, allowlist: HostAllowlist) -> Self {
        self.allowlist = Some(allowlist);
        self
    }

    /// The same launch keeping the output `output` asks for.
    #[must_use]
    pub fn with_output(mut self, output: OutputGrant) -> Self {
        self.output = Some(output);
        self
    }

    /// The same launch with the cgroup limits `resources` asks for, which only a launcher
    /// running attempts in cgroups ([`crate::cgroup::CgroupLauncher`]) enforces; `admit`
    /// accepts such a manifest only on a node built with one.
    #[must_use]
    pub const fn with_resources(mut self, resources: ResourceGrant) -> Self {
        self.resources = Some(resources);
        self
    }

    /// The limits the admitted manifest asked for; `None` when it asked for none.
    #[must_use]
    pub const fn resources(&self) -> Option<&ResourceGrant> {
        self.resources.as_ref()
    }

    /// The same launch with the attempt's action channel socket, a host path, bound into
    /// the sandbox at [`ward_launch::ACTION_SOCKET`] and named in
    /// [`crate::actions::ACTION_SOCKET_ENV`].
    #[must_use]
    pub fn with_action_socket(mut self, socket: PathBuf) -> Self {
        self.action_socket = Some(socket);
        self
    }

    /// The host path of the attempt's action channel socket; `None` without an `actions`
    /// grant.
    #[must_use]
    pub fn action_socket(&self) -> Option<&Path> {
        self.action_socket.as_deref()
    }

    /// The output grant the admitted manifest carried; `None` when nothing is returned.
    #[must_use]
    pub const fn output(&self) -> Option<&OutputGrant> {
        self.output.as_ref()
    }

    /// The host allowlist the admitted manifest named; `None` for an offline workload.
    #[must_use]
    pub const fn allowlist(&self) -> Option<&HostAllowlist> {
        self.allowlist.as_ref()
    }

    /// The node-allocated workspace bound writable into the sandbox.
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// The admitted argv.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The admitted wall-clock budget, measured from spawn.
    #[must_use]
    pub const fn budget(&self) -> Duration {
        self.budget
    }
}

/// Why a launch produced no running workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnError {
    /// Nothing was spawned: the attempt can be refused with no state change.
    Refused,
    /// A process may have started before the failure. The launcher has killed and reaped
    /// what it could; the attempt is ambiguous and is never re-run (ADR-0030 §6).
    Ambiguous,
}

/// How a running workload ended, as its reaper observed it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WorkloadExit {
    /// The workload ended on its own; `None` when a signal the node did not send ended it.
    Exited {
        /// The exit status code.
        code: Option<i32>,
    },
    /// The node killed the workload at its wall-clock budget.
    BudgetExceeded,
    /// The node killed and reaped the workload because a stop was requested.
    Stopped,
    /// The node lost track of the workload; what happened cannot be established.
    #[default]
    Lost,
}

/// How a workload ended and what of its stdio the launcher kept for the reaper.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkloadEnd {
    /// How it ended.
    pub exit: WorkloadExit,
    /// The head of each stream, up to the launch's output grant, and the full byte counts;
    /// empty when the launch had no output grant.
    pub stdio: CapturedStdio,
    /// What the workload's process tree used, measured from the cgroup it ran in; `None`
    /// when the launcher runs workloads in no cgroup of their own.
    pub usage: Option<NodeResourceUsage>,
}

/// A request to stop one running workload, shared by `stop`, its reaper and node shutdown.
#[derive(Clone, Debug, Default)]
pub struct StopSignal(Arc<AtomicBool>);

impl StopSignal {
    /// Ask the workload to stop; its reaper kills and reaps it.
    pub fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether a stop was requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The host process a workload was spawned as, identified by its pid, the start time
/// `/proc` reports for it and the boot it started in, so that neither a pid reused later
/// nor one from an earlier boot is ever taken for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadProcess {
    pid: u32,
    start_time: u64,
    boot: String,
}

impl WorkloadProcess {
    /// The process `pid`, started at `start_time` (clock ticks since boot) during `boot`.
    #[must_use]
    pub const fn new(pid: u32, start_time: u64, boot: String) -> Self {
        Self {
            pid,
            start_time,
            boot,
        }
    }

    /// The host pid.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// The start time `/proc` reported, in clock ticks since boot.
    #[must_use]
    pub const fn start_time(&self) -> u64 {
        self.start_time
    }

    /// The boot id of the boot the process started in.
    #[must_use]
    pub fn boot(&self) -> &str {
        &self.boot
    }
}

/// The launch port: spawns one workload.
///
/// The registry calls it on the attempt's own reaper thread, which then waits on the
/// result for as long as the workload runs.
pub trait TaskLauncher: Send + Sync {
    /// Spawn the workload `request` describes.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::Refused`] when nothing was spawned, and
    /// [`SpawnError::Ambiguous`] when a process may have started.
    fn launch(&self, request: &LaunchRequest) -> Result<Box<dyn RunningWorkload>, SpawnError>;

    /// End whatever still runs of a workload spawned as `process` by a node that has since
    /// restarted, and wait a bounded time for it to die. A process that no longer has
    /// exactly that identity is never signalled.
    fn end_survivor(&self, process: &WorkloadProcess);
}

/// A freeze or thaw of a workload's process tree that could not be confirmed. A failed
/// freeze has already continued whatever it stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreezeUnconfirmed;

/// Stops and continues one running workload's process tree (`pause` and `resume`).
///
/// The registry calls it under its lock, so calls for one workload never overlap.
pub trait WorkloadFreezer: Send + Sync + std::fmt::Debug {
    /// Stop every process of the workload and confirm it.
    ///
    /// # Errors
    ///
    /// Returns [`FreezeUnconfirmed`] if the freeze could not be confirmed; the workload
    /// then runs as before.
    fn freeze(&self) -> Result<(), FreezeUnconfirmed>;

    /// Continue every process frozen by [`Self::freeze`] and confirm none is still stopped.
    ///
    /// # Errors
    ///
    /// Returns [`FreezeUnconfirmed`] if that could not be confirmed.
    fn thaw(&self) -> Result<(), FreezeUnconfirmed>;
}

/// A spawned workload, owned by its reaper. Dropping it kills and reaps it.
pub trait RunningWorkload: Send {
    /// The host process id of the spawned workload.
    fn pid(&self) -> u32;

    /// The host process the workload runs as, if `/proc` identifies it.
    fn process(&self) -> Option<WorkloadProcess>;

    /// The freezer for this workload's process tree, shared with the registry.
    fn freezer(&self) -> Arc<dyn WorkloadFreezer>;

    /// The egress proxy this workload runs behind, if its manifest named an allowlist.
    fn egress(&self) -> Option<Arc<AttemptEgress>> {
        None
    }

    /// Wait until the workload ends, enforcing its budget, and kill and reap it as soon as
    /// `stop` is requested, calling `on_tick` between waits while it runs. Hands back the
    /// stdio the launch's output grant asked to keep.
    fn wait(self: Box<Self>, stop: &StopSignal, on_tick: &mut dyn FnMut()) -> WorkloadEnd;
}

/// The bubblewrap launcher: an offline sandbox over the workspace (`ward-launch`).
///
/// `bwrap` runs with `--die-with-parent` and is spawned from the attempt's reaper thread,
/// which lives exactly as long as the workload, so the sandbox dies with the node instead
/// of outliving it. Bubblewrap arms that only once it runs, so a node killed, or a stop
/// served, in the few milliseconds between a spawn and the sandbox's own setup can leave
/// that sandbox's inner process tree behind after the outer `bwrap` is reaped. Closing the
/// window needs a kill by cgroup or by process tree.
#[derive(Clone, Copy, Debug, Default)]
pub struct SandboxLauncher;

impl SandboxLauncher {
    /// Whether a real sandbox can run on this host.
    #[must_use]
    pub fn available() -> bool {
        ward_launch::available()
    }
}

impl SandboxLauncher {
    /// Launch `request`, inside the cgroup directory `cgroup` when one is given (the
    /// launch moves itself there before `bwrap` runs, [`ward_launch::Launch::cgroup`]).
    pub(crate) fn launch_in(
        request: &LaunchRequest,
        cgroup: Option<&Path>,
    ) -> Result<Box<dyn RunningWorkload>, SpawnError> {
        let egress = request
            .allowlist()
            .map(|allowlist| {
                let dir = egress_dir_beside(request.workspace()).ok_or(SpawnError::Refused)?;
                AttemptEgress::start(&dir, allowlist)
                    .map(Arc::new)
                    .map_err(|_| SpawnError::Refused)
            })
            .transpose()?;
        let launch = sandbox_launch(request, egress.as_deref().map(AttemptEgress::socket));
        let launch = match cgroup {
            Some(dir) => launch.cgroup(dir),
            None => launch,
        };
        let launch = launch.spawn().map_err(|_| SpawnError::Refused)?;
        Ok(Box::new(SandboxWorkload { launch, egress }))
    }
}

impl TaskLauncher for SandboxLauncher {
    fn launch(&self, request: &LaunchRequest) -> Result<Box<dyn RunningWorkload>, SpawnError> {
        Self::launch_in(request, None)
    }

    fn end_survivor(&self, process: &WorkloadProcess) {
        if current_boot().as_deref() == Some(process.boot()) {
            let _ = kill_tree(
                TreeRoot::recorded(process.pid(), process.start_time()),
                DEFAULT_SURVIVOR_SETTLE,
            );
        }
    }
}

fn current_boot() -> Option<String> {
    std::fs::read_to_string(BOOT_ID)
        .ok()
        .map(|boot| boot.trim().to_owned())
        .filter(|boot| !boot.is_empty())
}

fn sandbox_launch(request: &LaunchRequest, proxy_socket: Option<&Path>) -> Launch {
    let launch = Launch::new(request.workspace(), request.argv().to_vec())
        .budget(request.budget())
        .capture_bytes(OUTPUT_CAPTURE_BYTES)
        .clear_env();
    let launch = match request.output() {
        Some(output) => launch.raw_head(
            usize::try_from(output.stdio_bytes().min(MAX_OUTPUT_STDIO_BYTES)).unwrap_or(usize::MAX),
        ),
        None => launch,
    };
    let launch = match request.action_socket() {
        Some(socket) => launch.actions(socket).env(ACTION_SOCKET_ENV, ACTION_SOCKET),
        None => launch,
    };
    match proxy_socket {
        Some(socket) => launch.egress(socket).env(PROXY_SOCKET_ENV, PROXY_SOCKET),
        None => launch,
    }
}

struct SandboxWorkload {
    launch: RunningLaunch,
    egress: Option<Arc<AttemptEgress>>,
}

impl RunningWorkload for SandboxWorkload {
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
        Arc::new(SandboxFreezer {
            root: self.launch.tree_root(),
            frozen: Mutex::new(None),
            settle: DEFAULT_FREEZE_SETTLE,
            egress: self.egress.clone(),
        })
    }

    fn egress(&self) -> Option<Arc<AttemptEgress>> {
        self.egress.clone()
    }

    fn wait(self: Box<Self>, stop: &StopSignal, on_tick: &mut dyn FnMut()) -> WorkloadEnd {
        let Ok(outcome) = self
            .launch
            .wait_observed_stoppable(on_tick, &|| stop.is_requested())
        else {
            return WorkloadEnd::default();
        };
        let exit = if outcome.stopped {
            WorkloadExit::Stopped
        } else if outcome.timed_out {
            WorkloadExit::BudgetExceeded
        } else {
            WorkloadExit::Exited { code: outcome.code }
        };
        WorkloadEnd {
            exit,
            stdio: CapturedStdio {
                stdout: CapturedStream {
                    head: outcome.stdout_raw_head,
                    total: outcome.stdout_bytes,
                },
                stderr: CapturedStream {
                    head: outcome.stderr_raw_head,
                    total: outcome.stderr_bytes,
                },
            },
            usage: None,
        }
    }
}

/// Freezes a sandbox's process tree by signal, rooted at its outer `bwrap`, with its egress
/// proxy paused for as long as the tree is stopped.
#[derive(Debug)]
struct SandboxFreezer {
    root: Option<TreeRoot>,
    frozen: Mutex<Option<FrozenTree>>,
    settle: Duration,
    egress: Option<Arc<AttemptEgress>>,
}

impl SandboxFreezer {
    fn pause_egress(&self, paused: bool) {
        if let Some(egress) = &self.egress {
            egress.set_paused(paused);
        }
    }
}

impl WorkloadFreezer for SandboxFreezer {
    fn freeze(&self) -> Result<(), FreezeUnconfirmed> {
        let root = self.root.ok_or(FreezeUnconfirmed)?;
        let mut frozen = self.frozen.lock().map_err(|_| FreezeUnconfirmed)?;
        self.pause_egress(true);
        let tree = freeze_tree(root, self.settle).map_err(|_| {
            self.pause_egress(false);
            FreezeUnconfirmed
        })?;
        *frozen = Some(tree);
        Ok(())
    }

    fn thaw(&self) -> Result<(), FreezeUnconfirmed> {
        let mut frozen = self.frozen.lock().map_err(|_| FreezeUnconfirmed)?;
        let Some(tree) = frozen.as_ref() else {
            self.pause_egress(false);
            return Ok(());
        };
        if !thaw_tree(tree, self.settle) {
            return Err(FreezeUnconfirmed);
        }
        *frozen = None;
        self.pause_egress(false);
        Ok(())
    }
}

/// What a node needs to execute admitted tasks: its task root, its snapshot store and a
/// launcher. A node built with it advertises `start`, `stop`, `pause` and `revoke` together
/// at protocol 1.3, `network.proxy_allowlist` only when built
/// [`Self::with_network_allowlist`], and `output` only when built
/// [`Self::with_output_return`].
pub struct NodeExecution {
    task_root: TaskRoot,
    snapshots: SnapshotStore,
    launcher: Arc<dyn TaskLauncher>,
    stop_timeout: Duration,
    spawn_timeout: Duration,
    network_allowlist: bool,
    output_return: bool,
    scheduling: Option<SchedulingLimits>,
    resources: Option<ResourceEnforcement>,
    action_channel: bool,
}

impl std::fmt::Debug for NodeExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeExecution")
            .field("task_root", &self.task_root)
            .field("stop_timeout", &self.stop_timeout)
            .field("spawn_timeout", &self.spawn_timeout)
            .field("network_allowlist", &self.network_allowlist)
            .field("output_return", &self.output_return)
            .field("scheduling", &self.scheduling)
            .field("resources", &self.resources)
            .field("action_channel", &self.action_channel)
            .finish_non_exhaustive()
    }
}

impl NodeExecution {
    /// Execute under `task_root`, materialising from `snapshots`, spawning through
    /// `launcher`.
    #[must_use]
    pub fn new(
        task_root: TaskRoot,
        snapshots: SnapshotStore,
        launcher: Arc<dyn TaskLauncher>,
    ) -> Self {
        Self {
            task_root,
            snapshots,
            launcher,
            stop_timeout: DEFAULT_STOP_TIMEOUT,
            spawn_timeout: DEFAULT_SPAWN_TIMEOUT,
            network_allowlist: false,
            output_return: false,
            scheduling: None,
            resources: None,
            action_channel: false,
        }
    }

    /// Bound how many attempts execute at once and the host headroom `start` keeps
    /// ([`crate::scheduling`]); `None`, the default, bounds nothing and the node
    /// advertises no `scheduling` section.
    #[must_use]
    pub const fn with_scheduling(mut self, scheduling: Option<SchedulingLimits>) -> Self {
        self.scheduling = scheduling;
        self
    }

    /// The bound on attempts executing at once and the headroom `start` keeps, if any.
    #[must_use]
    pub const fn scheduling(&self) -> Option<SchedulingLimits> {
        self.scheduling
    }

    /// Honour a manifest's `resources` grant as `resources` says: only on a node whose
    /// launcher runs every attempt in a cgroup of its own
    /// ([`crate::cgroup::CgroupLauncher`]), which also measures each attempt. `None`, the
    /// default, refuses every such grant `unsupported_grant` and advertises no
    /// `resources` section.
    #[must_use]
    pub const fn with_resource_enforcement(
        mut self,
        resources: Option<ResourceEnforcement>,
    ) -> Self {
        self.resources = resources;
        self
    }

    /// What this node enforces on an attempt's process tree, if it runs attempts in
    /// cgroups.
    #[must_use]
    pub const fn resource_enforcement(&self) -> Option<ResourceEnforcement> {
        self.resources
    }

    /// Bound how long `stop` waits for the reaper to confirm the kill and reap.
    #[must_use]
    pub const fn with_stop_timeout(mut self, timeout: Duration) -> Self {
        self.stop_timeout = timeout;
        self
    }

    /// Whether this node honours a `network.custom` manifest, running its workload behind
    /// a per-attempt egress proxy ([`crate::egress`]). Off, every such manifest is refused
    /// `unsupported_grant` at `admit` and the node advertises `network.proxy_allowlist`
    /// `false`.
    #[must_use]
    pub const fn with_network_allowlist(mut self, enabled: bool) -> Self {
        self.network_allowlist = enabled;
        self
    }

    /// Whether this node honours a `network.custom` manifest.
    #[must_use]
    pub const fn honours_network_allowlist(&self) -> bool {
        self.network_allowlist
    }

    /// Whether this node honours a manifest's `output` grant, returning an ended
    /// attempt's bounded stdout, stderr and declared workspace files through `result`
    /// ([`crate::output`]). Off, every manifest with `output` is refused
    /// `unsupported_grant` at `admit`, `result` is `unsupported_operation` and the node
    /// advertises no `output` section.
    #[must_use]
    pub const fn with_output_return(mut self, enabled: bool) -> Self {
        self.output_return = enabled;
        self
    }

    /// Whether this node honours a manifest's `output` grant.
    #[must_use]
    pub const fn honours_output_return(&self) -> bool {
        self.output_return
    }

    /// Whether this node honours a manifest's `actions` grant, giving each such attempt
    /// its own action channel ([`crate::actions`]) that the control plane reads with
    /// `actions` and answers with `answer`. Off, every manifest with `actions` is refused
    /// `unsupported_grant` at `admit`, both requests are `unsupported_operation` and the
    /// node advertises no `actions` section.
    #[must_use]
    pub const fn with_action_channel(mut self, enabled: bool) -> Self {
        self.action_channel = enabled;
        self
    }

    /// Whether this node honours a manifest's `actions` grant.
    #[must_use]
    pub const fn honours_action_channel(&self) -> bool {
        self.action_channel
    }

    /// The task root workspaces are allocated under.
    #[must_use]
    pub const fn task_root(&self) -> &TaskRoot {
        &self.task_root
    }

    /// The node-owned snapshot store workspaces are materialised from.
    #[must_use]
    pub const fn snapshots(&self) -> &SnapshotStore {
        &self.snapshots
    }

    /// The launcher workloads are spawned through.
    #[must_use]
    pub fn launcher(&self) -> Arc<dyn TaskLauncher> {
        Arc::clone(&self.launcher)
    }

    /// How long `stop` waits for the reaper to confirm the kill and reap.
    #[must_use]
    pub const fn stop_timeout(&self) -> Duration {
        self.stop_timeout
    }

    /// How long `start` waits for the launcher to report a spawn.
    #[must_use]
    pub const fn spawn_timeout(&self) -> Duration {
        self.spawn_timeout
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn sleeping(nap: &str) -> bool {
        let cmdline = format!("sleep\0{nap}\0");
        std::fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|entry| std::fs::read(entry.path().join("cmdline")).ok())
            .any(|found| found == cmdline.as_bytes())
    }

    #[test]
    fn a_survivor_is_ended_only_under_its_recorded_identity_from_this_boot() {
        let nap = format!("30.{:06}", std::process::id() % 1_000_000);
        let mut child = std::process::Command::new("sh")
            .args(["-c", &format!("sleep {nap} & wait")])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let root = TreeRoot::of(child.id()).unwrap();
        let boot = current_boot().unwrap();
        for stranger in [
            WorkloadProcess::new(root.pid(), root.start_time(), "another-boot".to_owned()),
            WorkloadProcess::new(root.pid(), root.start_time() + 1, boot.clone()),
        ] {
            SandboxLauncher.end_survivor(&stranger);
            assert!(child.try_wait().unwrap().is_none(), "{stranger:?}");
        }

        SandboxLauncher.end_survivor(&WorkloadProcess::new(root.pid(), root.start_time(), boot));
        assert_eq!(child.wait().unwrap().code(), None);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while sleeping(&nap) {
            assert!(
                std::time::Instant::now() < deadline,
                "the sleep forked under the survivor outlived it"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_node_launch_never_inherits_the_node_environment() {
        let request = LaunchRequest::new(
            PathBuf::from("/tmp"),
            vec!["true".into()],
            Duration::from_secs(1),
        );
        let args = sandbox_launch(&request, None).args(Path::new("/tmp"));
        let clear = args.iter().position(|a| a == "--clearenv");
        let first_set = args.iter().position(|a| a == "--setenv");
        assert!(
            matches!((clear, first_set), (Some(c), Some(s)) if c < s),
            "{args:?}"
        );
        let joined = args.join(" ");
        assert!(!joined.contains(PROXY_SOCKET), "{joined}");
        assert!(!joined.contains(PROXY_SOCKET_ENV), "{joined}");
    }

    #[test]
    fn an_allowlisted_launch_binds_only_the_proxy_socket_and_names_it() {
        let request = LaunchRequest::new(
            PathBuf::from("/tmp"),
            vec!["true".into()],
            Duration::from_secs(1),
        )
        .with_allowlist(HostAllowlist::new(vec!["github.com".to_owned()]).unwrap());
        let args = sandbox_launch(&request, Some(Path::new("/host/x.egress/proxy.sock")))
            .args(Path::new("/tmp"));
        let joined = args.join(" ");
        assert!(joined.starts_with("--clearenv "), "{joined}");
        assert!(
            joined.contains("--bind /host/x.egress/proxy.sock /run/ward/proxy.sock"),
            "{joined}"
        );
        assert!(
            joined.contains("--setenv WARD_PROXY_SOCKET /run/ward/proxy.sock"),
            "{joined}"
        );
        assert!(joined.contains("--unshare-net"), "{joined}");
        assert!(!joined.contains("--relay"), "{joined}");
        assert!(!joined.contains("HTTP_PROXY"), "{joined}");
        assert_eq!(
            request.allowlist().map(HostAllowlist::patterns),
            Some(&["github.com".to_owned()][..])
        );
    }
}
