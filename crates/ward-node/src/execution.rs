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
//! node never runs a workload under less, or more, than its manifest asked for. A
//! `credentials` grant adds the routes that inject its leases to that proxy
//! ([`LaunchRequest::with_credential_routes`], [`crate::credentials`]); nothing about it
//! enters the sandbox. A workload naming a hosted agent adapter ([`crate::adapters`],
//! ADR-0036) runs the adapter's command line with its environment and read-only settings
//! files, and its hook socket when it has hooks ([`LaunchRequest::with_adapter`]); none of
//! it changes the workspace, the network namespace, the proxy or anything above. On a node
//! with a `ward-agent` shim ([`crate::shim`], ADR-0037) the adapter, and any workload behind
//! an egress proxy, runs under it, bound read-only, and, behind an egress proxy, with its
//! loopback relay and the environment that names it ([`LaunchRequest::with_agent_shim`]);
//! an offline workload naming no adapter runs without it.
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
use ward_node_protocol::{
    AdapterCapabilities, HostAllowlist, MAX_OUTPUT_STDIO_BYTES, OutputGrant, ResourceGrant,
};
use ward_proxy::{GatewayRoute, Hold, SystemResolver};
use ward_snapshot::SnapshotStore;

use crate::actions::ACTION_SOCKET_ENV;
use crate::adapters::AttemptAdapter;
use crate::cgroup::ResourceEnforcement;
use crate::credentials::NodeCredentials;
use crate::egress::{AttemptEgress, PROXY_SOCKET_ENV, egress_dir_beside};
use crate::output::{CapturedStdio, CapturedStream};
use crate::scheduling::SchedulingLimits;
use crate::shim::{AgentShim, relay_env};
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
#[derive(Clone, Debug)]
pub struct LaunchRequest {
    workspace: PathBuf,
    argv: Vec<String>,
    budget: Duration,
    allowlist: Option<HostAllowlist>,
    output: Option<OutputGrant>,
    resources: Option<ResourceGrant>,
    action_socket: Option<PathBuf>,
    credential_routes: Vec<GatewayRoute>,
    hold: Option<Arc<dyn Hold>>,
    adapter: Option<AdapterParts>,
    agent_shim: Option<AgentShim>,
}

/// What a hosted agent adapter adds to a launch: its environment, its settings files (each
/// host file and the sandbox path it is bound at, read-only), its hook socket and its
/// provider.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdapterParts {
    /// The adapter's non-secret environment.
    pub env: Vec<(String, String)>,
    /// Host file and sandbox path of each settings file.
    pub seeds: Vec<(PathBuf, String)>,
    /// Host path of the hook socket, for an adapter with hooks.
    pub hooks: Option<PathBuf>,
    /// The adapter's provider, if it names one.
    pub provider: Option<String>,
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
            credential_routes: Vec::new(),
            hold: None,
            adapter: None,
            agent_shim: None,
        }
    }

    /// The same launch run as the hosted agent adapter `adapter` (ADR-0036): its command
    /// line in place of the argv, its environment, its settings files bound read-only and
    /// its hook socket bound at [`ward_launch::HOOK_SOCKET`], named by `WARD_SOCKET`.
    #[must_use]
    pub fn with_adapter(mut self, adapter: &AttemptAdapter) -> Self {
        adapter.argv().clone_into(&mut self.argv);
        self.adapter = Some(AdapterParts {
            env: adapter.env(),
            seeds: adapter.seeds().to_vec(),
            hooks: adapter.hook_socket().map(Path::to_path_buf),
            provider: adapter.provider().map(str::to_owned),
        });
        self
    }

    /// The same launch run under the `ward-agent` shim `shim` (ADR-0037), bound read-only
    /// at [`ward_launch::AGENT_SHIM`] and, behind an egress proxy, relaying
    /// [`ward_launch::RELAY_ADDR`] to it, wherever the shim has something to run
    /// ([`Self::agent_shim`]); an offline launch naming no adapter is unchanged.
    #[must_use]
    pub fn with_agent_shim(mut self, shim: &AgentShim) -> Self {
        self.agent_shim = Some(shim.clone());
        self
    }

    /// The shim the launch runs under: a hosted adapter's launch, for its command hooks,
    /// and a launch behind an egress proxy, for the relay. `None` without a shim, and for an
    /// offline launch naming no adapter.
    #[must_use]
    pub fn agent_shim(&self) -> Option<&AgentShim> {
        self.agent_shim
            .as_ref()
            .filter(|_| self.adapter.is_some() || self.allowlist.is_some())
    }

    /// What a hosted adapter adds to the launch; `None` for a plain workload.
    #[must_use]
    pub const fn adapter(&self) -> Option<&AdapterParts> {
        self.adapter.as_ref()
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

    /// The same launch with the routes that inject the attempt's leased credentials
    /// ([`crate::credentials`]), served by its egress proxy.
    #[must_use]
    pub fn with_credential_routes(mut self, routes: Vec<GatewayRoute>) -> Self {
        self.credential_routes = routes;
        self
    }

    /// The credential routes the attempt's egress proxy serves; empty without a
    /// `credentials` grant.
    #[must_use]
    pub fn credential_routes(&self) -> &[GatewayRoute] {
        &self.credential_routes
    }

    /// The same launch with the hold its egress proxy asks about every request it would let
    /// through: the attempt's action channel holding the manifest's `hold` (#415,
    /// [`crate::actions::AttemptActions::hold`]).
    #[must_use]
    pub fn with_hold(mut self, hold: Arc<dyn Hold>) -> Self {
        self.hold = Some(hold);
        self
    }

    /// The hold the attempt's egress proxy asks; `None` without a manifest `hold`.
    #[must_use]
    pub fn hold(&self) -> Option<Arc<dyn Hold>> {
        self.hold.clone()
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
                AttemptEgress::start_held(
                    &dir,
                    allowlist,
                    request.credential_routes().to_vec(),
                    request.hold(),
                    Arc::new(SystemResolver),
                )
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
    let launch = match request.adapter() {
        Some(adapter) => with_adapter(launch, adapter),
        None => launch,
    };
    let launch = match request.agent_shim() {
        Some(shim) => under_shim(launch, shim, request, proxy_socket.is_some()),
        None => launch,
    };
    match proxy_socket {
        Some(socket) => launch.egress(socket).env(PROXY_SOCKET_ENV, PROXY_SOCKET),
        None => launch,
    }
}

fn with_adapter(launch: Launch, adapter: &AdapterParts) -> Launch {
    let launch = adapter
        .env
        .iter()
        .fold(launch, |launch, (name, value)| launch.env(name, value));
    let launch = adapter
        .seeds
        .iter()
        .fold(launch, |launch, (file, path)| launch.seed(file, path));
    match &adapter.hooks {
        Some(socket) => launch.hooks(socket),
        None => launch,
    }
}

fn under_shim(launch: Launch, shim: &AgentShim, request: &LaunchRequest, relayed: bool) -> Launch {
    let launch = launch.shim(shim.path());
    if !relayed {
        return launch;
    }
    let provider = request
        .adapter()
        .and_then(|adapter| adapter.provider.as_deref());
    relay_env(provider, request.credential_routes())
        .into_iter()
        .fold(launch, |launch, (name, value)| launch.env(name, value))
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
#[allow(clippy::struct_excessive_bools)] // one flag per operator-enabled capability
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
    approval_hold: bool,
    credentials: Option<Arc<NodeCredentials>>,
    agent_adapters: Option<AdapterCapabilities>,
    agent_shim: Option<AgentShim>,
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
            .field("approval_hold", &self.approval_hold)
            .field("credentials", &self.credentials)
            .field("agent_adapters", &self.agent_adapters)
            .field("agent_shim", &self.agent_shim)
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
            approval_hold: false,
            credentials: None,
            agent_adapters: None,
            agent_shim: None,
        }
    }

    /// Host the agent adapters `adapters` names on admitted workloads that name one
    /// ([`crate::adapters`], ADR-0036). `None`, the default, refuses every workload naming
    /// an adapter `unsupported_grant` at `admit` and advertises no `adapters` section.
    #[must_use]
    pub const fn with_agent_adapters(mut self, adapters: Option<AdapterCapabilities>) -> Self {
        self.agent_adapters = adapters;
        self
    }

    /// The agent adapters this node hosts, if any.
    #[must_use]
    pub const fn agent_adapters(&self) -> Option<AdapterCapabilities> {
        self.agent_adapters
    }

    /// Run every hosted adapter's attempt and every attempt with an egress proxy under the
    /// verified `ward-agent` shim `shim` ([`crate::shim`], `--agent-shim`, ADR-0037): an
    /// adapter's command hooks reach the attempt's hook socket, and an attempt with an
    /// egress proxy gets the shim's loopback relay, the proxy variables naming it and, for a
    /// hosted adapter whose provider the manifest grants a credential for, its base URL. An
    /// offline attempt naming no adapter runs without it. `None`, the default, binds no shim
    /// and runs no relay.
    #[must_use]
    pub fn with_agent_shim(mut self, shim: Option<AgentShim>) -> Self {
        self.agent_shim = shim;
        self
    }

    /// The shim hosted adapters and attempts behind an egress proxy run under, if any.
    #[must_use]
    pub const fn agent_shim(&self) -> Option<&AgentShim> {
        self.agent_shim.as_ref()
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

    /// Whether this node honours a manifest's `hold` (#415, ADR-0035), on a node that also
    /// offers the action channel and enforces a network allowlist: the attempt's egress
    /// proxy refuses each held capability until the control plane approves the request the
    /// node opens for it. Off, the default, every manifest with `hold` is refused
    /// `unsupported_grant` at `admit` and the `actions` section carries no `hold`.
    #[must_use]
    pub const fn with_approval_hold(mut self, enabled: bool) -> Self {
        self.approval_hold = enabled;
        self
    }

    /// Whether this node honours a manifest's `hold`.
    #[must_use]
    pub const fn honours_approval_hold(&self) -> bool {
        self.approval_hold && self.action_channel && self.network_allowlist
    }

    /// Broker the services `credentials` configures to attempts whose manifest grants them
    /// ([`crate::credentials`], ADR-0034), on a node that also enforces a network
    /// allowlist. `None`, the default, refuses every `credentials` grant `unsupported_grant`
    /// and the node advertises `credentials` as `false`.
    #[must_use]
    pub fn with_credentials(mut self, credentials: Option<Arc<NodeCredentials>>) -> Self {
        self.credentials = credentials;
        self
    }

    /// The services this node brokers, if it honours `credentials` grants at all.
    #[must_use]
    pub fn credentials(&self) -> Option<&Arc<NodeCredentials>> {
        self.credentials.as_ref().filter(|_| self.network_allowlist)
    }

    /// Whether this node honours a manifest's `credentials` grant.
    #[must_use]
    pub fn honours_credentials(&self) -> bool {
        self.credentials().is_some()
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

    /// `args` without one occurrence of each of `parts`, each a contiguous run.
    fn without(mut args: Vec<String>, parts: &[Vec<String>]) -> Vec<String> {
        for part in parts {
            let at = args
                .windows(part.len())
                .position(|window| window == part.as_slice())
                .unwrap_or_else(|| panic!("{part:?} not in {args:?}"));
            args.drain(at..at + part.len());
        }
        args
    }

    #[test]
    fn an_adapter_adds_its_environment_settings_and_hook_socket_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let command: Vec<String> = vec!["/opt/claude".into(), "-p".into(), "fix it".into()];
        let claude = AttemptAdapter::start(
            &dir.path().join("exec.adapter"),
            ward_agent_adapter::catalogue::launch("claude-code", &command).unwrap(),
        )
        .unwrap();
        let request = LaunchRequest::new(PathBuf::from("/tmp"), command, Duration::from_secs(1))
            .with_allowlist(HostAllowlist::new(vec!["localhost".to_owned()]).unwrap());
        let proxy = Some(Path::new("/host/x.egress/proxy.sock"));
        let plain = sandbox_launch(&request, proxy).args(Path::new("/tmp"));
        let hosted = request.clone().with_adapter(&claude);
        assert_eq!(
            hosted.argv(),
            request.argv(),
            "Claude Code adds no fixed argument"
        );
        let args = sandbox_launch(&hosted, proxy).args(Path::new("/tmp"));
        let s = |parts: &[&str]| parts.iter().map(ToString::to_string).collect::<Vec<_>>();
        let socket = claude.hook_socket().unwrap().display().to_string();
        let mut added: Vec<Vec<String>> = claude
            .env()
            .iter()
            .map(|(name, value)| s(&["--setenv", name, value]))
            .collect();
        added.extend(
            claude
                .seeds()
                .iter()
                .map(|(file, path)| s(&["--ro-bind", &file.display().to_string(), path])),
        );
        added.push(s(&[
            "--bind",
            &socket,
            "/run/ward/hooks.sock",
            "--setenv",
            "WARD_SOCKET",
            "/run/ward/hooks.sock",
        ]));
        assert_eq!(without(args, &added), plain, "nothing else changes");

        let codex = AttemptAdapter::start(
            &dir.path().join("other.adapter"),
            ward_agent_adapter::catalogue::launch("codex", &s(&["codex"])).unwrap(),
        )
        .unwrap();
        let plain =
            LaunchRequest::new(PathBuf::from("/tmp"), s(&["codex"]), Duration::from_secs(1));
        let args =
            sandbox_launch(&plain.clone().with_adapter(&codex), None).args(Path::new("/tmp"));
        assert_eq!(
            without(
                args,
                &[s(&["--setenv", "CODEX_HOME", "/home/agent/.codex"])]
            ),
            sandbox_launch(&plain, None).args(Path::new("/tmp")),
            "a hookless adapter binds no hook socket"
        );
    }

    #[test]
    fn under_the_shim_an_adapter_relays_to_its_proxy_and_learns_only_its_granted_base_url() {
        let dir = tempfile::tempdir().unwrap();
        let s = |parts: &[&str]| parts.iter().map(ToString::to_string).collect::<Vec<_>>();
        let command = s(&["/work/claude", "-p", "x"]);
        let claude = AttemptAdapter::start(
            &dir.path().join("exec.adapter"),
            ward_agent_adapter::catalogue::launch("claude-code", &command).unwrap(),
        )
        .unwrap();
        let shim = AgentShim::assumed(PathBuf::from("/host/ward-agent"));
        let proxy = Some(Path::new("/host/x.egress/proxy.sock"));
        let route = |prefix: &str| {
            GatewayRoute::new(
                prefix,
                "api.example.com",
                443,
                "x-api-key",
                ward_proxy::Secret::new(b"lease".to_vec()),
            )
            .unwrap()
        };
        let request = LaunchRequest::new(PathBuf::from("/tmp"), command, Duration::from_secs(1))
            .with_allowlist(HostAllowlist::new(vec!["localhost".to_owned()]).unwrap())
            .with_credential_routes(vec![route("/anthropic")]);
        let hosted = request.clone().with_adapter(&claude);
        let shimmed = hosted.clone().with_agent_shim(&shim);
        assert_eq!(
            shimmed.adapter().unwrap().provider.as_deref(),
            Some("anthropic")
        );
        let args = sandbox_launch(&shimmed, proxy).args(Path::new("/tmp"));
        let joined = args.join(" ");
        assert!(
            joined.contains("--ro-bind /host/ward-agent /run/ward/ward-agent"),
            "{joined}"
        );
        let run = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args[run + 1], "/run/ward/ward-agent");
        let read_only: Vec<String> = ward_launch::SHIM_READ_ONLY
            .iter()
            .flat_map(|dir| ["--ro".to_owned(), (*dir).to_owned()])
            .collect();
        assert_eq!(args[run + 2..run + 2 + read_only.len()], read_only);
        assert!(
            joined.ends_with("--relay 127.0.0.1:3128=/run/ward/proxy.sock -- /work/claude -p x"),
            "{joined}"
        );
        for (name, value) in [
            ("ANTHROPIC_BASE_URL", "http://127.0.0.1:3128/anthropic"),
            ("ANTHROPIC_API_KEY", "ward-gateway"),
            ("HTTPS_PROXY", "http://127.0.0.1:3128"),
        ] {
            assert!(
                joined.contains(&format!("--setenv {name} {value} ")),
                "{name}: {joined}"
            );
            assert!(
                joined.contains(&format!("--env {name} ")),
                "{name}: {joined}"
            );
        }
        assert!(!joined.contains("lease"), "{joined}");

        let ungranted = request
            .clone()
            .with_credential_routes(vec![route("/openai")])
            .with_adapter(&claude)
            .with_agent_shim(&shim);
        let joined = sandbox_launch(&ungranted, proxy)
            .args(Path::new("/tmp"))
            .join(" ");
        assert!(joined.contains("--setenv HTTPS_PROXY"), "{joined}");
        assert!(!joined.contains("ANTHROPIC_"), "{joined}");
        assert!(!joined.contains("OPENAI_"), "{joined}");

        let offline = LaunchRequest::new(
            PathBuf::from("/tmp"),
            s(&["/work/claude"]),
            Duration::from_secs(1),
        )
        .with_adapter(&claude)
        .with_agent_shim(&shim);
        let joined = sandbox_launch(&offline, None)
            .args(Path::new("/tmp"))
            .join(" ");
        assert!(joined.contains("-- /run/ward/ward-agent --ro"), "{joined}");
        assert!(!joined.contains("--relay"), "{joined}");
        assert!(!joined.contains("PROXY"), "{joined}");
        assert!(!joined.contains("ANTHROPIC_"), "{joined}");
    }

    #[test]
    fn under_the_shim_a_plain_workload_behind_a_proxy_relays_to_it_and_an_offline_one_is_unchanged()
    {
        let s = |parts: &[&str]| parts.iter().map(ToString::to_string).collect::<Vec<_>>();
        let shim = AgentShim::assumed(PathBuf::from("/host/ward-agent"));
        let proxy = Some(Path::new("/host/x.egress/proxy.sock"));
        let route = GatewayRoute::new(
            "/git",
            "git.example.com",
            443,
            "authorization",
            ward_proxy::Secret::new(b"Bearer lease".to_vec()),
        )
        .unwrap();
        let request = LaunchRequest::new(
            PathBuf::from("/tmp"),
            s(&["git", "clone", "http://127.0.0.1:3128/git/acme/widgets.git"]),
            Duration::from_secs(1),
        )
        .with_allowlist(HostAllowlist::new(vec!["git.example.com".to_owned()]).unwrap())
        .with_credential_routes(vec![route]);
        let shimmed = request.clone().with_agent_shim(&shim);
        assert_eq!(shimmed.agent_shim(), Some(&shim));
        let plain = sandbox_launch(&request, proxy).args(Path::new("/tmp"));
        let args = sandbox_launch(&shimmed, proxy).args(Path::new("/tmp"));
        let run = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args[run + 1], "/run/ward/ward-agent");
        let relay = args.iter().position(|arg| arg == "--relay").unwrap();
        assert_eq!(args[relay + 1], "127.0.0.1:3128=/run/ward/proxy.sock");
        assert_eq!(
            args[relay + 2..],
            s(&[
                "--",
                "git",
                "clone",
                "http://127.0.0.1:3128/git/acme/widgets.git"
            ])
        );
        let mut added: Vec<Vec<String>> = relay_env(None, request.credential_routes())
            .iter()
            .map(|(name, value)| s(&["--setenv", name, value]))
            .collect();
        added.push(s(&[
            "--ro-bind",
            "/host/ward-agent",
            "/run/ward/ward-agent",
        ]));
        let joined = args.join(" ");
        assert!(!joined.contains("lease"), "{joined}");
        assert!(!joined.contains("BASE_URL"), "{joined}");
        assert!(!joined.contains("API_KEY"), "{joined}");
        let outside: Vec<String> = without(args[..run].to_vec(), &added);
        assert_eq!(
            outside,
            plain[..plain.iter().position(|arg| arg == "--").unwrap()],
            "the sandbox is the same but for the shim and the proxy variables"
        );

        let offline = LaunchRequest::new(
            PathBuf::from("/tmp"),
            s(&["git", "status"]),
            Duration::from_secs(1),
        );
        assert_eq!(offline.clone().with_agent_shim(&shim).agent_shim(), None);
        assert_eq!(
            sandbox_launch(&offline.clone().with_agent_shim(&shim), None).args(Path::new("/tmp")),
            sandbox_launch(&offline, None).args(Path::new("/tmp")),
            "an offline workload naming no adapter never runs under the shim"
        );
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
