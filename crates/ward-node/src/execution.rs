//! Node-owned execution of admitted tasks (ADR-0030 §3–§6).
//!
//! The registry ([`crate::task`]) never spawns a process itself. It asks a
//! [`TaskLauncher`] for one, on a node-owned reaper thread per attempt that then waits on
//! the returned [`RunningWorkload`] and records how it ended. The port keeps the state
//! machine testable without a sandbox; [`SandboxLauncher`] is the real implementation over
//! the bubblewrap primitive in `ward-launch`.
//!
//! A launch is built only from node-owned state: the workspace the node allocated under
//! its task root ([`crate::workspace`]), the admitted envelope's argv and its mandatory
//! wall-clock budget. The sandbox is offline: it never binds an egress socket, so its
//! network namespace holds only loopback. The envelope's capability manifest is not
//! interpreted yet, so any network grant it carries is not honoured; the node fails closed
//! to the least authority rather than guessing at a grant.
//!
//! `pause` and `resume` act on the running workload through its [`WorkloadFreezer`], which
//! the reaper hands back with the spawned pid. The sandbox freezer stops the tree rooted at
//! the outer `bwrap`'s host pid with `SIGSTOP`, children first, and reports it frozen only
//! once the settle check in `ward_launch::freeze` confirms every process stopped (or ended,
//! or held in vfork wait on a stopped child) within [`DEFAULT_FREEZE_SETTLE`]; otherwise it
//! continues the tree again and refuses. Resuming sends `SIGCONT`, parents first, and
//! confirms nothing is still stopped. There is no cgroup freezer: the node creates no
//! delegated cgroup for a launch. The budget clock keeps running while a workload is
//! paused (ADR-0030 §3: the budget is always enforced), and `SIGKILL` ends a stopped
//! process as it is, so a paused workload can still be stopped or killed at its budget.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ward_launch::freeze::{FrozenTree, TreeRoot, freeze_tree, thaw_tree};
use ward_launch::{Launch, RunningLaunch};
use ward_snapshot::SnapshotStore;

use crate::workspace::TaskRoot;

/// Default bound on how long `stop` waits for the reaper to confirm the kill and reap.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default bound on how long `start` waits for the launcher to report a spawn.
pub const DEFAULT_SPAWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Default bound on how long `pause` waits for a freeze, and `resume` for a thaw, to be
/// confirmed.
pub const DEFAULT_FREEZE_SETTLE: Duration = ward_launch::freeze::FREEZE_SETTLE;

/// Bytes of each workload output stream the sandbox launcher retains (a head and a tail)
/// before discarding it. Output is drained so a chatty workload never blocks on a pipe.
pub const OUTPUT_CAPTURE_BYTES: usize = 64 * 1024;

/// One workload launch, built only from node-owned state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchRequest {
    workspace: PathBuf,
    argv: Vec<String>,
    budget: Duration,
}

impl LaunchRequest {
    /// A launch of `argv` over the node-allocated `workspace`, killed at `budget`.
    #[must_use]
    pub const fn new(workspace: PathBuf, argv: Vec<String>, budget: Duration) -> Self {
        Self {
            workspace,
            argv,
            budget,
        }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    Lost,
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

    /// The freezer for this workload's process tree, shared with the registry.
    fn freezer(&self) -> Arc<dyn WorkloadFreezer>;

    /// Wait until the workload ends, enforcing its budget, and kill and reap it as soon as
    /// `stop` is requested.
    fn wait(self: Box<Self>, stop: &StopSignal) -> WorkloadExit;
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

impl TaskLauncher for SandboxLauncher {
    fn launch(&self, request: &LaunchRequest) -> Result<Box<dyn RunningWorkload>, SpawnError> {
        sandbox_launch(request)
            .spawn()
            .map(|running| Box::new(SandboxWorkload(running)) as Box<dyn RunningWorkload>)
            .map_err(|_| SpawnError::Refused)
    }
}

fn sandbox_launch(request: &LaunchRequest) -> Launch {
    Launch::new(request.workspace(), request.argv().to_vec())
        .budget(request.budget())
        .capture_bytes(OUTPUT_CAPTURE_BYTES)
        .clear_env()
}

struct SandboxWorkload(RunningLaunch);

impl RunningWorkload for SandboxWorkload {
    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn freezer(&self) -> Arc<dyn WorkloadFreezer> {
        Arc::new(SandboxFreezer {
            root: self.0.tree_root(),
            frozen: Mutex::new(None),
            settle: DEFAULT_FREEZE_SETTLE,
        })
    }

    fn wait(self: Box<Self>, stop: &StopSignal) -> WorkloadExit {
        match self.0.wait_stoppable(&|| stop.is_requested()) {
            Ok(outcome) if outcome.stopped => WorkloadExit::Stopped,
            Ok(outcome) if outcome.timed_out => WorkloadExit::BudgetExceeded,
            Ok(outcome) => WorkloadExit::Exited { code: outcome.code },
            Err(_) => WorkloadExit::Lost,
        }
    }
}

/// Freezes a sandbox's process tree by signal, rooted at its outer `bwrap`.
#[derive(Debug)]
struct SandboxFreezer {
    root: Option<TreeRoot>,
    frozen: Mutex<Option<FrozenTree>>,
    settle: Duration,
}

impl WorkloadFreezer for SandboxFreezer {
    fn freeze(&self) -> Result<(), FreezeUnconfirmed> {
        let root = self.root.ok_or(FreezeUnconfirmed)?;
        let mut frozen = self.frozen.lock().map_err(|_| FreezeUnconfirmed)?;
        let tree = freeze_tree(root, self.settle).map_err(|_| FreezeUnconfirmed)?;
        *frozen = Some(tree);
        Ok(())
    }

    fn thaw(&self) -> Result<(), FreezeUnconfirmed> {
        let mut frozen = self.frozen.lock().map_err(|_| FreezeUnconfirmed)?;
        let Some(tree) = frozen.as_ref() else {
            return Ok(());
        };
        if !thaw_tree(tree, self.settle) {
            return Err(FreezeUnconfirmed);
        }
        *frozen = None;
        Ok(())
    }
}

/// What a node needs to execute admitted tasks: its task root, its snapshot store and a
/// launcher. A node built with it advertises `start`, `stop`, `pause` and `revoke` together
/// at protocol 1.3.
pub struct NodeExecution {
    task_root: TaskRoot,
    snapshots: SnapshotStore,
    launcher: Arc<dyn TaskLauncher>,
    stop_timeout: Duration,
    spawn_timeout: Duration,
}

impl std::fmt::Debug for NodeExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeExecution")
            .field("task_root", &self.task_root)
            .field("stop_timeout", &self.stop_timeout)
            .field("spawn_timeout", &self.spawn_timeout)
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
        }
    }

    /// Bound how long `stop` waits for the reaper to confirm the kill and reap.
    #[must_use]
    pub const fn with_stop_timeout(mut self, timeout: Duration) -> Self {
        self.stop_timeout = timeout;
        self
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

    #[test]
    fn a_node_launch_never_inherits_the_node_environment() {
        let request = LaunchRequest::new(
            PathBuf::from("/tmp"),
            vec!["true".into()],
            Duration::from_secs(1),
        );
        let args = sandbox_launch(&request).args(Path::new("/tmp"));
        let clear = args.iter().position(|a| a == "--clearenv");
        let first_set = args.iter().position(|a| a == "--setenv");
        assert!(
            matches!((clear, first_set), (Some(c), Some(s)) if c < s),
            "{args:?}"
        );
    }
}
