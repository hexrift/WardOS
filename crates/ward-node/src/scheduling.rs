//! Node capacity and admission control (#260, the first single-node slice).
//!
//! A node started with `--max-running <n>` executes at most `n` attempts at once. An
//! attempt counts from the moment its `start` spawned it until its reaper has reaped its
//! workload: a paused attempt counts, and so does one whose kill is still pending (also an
//! attempt a `revoke` ended before its reap was confirmed), because each still holds host
//! processes. With `--memory-floor <bytes>` or `--disk-floor <bytes>` as well, `start` also
//! requires the host's available memory (`MemAvailable`) and the available space on the
//! task root's filesystem to be at least the floor.
//!
//! A `start` that does not fit is refused `capacity_exhausted`, checked after the
//! admission is revalidated and before anything is materialised or spawned, so the task
//! stays `ready`, nothing is recorded and the same `start` (same operation id) may be
//! sent again once an attempt has ended. The node keeps no queue of its own: a refused
//! start is not remembered, so there is nothing to starve, reorder or lose across a
//! restart. The control plane's waiting attempts are its `ready` tasks, visible through
//! `inspect` and bounded by the registry (`MAX_NODE_TASKS`). The bound, the running count
//! and the headroom are reported, live, in the capability document's `scheduling` section
//! ([`SchedulingLimits::report`]).
//!
//! A floor the node cannot measure (an unreadable `/proc/meminfo`, a task root `statvfs`
//! refuses) refuses the `start` `resource_unavailable` rather than starting blind.

use std::path::Path;

use ward_node_protocol::{SchedulingCapabilities, TaskLifecycleRejectionReason};

use crate::task::MAX_NODE_TASKS;

type Reason = TaskLifecycleRejectionReason;

/// How many attempts a node executes at once and the headroom it keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulingLimits {
    max_running: u32,
    memory_floor_bytes: u64,
    disk_floor_bytes: u64,
}

impl SchedulingLimits {
    /// At most `max_running` attempts at once (1 to [`MAX_NODE_TASKS`]), refusing a start
    /// while available memory is below `memory_floor_bytes` or available disk under the
    /// task root below `disk_floor_bytes` (`0`: no floor). `None` outside those bounds.
    #[must_use]
    pub fn new(max_running: u32, memory_floor_bytes: u64, disk_floor_bytes: u64) -> Option<Self> {
        let within =
            usize::try_from(max_running).is_ok_and(|max| (1..=MAX_NODE_TASKS).contains(&max));
        within.then_some(Self {
            max_running,
            memory_floor_bytes,
            disk_floor_bytes,
        })
    }

    /// How many attempts may execute at once.
    #[must_use]
    pub const fn max_running(self) -> u32 {
        self.max_running
    }

    /// Whether one more attempt may start while `running` execute, with the task root at
    /// `task_root`.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::CapacityExhausted`] when the bound is reached or a floor is not
    /// met, and [`Reason::ResourceUnavailable`] when a floor cannot be measured.
    pub fn admit(self, running: usize, task_root: &Path) -> Result<(), Reason> {
        if usize::try_from(self.max_running).is_ok_and(|max| running >= max) {
            return Err(Reason::CapacityExhausted);
        }
        let above = |floor: u64, available: Option<u64>| match (floor, available) {
            (0, _) => Ok(()),
            (_, None) => Err(Reason::ResourceUnavailable),
            (floor, Some(available)) if available < floor => Err(Reason::CapacityExhausted),
            (_, Some(_)) => Ok(()),
        };
        above(self.memory_floor_bytes, memory_available_bytes())?;
        above(self.disk_floor_bytes, disk_available_bytes(task_root))
    }

    /// The capability document's `scheduling` section, read now; a headroom the node
    /// cannot measure reads `0`.
    #[must_use]
    pub fn report(self, running: usize, task_root: &Path) -> SchedulingCapabilities {
        SchedulingCapabilities {
            max_running: self.max_running,
            running: u32::try_from(running).unwrap_or(u32::MAX),
            memory_floor_bytes: self.memory_floor_bytes,
            memory_available_bytes: memory_available_bytes().unwrap_or(0),
            disk_floor_bytes: self.disk_floor_bytes,
            disk_available_bytes: disk_available_bytes(task_root).unwrap_or(0),
        }
    }
}

/// The host's available memory in bytes (`MemAvailable` of `/proc/meminfo`).
#[must_use]
pub fn memory_available_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kibibytes = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    kibibytes.checked_mul(1024)
}

/// The space available to the node's uid on the filesystem holding `dir`, in bytes.
#[must_use]
#[allow(clippy::useless_conversion)] // `statvfs` counts are narrower than u64 on 32-bit hosts
pub fn disk_available_bytes(dir: &Path) -> Option<u64> {
    let stat = nix::sys::statvfs::statvfs(dir).ok()?;
    u64::try_from(stat.blocks_available())
        .ok()?
        .checked_mul(u64::try_from(stat.fragment_size()).ok()?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use ward_events::{
        ExecutionAttemptId, LeaseId, NodeResourceUsage, SnapshotId, TaskId, WardEvent,
    };
    use ward_node_protocol::{
        CapabilityManifest, CapabilityManifestBytes, NetworkGrant, NodeCapacity, OperationId,
        ProtocolVersion, ResourceCapabilities, ResourceGrant, TaskAdmissionEnvelope, TaskBinding,
        TaskLifecycleContext, TaskLifecycleRejectionReason as Reason, TaskLifecycleResponse,
        TaskLifecycleState as State, TaskWorkload, WorkloadArgv,
    };

    use super::*;
    use crate::cgroup::ResourceEnforcement;
    use crate::execution::{NodeExecution, WorkloadExit};
    use crate::task::{MAX_NODE_TASKS, TaskRegistry};
    use crate::test_support::{
        FakeLauncher, FixedClock, NOW, envelope_input, eventually, node_admission, signed_admit,
    };
    use crate::workspace::{TaskRoot, import_snapshot, open_snapshot_store};

    struct Node {
        dir: tempfile::TempDir,
        launcher: FakeLauncher,
        tasks: Arc<Mutex<TaskRegistry>>,
        snapshot: SnapshotId,
    }

    fn ctx() -> TaskLifecycleContext {
        TaskLifecycleContext::new(ProtocolVersion::new(1, 3)).unwrap()
    }

    fn op(value: u64) -> OperationId {
        OperationId::new(value).unwrap()
    }

    fn binding(n: u128) -> TaskBinding {
        TaskBinding::new(
            TaskId::from_u128(100 + n),
            ExecutionAttemptId::from_u128(200 + n),
            LeaseId::from_u128(300 + n),
        )
    }

    fn capacity() -> NodeCapacity {
        NodeCapacity::new(4, 8 * 1024 * 1024 * 1024).unwrap()
    }

    impl Node {
        fn build(
            dir: tempfile::TempDir,
            scheduling: Option<SchedulingLimits>,
            resources: Option<ResourceEnforcement>,
        ) -> Self {
            let state = dir.path().join("state");
            let clock = FixedClock::at(NOW);
            let admission = node_admission(&state, &clock);
            let project = dir.path().join("project");
            std::fs::create_dir_all(&project).unwrap();
            std::fs::write(project.join("hello.txt"), b"hello").unwrap();
            let snapshots = open_snapshot_store(&state).unwrap();
            let snapshot = import_snapshot(&snapshots, &project).unwrap();
            let launcher = FakeLauncher::new();
            let execution = NodeExecution::new(
                TaskRoot::open(&dir.path().join("tasks")).unwrap(),
                snapshots,
                Arc::new(launcher.clone()),
            )
            .with_scheduling(scheduling)
            .with_resource_enforcement(resources);
            let tasks = Arc::new(Mutex::new(
                TaskRegistry::with_execution(MAX_NODE_TASKS, admission, execution).unwrap(),
            ));
            Self {
                dir,
                launcher,
                tasks,
                snapshot,
            }
        }

        fn new(scheduling: Option<SchedulingLimits>) -> Self {
            Self::build(tempfile::tempdir().unwrap(), scheduling, None)
        }

        fn restart(self) -> Self {
            let Self { dir, tasks, .. } = self;
            drop(tasks);
            Self::build(dir, None, None)
        }

        fn serve(
            &self,
            request: ward_node_protocol::TaskLifecycleRequest,
        ) -> TaskLifecycleResponse {
            TaskRegistry::serve(&self.tasks, ctx(), request).unwrap()
        }

        fn envelope(
            &self,
            binding: TaskBinding,
            manifest: CapabilityManifestBytes,
        ) -> TaskAdmissionEnvelope {
            let mut input = envelope_input(binding);
            input.workload = TaskWorkload::new(
                WorkloadArgv::new(vec!["true".to_owned()]).unwrap(),
                manifest,
                self.snapshot,
                45_000,
            )
            .unwrap();
            TaskAdmissionEnvelope::new(input).unwrap()
        }

        fn ready_with(
            &self,
            binding: TaskBinding,
            manifest: CapabilityManifestBytes,
        ) -> TaskLifecycleResponse {
            assert_eq!(
                self.serve(ctx().create(op(10), binding)),
                ctx().accepted(op(10), binding, State::Created)
            );
            self.serve(signed_admit(
                ctx(),
                op(20),
                binding,
                &self.envelope(binding, manifest),
            ))
        }

        fn ready(&self, binding: TaskBinding) {
            assert_eq!(
                self.ready_with(binding, offline()),
                ctx().accepted(op(20), binding, State::Ready)
            );
        }

        fn start(&self, binding: TaskBinding) -> TaskLifecycleResponse {
            self.serve(ctx().start(op(30), binding))
        }

        fn state(&self, binding: TaskBinding) -> State {
            match self.serve(ctx().inspect(binding)) {
                TaskLifecycleResponse::Inspected { state, .. } => state,
                other => panic!("inspect failed: {other:?}"),
            }
        }

        fn workspace(&self, binding: TaskBinding) -> PathBuf {
            self.dir
                .path()
                .join("tasks")
                .join(binding.task().to_string())
                .join(binding.attempt().to_string())
        }

        fn task_root(&self) -> PathBuf {
            self.dir.path().join("tasks")
        }
    }

    fn offline() -> CapabilityManifestBytes {
        CapabilityManifestBytes::encode(&CapabilityManifest::new(NetworkGrant::Offline)).unwrap()
    }

    fn limited(grant: ResourceGrant) -> CapabilityManifestBytes {
        CapabilityManifestBytes::encode(
            &CapabilityManifest::new(NetworkGrant::Offline).with_resources(grant),
        )
        .unwrap()
    }

    fn limits(max_running: u32) -> SchedulingLimits {
        SchedulingLimits::new(max_running, 0, 0).unwrap()
    }

    #[test]
    fn a_start_past_max_running_is_refused_capacity_exhausted_and_changes_nothing() {
        let node = Node::new(Some(limits(2)));
        for n in 0..3 {
            node.ready(binding(n));
        }
        for n in 0..2 {
            assert_eq!(
                node.start(binding(n)),
                ctx().accepted(op(30), binding(n), State::Running)
            );
        }
        assert_eq!(
            node.start(binding(2)),
            ctx().rejected(Some(op(30)), binding(2), Reason::CapacityExhausted)
        );
        assert_eq!(node.state(binding(2)), State::Ready);
        assert!(!node.workspace(binding(2)).exists(), "nothing materialised");
        assert_eq!(node.launcher.launches().len(), 2, "nothing spawned");
        assert_eq!(node.tasks.lock().unwrap().executing(), 2);

        assert_eq!(
            node.serve(ctx().stop(op(40), binding(0))),
            ctx().accepted(op(40), binding(0), State::Stopped)
        );
        assert_eq!(node.tasks.lock().unwrap().executing(), 1);
        assert_eq!(
            node.start(binding(2)),
            ctx().accepted(op(30), binding(2), State::Running),
            "the refused start is retried with the same operation id once a slot is free"
        );
        assert_eq!(node.launcher.launches().len(), 3);
    }

    #[test]
    fn a_paused_attempt_and_one_whose_kill_is_pending_still_hold_their_slot() {
        let node = Node::new(Some(limits(1)));
        node.ready(binding(0));
        node.ready(binding(1));
        assert_eq!(
            node.start(binding(0)),
            ctx().accepted(op(30), binding(0), State::Running)
        );
        assert_eq!(
            node.serve(ctx().pause(op(31), binding(0))),
            ctx().accepted(op(31), binding(0), State::Paused)
        );
        assert_eq!(
            node.start(binding(1)),
            ctx().rejected(Some(op(30)), binding(1), Reason::CapacityExhausted)
        );
        node.launcher.exit(WorkloadExit::Exited { code: Some(0) });
        eventually(|| node.state(binding(0)) == State::Exited);
        assert_eq!(
            node.start(binding(1)),
            ctx().accepted(op(30), binding(1), State::Running)
        );
    }

    #[test]
    fn a_start_below_the_memory_or_disk_floor_is_refused_capacity_exhausted() {
        for (memory, disk) in [(u64::MAX, 0), (0, u64::MAX)] {
            let node = Node::new(Some(SchedulingLimits::new(8, memory, disk).unwrap()));
            node.ready(binding(0));
            assert_eq!(
                node.start(binding(0)),
                ctx().rejected(Some(op(30)), binding(0), Reason::CapacityExhausted),
                "memory floor {memory}, disk floor {disk}"
            );
            assert_eq!(node.state(binding(0)), State::Ready);
            assert!(node.launcher.launches().is_empty());
        }
        let node = Node::new(Some(SchedulingLimits::new(8, 1, 1).unwrap()));
        node.ready(binding(0));
        assert_eq!(
            node.start(binding(0)),
            ctx().accepted(op(30), binding(0), State::Running),
            "a host above both floors starts"
        );
    }

    #[test]
    fn without_scheduling_limits_a_node_never_refuses_for_capacity() {
        let node = Node::new(None);
        for n in 0..5 {
            node.ready(binding(n));
            assert_eq!(
                node.start(binding(n)),
                ctx().accepted(op(30), binding(n), State::Running)
            );
        }
        assert_eq!(node.tasks.lock().unwrap().scheduling(), None);
    }

    #[test]
    fn the_scheduling_report_names_the_bound_the_running_count_and_the_headroom() {
        let node = Node::new(Some(SchedulingLimits::new(3, 7, 9).unwrap()));
        node.ready(binding(0));
        node.start(binding(0));
        let report = node.tasks.lock().unwrap().scheduling().unwrap();
        assert_eq!(report.max_running, 3);
        assert_eq!(report.running, 1);
        assert_eq!(report.memory_floor_bytes, 7);
        assert_eq!(report.disk_floor_bytes, 9);
        assert!(report.memory_available_bytes > 0);
        assert!(report.disk_available_bytes > 0);
        let measured = disk_available_bytes(&node.task_root()).unwrap();
        assert!(
            report.disk_available_bytes.abs_diff(measured) < 1 << 30,
            "the report reads the task root's filesystem: {report:?}, {measured}"
        );
    }

    #[test]
    fn scheduling_limits_are_bounded() {
        assert!(SchedulingLimits::new(0, 0, 0).is_none());
        assert!(SchedulingLimits::new(1, 0, 0).is_some());
        let max = u32::try_from(MAX_NODE_TASKS).unwrap();
        assert!(SchedulingLimits::new(max, 0, 0).is_some());
        assert!(SchedulingLimits::new(max + 1, 0, 0).is_none());
    }

    #[test]
    fn host_headroom_is_read_from_the_host() {
        assert!(memory_available_bytes().is_some_and(|bytes| bytes > 0));
        assert!(disk_available_bytes(Path::new("/")).is_some());
        assert_eq!(disk_available_bytes(Path::new("/nonexistent/ward")), None);
    }

    fn enforcing(enforces: ResourceCapabilities) -> Node {
        Node::build(
            tempfile::tempdir().unwrap(),
            None,
            Some(ResourceEnforcement::new(enforces, capacity())),
        )
    }

    #[test]
    fn a_resources_grant_is_honoured_only_when_every_limit_is_enforced_within_the_ceilings() {
        let grant = ResourceGrant::new(Some(500), Some(64 * 1024 * 1024), Some(32)).unwrap();
        let plain = Node::new(None);
        assert_eq!(
            plain.ready_with(binding(0), limited(grant)),
            ctx().rejected(Some(op(20)), binding(0), Reason::UnsupportedGrant),
            "a node running no attempt in a cgroup enforces no limit"
        );
        assert_eq!(plain.state(binding(0)), State::Created);

        let pids_only = enforcing(ResourceCapabilities {
            cpu: false,
            memory: false,
            pids: true,
        });
        assert_eq!(
            pids_only.ready_with(binding(0), limited(grant)),
            ctx().rejected(Some(op(20)), binding(0), Reason::UnsupportedGrant),
            "a limit the node has no controller for is refused, never dropped"
        );

        let all = ResourceCapabilities {
            cpu: true,
            memory: true,
            pids: true,
        };
        let node = enforcing(all);
        for (n, over) in [
            ResourceGrant::new(Some(4001), None, None).unwrap(),
            ResourceGrant::new(None, Some(8 * 1024 * 1024 * 1024 + 1), None).unwrap(),
            ResourceGrant::new(None, None, Some(ward_node_protocol::MAX_RESOURCE_PIDS + 1))
                .unwrap(),
        ]
        .into_iter()
        .enumerate()
        {
            let n = u128::try_from(n).unwrap() + 10;
            assert_eq!(
                node.ready_with(binding(n), limited(over)),
                ctx().rejected(Some(op(20)), binding(n), Reason::UnsupportedGrant),
                "{over:?} is above the node's ceilings"
            );
        }
        assert_eq!(
            node.ready_with(binding(0), limited(grant)),
            ctx().accepted(op(20), binding(0), State::Ready)
        );
        assert_eq!(
            node.start(binding(0)),
            ctx().accepted(op(30), binding(0), State::Running)
        );
        assert_eq!(
            node.launcher.launches()[0].resources(),
            Some(&grant),
            "the launch carries exactly the limits the manifest asked for"
        );
        node.ready(binding(1));
        node.start(binding(1));
        assert_eq!(node.launcher.launches()[1].resources(), None);
    }

    fn usage() -> NodeResourceUsage {
        NodeResourceUsage {
            cpu_millis_limit: Some(500),
            memory_limit_bytes: Some(64 * 1024 * 1024),
            pids_limit: Some(32),
            cpu_usage_usec: Some(12_345),
            memory_peak_bytes: Some(3 * 1024 * 1024),
            pids_peak: Some(4),
            memory_oom_kills: Some(0),
            pids_max_events: Some(0),
        }
    }

    #[test]
    fn measured_usage_is_recorded_durably_and_in_the_evidence_before_the_end() {
        let node = Node::new(None);
        node.ready(binding(0));
        node.launcher.set_usage(Some(usage()));
        node.start(binding(0));
        node.launcher.exit(WorkloadExit::Exited { code: Some(0) });
        eventually(|| node.state(binding(0)) == State::Exited);
        assert_eq!(node.tasks.lock().unwrap().usage(binding(0)), Some(usage()));
        let log = crate::evidence::verify(
            &crate::evidence::evidence_dir(&node.task_root(), binding(0)),
            binding(0),
        )
        .unwrap();
        let events: Vec<&WardEvent> = log.records().iter().map(|record| &record.event).collect();
        let at = events
            .iter()
            .position(|event| matches!(event, WardEvent::NodeAttemptResourceUsage { .. }))
            .expect("a usage record");
        assert_eq!(
            events[at],
            &WardEvent::NodeAttemptResourceUsage { usage: usage() }
        );
        assert!(matches!(events[at + 1], WardEvent::NodeAttemptEnded { .. }));

        let record = std::fs::read_to_string(
            node.dir
                .path()
                .join("state")
                .join(crate::records::TASKS_DIR)
                .join(format!("{}.json", binding(0).task())),
        )
        .unwrap();
        assert!(
            record.contains(r#""usage":{"cpu_millis_limit":500"#),
            "{record}"
        );

        let node = node.restart();
        assert_eq!(
            node.tasks.lock().unwrap().usage(binding(0)),
            Some(usage()),
            "the usage survives a restart with the task's record"
        );
    }

    #[test]
    fn an_attempt_without_measured_usage_records_none_and_its_record_is_unchanged() {
        let node = Node::new(None);
        node.ready(binding(0));
        node.start(binding(0));
        node.launcher.exit(WorkloadExit::Exited { code: Some(1) });
        eventually(|| node.state(binding(0)) == State::Exited);
        assert_eq!(node.tasks.lock().unwrap().usage(binding(0)), None);
        let record = std::fs::read_to_string(
            node.dir
                .path()
                .join("state")
                .join(crate::records::TASKS_DIR)
                .join(format!("{}.json", binding(0).task())),
        )
        .unwrap();
        assert!(!record.contains("usage"), "{record}");
        let log = crate::evidence::verify(
            &crate::evidence::evidence_dir(&node.task_root(), binding(0)),
            binding(0),
        )
        .unwrap();
        assert!(
            log.records()
                .iter()
                .all(|record| !matches!(record.event, WardEvent::NodeAttemptResourceUsage { .. }))
        );
    }
}
