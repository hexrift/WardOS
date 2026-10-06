//! Capsule backends: the execution-backend contract and placement (#263, ADR-0039).
//!
//! A [`CapsuleBackend`] is one mechanism a node runs attempts in, at one
//! [`IsolationLevel`]. Its contract is the node's own lifecycle, served through the ports
//! [`crate::execution`] already defines:
//!
//! * `prepare` is the registry's, before the backend is asked for anything: the workspace
//!   materialised under the task root and one [`crate::execution::LaunchRequest`] built
//!   from the admitted manifest;
//! * `start` is [`TaskLauncher::launch`];
//! * `pause` and `resume` are the [`crate::execution::WorkloadFreezer`] of the running
//!   workload;
//! * `stop` is [`crate::execution::RunningWorkload::wait`] once its stop is requested, or
//!   at the budget;
//! * `destroy` is dropping the running workload (it kills and reaps) and, after a restart,
//!   [`TaskLauncher::end_survivor`];
//! * `inspect` is the running workload's pid and host process;
//! * `exec` and `snapshot` are declared and no verb asks for them yet.
//!
//! [`CapsuleBackendDescriptor::serves`] says which of them a backend serves. The first
//! backend is the bubblewrap launch, [`CapsuleBackendDescriptor::BUBBLEWRAP`] at `sandbox`,
//! with or without a cgroup per attempt.
//!
//! [`CapsulePlacement`] decides which backend runs an attempt whose manifest names a
//! minimum level: one at exactly that level, a stronger one only when the operator's
//! policy allows it ([`StrongerPlacement`]), never a weaker one. No backend means
//! `unsupported_grant` at `admit`. The backend that ran an attempt is recorded in its task
//! record as a [`CapsuleRecord`].

use serde::{Deserialize, Serialize};
use ward_node_protocol::{IsolationCapabilities, IsolationLevel};

use crate::execution::TaskLauncher;

/// An operation of the Capsule backend contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapsuleOperation {
    /// Build what the capsule runs over from the admitted manifest.
    Prepare,
    /// Spawn the workload.
    Start,
    /// Run a further command in a running capsule.
    Exec,
    /// Stop every process of the capsule, confirmed.
    Pause,
    /// Continue a paused capsule, confirmed.
    Resume,
    /// Kill and reap the workload.
    Stop,
    /// Capture a running capsule's state.
    Snapshot,
    /// Remove what the capsule ran in, a survivor of a restart included.
    Destroy,
    /// Report the host process the capsule runs as.
    Inspect,
}

impl CapsuleOperation {
    /// Every operation of the contract.
    pub const ALL: [Self; 9] = [
        Self::Prepare,
        Self::Start,
        Self::Exec,
        Self::Pause,
        Self::Resume,
        Self::Stop,
        Self::Snapshot,
        Self::Destroy,
        Self::Inspect,
    ];
}

/// What a backend is: its id, the level it guarantees and the operations it serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapsuleBackendDescriptor {
    backend: &'static str,
    level: IsolationLevel,
    serves: &'static [CapsuleOperation],
}

impl CapsuleBackendDescriptor {
    /// The bubblewrap launch of `ward-launch`: a namespace sandbox over the attempt's
    /// workspace, serving everything but `exec` and `snapshot`.
    pub const BUBBLEWRAP: Self = Self {
        backend: "bubblewrap",
        level: IsolationLevel::Sandbox,
        serves: &[
            CapsuleOperation::Prepare,
            CapsuleOperation::Start,
            CapsuleOperation::Pause,
            CapsuleOperation::Resume,
            CapsuleOperation::Stop,
            CapsuleOperation::Destroy,
            CapsuleOperation::Inspect,
        ],
    };

    /// The backend's id, as its task records name it.
    #[must_use]
    pub const fn backend(self) -> &'static str {
        self.backend
    }

    /// The isolation level the backend guarantees.
    #[must_use]
    pub const fn level(self) -> IsolationLevel {
        self.level
    }

    /// Whether the backend serves `operation`; the registry never asks it for one it does
    /// not.
    #[must_use]
    pub fn serves(self, operation: CapsuleOperation) -> bool {
        self.serves.contains(&operation)
    }
}

/// A mechanism a node runs attempts in, at one isolation level.
pub trait CapsuleBackend: TaskLauncher {
    /// Which backend this is, the level it guarantees and the operations it serves.
    fn descriptor(&self) -> CapsuleBackendDescriptor;
}

/// Whether an attempt may run on a backend stronger than its manifest's minimum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrongerPlacement {
    /// Only a backend at exactly the minimum runs it.
    Refused,
    /// The weakest backend at or above the minimum runs it.
    Allowed,
}

/// The backends a node runs attempts on and the operator's placement policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsulePlacement {
    backends: Vec<CapsuleBackendDescriptor>,
    stronger: StrongerPlacement,
}

impl CapsulePlacement {
    /// Place on `backends` under `stronger`.
    #[must_use]
    pub const fn new(backends: Vec<CapsuleBackendDescriptor>, stronger: StrongerPlacement) -> Self {
        Self { backends, stronger }
    }

    /// The backend an attempt whose manifest names `minimum` runs on: one at exactly
    /// `minimum`, otherwise, only when stronger placement is allowed, the weakest above it;
    /// never a weaker one. `None` when no backend qualifies.
    #[must_use]
    pub fn place(&self, minimum: IsolationLevel) -> Option<CapsuleBackendDescriptor> {
        let candidates = self
            .backends
            .iter()
            .copied()
            .filter(|backend| match self.stronger {
                StrongerPlacement::Refused => backend.level() == minimum,
                StrongerPlacement::Allowed => backend.level() >= minimum,
            });
        candidates.min_by_key(|backend| backend.level())
    }

    /// The levels the node offers, as the capability document's `isolation` flags say
    /// them.
    #[must_use]
    pub fn isolation(&self, base: IsolationCapabilities) -> IsolationCapabilities {
        self.backends.iter().fold(base, |isolation, backend| {
            isolation.offering(backend.level())
        })
    }
}

/// The backend that ran an attempt, as its task record keeps it:
/// `{"backend":"bubblewrap","isolation":"sandbox"}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleRecord {
    backend: String,
    isolation: IsolationLevel,
}

impl CapsuleRecord {
    const MAX_BACKEND_BYTES: usize = 32;

    /// The backend's id.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// The level the backend guarantees.
    #[must_use]
    pub const fn isolation(&self) -> IsolationLevel {
        self.isolation
    }

    /// Whether the backend id is 1–32 bytes of `a-z 0-9 -`.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        (1..=Self::MAX_BACKEND_BYTES).contains(&self.backend.len())
            && self
                .backend
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }
}

impl From<CapsuleBackendDescriptor> for CapsuleRecord {
    fn from(descriptor: CapsuleBackendDescriptor) -> Self {
        Self {
            backend: descriptor.backend().to_owned(),
            isolation: descriptor.level(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use ward_node_protocol::{ExecutionBackendCapabilities, NamespaceCapabilities};

    use super::*;
    use crate::execution::SandboxLauncher;

    const fn backend(level: IsolationLevel) -> CapsuleBackendDescriptor {
        CapsuleBackendDescriptor {
            backend: "test",
            level,
            serves: &[],
        }
    }

    #[test]
    fn the_bubblewrap_backend_is_a_sandbox_serving_everything_but_exec_and_snapshot() {
        let bubblewrap = SandboxLauncher.descriptor();
        assert_eq!(bubblewrap, CapsuleBackendDescriptor::BUBBLEWRAP);
        assert_eq!(bubblewrap.backend(), "bubblewrap");
        assert_eq!(bubblewrap.level(), IsolationLevel::Sandbox);
        for operation in CapsuleOperation::ALL {
            assert_eq!(
                bubblewrap.serves(operation),
                !matches!(
                    operation,
                    CapsuleOperation::Exec | CapsuleOperation::Snapshot
                ),
                "{operation:?}"
            );
        }
    }

    #[test]
    fn placement_never_runs_an_attempt_weaker_than_its_floor() {
        let sandbox_only = CapsulePlacement::new(
            vec![CapsuleBackendDescriptor::BUBBLEWRAP],
            StrongerPlacement::Allowed,
        );
        assert_eq!(
            sandbox_only.place(IsolationLevel::Sandbox),
            Some(CapsuleBackendDescriptor::BUBBLEWRAP)
        );
        for floor in [
            IsolationLevel::Container,
            IsolationLevel::Microvm,
            IsolationLevel::Vm,
        ] {
            assert_eq!(sandbox_only.place(floor), None, "{floor}");
        }
        for stronger in [StrongerPlacement::Refused, StrongerPlacement::Allowed] {
            let none = CapsulePlacement::new(Vec::new(), stronger);
            for floor in IsolationLevel::ALL {
                assert_eq!(none.place(floor), None, "{floor}");
            }
        }
    }

    #[test]
    fn placement_runs_stronger_only_when_the_operator_allows_it_and_then_on_the_weakest() {
        let container = backend(IsolationLevel::Container);
        let microvm = backend(IsolationLevel::Microvm);
        let ladder = vec![microvm, CapsuleBackendDescriptor::BUBBLEWRAP, container];

        let exact = CapsulePlacement::new(ladder.clone(), StrongerPlacement::Refused);
        assert_eq!(
            exact.place(IsolationLevel::Sandbox),
            Some(CapsuleBackendDescriptor::BUBBLEWRAP)
        );
        assert_eq!(exact.place(IsolationLevel::Container), Some(container));
        assert_eq!(exact.place(IsolationLevel::Microvm), Some(microvm));
        assert_eq!(exact.place(IsolationLevel::Vm), None);

        let container_only = CapsulePlacement::new(vec![container], StrongerPlacement::Refused);
        assert_eq!(
            container_only.place(IsolationLevel::Sandbox),
            None,
            "no silent upgrade without the operator's policy"
        );
        let upgrading = CapsulePlacement::new(vec![microvm, container], StrongerPlacement::Allowed);
        assert_eq!(upgrading.place(IsolationLevel::Sandbox), Some(container));
        assert_eq!(upgrading.place(IsolationLevel::Container), Some(container));
        assert_eq!(upgrading.place(IsolationLevel::Microvm), Some(microvm));
        assert_eq!(upgrading.place(IsolationLevel::Vm), None);
    }

    #[test]
    fn a_placement_offers_its_backends_levels_through_the_isolation_flags() {
        let base = IsolationCapabilities {
            namespaces: NamespaceCapabilities {
                sandbox: false,
                user_namespace: true,
            },
            backends: ExecutionBackendCapabilities::default(),
        };
        let sandbox_only = CapsulePlacement::new(
            vec![CapsuleBackendDescriptor::BUBBLEWRAP],
            StrongerPlacement::Refused,
        );
        assert_eq!(
            sandbox_only.isolation(base),
            IsolationCapabilities {
                namespaces: NamespaceCapabilities {
                    sandbox: true,
                    user_namespace: true,
                },
                backends: ExecutionBackendCapabilities::default(),
            }
        );
        let both = CapsulePlacement::new(
            vec![
                CapsuleBackendDescriptor::BUBBLEWRAP,
                backend(IsolationLevel::Microvm),
            ],
            StrongerPlacement::Refused,
        );
        let offered = both.isolation(base);
        for level in IsolationLevel::ALL {
            assert_eq!(
                offered.offers(level),
                matches!(level, IsolationLevel::Sandbox | IsolationLevel::Microvm),
                "{level}"
            );
        }
    }

    #[test]
    fn a_capsule_record_names_the_backend_and_its_level_in_one_spelling() {
        let record = CapsuleRecord::from(CapsuleBackendDescriptor::BUBBLEWRAP);
        assert_eq!(record.backend(), "bubblewrap");
        assert_eq!(record.isolation(), IsolationLevel::Sandbox);
        assert!(record.is_well_formed());
        assert_eq!(
            serde_json::to_string(&record).unwrap(),
            r#"{"backend":"bubblewrap","isolation":"sandbox"}"#
        );
        assert_eq!(
            serde_json::from_str::<CapsuleRecord>(
                r#"{"backend":"bubblewrap","isolation":"sandbox"}"#
            )
            .unwrap(),
            record
        );
        for bad in [
            r#"{"backend":"bubblewrap"}"#,
            r#"{"backend":"bubblewrap","isolation":"kvm"}"#,
            r#"{"backend":"bubblewrap","isolation":"sandbox","pid":1}"#,
        ] {
            assert!(serde_json::from_str::<CapsuleRecord>(bad).is_err(), "{bad}");
        }
        for (backend, well_formed) in [
            ("", false),
            ("Bubblewrap", false),
            ("bubble wrap", false),
            (&"a".repeat(33)[..], false),
            (&"a".repeat(32)[..], true),
            ("runc", true),
        ] {
            let record = CapsuleRecord {
                backend: backend.to_owned(),
                isolation: IsolationLevel::Container,
            };
            assert_eq!(record.is_well_formed(), well_formed, "{backend:?}");
        }
    }
}
