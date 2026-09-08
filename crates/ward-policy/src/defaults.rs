//! The built-in system default policy (`docs/security-model.md` §3.1).

use crate::error::PolicyError;
use crate::manifest::{MemoryMax, ResourceLimits};
use crate::schema::Policy;
use crate::types::{ByteSize, CpuWeight, Percent, PidsMax};

/// The image-shipped system default policy, as YAML.
///
/// This is the base that `/etc/ward/policy.d/*.yaml` overlays. It mirrors
/// `docs/security-model.md` §3.1 exactly; a test asserts it parses and yields the
/// documented values.
pub const DEFAULT_POLICY_YAML: &str = r"# WardOS built-in system policy (docs/security-model.md §3.1).
agent:
  filesystem:
    repo: write
    host: deny
  network:
    mode: development
    deny_private_networks: true
  secrets:
    github:
      decision: ask
      scope: [repo:current, contents:read, issues:read]
    npm-publish: deny
    pypi-publish: deny
    'cloud-*': deny
    ssh-signing:
      decision: ask
      scope: [per-host]
  containers:
    allow: true
  resources:
    cpu_weight: 100
    memory_max: 50%
    pids_max: 4096
    disk_quota: 20GiB
observer:
  default: live
";

/// Default cgroup `cpu.weight`.
pub const DEFAULT_CPU_WEIGHT: CpuWeight = CpuWeight::from_const(100);

/// Default memory ceiling: 50% of host memory.
pub const DEFAULT_MEMORY_PERCENT: Percent = Percent::from_const(50);

/// Default cgroup `pids.max`.
pub const DEFAULT_PIDS_MAX: PidsMax = PidsMax::from_const(4096);

/// Default disk quota on `/env`: 20 GiB.
pub const DEFAULT_DISK_QUOTA: ByteSize = ByteSize::from_const(20 * (1 << 30));

/// The resource limits of the built-in default, used as the floor when the system
/// layer omits a limit.
#[must_use]
pub const fn default_resource_limits() -> ResourceLimits {
    ResourceLimits {
        cpu_weight: DEFAULT_CPU_WEIGHT,
        memory_max: MemoryMax {
            bytes: None,
            percent_of_host: Some(DEFAULT_MEMORY_PERCENT),
        },
        pids_max: DEFAULT_PIDS_MAX,
        disk_quota: DEFAULT_DISK_QUOTA,
    }
}

/// Parses [`DEFAULT_POLICY_YAML`].
///
/// # Errors
/// Returns [`PolicyError`] only if the embedded document is invalid, which the test
/// suite rules out.
pub fn default_policy() -> Result<Policy, PolicyError> {
    Policy::from_yaml(DEFAULT_POLICY_YAML)
}
