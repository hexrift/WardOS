//! `ward-sandbox` — OCI runtime-spec generator and `crun` driver for the `WardOS`
//! agent sandbox (architecture §6, ADR-0002, ADR-0003).
//!
//! The crate has two halves:
//!
//! * [`SandboxSpec`], a typed builder that renders a rootless OCI `config.json`
//!   encoding the `WardOS` isolation choices (user/mount/pid/net/ipc/uts/cgroup
//!   namespaces, empty capabilities, `noNewPrivileges`, a baseline
//!   [`seccomp`] profile, and cgroups v2 limits);
//! * [`CrunRuntime`], a minimal [`Runtime`] over the `crun` binary.
//!
//! Isolation guarantees require an unprivileged host and are validated
//! elsewhere; this crate only generates the declarative surface and drives the
//! runtime.

pub mod ci;
pub mod error;
pub mod runtime;
pub mod seccomp;
pub mod spec;

pub use error::{Result, SandboxError};
pub use runtime::{ContainerState, CrunRuntime, Runtime};
pub use seccomp::Profile;
pub use spec::{CgroupLimits, IdMap, SandboxSpec};
