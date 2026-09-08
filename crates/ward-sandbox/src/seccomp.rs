//! Typed seccomp profile for the agent sandbox (architecture §6, ADR-0002).
//!
//! The baseline is default-allow, then denies the syscall families the threat
//! model calls out as escape or kernel-attack surface. Denials are expressed as
//! typed data so the set is reviewable and testable, not a hand-written blob.

use serde::Serialize;

/// `EPERM`: the syscall returns "operation not permitted".
const EPERM: i32 = 1;
/// `ENOSYS`: the syscall reports "not implemented" so callers feature-detect and
/// fall back (used for `io_uring` so async runtimes degrade to epoll cleanly).
const ENOSYS: i32 = 38;

/// Action taken by the kernel when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Action {
    /// Allow the syscall.
    #[serde(rename = "SCMP_ACT_ALLOW")]
    Allow,
    /// Fail the syscall with an errno, without running it.
    #[serde(rename = "SCMP_ACT_ERRNO")]
    Errno,
    /// Kill the calling process.
    #[serde(rename = "SCMP_ACT_KILL_PROCESS")]
    KillProcess,
}

/// One rule: a set of syscall names sharing an action.
#[derive(Debug, Clone, Serialize)]
pub struct Syscall {
    /// Syscall names this rule matches.
    pub names: Vec<String>,
    /// Action applied when a listed syscall is invoked.
    pub action: Action,
    /// Errno returned for [`Action::Errno`]; omitted otherwise.
    #[serde(rename = "errnoRet", skip_serializing_if = "Option::is_none")]
    pub errno_ret: Option<i32>,
}

/// A complete OCI seccomp profile.
#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    /// Fallback action for syscalls no rule matches.
    #[serde(rename = "defaultAction")]
    pub default_action: Action,
    /// Architectures the filter applies to (compat ABIs included to close the
    /// 32-bit-syscall bypass).
    pub architectures: Vec<String>,
    /// Deny rules, evaluated before the default action.
    pub syscalls: Vec<Syscall>,
}

fn errno(names: &[&str], code: i32) -> Syscall {
    Syscall {
        names: names.iter().map(|s| (*s).to_string()).collect(),
        action: Action::Errno,
        errno_ret: Some(code),
    }
}

fn kill(names: &[&str]) -> Syscall {
    Syscall {
        names: names.iter().map(|s| (*s).to_string()).collect(),
        action: Action::KillProcess,
        errno_ret: None,
    }
}

impl Profile {
    /// The `WardOS` baseline profile: default-allow with the dangerous families denied.
    #[must_use]
    pub fn baseline() -> Self {
        Self {
            default_action: Action::Allow,
            architectures: vec![
                "SCMP_ARCH_X86_64".to_string(),
                "SCMP_ARCH_X86".to_string(),
                "SCMP_ARCH_X32".to_string(),
                "SCMP_ARCH_AARCH64".to_string(),
            ],
            syscalls: vec![
                // Mount family: block remounting the rootfs or escaping the mount ns.
                errno(
                    &[
                        "mount",
                        "umount",
                        "umount2",
                        "move_mount",
                        "open_tree",
                        "fsopen",
                        "fsconfig",
                        "fsmount",
                        "fspick",
                        "mount_setattr",
                        "pivot_root",
                    ],
                    EPERM,
                ),
                // Debugging/foreign-memory: no ptrace of siblings (O4).
                errno(&["ptrace", "process_vm_readv", "process_vm_writev"], EPERM),
                // Kernel programmability and keyrings: bpf/keyring escape surface.
                errno(&["bpf", "keyctl", "add_key", "request_key"], EPERM),
                // Kernel modules: loading code into the kernel.
                errno(&["init_module", "finit_module", "delete_module"], EPERM),
                // userfaultfd: userspace page-fault handling used in LPE races.
                errno(&["userfaultfd"], EPERM),
                // io_uring: broad async syscall surface, default-denied as unsupported.
                errno(
                    &["io_uring_setup", "io_uring_enter", "io_uring_register"],
                    ENOSYS,
                ),
                // Catastrophic host operations: kill the caller outright.
                kill(&["kexec_load", "kexec_file_load", "reboot"]),
            ],
        }
    }

    /// Every syscall name denied by this profile, flattened.
    #[must_use]
    pub fn denied_names(&self) -> Vec<&str> {
        self.syscalls
            .iter()
            .flat_map(|s| s.names.iter().map(String::as_str))
            .collect()
    }
}
