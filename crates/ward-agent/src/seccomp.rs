//! Convert the typed [`Profile`] from `ward-sandbox` into seccomp BPF and install it.
//!
//! Syscall names are resolved with the `syscalls` tables for each architecture
//! the profile declares — never hand-written. A name that resolves on none of
//! them is an error. A name that exists only on a declared *non-native* ABI
//! (e.g. `umount`, which is i386-only) cannot be filtered by number here; it is
//! reported as unreachable rather than dropped silently, and is in fact
//! unreachable because seccompiler's filter prologue kills any syscall made
//! through a non-native ABI, which also closes the 32-bit bypass.
//!
//! `seccompiler` filters carry a single match action, so the profile is grouped
//! by action into one filter each and every program is installed. The kernel
//! evaluates all installed filters and applies the most restrictive result, so
//! stacking is equivalent to one multi-action filter.

use std::collections::BTreeMap;
use std::str::FromStr;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch, apply_filter};
use ward_sandbox::seccomp::{Action, Profile};

use crate::error::{AgentError, Result};

/// The OCI architecture tag and seccompiler target for the running machine.
pub fn native_arch() -> Result<(&'static str, TargetArch)> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(("SCMP_ARCH_X86_64", TargetArch::x86_64)),
        "aarch64" => Ok(("SCMP_ARCH_AARCH64", TargetArch::aarch64)),
        other => Err(AgentError::UnsupportedArch(other.to_string())),
    }
}

/// Name-to-number lookup for one ABI; `None` when the ABI has no such syscall.
type Table = fn(&str) -> Option<i64>;

fn table(tag: &str) -> Result<Table> {
    fn x86_64(name: &str) -> Option<i64> {
        syscalls::x86_64::Sysno::from_str(name)
            .ok()
            .map(|s| s.id().into())
    }
    fn x86(name: &str) -> Option<i64> {
        syscalls::x86::Sysno::from_str(name)
            .ok()
            .map(|s| s.id().into())
    }
    fn aarch64(name: &str) -> Option<i64> {
        syscalls::aarch64::Sysno::from_str(name)
            .ok()
            .map(|s| s.id().into())
    }
    match tag {
        "SCMP_ARCH_X86_64" | "SCMP_ARCH_X32" => Ok(x86_64),
        "SCMP_ARCH_X86" => Ok(x86),
        "SCMP_ARCH_AARCH64" => Ok(aarch64),
        other => Err(AgentError::UnsupportedArch(other.to_string())),
    }
}

fn to_action(action: Action, errno: Option<i32>) -> Result<SeccompAction> {
    Ok(match action {
        Action::Allow => SeccompAction::Allow,
        Action::KillProcess => SeccompAction::KillProcess,
        Action::Errno => {
            let code =
                errno.ok_or_else(|| AgentError::Profile("Errno rule without errno".into()))?;
            let code =
                u32::try_from(code).map_err(|_| AgentError::Profile(format!("errno {code}")))?;
            SeccompAction::Errno(code)
        }
    })
}

/// The result of compiling a profile for one architecture.
#[derive(Debug)]
pub struct Compiled {
    /// One BPF program per distinct rule action, in a deterministic order.
    pub programs: Vec<BpfProgram>,
    /// Names the profile denies on another declared ABI but which do not exist
    /// on the native one (and so cannot be invoked through it).
    pub unreachable: Vec<String>,
}

/// Compile `profile` for the native architecture `tag`/`arch`.
pub fn compile(profile: &Profile, tag: &str, arch: TargetArch) -> Result<Compiled> {
    // Every declared ABI must be one we have a table for, whether or not any
    // name ends up needing it.
    let tables = profile
        .architectures
        .iter()
        .map(|t| table(t).map(|f| (t.as_str(), f)))
        .collect::<Result<Vec<_>>>()?;
    let Some(&(_, native)) = tables.iter().find(|(t, _)| *t == tag) else {
        return Err(AgentError::Profile(format!("profile does not cover {tag}")));
    };
    let others = tables.iter().filter(|(t, _)| *t != tag);
    let known_elsewhere = |name: &str| others.clone().any(|(_, f)| f(name).is_some());
    let default = to_action(profile.default_action, None)?;
    // Keyed by the action's Debug form so equal actions share a filter.
    let mut groups: BTreeMap<String, (SeccompAction, BTreeMap<i64, Vec<_>>)> = BTreeMap::new();
    let mut unreachable = Vec::new();

    for rule in &profile.syscalls {
        let action = to_action(rule.action, rule.errno_ret)?;
        let group = groups
            .entry(format!("{action:?}"))
            .or_insert_with(|| (action, BTreeMap::new()));
        for name in &rule.names {
            match native(name) {
                Some(nr) => {
                    group.1.insert(nr, Vec::new());
                }
                None if known_elsewhere(name) => unreachable.push(name.clone()),
                None => return Err(AgentError::Profile(format!("unknown syscall `{name}`"))),
            }
        }
    }

    let mut programs = Vec::with_capacity(groups.len());
    for (action, rules) in groups.into_values() {
        let filter = SeccompFilter::new(rules, default.clone(), action, arch)?;
        programs.push(BpfProgram::try_from(filter)?);
    }
    Ok(Compiled {
        programs,
        unreachable,
    })
}

/// Compile `profile` for this machine and install every program on the calling
/// thread. Returns what was compiled so the caller can report it.
pub fn apply(profile: &Profile) -> Result<Compiled> {
    let (tag, arch) = native_arch()?;
    let compiled = compile(profile, tag, arch)?;
    for program in &compiled.programs {
        apply_filter(program)?;
    }
    Ok(compiled)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use seccompiler::sock_filter;
    use ward_sandbox::seccomp::Syscall;

    use super::*;

    const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K

    fn compiled(profile: &Profile) -> Result<Compiled> {
        let (tag, arch) = native_arch().unwrap();
        compile(profile, tag, arch)
    }

    fn resolve(tag: &str, name: &str) -> Result<Option<i64>> {
        Ok(table(tag)?(name))
    }

    fn compared_numbers(program: &[sock_filter]) -> Vec<i64> {
        program
            .iter()
            .filter(|i| i.code == BPF_JEQ_K)
            .map(|i| i64::from(i.k))
            .collect()
    }

    #[test]
    fn every_denied_name_is_filtered_or_reported_unreachable() {
        let profile = Profile::baseline();
        let (tag, _) = native_arch().unwrap();
        let out = compiled(&profile).unwrap();
        let numbers: Vec<i64> = out
            .programs
            .iter()
            .flat_map(|p| compared_numbers(p))
            .collect();
        for name in profile.denied_names() {
            match resolve(tag, name).unwrap() {
                Some(nr) => assert!(numbers.contains(&nr), "{name} ({nr}) not in filter"),
                None => assert!(
                    out.unreachable.contains(&name.to_string()),
                    "{name} dropped"
                ),
            }
        }
        // `umount` is the one i386-only name in the baseline.
        assert_eq!(out.unreachable, vec!["umount".to_string()]);
    }

    #[test]
    fn one_program_per_distinct_action() {
        let out = compiled(&Profile::baseline()).unwrap();
        assert_eq!(out.programs.len(), 3, "EPERM, ENOSYS and KILL groups");
        assert!(out.programs.iter().all(|p| !p.is_empty()));
    }

    #[test]
    fn unknown_syscall_name_is_an_error() {
        let mut profile = Profile::baseline();
        profile.syscalls.push(Syscall {
            names: vec!["definitely_not_a_syscall".into()],
            action: Action::Errno,
            errno_ret: Some(1),
        });
        let err = compiled(&profile).unwrap_err();
        assert!(matches!(err, AgentError::Profile(_)), "{err}");
        assert!(err.to_string().contains("definitely_not_a_syscall"));
    }

    #[test]
    fn unknown_architecture_tag_is_an_error() {
        let mut profile = Profile::baseline();
        profile.architectures.push("SCMP_ARCH_VAX".into());
        assert!(matches!(
            compiled(&profile),
            Err(AgentError::UnsupportedArch(a)) if a == "SCMP_ARCH_VAX"
        ));
    }

    #[test]
    fn profile_must_declare_the_native_architecture() {
        let mut profile = Profile::baseline();
        profile.architectures = vec!["SCMP_ARCH_X86".into()];
        assert!(matches!(compiled(&profile), Err(AgentError::Profile(_))));
    }

    #[test]
    fn errno_rule_without_errno_is_an_error() {
        let mut profile = Profile::baseline();
        profile.syscalls.push(Syscall {
            names: vec!["mount".into()],
            action: Action::Errno,
            errno_ret: None,
        });
        assert!(matches!(compiled(&profile), Err(AgentError::Profile(_))));
    }

    #[test]
    fn rule_identical_to_default_is_rejected() {
        let mut profile = Profile::baseline();
        profile.syscalls.push(Syscall {
            names: vec!["read".into()],
            action: Action::Allow,
            errno_ret: None,
        });
        assert!(matches!(compiled(&profile), Err(AgentError::Seccomp(_))));
    }
}
