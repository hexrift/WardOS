//! Landlock ruleset construction and enforcement (architecture §6, ADR-0003).
//!
//! The ruleset is an allow-list: everything not covered by a [`PathSets`]
//! entry is inaccessible. Enforcement is best-effort against the ABI the
//! kernel actually offers, but a kernel with no Landlock at all is a hard
//! failure unless the caller explicitly opts out.

use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, BitFlags, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
};

use crate::error::{AgentError, Result};

/// Highest Landlock ABI this shim asks for; older kernels degrade best-effort.
const TARGET_ABI: ABI = ABI::V5;

/// Directories the agent may read, write and execute under.
pub const DEFAULT_RW: &[&str] = &["/work", "/env", "/tmp"];
/// Directories the agent may read and execute under.
pub const DEFAULT_RO: &[&str] = &["/usr", "/bin", "/lib", "/lib64", "/etc", "/proc"];
/// Paths the agent may read, write and `ioctl` but not create or remove under.
pub const DEFAULT_IO: &[&str] = &["/dev"];

/// The three access tiers the ruleset grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSets {
    /// Full access: read, write, execute, create, remove, rename.
    pub rw: Vec<PathBuf>,
    /// Read and execute only.
    pub ro: Vec<PathBuf>,
    /// Read, write and `ioctl` on existing files only (devices, the control socket).
    pub io: Vec<PathBuf>,
}

impl PathSets {
    /// The ADR-0003 defaults: rw under `/work`, `/env`, `/tmp` and `home`; ro
    /// under the system directories; io on `/dev` and the control `socket`.
    pub fn defaults(home: Option<&Path>, socket: Option<&Path>) -> Self {
        let mut rw = to_paths(DEFAULT_RW);
        rw.extend(home.map(Path::to_path_buf));
        let mut io = to_paths(DEFAULT_IO);
        io.extend(socket.map(Path::to_path_buf));
        Self {
            rw,
            ro: to_paths(DEFAULT_RO),
            io,
        }
    }

    /// Build the ruleset. Missing `ro`/`io` paths are skipped; a missing `rw`
    /// path is an error because the agent would be left without a writable root.
    pub fn build(&self) -> Result<RulesetCreated> {
        if let Some(missing) = self.rw.iter().find(|p| !p.exists()) {
            return Err(AgentError::MissingRwPath(missing.clone()));
        }
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(TARGET_ABI))?
            .create()?
            .add_rules(path_beneath_rules(&self.rw, AccessFs::from_all(TARGET_ABI)))?
            .add_rules(path_beneath_rules(
                &self.ro,
                AccessFs::from_read(TARGET_ABI),
            ))?
            .add_rules(path_beneath_rules(&self.io, io_access()))?;
        Ok(ruleset)
    }
}

fn to_paths(list: &[&str]) -> Vec<PathBuf> {
    list.iter().map(PathBuf::from).collect()
}

fn io_access() -> BitFlags<AccessFs> {
    AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::IoctlDev
}

/// What enforcement achieved.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The ruleset is enforced (fully, or partially on an older ABI).
    Enforced(RulesetStatus),
    /// The kernel has no Landlock and the caller allowed continuing without it.
    Skipped,
}

/// Whether the running kernel can enforce any Landlock ruleset at all.
pub fn is_available() -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(Ruleset::create)
        .is_ok()
}

/// Enforce `sets` on the calling thread (and every child it will spawn).
/// Also sets `PR_SET_NO_NEW_PRIVS`. Fails closed when Landlock is unavailable
/// unless `allow_missing` is set.
pub fn apply(sets: &PathSets, allow_missing: bool) -> Result<Outcome> {
    let status = sets.build()?.restrict_self()?;
    match status.ruleset {
        RulesetStatus::NotEnforced if allow_missing => Ok(Outcome::Skipped),
        RulesetStatus::NotEnforced => Err(AgentError::LandlockUnavailable {
            status: format!("{:?}", status.landlock),
        }),
        enforced => Ok(Outcome::Enforced(enforced)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_adr_0003() {
        let sets = PathSets::defaults(
            Some(Path::new("/home/agent")),
            Some(Path::new("/run/w.sock")),
        );
        for p in ["/work", "/env", "/tmp", "/home/agent"] {
            assert!(sets.rw.contains(&PathBuf::from(p)), "rw missing {p}");
        }
        for p in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
            assert!(sets.ro.contains(&PathBuf::from(p)), "ro missing {p}");
        }
        assert_eq!(
            sets.io,
            vec![PathBuf::from("/dev"), PathBuf::from("/run/w.sock")]
        );
    }

    #[test]
    fn defaults_without_home_or_socket() {
        let sets = PathSets::defaults(None, None);
        assert_eq!(sets.rw, to_paths(DEFAULT_RW));
        assert_eq!(sets.io, to_paths(DEFAULT_IO));
    }

    #[test]
    fn missing_rw_path_is_an_error() {
        let sets = PathSets {
            rw: vec![PathBuf::from("/definitely/not/here")],
            ro: vec![],
            io: vec![],
        };
        assert!(matches!(sets.build(), Err(AgentError::MissingRwPath(_))));
    }

    #[test]
    fn builds_ruleset_and_skips_missing_ro_paths() {
        if !is_available() {
            eprintln!("skipping: landlock unavailable");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let sets = PathSets {
            rw: vec![dir.path().to_path_buf()],
            ro: vec![PathBuf::from("/usr"), PathBuf::from("/definitely/not/here")],
            io: vec![PathBuf::from("/dev/null")],
        };
        sets.build().expect("ruleset builds");
    }
}
