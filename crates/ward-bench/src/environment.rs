//! Runtime metadata collection (#150 item 2: "record image/source and
//! runtime metadata").

use std::process::Command;

use crate::report::Environment;

/// `WardOS`'s own workspace version, baked in at compile time from this
/// crate's `Cargo.toml`, which shares `workspace.package.version` with every
/// other crate here — so it is `ward`'s own version, not just this tool's.
const WARDOS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Collect what this process can learn about the host and checkout without
/// running anything that could take real time or touch the network.
#[must_use]
pub fn collect() -> Environment {
    Environment {
        wardos_version: WARDOS_VERSION.to_string(),
        git_commit: git_head(),
        git_dirty: git_dirty(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        kernel_release: kernel_release(),
        cpu_count: std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        ci: is_ci(),
        ci_runner_os: std::env::var("ImageOS")
            .ok()
            .or_else(|| std::env::var("RUNNER_OS").ok()),
    }
}

fn is_ci() -> bool {
    std::env::var_os("CI").is_some_and(|v| !v.is_empty())
        || std::env::var_os("GITHUB_ACTIONS").is_some_and(|v| !v.is_empty())
}

/// `git rev-parse HEAD`, best-effort: `None` for a non-git checkout, a
/// missing `git`, or any other failure — never an error, since this is
/// metadata, not something a benchmark run should fail over.
fn git_head() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Whether `git status --porcelain` reports anything, best-effort.
fn git_dirty() -> Option<bool> {
    let out = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(!out.stdout.is_empty())
}

/// `uname -r`, best-effort.
fn kernel_release() -> Option<String> {
    let out = Command::new("uname").arg("-r").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn collect_never_panics_and_fills_the_static_fields() {
        let env = collect();
        assert_eq!(env.wardos_version, WARDOS_VERSION);
        assert!(env.cpu_count >= 1);
        assert!(matches!(env.build_profile, "debug" | "release"));
    }
}
