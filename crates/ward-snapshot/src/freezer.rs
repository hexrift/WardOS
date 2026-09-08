//! Freezing the tree's writers for the duration of a frozen-copy capture.
//!
//! The capture engine assumes a quiescent tree. Making it quiescent is the caller's job
//! (`wardd` freezes the whole session cgroup, which includes nested containers because
//! they live under it). This module defines the [`Freezer`] contract and two
//! implementations: [`NoopFreezer`] for trees that are already quiescent (Btrfs
//! read-only snapshots, tests, benchmarks) and [`CgroupV2Freezer`] for `cgroup.freeze`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Something that can stop and restart the processes writing to a worktree.
pub trait Freezer {
    /// Stop the writers. Must not return until they are stopped (or fail).
    ///
    /// # Errors
    /// Implementation-specific; [`crate::capture_with_freezer`] propagates it without
    /// capturing.
    fn freeze(&self) -> Result<()>;

    /// Restart the writers. Called exactly once after a successful `freeze`, even when
    /// the capture itself failed.
    ///
    /// # Errors
    /// Implementation-specific.
    fn thaw(&self) -> Result<()>;
}

/// A freezer that does nothing. Use when the tree is known to be quiescent.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopFreezer;

impl Freezer for NoopFreezer {
    fn freeze(&self) -> Result<()> {
        Ok(())
    }

    fn thaw(&self) -> Result<()> {
        Ok(())
    }
}

/// Freezes a cgroup v2 hierarchy by writing `1`/`0` to `<path>/cgroup.freeze`.
///
/// After writing `1` it waits (up to `settle_timeout`) for `cgroup.events` to report
/// `frozen 1`, because the write returns before every task has actually stopped. If
/// `cgroup.events` does not exist the wait is skipped. No privileged operation is
/// performed by this crate itself; whoever owns the cgroup directory decides whether the
/// write succeeds.
#[derive(Debug, Clone)]
pub struct CgroupV2Freezer {
    /// The cgroup directory (e.g. `/sys/fs/cgroup/ward/sess_…`).
    pub path: PathBuf,
    /// How long to wait for `frozen 1` after writing.
    pub settle_timeout: Duration,
}

impl CgroupV2Freezer {
    /// Freezer for the cgroup at `path` with a 2-second settle timeout.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        CgroupV2Freezer {
            path: path.into(),
            settle_timeout: Duration::from_secs(2),
        }
    }

    fn write_state(&self, value: &str) -> Result<()> {
        let file = self.path.join("cgroup.freeze");
        std::fs::write(&file, value)
            .map_err(|e| Error::Freezer(format!("write {value} to {}: {e}", file.display())))
    }

    fn wait_frozen(&self, want: bool) -> Result<()> {
        let events = self.path.join("cgroup.events");
        if !events.exists() {
            return Ok(());
        }
        let deadline = Instant::now() + self.settle_timeout;
        loop {
            if read_frozen(&events)? == Some(want) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Freezer(format!(
                    "{} did not report frozen {} within {:?}",
                    events.display(),
                    u8::from(want),
                    self.settle_timeout
                )));
            }
            std::thread::sleep(Duration::from_micros(200));
        }
    }
}

fn read_frozen(events: &Path) -> Result<Option<bool>> {
    let text = std::fs::read_to_string(events)
        .map_err(|e| Error::Freezer(format!("read {}: {e}", events.display())))?;
    Ok(text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("frozen"), Some("1")) => Some(true),
            (Some("frozen"), Some("0")) => Some(false),
            _ => None,
        }
    }))
}

impl Freezer for CgroupV2Freezer {
    fn freeze(&self) -> Result<()> {
        self.write_state("1")?;
        self.wait_frozen(true)
    }

    fn thaw(&self) -> Result<()> {
        self.write_state("0")?;
        self.wait_frozen(false)
    }
}
