//! Snapshot metadata: everything about a snapshot that is *not* part of its identity.
//!
//! The manifest determines the [`SnapshotId`]; the metadata records who captured it, in
//! which session, with which policy, and — informationally — what the worktree's `.git`
//! claimed at the time. Two snapshots of identical trees have identical ids and may have
//! different metadata (for instance different roles).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::capture::CapturePolicy;
use crate::hash::SnapshotId;

/// The lifecycle role of a snapshot (`docs/snapshots-and-git.md` §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Taken at session start (`ward up` / `ward claude`).
    Entry,
    /// Taken on a verification request.
    Candidate,
    /// A candidate that `TamperWard` accepted (same id, new role record).
    Accepted,
    /// Taken at session end (policy-controlled).
    Final,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Role::Entry => "entry",
            Role::Candidate => "candidate",
            Role::Accepted => "accepted",
            Role::Final => "final",
        })
    }
}

/// How the bytes were captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureMode {
    /// Read-only Btrfs subvolume snapshot; hashing happened off the frozen path.
    BtrfsSnapshot,
    /// Hashed and copied from the frozen tree (this crate's [`crate::capture`]).
    FrozenCopy,
}

impl std::fmt::Display for CaptureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CaptureMode::BtrfsSnapshot => "btrfs-snapshot",
            CaptureMode::FrozenCopy => "frozen-copy",
        })
    }
}

/// What the worktree's `.git` said at capture time.
///
/// **Informational only.** These values are read from an agent-controlled directory
/// (`docs/snapshots-and-git.md` §1). They exist because they are useful to humans and to
/// `TamperWard`'s reporting; no component in Zone 0/1/2 may make a trust decision from
/// them. In particular this crate never spawns `git` (which would execute hooks and
/// `core.fsmonitor` from an untrusted repository); [`GitContext::read`] parses `HEAD`,
/// loose refs and `packed-refs` as plain text and gives up quietly on anything else.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GitContext {
    /// The commit `HEAD` resolves to, if it could be resolved textually.
    pub head: Option<String>,
    /// The branch name from a symbolic `HEAD`, or `"detached"` when `HEAD` holds a sha.
    pub branch: Option<String>,
    /// Whether the worktree differed from `HEAD`. Determining this needs the index and
    /// tree comparison; it is `None` unless the caller supplies it from a trusted
    /// computation (for instance a diff between two snapshots).
    pub dirty: Option<bool>,
}

impl GitContext {
    /// Best-effort textual read of `<root>/.git`.
    ///
    /// Handles both a `.git` directory and a `.git` file (`gitdir: ...`, linked
    /// worktrees) — the latter only when the referenced directory is reachable. Any
    /// malformed or missing piece yields `None` fields rather than an error.
    #[must_use]
    pub fn read(root: &Path) -> GitContext {
        let mut ctx = GitContext::default();
        let Some(git_dir) = resolve_git_dir(root) else {
            return ctx;
        };
        let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) else {
            return ctx;
        };
        let head = head.trim();
        if let Some(reference) = head.strip_prefix("ref: ") {
            let reference = reference.trim();
            ctx.branch = Some(
                reference
                    .strip_prefix("refs/heads/")
                    .unwrap_or(reference)
                    .to_owned(),
            );
            ctx.head = resolve_ref(&git_dir, reference);
        } else if is_hex_sha(head) {
            ctx.branch = Some("detached".to_owned());
            ctx.head = Some(head.to_owned());
        }
        ctx
    }
}

fn resolve_git_dir(root: &Path) -> Option<std::path::PathBuf> {
    let dot_git = root.join(".git");
    let meta = std::fs::symlink_metadata(&dot_git).ok()?;
    if meta.is_dir() {
        return Some(dot_git);
    }
    if meta.is_file() {
        let text = std::fs::read_to_string(&dot_git).ok()?;
        let target = text.trim().strip_prefix("gitdir:")?.trim();
        let path = Path::new(target);
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            root.join(path)
        };
        // A linked worktree's git dir has `commondir` pointing at the shared repository;
        // HEAD lives in the linked dir, refs in the common dir. Reading HEAD from the
        // linked dir is enough for the informational fields.
        return std::fs::symlink_metadata(&resolved)
            .ok()
            .filter(std::fs::Metadata::is_dir)
            .map(|_| resolved);
    }
    None
}

fn resolve_ref(git_dir: &Path, reference: &str) -> Option<String> {
    if reference.contains("..") || reference.starts_with('/') {
        return None;
    }
    let candidates = [Some(git_dir.to_path_buf()), common_dir(git_dir)];
    for dir in candidates.iter().flatten() {
        if let Ok(text) = std::fs::read_to_string(dir.join(reference)) {
            let sha = text.trim();
            if is_hex_sha(sha) {
                return Some(sha.to_owned());
            }
        }
        if let Ok(packed) = std::fs::read_to_string(dir.join("packed-refs")) {
            for line in packed.lines() {
                let mut parts = line.split_whitespace();
                if let (Some(sha), Some(name)) = (parts.next(), parts.next())
                    && name == reference
                    && is_hex_sha(sha)
                {
                    return Some(sha.to_owned());
                }
            }
        }
    }
    None
}

fn common_dir(git_dir: &Path) -> Option<std::path::PathBuf> {
    let text = std::fs::read_to_string(git_dir.join("commondir")).ok()?;
    let p = Path::new(text.trim());
    Some(if p.is_absolute() {
        p.to_path_buf()
    } else {
        git_dir.join(p)
    })
}

fn is_hex_sha(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Metadata record stored next to a manifest (`docs/snapshots-and-git.md` §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// Merkle root of the manifest.
    pub id: SnapshotId,
    /// Stable project id (from `.ward/` or a path hash; assigned by `wardd`).
    pub project: String,
    /// Lifecycle role.
    pub role: Role,
    /// Session id (`sess_…`).
    pub session: String,
    /// RFC 3339 UTC timestamp with millisecond precision, e.g. `2026-09-07T22:14:03.118Z`.
    pub created: String,
    /// Capturing component and version, e.g. `wardd 0.1.0 (image digest sha256:…)`.
    pub captured_by: String,
    /// Capture mode.
    pub capture_mode: CaptureMode,
    /// Informational git context; never trusted (see [`GitContext`]).
    pub git_context: GitContext,
    /// The policy in force during capture.
    pub policy: CapturePolicy,
}

impl SnapshotMeta {
    /// Build a record with `created` set to now, an empty [`GitContext`] and the default
    /// [`CapturePolicy`]; use [`SnapshotMeta::with_git_context`] and
    /// [`SnapshotMeta::with_policy`] to fill those in.
    #[must_use]
    pub fn new(
        id: SnapshotId,
        project: impl Into<String>,
        role: Role,
        session: impl Into<String>,
        captured_by: impl Into<String>,
        capture_mode: CaptureMode,
    ) -> Self {
        SnapshotMeta {
            id,
            project: project.into(),
            role,
            session: session.into(),
            created: rfc3339_millis(SystemTime::now()),
            captured_by: captured_by.into(),
            capture_mode,
            git_context: GitContext::default(),
            policy: CapturePolicy::default(),
        }
    }

    /// Set the informational git context.
    #[must_use]
    pub fn with_git_context(mut self, git_context: GitContext) -> Self {
        self.git_context = git_context;
        self
    }

    /// Set the capture policy that was in force.
    #[must_use]
    pub fn with_policy(mut self, policy: CapturePolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// Format a time as RFC 3339 UTC with millisecond precision (`YYYY-MM-DDTHH:MM:SS.mmmZ`).
/// Times before the epoch clamp to the epoch.
#[must_use]
pub fn rfc3339_millis(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = d.as_secs();
    let millis = d.subsec_millis();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, dd) = civil_from_days(days);
    format!("{y:04}-{m:02}-{dd:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

/// Howard Hinnant's `civil_from_days`, for days since 1970-01-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339_millis(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(1_788_000_000_000 + 118);
        assert_eq!(rfc3339_millis(t), "2026-08-29T10:40:00.118Z");
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(rfc3339_millis(t), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn role_and_mode_serialise_as_documented() {
        assert_eq!(
            serde_json::to_string(&Role::Candidate).ok().as_deref(),
            Some("\"candidate\"")
        );
        assert_eq!(
            serde_json::to_string(&CaptureMode::BtrfsSnapshot)
                .ok()
                .as_deref(),
            Some("\"btrfs-snapshot\"")
        );
        assert_eq!(
            serde_json::to_string(&CaptureMode::FrozenCopy)
                .ok()
                .as_deref(),
            Some("\"frozen-copy\"")
        );
    }
}
