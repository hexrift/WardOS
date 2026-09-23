//! Storage usage accounting and scratch-ownership reporting (`ward snapshot
//! usage`, #151).
//!
//! This module answers two read-only questions: how big is the state root
//! (broken down by category — shared blobs, manifests, snapshot metadata,
//! session logs), and which leftover `ward-*` scratch directories under the OS
//! temp dir belong to an operation that has definitely finished. It never
//! deletes, renames, or truncates anything. Actual reclamation of the CAS
//! categories this module reports on — conservative mark-and-sweep with leases
//! (#151 items 2–3) — lives in [`crate::retention`] and `ward_snapshot::gc`
//! instead (`ward snapshot gc`); reclaiming the leftover scratch directories
//! this module also reports on (startup reconciliation, #151 item 5) and a
//! low-space preflight (item 6) remain out of scope everywhere in this crate.
//!
//! Scratch liveness is deliberately never inferred from a process id or a
//! filesystem timestamp (the issue's own explicit constraint): only from
//! recorded state written by the code that created the scratch — the owner
//! marker [`crate::session::OWNER_MARKER`], whether a daemon currently answers
//! for that session ([`crate::daemon::serving`], a real socket handshake, not a
//! pid-file check), and whether that session's event log has been sealed
//! ([`ward_events::log::head_file_path`]).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ward_snapshot::{CasUsage, CategoryUsage, cas_usage_at};

use crate::daemon;
use crate::error::{Error, Result};
use crate::session::{OWNER_MARKER, session_dir};

/// Storage usage of one `$WARD_STATE_DIR`: the snapshot CAS categories plus
/// session logs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageUsage {
    /// Deduplicated file/symlink content (`cas/blobs`); shared across every
    /// snapshot that references it, so this is the store's real footprint for
    /// content, not the sum of what any one snapshot captured.
    pub blobs: CategoryUsage,
    /// Stored snapshot manifests (`cas/manifests`).
    pub manifests: CategoryUsage,
    /// Stored `(snapshot, role)` metadata records (`cas/meta`).
    pub meta: CategoryUsage,
    /// Every session's own `session.json` and `events.log` (and, once sealed,
    /// its `HEAD` file).
    pub session_logs: CategoryUsage,
}

impl StorageUsage {
    /// The four categories' combined bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.blobs.bytes + self.manifests.bytes + self.meta.bytes + self.session_logs.bytes
    }
}

/// Compute [`StorageUsage`] for `state` (`$WARD_STATE_DIR`). Read-only; walks
/// directory metadata only, never opens or hashes content, and never creates
/// `cas/` or any of its category directories — unlike `SnapshotStore::open`,
/// which exists to create them and would otherwise turn this report into a
/// mutation of a fresh or CAS-less state root.
pub fn compute(state: &Path) -> Result<StorageUsage> {
    let CasUsage {
        blobs,
        manifests,
        meta,
    } = cas_usage_at(state.join("cas")).map_err(|e| Error::Snapshot(e.to_string()))?;
    let session_logs = session_logs_usage(state)?;
    Ok(StorageUsage {
        blobs,
        manifests,
        meta,
        session_logs,
    })
}

/// Sum of every session directory's own files (never recursing into a nested
/// directory — a session directory holds no subdirectories today, but this
/// keeps a future one from being silently double-counted or mis-typed).
fn session_logs_usage(state: &Path) -> Result<CategoryUsage> {
    let sessions = state.join("sessions");
    let mut usage = CategoryUsage::default();
    let entries = match std::fs::read_dir(&sessions) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(usage),
        Err(e) => return Err(Error::io(&sessions, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(&sessions, e))?;
        let file_type = entry.file_type().map_err(|e| Error::io(&sessions, e))?;
        if file_type.is_dir() {
            add_dir_files(&entry.path(), &mut usage)?;
        }
    }
    Ok(usage)
}

/// Add every regular file directly inside `dir` to `usage` (not recursive; a
/// control socket there is a socket, not a file, so `file_type().is_file()`
/// already excludes it without a special case).
fn add_dir_files(dir: &Path, usage: &mut CategoryUsage) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        // Tolerate a concurrent remover (this session's own cleanup, another
        // `ward` process) taking the entry out from under us; see the matching
        // comment in `ward_snapshot::cas::walk_dir_usage`.
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::io(dir, e)),
        };
        if file_type.is_file() {
            let len = match entry.metadata() {
                Ok(m) => m.len(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Error::io(dir, e)),
            };
            usage.objects += 1;
            usage.bytes += len;
        }
    }
    Ok(())
}

/// One `ward-*` scratch directory found under the OS temp dir
/// ([`crate::session::run_dir_path`]'s naming), with what the scan could
/// establish about who owns it and whether it is still needed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchEntry {
    /// The scratch directory's path.
    pub path: PathBuf,
    /// The full session id recorded in its owner marker, when legible.
    pub owner: Option<String>,
    /// Total bytes found under `path`, or `None` if some part of it could
    /// not be read (a subdirectory this process lacks permission for, most
    /// sharply) — deliberately not `0`, which would be indistinguishable
    /// from a fully-inspected, genuinely empty entry. A `None` here always
    /// accompanies [`ScratchStatus::Unknown`], but the reverse isn't true:
    /// `Unknown` alone (an absent or unparseable owner marker on an
    /// otherwise fully readable entry) still carries a real `Some` count.
    pub bytes: Option<u64>,
    /// What the scan could establish about its liveness.
    pub status: ScratchStatus,
}

/// How a scratch entry's owning operation was classified. See the module docs
/// for why this is never derived from a PID or an mtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScratchStatus {
    /// A daemon currently answers for the owning session: this scratch may be
    /// in active use behind it. Never a candidate for reclamation.
    Active,
    /// The owning session's event log is sealed — `SessionEnded` (or an
    /// equivalent stop) was already recorded and fsynced — so the one `ward`
    /// invocation that created this scratch had, by then, already finished.
    /// Anything still here afterward was never cleaned up: most likely that
    /// process was interrupted (killed, crashed) between finishing its work
    /// and its own `remove_dir_all`.
    Orphaned,
    /// No daemon answers for the owner and its log is not sealed, or ownership
    /// could not be established at all (no marker, or a marker naming a
    /// session with no record on disk). This may be a still-running
    /// foreground command with no daemon behind it; the honest answer is "not
    /// established", so it is never treated as reclaimable.
    Unknown,
}

/// List every `ward-*` scratch directory under the OS temp dir and classify
/// each against `state` (`$WARD_STATE_DIR`). Read-only: sums file sizes and
/// reads each entry's owner marker, never opens, follows, or removes anything
/// else. A directory whose name collides with WardOS's own (`ward-*`) but that
/// something else created is indistinguishable from ours by name alone; its
/// owner marker will simply be absent or unparseable, and it is reported as
/// [`ScratchStatus::Unknown`] rather than guessed at. A single entry this
/// process cannot fully read (another local user's own `ward-*`-prefixed
/// directory, made unreadable to us, most sharply) is likewise reported as
/// `Unknown` rather than aborting the scan of everything else in `/tmp` —
/// see [`scan_one_entry`].
pub fn scan_scratch(state: &Path) -> Result<Vec<ScratchEntry>> {
    let temp = std::env::temp_dir();
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&temp) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error::io(&temp, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(&temp, e))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with("ward-") {
            continue;
        }
        // `file_type()` does not follow a symlink, so a `ward-*` name planted as
        // a symlink by another local user (shared, world-writable temp dir) is
        // excluded here rather than traversed into. It is still only a first
        // look, not a guarantee about what `open_dir_no_symlink` below finds a
        // moment later — see that function's own doc comment for the race this
        // alone cannot close.
        let Ok(file_type) = entry.file_type() else {
            continue; // vanished between readdir and stat; nothing to report
        };
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        match open_dir_no_symlink(&path) {
            Ok(dir) => {
                let owner = read_owner_marker(&dir);
                out.push(scan_one_entry(state, path, owner, dir, sum_dir_bytes));
            }
            Err(_) => {
                // Vanished, permission-denied, or — the race this guards
                // against — replaced with a symlink or a non-directory in the
                // window between the `file_type()` lstat above and this open:
                // `O_NOFOLLOW | O_DIRECTORY` refuses exactly that atomically,
                // rather than silently traversing into whatever now sits at
                // this name. Reported the same way any other uninspectable
                // entry is: no owner read, no bytes summed, `Unknown`.
                out.push(ScratchEntry {
                    path,
                    owner: None,
                    bytes: None,
                    status: ScratchStatus::Unknown,
                });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Open `dir` for reading, refusing atomically — no separate check-then-open
/// window for a concurrent replacement to land in — if its final path
/// component is not, at the instant of the open, a real directory: not a
/// symlink (`O_NOFOLLOW`), not a plain file, FIFO, socket or device
/// (`O_DIRECTORY`). The OS temp dir is shared and world-writable, so a
/// co-resident user can rename the directory an earlier `lstat`/`file_type()`
/// checked and put a symlink (to, say, another user's private tree) in its
/// place before a naive second `open`/`read_dir` by path gets to it; the
/// caller here holds the resulting descriptor for every further read against
/// this entry ([`read_owner_marker`], [`sum_dir_bytes`]) instead of ever
/// reopening it by path again.
fn open_dir_no_symlink(dir: &Path) -> std::result::Result<nix::dir::Dir, nix::Error> {
    nix::dir::Dir::open(
        dir,
        nix::fcntl::OFlag::O_RDONLY
            | nix::fcntl::OFlag::O_DIRECTORY
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
}

/// Build one [`ScratchEntry`], containing any traversal failure to just this
/// entry. `sum` is [`sum_dir_bytes`] in production, injected here so the
/// containment behaviour below is directly testable with a synthetic error —
/// a real permission-denied fixture would be silently bypassed in a test
/// suite that happens to run as root, where `EACCES` never fires.
///
/// The OS temp dir is shared: another local user's `ward-*`-prefixed entry
/// (or one of ours that raced a concurrent remover) can contain a
/// subdirectory we cannot read — most sharply, an attacker-owned
/// `/tmp/ward-*` made deliberately unreadable to us. Before this existed,
/// that single entry's traversal error propagated out of the whole scan,
/// so one uninspectable directory anywhere in `/tmp` denied `ward snapshot
/// usage` entirely, including every one of the caller's own legitimate
/// entries. A traversal failure here is therefore never propagated: the
/// byte count from whatever was summed before the failure is discarded
/// (never presented as if it were the exact, complete total), and the
/// status is forced to `Unknown` — the same "not established" answer an
/// absent or unparseable owner marker already gets — regardless of what
/// the owner marker on its own would otherwise have classified as.
fn scan_one_entry(
    state: &Path,
    path: PathBuf,
    owner: Option<String>,
    dir: nix::dir::Dir,
    sum: impl FnOnce(nix::dir::Dir, &mut u64) -> Result<()>,
) -> ScratchEntry {
    let mut summed = 0u64;
    let (bytes, status) = if sum(dir, &mut summed).is_ok() {
        (Some(summed), classify(state, owner.as_deref()))
    } else {
        (None, ScratchStatus::Unknown)
    };
    ScratchEntry {
        path,
        owner,
        bytes,
        status,
    }
}

/// Generous headroom over the exact text a real owner marker ever contains
/// (`sess_` + a 26-character Crockford ULID body = 31 bytes) plus whatever
/// trailing whitespace/newline a text editor or shell redirect might add.
/// Anything longer is refused outright rather than read to EOF: the marker
/// is untrusted, attacker-controlled input from a shared, world-writable
/// directory, and an unbounded read would let it force arbitrary memory
/// growth.
const MAX_OWNER_MARKER_LEN: usize = 128;

/// The full session id [`crate::session::run_dir`] recorded as this
/// directory's owner, if the marker is present, non-empty, a real regular
/// file — never a symlink, FIFO, socket or device — and no longer than
/// [`MAX_OWNER_MARKER_LEN`]. The OS temp dir is shared and world-writable, so
/// another local user can plant `<ward-*>/.ward-owner` as:
///
/// - a symlink to an arbitrary path (e.g. a victim's private key), which
///   would disclose that target's content verbatim as this entry's reported
///   owner — refused atomically by the `O_NOFOLLOW` open itself, so there is
///   no separate check-then-read window to race;
/// - a FIFO, which a plain blocking open-for-read would wait on forever if
///   nothing has it open for writing, hanging the whole usage scan —
///   refused by opening with `O_NONBLOCK` (so the open itself can never
///   block) and then `fstat`ing the already-open descriptor (not re-stating
///   the path, which would reopen the TOCTOU window) to require a regular
///   file before any read is attempted;
/// - an oversized regular file, which an unbounded read would load into
///   memory in full — refused by capping the read at
///   [`MAX_OWNER_MARKER_LEN`] `+ 1` bytes and rejecting anything that fills
///   that cap, rather than silently truncating and treating a cut-off
///   marker as legitimate.
///
/// Anything that doesn't clear all of the above is treated exactly like a
/// missing marker.
///
/// Takes `dir` as an already-open directory descriptor
/// ([`open_dir_no_symlink`]), not a path: `O_NOFOLLOW` on opening the marker
/// itself only refuses a symlinked *final* component, not a directory
/// component earlier in the path — a co-resident user who renames `dir`'s own
/// directory out from under a path-based open and puts a symlink in its place
/// would otherwise still be followed. Resolving the marker with `openat`
/// against a descriptor obtained before that swap could happen closes that
/// window: the descriptor keeps referring to the directory it was opened
/// against regardless of what a later rename does to the name that used to
/// point at it.
fn read_owner_marker(dir: &nix::dir::Dir) -> Option<String> {
    use std::io::Read;

    let fd = nix::fcntl::openat(
        dir,
        OWNER_MARKER,
        nix::fcntl::OFlag::O_RDONLY
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_NONBLOCK
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .ok()?;
    let file = std::fs::File::from(fd);
    // `fstat`s the descriptor we already hold open, not the path again — the
    // object this checks is exactly the object the read below reads from,
    // with no window for it to have been swapped in between.
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    file.take(MAX_OWNER_MARKER_LEN as u64 + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > MAX_OWNER_MARKER_LEN {
        return None;
    }
    let text = std::str::from_utf8(&buf).ok()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Sum every regular file's size under the already-open directory `dir`
/// ([`open_dir_no_symlink`]), recursing into subdirectories. Iterative (an
/// explicit worklist, not self-recursion): `dir` is under the shared,
/// world-writable OS temp dir, so another local user can create an
/// arbitrarily deep chain of nested directories there with no filesystem
/// depth limit low enough to stop them; a call-stack recursion over that
/// input is a local stack-overflow DoS reachable by any co-resident user.
///
/// Every subdirectory is opened `openat`-relative to its own already-open
/// parent descriptor, with the same `O_NOFOLLOW | O_DIRECTORY` guarantee
/// `open_dir_no_symlink` documents: the walk only ever descends through real
/// directories, resolved beneath a descriptor this process already holds,
/// never by re-resolving a path (`dir_a/dir_b/dir_c`) from the top on every
/// step. A co-resident user renaming `dir_b` out and putting a symlink in
/// its place between this walk listing `dir_a` and descending into `dir_b`
/// therefore cannot redirect the walk anywhere: the `openat` for `dir_b`
/// checks *its* own final component against *`dir_a`'s* descriptor at the
/// moment of that call, not against whatever `dir_a/dir_b` resolves to if
/// walked fresh from the root. Each entry's type and size are read together
/// via one `fstatat(..., AT_SYMLINK_NOFOLLOW)` — the same object the
/// subsequent `openat` (for a directory) or byte count (for a regular file)
/// then acts on, with no separate stat-then-open step for either to race.
fn sum_dir_bytes(dir: nix::dir::Dir, total: &mut u64) -> Result<()> {
    // The `PathBuf` alongside each descriptor is display-only, for error
    // messages; every actual read below goes through the descriptor, never a
    // re-resolved path.
    let mut stack = vec![(PathBuf::from("."), dir)];
    while let Some((path, mut dh)) = stack.pop() {
        // `Dir::iter` needs `&mut dh`, and the `fstatat`/`openat` calls below
        // need their own borrow of `dh` too (as `Fd: AsFd`) — so every name
        // is collected into an owned buffer first, ending the iterator's
        // mutable borrow, before `dh` is borrowed again (immutably, any
        // number of times) for the actual per-entry work below.
        let mut names = Vec::new();
        for entry in dh.iter() {
            let entry = entry
                .map_err(std::io::Error::from)
                .map_err(|e| Error::io(&path, e))?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            names.push(name.to_owned());
        }
        for name in &names {
            let child_path = path.join(std::str::from_utf8(name.to_bytes()).unwrap_or("?"));
            let st = match nix::sys::stat::fstatat(
                &dh,
                name.as_c_str(),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            ) {
                Ok(st) => st,
                // Vanished between readdir and stat (a concurrent remover —
                // this session's own cleanup, another `ward` process): see
                // the matching comment in `add_dir_files`.
                Err(nix::Error::ENOENT) => continue,
                Err(e) => return Err(Error::io(&child_path, std::io::Error::from(e))),
            };
            // `st_mode`'s type bits are a field (masked by `S_IFMT`), not
            // independent flags: `S_IFLNK`'s own bit pattern is a superset of
            // `S_IFREG`'s, so a bitflags `.contains(S_IFREG)` on the raw mode
            // would wrongly read true for a symlink too. Masking first and
            // comparing the extracted type for exact equality is what a
            // symlink actually needs to fall through both arms below.
            let file_type = nix::sys::stat::SFlag::from_bits_truncate(
                st.st_mode & nix::sys::stat::SFlag::S_IFMT.bits(),
            );
            if file_type == nix::sys::stat::SFlag::S_IFDIR {
                match nix::dir::Dir::openat(
                    &dh,
                    name.as_c_str(),
                    nix::fcntl::OFlag::O_RDONLY
                        | nix::fcntl::OFlag::O_DIRECTORY
                        | nix::fcntl::OFlag::O_NOFOLLOW
                        | nix::fcntl::OFlag::O_CLOEXEC,
                    nix::sys::stat::Mode::empty(),
                ) {
                    Ok(sub) => stack.push((child_path, sub)),
                    // Vanished, or `fstatat` above raced a replacement of this
                    // exact name with a symlink/non-directory in the instant
                    // before this `openat` — refused atomically by the same
                    // `O_NOFOLLOW | O_DIRECTORY` guarantee, rather than ever
                    // being followed.
                    Err(nix::Error::ENOENT | nix::Error::ELOOP | nix::Error::ENOTDIR) => {}
                    Err(e) => return Err(Error::io(&child_path, std::io::Error::from(e))),
                }
            } else if file_type == nix::sys::stat::SFlag::S_IFREG {
                *total += u64::try_from(st.st_size).unwrap_or(0);
            }
        }
    }
    Ok(())
}

/// Classify one scratch entry's owning operation (see [`ScratchStatus`]).
///
/// `owner` is untrusted: it comes verbatim from a marker file inside a
/// shared, world-writable directory, with only `trim()` + non-empty checks
/// applied by [`read_owner_marker`]. Before it reaches a path join
/// ([`session_dir`]) or a socket lookup ([`daemon::serving`]), it must parse
/// as an actual [`ward_events::SessionId`] — the same `sess_<26-char
/// Crockford ULID>` shape [`crate::ids::new_session_id`] generates. Without
/// this, a marker containing e.g. `../../../../etc` would let
/// `session_dir`/`socket_path` resolve outside `sessions/`, turning this
/// read-only report into a path-traversal existence oracle (via
/// `head_file_path(..).exists()`) and letting an attacker who can bind a
/// Unix socket at a path of their choosing spoof `ScratchStatus::Active`.
/// Anything that doesn't parse is `Unknown`, exactly like an absent marker.
fn classify(state: &Path, owner: Option<&str>) -> ScratchStatus {
    let Some(owner) = owner else {
        return ScratchStatus::Unknown;
    };
    if owner.parse::<ward_events::SessionId>().is_err() {
        return ScratchStatus::Unknown;
    }
    if daemon::serving(state, owner) {
        return ScratchStatus::Active;
    }
    let log_path = session_dir(state, owner).join("events.log");
    if ward_events::log::head_file_path(&log_path).exists() {
        ScratchStatus::Orphaned
    } else {
        ScratchStatus::Unknown
    }
}

/// Total bytes of every entry classified [`ScratchStatus::Orphaned`]. An
/// `Orphaned` entry always has a `Some` byte count in practice (the status
/// itself is only ever reached once the entry has been fully summed — see
/// [`scan_one_entry`]), but this sums only the `Some` values regardless,
/// rather than assuming that invariant here too.
#[must_use]
pub fn orphaned_bytes(entries: &[ScratchEntry]) -> u64 {
    entries
        .iter()
        .filter(|e| e.status == ScratchStatus::Orphaned)
        .filter_map(|e| e.bytes)
        .sum()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn compute_reports_zero_on_an_empty_state_root() {
        let state = tempfile::tempdir().unwrap();
        let usage = compute(state.path()).unwrap();
        assert_eq!(usage, StorageUsage::default());
        assert_eq!(usage.total_bytes(), 0);
    }

    #[test]
    fn compute_never_creates_anything_under_an_empty_or_cas_less_state_root() {
        // `ward snapshot usage`'s whole contract is read-only (see the module
        // doc comment and `compute`'s own doc comment). Before `cas_usage_at`
        // existed, `compute` reached `SnapshotStore::open`/`Cas::open`, whose
        // entire purpose is to *create* `cas/{blobs,manifests,meta}` — so a
        // usage report against an empty state root silently wrote three
        // directories to it. Snapshotting the state root's own tree before
        // and after (not just the numeric result, which this bug never
        // affected) is what actually catches that: an assertion on `usage`
        // alone regressed silently the first time.
        let state = tempfile::tempdir().unwrap();
        let before = list_tree(state.path());
        assert!(
            before.is_empty(),
            "the fixture itself must start truly empty"
        );

        let usage = compute(state.path()).unwrap();
        assert_eq!(usage, StorageUsage::default());

        let after = list_tree(state.path());
        assert_eq!(
            after, before,
            "a read-only usage report must never create so much as one \
             directory under the state root: {after:?}"
        );
    }

    /// Every path under `root`, relative to it, sorted — used to assert a
    /// supposedly read-only call left the tree byte-for-byte/path-for-path
    /// unchanged.
    fn list_tree(root: &Path) -> Vec<PathBuf> {
        fn walk(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                out.push(path.strip_prefix(root).unwrap().to_path_buf());
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    walk(&path, root, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    #[test]
    fn compute_counts_cas_and_session_log_bytes() {
        let state = tempfile::tempdir().unwrap();
        let store = ward_snapshot::SnapshotStore::open(state.path().join("cas")).unwrap();
        let worktree = tempfile::tempdir().unwrap();
        std::fs::write(worktree.path().join("f"), b"some content").unwrap();
        store
            .store_snapshot(
                worktree.path(),
                ward_snapshot::SnapshotRole::Entry,
                ward_snapshot::CaptureOptions::default(),
            )
            .unwrap();

        let dir = session_dir(state.path(), "sess_usage_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.json"), b"{}").unwrap();
        std::fs::write(dir.join("events.log"), b"pretend-log-bytes").unwrap();

        let usage = compute(state.path()).unwrap();
        assert!(usage.blobs.objects >= 1, "the captured file was stored");
        assert!(usage.manifests.objects >= 1);
        assert!(usage.meta.objects >= 1);
        assert_eq!(usage.session_logs.objects, 2);
        assert_eq!(
            usage.session_logs.bytes,
            (b"{}".len() + b"pretend-log-bytes".len()) as u64
        );
        assert_eq!(
            usage.total_bytes(),
            usage.blobs.bytes + usage.manifests.bytes + usage.meta.bytes + usage.session_logs.bytes
        );
    }

    #[test]
    fn scan_scratch_ignores_directories_that_are_not_wards() {
        let state = tempfile::tempdir().unwrap();
        let unrelated = std::env::temp_dir().join(format!("not-ward-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&unrelated);
        std::fs::create_dir_all(&unrelated).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        assert!(
            entries.iter().all(|e| e.path != unrelated),
            "a non-`ward-` prefixed directory must never be reported"
        );

        std::fs::remove_dir_all(&unrelated).unwrap();
    }

    #[test]
    fn a_scratch_dir_with_no_owner_marker_is_unknown() {
        let state = tempfile::tempdir().unwrap();
        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-nomarker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("payload"), vec![b'x'; 10]).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.owner, None);
        assert_eq!(entry.status, ScratchStatus::Unknown);
        assert_eq!(
            entry.bytes,
            Some(10),
            "fully readable, just unrecorded: a real byte count, not None — \
             None is reserved for an entry that could not be inspected at all"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_scratch_dir_owned_by_an_unrecorded_session_is_unknown() {
        let state = tempfile::tempdir().unwrap();
        let dir = std::env::temp_dir().join(format!("ward-usagetest-ghost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Well-formed (a real `SessionId`'s own textual shape), just never
        // recorded anywhere on disk.
        let owner = ward_events::SessionId::from_u128(0x1234).to_string();
        std::fs::write(dir.join(OWNER_MARKER), &owner).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.owner.as_deref(), Some(owner.as_str()));
        assert_eq!(
            entry.status,
            ScratchStatus::Unknown,
            "no daemon, no sealed log: this could still be a running foreground command"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_scratch_dir_whose_owner_marker_does_not_parse_as_a_session_id_is_unknown() {
        // A marker that isn't a real `SessionId`'s textual shape must never
        // reach `session_dir`/`daemon::serving`'s path joins — see the doc
        // comment on `classify`. A path-traversal payload is the sharpest
        // instance: if it were joined in unchecked, `session_dir` would
        // resolve outside `sessions/`, turning this read-only report into an
        // existence oracle for an attacker-chosen path.
        let state = tempfile::tempdir().unwrap();
        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-traversal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(OWNER_MARKER), "../../../../etc/passwd").unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.owner.as_deref(), Some("../../../../etc/passwd"));
        assert_eq!(
            entry.status,
            ScratchStatus::Unknown,
            "a marker that isn't a real SessionId's shape must classify as Unknown, \
             never reach a path join"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_scratch_dir_whose_owner_marker_is_a_symlink_is_treated_as_unset() {
        // The OS temp dir is shared and world-writable: another local user
        // can plant `.ward-owner` as a symlink to an arbitrary file (e.g. a
        // victim's private key). Reading through it would disclose that
        // file's content verbatim as this entry's reported owner — see the
        // doc comment on `read_owner_marker`.
        let state = tempfile::tempdir().unwrap();
        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let secret = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            secret.path(),
            "sess_should_never_be_disclosed_via_a_symlink",
        )
        .unwrap();
        std::os::unix::fs::symlink(secret.path(), dir.join(OWNER_MARKER)).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(
            entry.owner, None,
            "a symlinked marker must never be followed or its target disclosed"
        );
        assert_eq!(entry.status, ScratchStatus::Unknown);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_scratch_dir_whose_owner_marker_is_a_fifo_with_no_writer_returns_promptly_as_unset() {
        // A FIFO with no writer open would block a plain `open(O_RDONLY)`
        // forever; this test itself would hang if `read_owner_marker` ever
        // regressed to opening without `O_NONBLOCK`, rather than failing
        // cleanly — which is exactly why the fix opens non-blocking and
        // `fstat`s the descriptor before ever attempting a read.
        let state = tempfile::tempdir().unwrap();
        let dir = std::env::temp_dir().join(format!("ward-usagetest-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        nix::unistd::mkfifo(
            &dir.join(OWNER_MARKER),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(
            entry.owner, None,
            "a FIFO marker must never be read from, with or without a writer"
        );
        assert_eq!(entry.status, ScratchStatus::Unknown);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_oversized_owner_marker_is_rejected_rather_than_truncated() {
        let state = tempfile::tempdir().unwrap();
        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-oversized-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // One byte over the cap: large enough to prove the read is bounded
        // (not merely large by accident), too small to make the test slow.
        std::fs::write(dir.join(OWNER_MARKER), vec![b'A'; MAX_OWNER_MARKER_LEN + 1]).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(
            entry.owner, None,
            "a marker over the length cap must be refused outright, never truncated \
             and treated as a legitimate (if garbled) owner"
        );
        assert_eq!(entry.status, ScratchStatus::Unknown);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_traversal_failure_on_one_entry_is_contained_to_that_entry() {
        // A synthetic failure, not a real permission-denied fixture: a test
        // suite that happens to run as root would never actually see EACCES
        // from chmod 000 (root bypasses the DAC check), which would make a
        // permission-bit-based regression silently pass for the wrong
        // reason in exactly the environment most likely to run CI as root.
        // Injecting the error directly exercises the containment logic
        // itself, independent of who's running the test.
        let state = tempfile::tempdir().unwrap();
        let path = PathBuf::from("/tmp/ward-synthetic-failure");
        let owner = Some("sess_irrelevant".to_owned());
        // A real, harmless directory to open — the failure itself is
        // injected via `sum` below, not by anything about this directory.
        let scratch = tempfile::tempdir().unwrap();
        let dir = open_dir_no_symlink(scratch.path()).unwrap();

        let entry = scan_one_entry(state.path(), path.clone(), owner, dir, |_, _| {
            Err(Error::io(
                &path,
                std::io::Error::other("EACCES (synthetic)"),
            ))
        });

        assert_eq!(entry.path, path);
        assert_eq!(
            entry.bytes, None,
            "a partial sum from before the failure must never be reported as an \
             exact (and, worse, indistinguishable-from-genuinely-empty) 0"
        );
        assert_eq!(
            entry.status,
            ScratchStatus::Unknown,
            "an entry that could not be fully traversed is not established, \
             whatever its owner marker on its own would otherwise say"
        );
    }

    #[test]
    fn an_unreadable_entry_does_not_prevent_a_healthy_sibling_from_being_reported() {
        if nix::unistd::geteuid().is_root() {
            eprintln!("skipping: root bypasses the directory permission bits this needs");
            return;
        }
        let state = tempfile::tempdir().unwrap();

        let denied =
            std::env::temp_dir().join(format!("ward-usagetest-denied-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&denied);
        std::fs::create_dir_all(&denied).unwrap();
        std::fs::create_dir(denied.join("unreadable")).unwrap();
        std::fs::write(denied.join("unreadable").join("payload"), b"secret").unwrap();
        std::fs::set_permissions(
            denied.join("unreadable"),
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .unwrap();

        let healthy =
            std::env::temp_dir().join(format!("ward-usagetest-healthy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&healthy);
        std::fs::create_dir_all(&healthy).unwrap();
        std::fs::write(healthy.join("payload"), vec![b'h'; 9]).unwrap();

        let result = scan_scratch(state.path());

        // Restore permissions before any assertion can early-return, so
        // cleanup always runs even if an assertion below fails.
        std::fs::set_permissions(
            denied.join("unreadable"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();

        let entries = result.unwrap();
        let denied_entry = entries.iter().find(|e| e.path == denied).unwrap();
        assert_eq!(denied_entry.status, ScratchStatus::Unknown);
        assert_eq!(
            denied_entry.bytes, None,
            "the unreadable entry's own size must be reported as unavailable, \
             never as 0"
        );
        let healthy_entry = entries.iter().find(|e| e.path == healthy).unwrap();
        assert_eq!(
            healthy_entry.bytes,
            Some(9),
            "an unrelated unreadable entry elsewhere in the temp dir must not \
             degrade a healthy entry's own report"
        );

        std::fs::remove_dir_all(&denied).unwrap();
        std::fs::remove_dir_all(&healthy).unwrap();
    }

    #[test]
    fn sum_dir_bytes_handles_a_deeply_nested_tree_without_recursing_on_the_call_stack() {
        // Not a literal stack-overflow reproduction (that would abort the
        // whole test process rather than fail cleanly) — this proves the
        // iterative worklist walk produces the right answer over a tree far
        // deeper than a routine one, which self-recursion could not do
        // without growing the call stack proportionally.
        let mut dir = tempfile::tempdir().unwrap().keep();
        let root = dir.clone();
        // Bounded by PATH_MAX (each level adds "d/" to the absolute path),
        // not by any property of the walk itself — comfortably deeper than
        // any real scratch-directory tree, which is the point.
        for _ in 0..1500 {
            dir.push("d");
            std::fs::create_dir(&dir).unwrap();
        }
        std::fs::write(dir.join("leaf"), vec![b'z'; 7]).unwrap();

        let mut total = 0u64;
        sum_dir_bytes(open_dir_no_symlink(&root).unwrap(), &mut total).unwrap();
        assert_eq!(total, 7);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_scratch_dir_whose_owner_session_is_sealed_is_orphaned() {
        let state = tempfile::tempdir().unwrap();
        let owner = ward_events::SessionId::from_u128(0x005e_a1ed).to_string();
        let log_dir = session_dir(state.path(), &owner);
        std::fs::create_dir_all(&log_dir).unwrap();
        let log_path = log_dir.join("events.log");
        std::fs::write(&log_path, b"sealed log contents").unwrap();
        // `LocalLog::seal` writes the chain head to this exact sibling path; a
        // usage scan only ever checks whether it exists (see `classify`), so
        // reproducing just that fact is a faithful, minimal fixture.
        std::fs::write(ward_events::log::head_file_path(&log_path), b"head").unwrap();

        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-sealed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(OWNER_MARKER), owner.as_bytes()).unwrap();
        std::fs::write(dir.join("socket-standin"), vec![b'y'; 5]).unwrap();
        // The marker itself is a real file under `dir` too, so it counts toward
        // the entry's bytes exactly like any other leftover scratch content.
        let expected_bytes = owner.len() as u64 + 5;

        // The real OS temp dir is shared with every other test in this binary
        // (and, in principle, any other WardOS process on the machine), so only
        // this one entry's own numbers are asserted here — `orphaned_bytes`'s
        // summation itself is covered in isolation below.
        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.status, ScratchStatus::Orphaned);
        assert_eq!(entry.bytes, Some(expected_bytes));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn orphaned_bytes_sums_only_the_orphaned_entries() {
        let entries = vec![
            ScratchEntry {
                path: PathBuf::from("/tmp/ward-a"),
                owner: Some("sess_a".to_owned()),
                bytes: Some(10),
                status: ScratchStatus::Orphaned,
            },
            ScratchEntry {
                path: PathBuf::from("/tmp/ward-b"),
                owner: Some("sess_b".to_owned()),
                bytes: Some(1000),
                status: ScratchStatus::Active,
            },
            ScratchEntry {
                path: PathBuf::from("/tmp/ward-c"),
                owner: None,
                bytes: Some(5000),
                status: ScratchStatus::Unknown,
            },
            ScratchEntry {
                path: PathBuf::from("/tmp/ward-d"),
                owner: Some("sess_d".to_owned()),
                bytes: Some(20),
                status: ScratchStatus::Orphaned,
            },
            // An unreadable entry must never contribute to the orphaned
            // total, even hypothetically: it's never Orphaned in practice
            // (scan_one_entry always pairs `None` with `Unknown`), but
            // `orphaned_bytes` filters on `Some` regardless of that
            // invariant — see its own doc comment.
            ScratchEntry {
                path: PathBuf::from("/tmp/ward-e"),
                owner: None,
                bytes: None,
                status: ScratchStatus::Unknown,
            },
        ];
        assert_eq!(
            orphaned_bytes(&entries),
            30,
            "only the two Orphaned entries (10 + 20) count; Active and Unknown never do"
        );
    }

    #[test]
    fn an_unavailable_byte_count_serializes_as_json_null_never_as_zero() {
        // The `--json` CLI output serializes `ScratchEntry` directly (see
        // `ward-cli`'s `cmd_snapshot_usage`), so this is the same shape a
        // JSON consumer of `ward snapshot usage --json` actually receives.
        let unreadable = ScratchEntry {
            path: PathBuf::from("/tmp/ward-unreadable"),
            owner: None,
            bytes: None,
            status: ScratchStatus::Unknown,
        };
        let readable_empty = ScratchEntry {
            path: PathBuf::from("/tmp/ward-empty"),
            owner: None,
            bytes: Some(0),
            status: ScratchStatus::Unknown,
        };

        let unreadable_json = serde_json::to_value(&unreadable).unwrap();
        assert_eq!(
            unreadable_json["bytes"],
            serde_json::Value::Null,
            "an uninspectable entry must serialize its size as JSON null, \
             never as the number 0 — a JSON consumer must be able to tell \
             it apart from a genuinely empty entry: {unreadable_json}"
        );

        let readable_empty_json = serde_json::to_value(&readable_empty).unwrap();
        assert_eq!(
            readable_empty_json["bytes"],
            serde_json::json!(0),
            "a fully inspected, genuinely empty entry must still serialize \
             as the real number 0, not be conflated with the unavailable \
             case above: {readable_empty_json}"
        );
    }

    #[test]
    fn a_scratch_dir_whose_owner_session_a_daemon_is_serving_is_active_even_though_unsealed() {
        use crate::control::Response;
        use crate::daemon::bind_socket;

        let state = tempfile::tempdir().unwrap();
        let owner = ward_events::SessionId::from_u128(0x00ac_71fe).to_string();
        let log_dir = session_dir(state.path(), &owner);
        std::fs::create_dir_all(&log_dir).unwrap();
        // Deliberately unsealed: an active session's log has no HEAD file yet.
        // Were `classify` to check the log before the daemon, this would
        // wrongly read as `Orphaned`; the daemon-serving check must win.
        std::fs::write(log_dir.join("events.log"), b"open log, no seal").unwrap();

        let socket = crate::control::SOCKET_NAME;
        let listener = bind_socket(&log_dir.join(socket)).unwrap();
        let server = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                // Answer exactly one `Ping` the way `RemoteSink::connect`'s
                // handshake expects, then let the connection close.
                use std::io::{BufRead, BufReader, Write};
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    let mut resp = serde_json::to_vec(&Response::Ok).unwrap();
                    resp.push(b'\n');
                    let _ = writer.write_all(&resp);
                }
            }
        });

        let dir =
            std::env::temp_dir().join(format!("ward-usagetest-active-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(OWNER_MARKER), owner.as_bytes()).unwrap();

        let entries = scan_scratch(state.path()).unwrap();
        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert_eq!(entry.status, ScratchStatus::Active);

        server.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_dir_no_symlink_refuses_a_symlinked_target() {
        // The shape a swap race leaves behind at the instant this scan reaches
        // it: a co-resident user renamed the real directory out and put a
        // symlink in its place. `open_dir_no_symlink` is what every entry —
        // top-level `ward-*` and every nested directory `sum_dir_bytes` opens
        // via the same guarantee — is opened through, so refusing this is
        // what keeps the whole walk from ever being redirected.
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("secret"), b"do not disclose").unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(
            open_dir_no_symlink(&link).is_err(),
            "a symlinked target must never be opened as if it were the real directory"
        );
        // The genuine directory underneath is unaffected — this isn't a
        // blanket refusal of directories, only of the symlink hop itself.
        assert!(open_dir_no_symlink(&real).is_ok());
    }

    #[test]
    fn sum_dir_bytes_does_not_follow_a_symlinked_subdirectory() {
        // Reproduces the disk state a rename-then-symlink race against a
        // *nested* directory leaves behind: by the time `sum_dir_bytes`
        // reaches `top/link`, it is a symlink to a directory with unrelated
        // content elsewhere on the filesystem, not the plain subdirectory an
        // earlier, non-atomic check-then-open might have seen.
        let base = tempfile::tempdir().unwrap();
        let elsewhere = base.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("f"), vec![b'x'; 999]).unwrap();

        let top = base.path().join("top");
        std::fs::create_dir(&top).unwrap();
        std::fs::write(top.join("own_file"), vec![b'y'; 3]).unwrap();
        std::os::unix::fs::symlink(&elsewhere, top.join("link")).unwrap();

        let dir = open_dir_no_symlink(&top).unwrap();
        let mut total = 0u64;
        sum_dir_bytes(dir, &mut total).unwrap();
        assert_eq!(
            total, 3,
            "a symlinked subdirectory must never be descended into or counted, \
             only this directory's own real file"
        );
    }
}
