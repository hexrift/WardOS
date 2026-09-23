//! Conservative mark-and-sweep reclamation for the CAS, with leases (#151 items 2–3).
//!
//! # Retention roots (item 2)
//!
//! This module knows nothing about sessions, verification attempts, or evidence —
//! that semantic knowledge belongs to whatever crate owns those concepts (`ward-daemon`'s
//! `retention` module, for this workspace). It only knows [`RootSet`]: an opaque set of
//! [`SnapshotId`]s a caller has already determined are live. [`plan`] resolves that set
//! down to a concrete list of dead objects; it is the caller's job to build a `RootSet`
//! that actually reflects "active session entry/candidate snapshots, in-flight
//! verification, pinned evidence and user-kept restore backups" (the issue's own list) —
//! see [`mark_kept`]/[`kept_ids`] below for the one piece of that list (user-kept backups)
//! that has no other durable home to be read back from.
//!
//! # Leases (item 3)
//!
//! A manifest or blob a capture is actively writing has, by definition, no root pointing
//! at it yet — that only happens once the caller who asked for the capture records the
//! resulting [`SnapshotId`] somewhere durable (a session's `session.json`, a verification
//! attempt's marker). [`LeaseGuard::acquire_capture`] closes that gap: [`SnapshotStore`]
//! (see `lib.rs`) holds one for the whole span of every capture, from before the first
//! blob is written to after the manifest and its metadata are stored.
//!
//! The lease is deliberately coarse — CAS-wide, not scoped to the specific objects one
//! capture happens to be writing. [`any_lease_active`] treats *any* unexpired lease as a
//! reason to plan zero deletions for the *entire* store. A finer-grained lease (scoped to
//! the exact blob digests and manifest id one capture touches) would let a sweep reclaim
//! elsewhere in the store while a capture runs, but that is real complexity — tracking a
//! growing, crash-safe set of protected object ids per lease — for a benefit (less pausing
//! of GC) this first cut does not need. Coarse-and-obviously-correct is the safer place to
//! start; narrowing the pause to just the objects a capture actually touches is a natural
//! follow-up once this ships. See the module's own tests for what this buys regardless:
//! a lease that exists at all, protecting nothing in particular, still keeps a sweep from
//! ever deleting the specific blob a concurrent capture is mid-write on, simply by refusing
//! to delete *anything* while it is held.
//!
//! Every lease is an explicit record on disk with a caller-supplied `now` and an expiry —
//! **never** a process id (pids are reused) or a file's mtime (a long capture's first blob
//! legitimately has an old mtime by the time the capture finishes). [`any_lease_active`]
//! only ever compares a lease's own recorded `expires_unix_ms` against the `now` the caller
//! passes in, which is what makes every scenario below reproducible without a real sleep.
//!
//! # Conservative by construction
//!
//! [`plan`] keeps an object whenever it cannot be sure the object is dead:
//!
//! * any unexpired lease anywhere → nothing is planned for deletion, full stop;
//! * a root's own manifest cannot be loaded (missing, corrupt, or any I/O error) → the
//!   *entire* plan is refused ([`plan`] returns `Err`): an incomplete root set can only
//!   ever make deletions *less* safe, never more, so a caller sees no plan at all rather
//!   than a plan computed against roots it could not fully resolve;
//! * a category's own directory cannot be listed (permission, transient I/O) → that
//!   category simply contributes no candidates, rather than failing the whole plan (unlike
//!   an unresolvable root, this only ever under-reports what could be reclaimed, never
//!   over-reports it);
//! * one entry within a category cannot be inspected (`read_dir` yielding an error for
//!   that one entry, a `file_type()`/`metadata()` that fails) → that one entry is skipped,
//!   never added to the plan.
//!
//! # Interruption safety
//!
//! [`apply`] deletes one object at a time via a single `remove_file` — already the
//! filesystem's own atomic unit, so there is no multi-file transaction a crash could tear.
//! A crash mid-`apply` leaves every object touched so far actually gone and every object
//! not yet reached untouched; re-running [`plan`]/[`apply`] afterward recomputes from
//! current disk state and produces the same conservative result. [`apply`] also re-checks
//! for an active lease before deleting anything and again before every single deletion
//! ([`apply_with_hook`] exposes the check point between deletions for deterministic
//! tests), so a lease acquired after [`plan`] ran — even mid-`apply` — stops the rest of
//! the sweep rather than racing a capture that starts partway through.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cas::write_atomic;
use crate::error::{Result, SnapshotError};
use crate::id::{Digest, SnapshotId};
use crate::manifest::Manifest;

/// How long a capture's lease protects the store by default before it would need
/// renewing. Generous relative to any capture this crate can perform today (a portable
/// frozen-copy walk of a worktree): long enough that no real capture is expected to
/// outlive it, so [`LeaseGuard`] does not need a renewal call wired into the capture
/// loop for this first cut (see the module doc comment on lease granularity for the
/// same "start conservative, narrow later" reasoning).
pub const DEFAULT_CAPTURE_LEASE_TTL: Duration = Duration::from_secs(60 * 60);

fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn leases_dir(cas_root: &Path) -> PathBuf {
    cas_root.join("leases")
}

fn kept_dir(cas_root: &Path) -> PathBuf {
    cas_root.join("kept")
}

// ---------------------------------------------------------------------------------
// Leases
// ---------------------------------------------------------------------------------

/// What a lease protects the store for. `Capture` is the only purpose this crate issues
/// today (see the module doc comment); the enum stays open for a future purpose (e.g. a
/// materialise-for-verify lease) without a breaking change to the on-disk shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeasePurpose {
    /// A [`crate::SnapshotStore`] capture in progress.
    Capture,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LeaseRecord {
    purpose: LeasePurpose,
    created_unix_ms: u64,
    expires_unix_ms: u64,
}

impl LeaseRecord {
    fn is_active(&self, now: SystemTime) -> bool {
        unix_ms(now) < self.expires_unix_ms
    }
}

/// A unique-enough, process-local counter for lease file names — the same shape
/// `cas::write_atomic`'s own temp-file naming already uses, reused here rather than
/// pulling in a UUID dependency for what is, on disk, just a distinguishing suffix.
static NEXT_LEASE_SEQ: AtomicU64 = AtomicU64::new(0);

fn lease_path(cas_root: &Path, purpose: LeasePurpose) -> PathBuf {
    let token = match purpose {
        LeasePurpose::Capture => "capture",
    };
    leases_dir(cas_root).join(format!(
        "{token}-{}-{}.json",
        std::process::id(),
        NEXT_LEASE_SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

/// An explicit, disk-recorded claim that the store must not be swept while it is held —
/// see the module doc comment for why this is coarse (CAS-wide) and why it is never
/// inferred from a pid or an mtime.
///
/// Dropping without calling [`Self::release`] still removes the lease file (best
/// effort): the file itself carries no information worth preserving once its holder is
/// gone (unlike an attempt marker, which is the *only* record of what happened), so
/// there is nothing for a reconciliation pass to do with a leftover one — it would
/// simply sit there until its own `expires_unix_ms` passes and [`any_lease_active`] stops
/// counting it, which is a bounded, harmless staleness window, not a correctness gap.
/// A lease that fails to be removed on drop (a rare I/O error) is exactly that: it keeps
/// protecting the whole store, conservatively, until it expires.
pub struct LeaseGuard {
    path: PathBuf,
    released: bool,
}

impl LeaseGuard {
    /// Acquire a capture lease for `cas_root`, protecting the whole store until it is
    /// released or [`DEFAULT_CAPTURE_LEASE_TTL`] passes, using the real clock.
    pub fn acquire_capture(cas_root: &Path) -> Result<Self> {
        Self::acquire_capture_at(cas_root, SystemTime::now(), DEFAULT_CAPTURE_LEASE_TTL)
    }

    /// [`Self::acquire_capture`] with an explicit `now` and `ttl`, for deterministic
    /// tests (no real sleep needed to exercise expiry).
    pub fn acquire_capture_at(cas_root: &Path, now: SystemTime, ttl: Duration) -> Result<Self> {
        let dir = leases_dir(cas_root);
        fs::create_dir_all(&dir).map_err(|e| SnapshotError::io(&dir, e))?;
        let path = lease_path(cas_root, LeasePurpose::Capture);
        let record = LeaseRecord {
            purpose: LeasePurpose::Capture,
            created_unix_ms: unix_ms(now),
            expires_unix_ms: unix_ms(now) + u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|e| SnapshotError::Manifest(format!("lease serialize: {e}")))?;
        write_atomic(&path, &bytes)?;
        Ok(Self {
            path,
            released: false,
        })
    }

    /// Release the lease early (capture finished before its TTL).
    pub fn release(mut self) {
        self.released = true;
        let _ = fs::remove_file(&self.path);
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if !self.released {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Whether any lease under `cas_root` is currently unexpired, judged solely against the
/// caller-supplied `now` (never the real clock directly, so every caller of [`plan`] and
/// [`apply`] — including tests — controls it explicitly).
///
/// Conservative on every I/O failure: a lease file that cannot be read, or whose content
/// cannot be parsed, is treated as an active lease rather than ignored — it might be a
/// perfectly live lease this call merely raced (e.g. mid-[`LeaseGuard::acquire_capture_at`]'s
/// own write-temp-then-rename, briefly absent as *that* temp file rather than yet visible
/// under its real name, which reads as a benign "gone" below, not a parse failure — but an
/// unreadable *published* lease is different: this function has no way to tell "definitely
/// expired garbage" apart from "a lease this process merely could not read", and only the
/// former is safe to ignore).
fn any_lease_active(cas_root: &Path, now: SystemTime) -> Result<bool> {
    let dir = leases_dir(cas_root);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(SnapshotError::io(&dir, e)),
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
            continue;
        }
        match fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<LeaseRecord>(&bytes) {
                Ok(record) => {
                    if record.is_active(now) {
                        return Ok(true);
                    }
                }
                Err(_) => return Ok(true), // unreadable content: assume active, see doc comment
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // benign race, see doc comment
            Err(_) => return Ok(true), // unreadable file: assume active, see doc comment
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------------
// User-kept snapshots (the one piece of "retention roots" with no other durable home)
// ---------------------------------------------------------------------------------

/// Mark `id` as explicitly kept: a user-kept restore backup, or any other snapshot a
/// caller wants to retain indefinitely with no other root pointing at it. Idempotent.
///
/// This is deliberately the smallest possible marker, not a pinning UX: one durable fact
/// per id ("keep this"), no reason text, no expiry, no listing beyond [`kept_ids`]. A
/// fuller policy (why, until when, by whom) is follow-up work once there is a concrete
/// caller for it.
pub fn mark_kept(cas_root: &Path, id: SnapshotId) -> Result<()> {
    let dir = kept_dir(cas_root);
    fs::create_dir_all(&dir).map_err(|e| SnapshotError::io(&dir, e))?;
    let path = dir.join(format!("{}.json", id.digest().to_hex()));
    write_atomic(&path, b"{}")
}

/// Undo [`mark_kept`]. Removing a marker that is not there is not an error.
pub fn unmark_kept(cas_root: &Path, id: SnapshotId) -> Result<()> {
    let path = kept_dir(cas_root).join(format!("{}.json", id.digest().to_hex()));
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SnapshotError::io(&path, e)),
    }
}

/// Every id [`mark_kept`] currently marks. An unreadable marker's own filename is still
/// trusted for its id (the same reasoning `ward-daemon`'s attempt markers use for a
/// corrupt marker's filename) — the file's content is never anything but `{}` today, so a
/// filename that parses as a digest is enough on its own.
pub fn kept_ids(cas_root: &Path) -> Result<RootSet> {
    let dir = kept_dir(cas_root);
    let mut roots = RootSet::new();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(roots),
        Err(e) => return Err(SnapshotError::io(&dir, e)),
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(hex) = name.strip_suffix(".json") else {
            continue;
        };
        if let Ok(digest) = Digest::from_hex(hex) {
            roots.insert(SnapshotId(digest));
        }
    }
    Ok(roots)
}

// ---------------------------------------------------------------------------------
// Retention roots
// ---------------------------------------------------------------------------------

/// An opaque set of snapshot ids a caller has determined are live retention roots. See
/// the module doc comment: this crate never decides what belongs in it, only what
/// follows once it is given one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootSet {
    ids: BTreeSet<SnapshotId>,
}

impl RootSet {
    /// An empty root set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `id` as a root. Returns `false` if it was already present.
    pub fn insert(&mut self, id: SnapshotId) -> bool {
        self.ids.insert(id)
    }

    /// Add every id `other` while consuming it — a convenience for merging several
    /// root sources (session entries, attempt candidates, evidence, kept markers)
    /// computed independently.
    pub fn extend(&mut self, other: impl IntoIterator<Item = SnapshotId>) {
        self.ids.extend(other);
    }

    /// Whether `id` is a root.
    #[must_use]
    pub fn contains(&self, id: &SnapshotId) -> bool {
        self.ids.contains(id)
    }

    /// Number of distinct root ids.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether there are no roots at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Iterate the root ids.
    pub fn iter(&self) -> impl Iterator<Item = &SnapshotId> {
        self.ids.iter()
    }
}

impl FromIterator<SnapshotId> for RootSet {
    fn from_iter<T: IntoIterator<Item = SnapshotId>>(iter: T) -> Self {
        Self {
            ids: iter.into_iter().collect(),
        }
    }
}

// ---------------------------------------------------------------------------------
// Mark-and-sweep
// ---------------------------------------------------------------------------------

/// Which CAS category a [`PlannedObject`] belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// `blobs/`.
    Blob,
    /// `manifests/`.
    Manifest,
    /// `meta/`.
    Meta,
}

/// One object [`plan`] found unreachable from the given roots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedObject {
    /// Its on-disk path.
    pub path: PathBuf,
    /// Its size in bytes, as observed at plan time.
    pub bytes: u64,
    /// Which category it belongs to.
    pub category: Category,
    /// A human-readable label: the blob digest, the manifest id, or `<id>.<role>` for a
    /// meta record.
    pub label: String,
}

/// What a sweep would do (`dry_run`, the default) or has done (after [`apply`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepPlan {
    /// Objects with nothing pointing at them, oldest concern first: blobs, then
    /// manifests, then meta records.
    pub objects: Vec<PlannedObject>,
    /// Whether an active lease made this plan empty regardless of what the mark phase
    /// would otherwise have found reclaimable — surfaced explicitly so `ward snapshot gc`
    /// can report "nothing to do because a capture is in progress" rather than a plan
    /// that merely looks empty.
    pub lease_active: bool,
    /// How many roots the plan was computed against, for the human summary.
    pub roots: usize,
}

impl SweepPlan {
    /// Total bytes [`objects`](Self::objects) would reclaim.
    #[must_use]
    pub fn reclaimable_bytes(&self) -> u64 {
        self.objects.iter().map(|o| o.bytes).sum()
    }

    /// Whether there is nothing to reclaim.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

/// What [`apply`] actually did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepReport {
    /// Objects actually removed.
    pub deleted: Vec<PlannedObject>,
    /// Planned objects left alone because a lease became active — at the very start of
    /// `apply`, or partway through, see the module doc comment — rather than because
    /// they were found live after all.
    pub skipped_due_to_lease: Vec<PlannedObject>,
}

impl SweepReport {
    /// Total bytes actually reclaimed.
    #[must_use]
    pub fn reclaimed_bytes(&self) -> u64 {
        self.deleted.iter().map(|o| o.bytes).sum()
    }
}

/// Regular files directly inside `dir` (not recursive), tolerating a missing `dir` as
/// empty and skipping any single entry this process cannot fully inspect — see the
/// module doc comment's "conservative by construction" section for why a listing
/// failure degrades to "found nothing new here" rather than aborting the whole plan.
fn list_flat(dir: &Path) -> Vec<(PathBuf, String, u64)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        out.push((entry.path(), name, meta.len()));
    }
    out
}

/// [`list_flat`] over `blobs/`'s two-level hex-prefix sharding.
fn list_blobs(blobs_dir: &Path) -> Vec<(PathBuf, String, u64)> {
    let mut out = Vec::new();
    let Ok(shards) = fs::read_dir(blobs_dir) else {
        return out;
    };
    for shard in shards {
        let Ok(shard) = shard else { continue };
        let Ok(file_type) = shard.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        out.extend(list_flat(&shard.path()));
    }
    out
}

/// Load the manifest for root `id`, as a `Result` rather than an `Option`: unlike a
/// walk-time listing failure, this feeds directly into the live-blob set every other
/// deletion decision depends on, so any failure here must abort the whole plan rather
/// than silently resolving to "no entries" (which would make every blob that manifest
/// legitimately references look dead).
fn load_root_manifest(cas_root: &Path, id: SnapshotId) -> Result<Manifest> {
    let path = cas_root.join("manifests").join(id.digest().to_hex());
    let bytes = fs::read(&path).map_err(|e| SnapshotError::io(&path, e))?;
    let manifest = Manifest::parse(&bytes)?;
    if manifest.id() != id {
        return Err(SnapshotError::Integrity(format!(
            "root manifest {id} does not hash to its id"
        )));
    }
    Ok(manifest)
}

/// Compute what a sweep of `cas_root` would reclaim, given `roots` and `now`. Never
/// deletes anything itself — see [`apply`] for that. Fails only when the roots
/// themselves could not be fully resolved (see the module doc comment); anything less
/// than that degrades the plan rather than refusing it outright.
pub fn plan(cas_root: &Path, roots: &RootSet, now: SystemTime) -> Result<SweepPlan> {
    let lease_active = any_lease_active(cas_root, now)?;
    let mut out = SweepPlan {
        objects: Vec::new(),
        lease_active,
        roots: roots.len(),
    };
    if lease_active {
        return Ok(out);
    }

    // The live blob set: every content digest any root manifest actually references.
    // A failure resolving *any* root aborts the whole plan (see `load_root_manifest`'s
    // doc comment) — an incomplete live-blob set can only make blob deletion less safe.
    let mut live_blobs: BTreeSet<Digest> = BTreeSet::new();
    for &id in roots.iter() {
        let manifest = load_root_manifest(cas_root, id)?;
        for entry in manifest.entries() {
            if let Some(d) = entry.content {
                live_blobs.insert(d);
            }
        }
    }

    for (path, name, bytes) in list_flat(&cas_root.join("manifests")) {
        let Ok(digest) = Digest::from_hex(&name) else {
            continue; // not one of our manifest files; leave it alone
        };
        let id = SnapshotId(digest);
        if !roots.contains(&id) {
            out.objects.push(PlannedObject {
                path,
                bytes,
                category: Category::Manifest,
                label: id.to_string(),
            });
        }
    }

    for (path, name, bytes) in list_flat(&cas_root.join("meta")) {
        // `<hex>.<role>.json`; only the id half decides liveness (see the module doc
        // comment: keep every role recorded for a live id, not just the role a
        // particular root happens to remember).
        let Some(hex) = name.split('.').next() else {
            continue;
        };
        let Ok(digest) = Digest::from_hex(hex) else {
            continue;
        };
        let id = SnapshotId(digest);
        if !roots.contains(&id) {
            out.objects.push(PlannedObject {
                path,
                bytes,
                category: Category::Meta,
                label: name,
            });
        }
    }

    for (path, name, bytes) in list_blobs(&cas_root.join("blobs")) {
        let Ok(digest) = Digest::from_hex(&name) else {
            continue;
        };
        if !live_blobs.contains(&digest) {
            out.objects.push(PlannedObject {
                path,
                bytes,
                category: Category::Blob,
                label: digest.to_string(),
            });
        }
    }

    Ok(out)
}

/// [`apply`] with a hook invoked before each deletion attempt, in plan order, with the
/// index about to be attempted. Production code never needs anything other than a no-op
/// hook (that is what [`apply`] passes); it exists so a test can deterministically make
/// something happen *between* two specific deletions — most sharply, acquire a lease
/// right after the first object is deleted and confirm the rest of the plan is then left
/// alone — without any real concurrency or timing.
pub fn apply_with_hook(
    cas_root: &Path,
    plan: &SweepPlan,
    now: SystemTime,
    mut before_each: impl FnMut(usize),
) -> Result<SweepReport> {
    let mut report = SweepReport::default();
    if plan.lease_active || any_lease_active(cas_root, now)? {
        report.skipped_due_to_lease.clone_from(&plan.objects);
        return Ok(report);
    }
    for (i, obj) in plan.objects.iter().enumerate() {
        before_each(i);
        if any_lease_active(cas_root, now)? {
            report
                .skipped_due_to_lease
                .extend_from_slice(&plan.objects[i..]);
            break;
        }
        match fs::remove_file(&obj.path) {
            Ok(()) => report.deleted.push(obj.clone()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already gone — another sweep, or the object's own owner cleaning up
                // concurrently. Not this call's doing, but not a problem either.
            }
            Err(e) => return Err(SnapshotError::io(&obj.path, e)),
        }
    }
    Ok(report)
}

/// Execute `plan` against `cas_root`: delete every planned object, one `remove_file` at a
/// time (see the module doc comment's "interruption safety" section), re-checking for an
/// active lease before starting and before every individual deletion.
pub fn apply(cas_root: &Path, plan: &SweepPlan, now: SystemTime) -> Result<SweepReport> {
    apply_with_hook(cas_root, plan, now, |_| {})
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cas::Cas;
    use crate::manifest::{Entry, EntryType};

    fn cas_at(dir: &Path) -> (Cas, PathBuf) {
        let cas = Cas::open(dir).unwrap();
        (cas, dir.to_path_buf())
    }

    #[test]
    fn a_blob_unreferenced_by_any_root_is_planned_and_swept() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, root) = cas_at(dir.path());
        let live = cas.put_blob(b"kept content").unwrap();
        let dead = cas.put_blob(b"unreachable content").unwrap();
        let manifest = Manifest::from_entries(vec![Entry {
            path: b"f".to_vec(),
            kind: EntryType::File,
            mode: 0o644,
            size: b"kept content".len() as u64,
            content: Some(live),
        }])
        .unwrap();
        let id = cas.put_manifest(&manifest).unwrap();

        let mut roots = RootSet::new();
        roots.insert(id);
        let now = SystemTime::now();
        let p = plan(&root, &roots, now).unwrap();
        assert!(!p.lease_active);
        assert_eq!(p.objects.len(), 1, "only the unreferenced blob: {p:?}");
        assert_eq!(p.objects[0].category, Category::Blob);
        assert_eq!(p.objects[0].label, dead.to_string());

        let report = apply(&root, &p, now).unwrap();
        assert_eq!(report.deleted.len(), 1);
        assert!(cas.has_blob(live), "the live blob must survive");
        assert!(!cas.has_blob(dead), "the dead blob must be gone");
    }

    #[test]
    fn an_empty_root_set_still_keeps_a_manifest_it_was_never_told_about_if_a_lease_covers_it() {
        // Belt and braces: even with zero roots, an active lease must still block
        // every deletion — the coarse, CAS-wide guarantee the module doc comment
        // describes, independent of what the lease is even protecting.
        let dir = tempfile::tempdir().unwrap();
        let (cas, root) = cas_at(dir.path());
        let d = cas.put_blob(b"mid-write content").unwrap();
        let now = SystemTime::now();
        let _lease = LeaseGuard::acquire_capture_at(&root, now, DEFAULT_CAPTURE_LEASE_TTL).unwrap();

        let p = plan(&root, &RootSet::new(), now).unwrap();
        assert!(p.lease_active);
        assert!(p.is_empty());
        assert!(cas.has_blob(d));
    }

    #[test]
    fn a_lease_acquired_between_mark_and_sweep_stops_deletion_even_though_nothing_roots_it() {
        // The scenario the issue names explicitly: a sweep observes a lease acquired
        // concurrently with mark, protecting an object that isn't linked into any root
        // yet. `plan` runs first (no lease yet, so the blob would be planned); the
        // lease is then acquired; `apply` must still refuse to delete it.
        let dir = tempfile::tempdir().unwrap();
        let (cas, root) = cas_at(dir.path());
        let d = cas.put_blob(b"about to be protected").unwrap();
        let now = SystemTime::now();

        let p = plan(&root, &RootSet::new(), now).unwrap();
        assert!(!p.lease_active);
        assert_eq!(
            p.objects.len(),
            1,
            "unreferenced, so planned before the lease exists"
        );

        let lease = LeaseGuard::acquire_capture_at(&root, now, DEFAULT_CAPTURE_LEASE_TTL).unwrap();
        let report = apply(&root, &p, now).unwrap();
        assert!(
            report.deleted.is_empty(),
            "the lease must stop the deletion"
        );
        assert_eq!(report.skipped_due_to_lease.len(), 1);
        assert!(cas.has_blob(d), "the blob must survive");
        lease.release();
    }

    #[test]
    fn a_lease_acquired_mid_apply_stops_the_rest_of_the_plan_but_not_what_already_ran() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, root) = cas_at(dir.path());
        let a = cas.put_blob(b"first dead blob").unwrap();
        let b = cas.put_blob(b"second dead blob").unwrap();
        let now = SystemTime::now();
        let p = plan(&root, &RootSet::new(), now).unwrap();
        assert_eq!(p.objects.len(), 2);

        // Deterministic interleaving via the hook, not a thread or a sleep: acquire a
        // lease the instant the first deletion is about to run, so the second is the
        // one that must be left alone.
        let lease_cell = std::cell::RefCell::new(None);
        let report = apply_with_hook(&root, &p, now, |i| {
            if i == 1 {
                *lease_cell.borrow_mut() = Some(
                    LeaseGuard::acquire_capture_at(&root, now, DEFAULT_CAPTURE_LEASE_TTL).unwrap(),
                );
            }
        })
        .unwrap();

        assert_eq!(report.deleted.len(), 1, "the first deletion already ran");
        assert_eq!(report.skipped_due_to_lease.len(), 1);
        let deleted_digest: Digest = report.deleted[0].label.parse().unwrap();
        let surviving = if deleted_digest == a { b } else { a };
        assert!(cas.has_blob(surviving), "the second blob must survive");
    }

    #[test]
    fn a_lease_that_expired_during_a_slow_sweep_is_correctly_treated_as_gone() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, root) = cas_at(dir.path());
        let d = cas.put_blob(b"eventually reclaimable").unwrap();
        let t0 = SystemTime::now();
        let ttl = Duration::from_secs(5);
        let lease = LeaseGuard::acquire_capture_at(&root, t0, ttl).unwrap();

        // At t0 the lease is active: plan must be empty.
        let still_active = plan(&root, &RootSet::new(), t0).unwrap();
        assert!(still_active.lease_active);

        // At t0 + 2*ttl the very same on-disk lease has expired — judged purely from
        // its own recorded expiry against the `now` passed in, never a real sleep.
        let later = t0 + ttl * 2;
        let after_expiry = plan(&root, &RootSet::new(), later).unwrap();
        assert!(!after_expiry.lease_active);
        assert_eq!(after_expiry.objects.len(), 1);

        let report = apply(&root, &after_expiry, later).unwrap();
        assert_eq!(report.deleted.len(), 1);
        assert!(!cas.has_blob(d));
        // The lease file itself is still on disk (never removed just because it
        // expired — only `release`/`Drop` remove it) but no longer counts as active.
        drop(lease);
    }

    #[test]
    fn an_unresolvable_root_aborts_the_whole_plan_rather_than_deleting_around_it() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, root) = cas_at(dir.path());
        let d = cas
            .put_blob(b"would look dead without the missing root")
            .unwrap();
        // A root id naming a manifest that was never actually stored.
        let phantom = SnapshotId(Digest::from_bytes([0x42; 32]));
        let mut roots = RootSet::new();
        roots.insert(phantom);

        let result = plan(&root, &roots, SystemTime::now());
        assert!(
            result.is_err(),
            "an unresolvable root must refuse the whole plan, not silently drop it"
        );
        assert!(cas.has_blob(d), "nothing must be touched on this path");
    }

    #[test]
    fn a_manifest_and_its_meta_survive_when_rooted_and_are_planned_when_not() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, root) = cas_at(dir.path());
        let manifest = Manifest::from_entries(Vec::new()).unwrap();
        let id = cas.put_manifest(&manifest).unwrap();
        cas.put_meta(&crate::meta::SnapshotMeta {
            id,
            role: crate::id::SnapshotRole::Candidate,
            entries: 0,
            bytes: 0,
            capture_mode: crate::meta::CaptureMode::FrozenCopy,
            git_context: None,
        })
        .unwrap();

        let now = SystemTime::now();
        let empty_roots = plan(&root, &RootSet::new(), now).unwrap();
        assert_eq!(
            empty_roots.objects.len(),
            2,
            "manifest + meta: {empty_roots:?}"
        );

        let mut roots = RootSet::new();
        roots.insert(id);
        let rooted = plan(&root, &roots, now).unwrap();
        assert!(
            rooted.is_empty(),
            "rooted, so neither is planned: {rooted:?}"
        );
    }

    #[test]
    fn mark_kept_produces_a_root_kept_ids_can_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, root) = cas_at(dir.path());
        let manifest = Manifest::from_entries(Vec::new()).unwrap();
        let id = cas.put_manifest(&manifest).unwrap();

        assert!(kept_ids(&root).unwrap().is_empty());
        mark_kept(&root, id).unwrap();
        let kept = kept_ids(&root).unwrap();
        assert!(kept.contains(&id));
        assert_eq!(kept.len(), 1);

        let p = plan(&root, &kept, SystemTime::now()).unwrap();
        assert!(p.is_empty(), "a kept id must be treated as a root: {p:?}");

        unmark_kept(&root, id).unwrap();
        assert!(kept_ids(&root).unwrap().is_empty());
    }

    #[test]
    fn unmark_kept_on_an_absent_marker_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let phantom = SnapshotId(Digest::from_bytes([0x7; 32]));
        unmark_kept(dir.path(), phantom).unwrap();
    }

    #[test]
    fn plan_on_a_cas_less_state_root_reports_nothing_and_touches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let before: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(before.is_empty(), "fixture must start empty");
        let p = plan(dir.path(), &RootSet::new(), SystemTime::now()).unwrap();
        assert!(p.is_empty());
        assert!(!p.lease_active);
    }
}
