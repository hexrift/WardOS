//! Rebuilding a snapshot into a fresh directory for the verifier.
//!
//! Safety properties, each pinned by a test in `tests/materialise.rs`:
//!
//! * The destination must be absent or an empty directory that is not a symlink.
//! * Every path was validated at manifest parse ([`RelPath`]): no `..`, no absolute
//!   paths, no empty components — so `dest.join(path)` is strictly inside `dest`.
//! * Symlinks are created as symlinks, never followed, whatever they point at.
//! * No entry is ever created *through* a symlink: if `a` is a symlink entry, an entry
//!   `a/b` is refused ([`Error::PathThroughSymlink`]). Files are opened with
//!   `O_CREAT|O_EXCL`, which also fails on a dangling symlink at the final component.
//! * Modes are applied with setuid, setgid and sticky bits masked off (`& 0o777`), and
//!   directory modes are applied last (children first) so a read-only directory does not
//!   block its own contents.
//! * FIFOs, sockets and devices are never created; they are listed in the report.
//! * Blobs are reflinked from the store when possible, else copied.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::hash::SnapshotId;
use crate::manifest::{Entry, EntryKind, Manifest};
use crate::path::RelPath;
use crate::store::Store;

/// Bits kept when applying modes: rwx for user, group and other.
pub const MATERIALISE_MODE_MASK: u32 = 0o777;

/// What [`materialise`] produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MaterialiseReport {
    /// Regular files written.
    pub files: u64,
    /// Directories created (explicit entries plus implicit parents).
    pub dirs: u64,
    /// Symlinks created.
    pub symlinks: u64,
    /// Logical bytes written.
    pub bytes: u64,
    /// Files that were reflinked rather than copied.
    pub reflinked: u64,
    /// Unsupported entries (FIFO/socket/device) that were skipped.
    pub skipped_unsupported: Vec<RelPath>,
    /// Wall time.
    pub duration: Duration,
}

/// Materialise snapshot `id` from `store` into `dest`.
///
/// # Errors
/// [`Error::MissingManifest`] / [`Error::MissingBlob`] for absent content;
/// [`Error::DestinationNotEmpty`]; [`Error::PathThroughSymlink`]; I/O errors.
pub fn materialise(store: &Store, id: &SnapshotId, dest: &Path) -> Result<MaterialiseReport> {
    let manifest = store.get_manifest(id)?;
    materialise_manifest(store, &manifest, dest)
}

/// Materialise an already-loaded manifest. See [`materialise`].
///
/// # Errors
/// See [`materialise`].
pub fn materialise_manifest(
    store: &Store,
    manifest: &Manifest,
    dest: &Path,
) -> Result<MaterialiseReport> {
    let t0 = Instant::now();
    prepare_dest(dest)?;
    let mut report = MaterialiseReport::default();
    let mut dirs: HashSet<Vec<u8>> = HashSet::new();
    let mut symlinks: HashSet<Vec<u8>> = HashSet::new();
    let mut dir_modes: Vec<(PathBuf, u32)> = Vec::new();

    for entry in manifest.entries() {
        ensure_parents(dest, &entry.path, &mut dirs, &symlinks, &mut report)?;
        let target = dest.join(entry.path.as_path());
        match entry.kind {
            EntryKind::Dir => {
                fs::create_dir(&target).map_err(|e| Error::io("mkdir", &target, e))?;
                dirs.insert(entry.path.as_bytes().to_vec());
                dir_modes.push((target, entry.mode & MATERIALISE_MODE_MASK));
                report.dirs += 1;
            }
            EntryKind::File => {
                write_file(store, entry, &target, &mut report)?;
            }
            EntryKind::Symlink => {
                let link_target = store_symlink_target(store, entry)?;
                let os: &std::ffi::OsStr = std::os::unix::ffi::OsStrExt::from_bytes(&link_target);
                std::os::unix::fs::symlink(os, &target)
                    .map_err(|e| Error::io("symlink", &target, e))?;
                symlinks.insert(entry.path.as_bytes().to_vec());
                report.symlinks += 1;
            }
            EntryKind::Unsupported => {
                report.skipped_unsupported.push(entry.path.clone());
            }
        }
    }

    // Children before parents: reverse of bytewise order, since a parent sorts before
    // everything below it.
    for (path, mode) in dir_modes.iter().rev() {
        fs::set_permissions(path, fs::Permissions::from_mode(*mode))
            .map_err(|e| Error::io("chmod", path, e))?;
    }
    report.duration = t0.elapsed();
    Ok(report)
}

fn prepare_dest(dest: &Path) -> Result<()> {
    match fs::symlink_metadata(dest) {
        Ok(m) if m.is_dir() => {
            let mut it = fs::read_dir(dest).map_err(|e| Error::io("readdir", dest, e))?;
            if it.next().is_some() {
                return Err(Error::DestinationNotEmpty(dest.to_path_buf()));
            }
            Ok(())
        }
        Ok(_) => Err(Error::DestinationNotEmpty(dest.to_path_buf())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dest).map_err(|e| Error::io("mkdir", dest, e))
        }
        Err(e) => Err(Error::io("stat", dest, e)),
    }
}

/// Create implicit parent directories, refusing to pass through a symlink entry.
fn ensure_parents(
    dest: &Path,
    path: &RelPath,
    dirs: &mut HashSet<Vec<u8>>,
    symlinks: &HashSet<Vec<u8>>,
    report: &mut MaterialiseReport,
) -> Result<()> {
    let bytes = path.as_bytes();
    let mut end = 0usize;
    while let Some(off) = bytes[end..].iter().position(|b| *b == b'/') {
        end += off;
        let prefix = &bytes[..end];
        if symlinks.contains(prefix) {
            return Err(Error::PathThroughSymlink {
                path: bytes.to_vec(),
            });
        }
        if !dirs.contains(prefix) {
            let os: &std::ffi::OsStr = std::os::unix::ffi::OsStrExt::from_bytes(prefix);
            let p = dest.join(os);
            match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(Error::PathThroughSymlink {
                        path: bytes.to_vec(),
                    });
                }
                Ok(m) if m.is_dir() => {}
                Ok(_) => {
                    return Err(Error::io(
                        "mkdir",
                        &p,
                        std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "parent is not a directory",
                        ),
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&p).map_err(|e| Error::io("mkdir", &p, e))?;
                    report.dirs += 1;
                }
                Err(e) => return Err(Error::io("stat", &p, e)),
            }
            dirs.insert(prefix.to_vec());
        }
        end += 1;
    }
    Ok(())
}

fn write_file(
    store: &Store,
    entry: &Entry,
    target: &Path,
    report: &mut MaterialiseReport,
) -> Result<()> {
    let blob = store.blob_path(&entry.hash);
    if !blob.is_file() {
        return Err(Error::MissingBlob(entry.hash));
    }
    // `reflink_or_copy` creates the destination with O_CREAT|O_EXCL semantics (fails on
    // an existing path, including a dangling symlink) and never follows a final-component
    // symlink; parents were validated by `ensure_parents`.
    match reflink_copy::reflink_or_copy(&blob, target) {
        Ok(None) => report.reflinked += 1,
        Ok(Some(_)) => {}
        Err(e) => return Err(Error::io("reflink_or_copy", target, e)),
    }
    fs::set_permissions(
        target,
        fs::Permissions::from_mode(entry.mode & MATERIALISE_MODE_MASK),
    )
    .map_err(|e| Error::io("chmod", target, e))?;
    report.files += 1;
    report.bytes += entry.size;
    Ok(())
}

/// A symlink's target bytes are stored by [`Store::ingest`] as a blob under the hash the
/// manifest records for the symlink, so the manifest stays the sole source of truth and
/// the target is verified like any other content.
fn store_symlink_target(store: &Store, entry: &Entry) -> Result<Vec<u8>> {
    let bytes = store.read_blob(&entry.hash)?;
    let actual = crate::hash::ContentHash::of(&bytes);
    if actual != entry.hash {
        return Err(Error::HashMismatch {
            path: store.blob_path(&entry.hash),
            expected: entry.hash,
            actual,
        });
    }
    Ok(bytes)
}
