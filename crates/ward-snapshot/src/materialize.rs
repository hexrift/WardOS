//! Materialise a snapshot into a fresh directory tree, safely.
//!
//! Materialisation writes relative to a fresh root. Every path is re-validated
//! against `..`, and each ancestor is checked to be a real directory before we
//! descend, so a symlink entry can never be used to escape the destination —
//! symlinks are written *as symlinks* and never followed.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::cas::Cas;
use crate::error::{Result, SnapshotError};
use crate::manifest::{Entry, EntryType, Manifest, validate_path};

pub(crate) fn materialize(cas: &Cas, manifest: &Manifest, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).map_err(|e| SnapshotError::io(dest, e))?;

    for e in manifest.entries() {
        let path = checked_path(dest, &e.path)?;
        match e.kind {
            EntryType::Dir | EntryType::SubmoduleWorktree => {
                create_dir(&path)?;
            }
            EntryType::File => {
                let digest = e
                    .content
                    .ok_or_else(|| SnapshotError::Manifest("file without content".into()))?;
                let bytes = cas.get_blob(digest)?;
                fs::write(&path, &bytes).map_err(|err| SnapshotError::io(&path, err))?;
                set_mode(&path, e.mode)?;
            }
            EntryType::Symlink => {
                let digest = e
                    .content
                    .ok_or_else(|| SnapshotError::Manifest("symlink without target".into()))?;
                let target = cas.get_blob(digest)?;
                let target = Path::new(std::ffi::OsStr::from_bytes(&target));
                std::os::unix::fs::symlink(target, &path)
                    .map_err(|err| SnapshotError::io(&path, err))?;
            }
            EntryType::Unsupported => {} // cannot portably recreate device/fifo/socket nodes
        }
    }

    // Apply directory modes last, deepest first, so read-only dirs do not block
    // writing their children.
    for e in manifest.entries().iter().rev() {
        if matches!(e.kind, EntryType::Dir | EntryType::SubmoduleWorktree) {
            set_mode(&checked_path(dest, &e.path)?, e.mode)?;
        }
    }
    Ok(())
}

/// Resolve `rel` under `dest`, refusing `..` and any symlinked ancestor.
fn checked_path(dest: &Path, rel: &[u8]) -> Result<PathBuf> {
    validate_path(rel)?;
    let mut cur = dest.to_path_buf();
    let segs: Vec<&[u8]> = rel.split(|&b| b == b'/').collect();
    for (i, seg) in segs.iter().enumerate() {
        cur.push(Path::new(std::ffi::OsStr::from_bytes(seg)));
        let is_last = i + 1 == segs.len();
        if is_last {
            break;
        }
        // Every ancestor must already exist as a real directory.
        let meta = fs::symlink_metadata(&cur).map_err(|e| SnapshotError::io(&cur, e))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(SnapshotError::UnsafePath(format!(
                "ancestor {:?} is not a real directory",
                cur.display()
            )));
        }
    }
    Ok(cur)
}

fn create_dir(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(SnapshotError::io(path, e)),
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| SnapshotError::io(path, e))
}

/// Materialise a single entry's bytes without writing to disk (used by `cat`).
pub(crate) fn read_entry_bytes(cas: &Cas, entry: &Entry) -> Result<Vec<u8>> {
    match entry.content {
        Some(d) => cas.get_blob(d),
        None => Err(SnapshotError::NoSuchEntry(format!(
            "{:?} has no content",
            String::from_utf8_lossy(&entry.path)
        ))),
    }
}
