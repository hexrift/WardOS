//! The capture-backend seam.
//!
//! Capture always walks a *frozen, read-only* tree. How that tree is produced
//! is the one thing that differs between platforms: on Btrfs `wardd` takes an
//! O(1) read-only subvolume snapshot; elsewhere it hashes the frozen worktree
//! in place. A backend hands capture a path to walk and names the mode used.
//!
//! Only [`FrozenCopy`] is implemented here (Btrfs is unavailable in this
//! environment). A `Btrfs` backend adds itself by implementing [`Backend`]:
//! its [`Frozen`] guard would mount the snapshot and delete the subvolume on
//! drop, with no change to the capture code.

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::meta::CaptureMode;

/// A frozen, read-only view of a source tree, valid until dropped.
pub trait Frozen {
    /// The directory to walk.
    fn root(&self) -> &Path;
}

/// Produces a [`Frozen`] view of a source directory.
pub trait Backend {
    /// The capture mode this backend records in metadata.
    fn mode(&self) -> CaptureMode;
    /// Freeze `source` and return a guard exposing the tree to walk.
    fn freeze(&self, source: &Path) -> Result<Box<dyn Frozen>>;
}

/// Portable backend: treats the source directory itself as the frozen tree.
///
/// In production `wardd` freezes the session cgroup before capture; here the
/// tree is assumed quiescent and walked directly.
#[derive(Clone, Copy, Debug, Default)]
pub struct FrozenCopy;

struct InPlace(PathBuf);

impl Frozen for InPlace {
    fn root(&self) -> &Path {
        &self.0
    }
}

impl Backend for FrozenCopy {
    fn mode(&self) -> CaptureMode {
        CaptureMode::FrozenCopy
    }

    fn freeze(&self, source: &Path) -> Result<Box<dyn Frozen>> {
        Ok(Box::new(InPlace(source.to_path_buf())))
    }
}
