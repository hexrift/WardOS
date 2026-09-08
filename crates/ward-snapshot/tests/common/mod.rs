//! Shared helpers for the integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ward_snapshot::{Capture, CapturePolicy, Manifest, RelPath, Store};

/// A temporary directory that is removed on drop.
pub fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ward-snapshot-test-")
        .tempdir()
        .expect("tempdir")
}

/// Join raw bytes onto a path.
pub fn join_bytes(root: &Path, rel: &[u8]) -> PathBuf {
    root.join(OsStr::from_bytes(rel))
}

/// Write `content` at `root/rel`, creating parents.
pub fn write(root: &Path, rel: &str, content: &[u8]) -> PathBuf {
    write_bytes(root, rel.as_bytes(), content)
}

/// Write `content` at `root/<rel bytes>`, creating parents.
pub fn write_bytes(root: &Path, rel: &[u8], content: &[u8]) -> PathBuf {
    let p = join_bytes(root, rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir -p");
    }
    std::fs::write(&p, content).expect("write");
    p
}

/// Create a directory at `root/rel`.
pub fn mkdir(root: &Path, rel: &str) -> PathBuf {
    let p = root.join(rel);
    std::fs::create_dir_all(&p).expect("mkdir -p");
    p
}

/// Create a symlink at `root/rel` pointing at `target` (raw bytes, not resolved).
pub fn symlink(root: &Path, rel: &str, target: &[u8]) -> PathBuf {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir -p");
    }
    std::os::unix::fs::symlink(OsStr::from_bytes(target), &p).expect("symlink");
    p
}

/// chmod.
pub fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// Capture with the default policy.
pub fn capture(root: &Path) -> Manifest {
    Capture::run(root, &CapturePolicy::default(), None).expect("capture")
}

/// Capture with a policy.
pub fn capture_with(root: &Path, policy: &CapturePolicy) -> Manifest {
    Capture::run(root, policy, None).expect("capture")
}

/// Paths in a manifest, lossy-decoded for assertions.
pub fn paths(m: &Manifest) -> Vec<String> {
    m.entries().iter().map(|e| e.path.to_string()).collect()
}

/// Build a `RelPath` or panic.
pub fn rp(s: &str) -> RelPath {
    RelPath::new(s).expect("valid path")
}

/// Capture `root`, store manifest and blobs into a fresh store, return both.
pub fn capture_and_store(root: &Path, store_dir: &Path) -> (Store, Manifest) {
    let store = Store::open(store_dir).expect("open store");
    let m = capture(root);
    store.put_manifest(&m).expect("put manifest");
    store
        .ingest(root, &m, ward_snapshot::IngestOptions::default())
        .expect("ingest");
    (store, m)
}

/// `mkfifo` via coreutils; returns false when unavailable.
pub fn mkfifo(p: &Path) -> bool {
    std::process::Command::new("mkfifo")
        .arg(p)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
