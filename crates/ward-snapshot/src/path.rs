//! Validated relative paths as raw bytes.
//!
//! Manifest paths are **bytes, not strings**: Linux file names are arbitrary byte
//! sequences and the snapshot id must be stable for any name a repository can contain
//! (`docs/snapshots-and-git.md` §3). No normalisation (Unicode or otherwise) is applied,
//! so `é` as NFC and NFD are two different paths, exactly as they are on disk.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::error::{Error, PathError, Result};

/// Upper bound on the byte length of a manifest path. Linux's `PATH_MAX` is 4096; the
/// manifest allows a little more so a worktree at the limit can still be captured.
pub const MAX_PATH_BYTES: usize = 8192;

/// A validated, relative, `/`-separated path of raw bytes.
///
/// Invariants (enforced by every constructor):
/// * non-empty,
/// * does not start with `/`,
/// * contains no NUL byte,
/// * every `/`-separated component is non-empty and is neither `.` nor `..`,
/// * at most [`MAX_PATH_BYTES`] bytes.
///
/// Ordering is bytewise (`Ord` on the underlying bytes), which is the manifest order.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(Vec<u8>);

impl RelPath {
    /// Validate `bytes` as a relative path.
    ///
    /// # Errors
    /// Returns [`Error::InvalidPath`] describing the first violated rule.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        match validate(&bytes) {
            Ok(()) => Ok(RelPath(bytes)),
            Err(reason) => Err(Error::InvalidPath {
                path: bytes,
                reason,
            }),
        }
    }

    /// Validate an [`OsStr`] (taken as raw bytes) as a relative path.
    ///
    /// # Errors
    /// See [`RelPath::new`].
    pub fn from_os_str(s: &OsStr) -> Result<Self> {
        Self::new(s.as_bytes())
    }

    /// Validate a [`Path`] as a relative path (its raw bytes; no normalisation).
    ///
    /// # Errors
    /// See [`RelPath::new`].
    pub fn from_path(p: &Path) -> Result<Self> {
        Self::from_os_str(p.as_os_str())
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The path as an [`OsStr`] (lossless on Unix).
    #[must_use]
    pub fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(&self.0)
    }

    /// The path as a [`Path`] (lossless on Unix).
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(self.as_os_str())
    }

    /// The `/`-separated components, each non-empty.
    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.0.split(|b| *b == b'/')
    }

    /// The parent path, or `None` for a single-component path.
    #[must_use]
    pub fn parent(&self) -> Option<RelPath> {
        let idx = self.0.iter().rposition(|b| *b == b'/')?;
        Some(RelPath(self.0[..idx].to_vec()))
    }

    /// Append a single component.
    ///
    /// # Errors
    /// Returns [`Error::InvalidPath`] if `name` is not a valid single component.
    pub fn join(&self, name: &[u8]) -> Result<RelPath> {
        let mut bytes = Vec::with_capacity(self.0.len() + 1 + name.len());
        bytes.extend_from_slice(&self.0);
        bytes.push(b'/');
        bytes.extend_from_slice(name);
        Self::new(bytes)
    }

    /// True if `self` is `ancestor` or lies below it.
    #[must_use]
    pub fn starts_with(&self, ancestor: &RelPath) -> bool {
        let a = &ancestor.0;
        self.0 == *a || (self.0.len() > a.len() && self.0.starts_with(a) && self.0[a.len()] == b'/')
    }

    /// Consume into the raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

fn validate(bytes: &[u8]) -> std::result::Result<(), PathError> {
    if bytes.is_empty() {
        return Err(PathError::Empty);
    }
    if bytes.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    if bytes[0] == b'/' {
        return Err(PathError::Absolute);
    }
    if bytes.contains(&0) {
        return Err(PathError::Nul);
    }
    for component in bytes.split(|b| *b == b'/') {
        match component {
            b"" => return Err(PathError::EmptyComponent),
            b"." => return Err(PathError::DotComponent),
            b".." => return Err(PathError::DotDotComponent),
            _ => {}
        }
    }
    Ok(())
}

impl std::fmt::Debug for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RelPath({:?})", String::from_utf8_lossy(&self.0))
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.0))
    }
}

impl AsRef<[u8]> for RelPath {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<Path> for RelPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl TryFrom<&str> for RelPath {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        RelPath::new(value.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_paths() {
        assert!(RelPath::new("a").is_ok());
        assert!(RelPath::new("a/b/c").is_ok());
        assert!(RelPath::new(b"sp ace/new\nline/\xff\xfe".to_vec()).is_ok());
        assert!(RelPath::new("...").is_ok());
        assert!(RelPath::new(".git").is_ok());
        assert!(RelPath::new("a/..b").is_ok());
    }

    #[test]
    fn rejects_hostile_paths() {
        let reason = |s: &[u8]| match RelPath::new(s.to_vec()) {
            Err(Error::InvalidPath { reason, .. }) => Some(reason),
            _ => None,
        };
        assert_eq!(reason(b""), Some(PathError::Empty));
        assert_eq!(reason(b"/etc/passwd"), Some(PathError::Absolute));
        assert_eq!(reason(b"a//b"), Some(PathError::EmptyComponent));
        assert_eq!(reason(b"a/"), Some(PathError::EmptyComponent));
        assert_eq!(reason(b"./a"), Some(PathError::DotComponent));
        assert_eq!(reason(b"a/./b"), Some(PathError::DotComponent));
        assert_eq!(reason(b".."), Some(PathError::DotDotComponent));
        assert_eq!(reason(b"a/../b"), Some(PathError::DotDotComponent));
        assert_eq!(reason(b"a/..\0"), Some(PathError::Nul));
        assert_eq!(reason(b"a\0b"), Some(PathError::Nul));
        assert_eq!(
            reason(&vec![b'a'; MAX_PATH_BYTES + 1]),
            Some(PathError::TooLong)
        );
    }

    #[test]
    fn parent_and_starts_with() {
        let p = RelPath::new("a/b/c").ok();
        let parent = p.as_ref().and_then(RelPath::parent);
        assert_eq!(parent.as_ref().map(RelPath::as_bytes), Some(&b"a/b"[..]));
        let a = RelPath::new("a").ok();
        let ab = RelPath::new("ab").ok();
        if let (Some(p), Some(a), Some(ab)) = (p, a, ab) {
            assert!(p.starts_with(&a));
            assert!(!p.starts_with(&ab));
            assert!(a.parent().is_none());
        }
    }
}
