//! The canonical snapshot manifest and its Merkle serialisation.
//!
//! A manifest is a bytewise-sorted list of entries, one per line of the form
//! `<type> <mode> <size> <content-hash> <path-bytes>` (see `docs/snapshots-and-git.md` §3).
//! Records are NUL-terminated so that raw path bytes — which may contain spaces
//! or newlines but never a NUL — round-trip without escaping. The BLAKE3 hash of
//! the serialisation is the manifest hash and thus the [`SnapshotId`].

use crate::error::SnapshotError;
use crate::id::{Digest, SnapshotId};

const MAGIC: &[u8] = b"ward-snapshot-manifest/1\n";

/// Kind of filesystem object an entry describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryType {
    /// A regular file; content is stored as a blob.
    File,
    /// A directory.
    Dir,
    /// A symbolic link; the *target bytes* are stored as a blob, never followed.
    Symlink,
    /// The worktree of a submodule (a directory that itself contains a `.git`);
    /// its contents are recursed as ordinary files.
    SubmoduleWorktree,
    /// A FIFO, socket, or device node: recorded by name, content omitted.
    Unsupported,
}

impl EntryType {
    fn token(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
            Self::SubmoduleWorktree => "submodule-worktree",
            Self::Unsupported => "unsupported",
        }
    }

    fn from_token(t: &[u8]) -> Result<Self, SnapshotError> {
        Ok(match t {
            b"file" => Self::File,
            b"dir" => Self::Dir,
            b"symlink" => Self::Symlink,
            b"submodule-worktree" => Self::SubmoduleWorktree,
            b"unsupported" => Self::Unsupported,
            other => {
                return Err(SnapshotError::Manifest(format!(
                    "unknown entry type {:?}",
                    String::from_utf8_lossy(other)
                )));
            }
        })
    }

    /// Whether an entry of this kind carries stored content (a blob).
    fn has_content(self) -> bool {
        matches!(self, Self::File | Self::Symlink)
    }
}

/// One manifest entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Path relative to the snapshot root: raw bytes, `/`-separated, no leading `/`.
    pub path: Vec<u8>,
    /// The kind of object.
    pub kind: EntryType,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    /// Size in bytes: file length, or symlink-target length; `0` otherwise.
    pub size: u64,
    /// Content digest for files and symlinks; `None` for dirs and unsupported nodes.
    pub content: Option<Digest>,
}

/// A canonical, sorted, de-duplicated set of entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    entries: Vec<Entry>,
}

impl Manifest {
    /// Build a manifest from arbitrary entries: validates each path, sorts
    /// bytewise, and rejects duplicates. This is the single choke point that
    /// enforces path safety (no `..`, absolute, empty, or NUL-bearing paths).
    pub fn from_entries(mut entries: Vec<Entry>) -> Result<Self, SnapshotError> {
        for e in &entries {
            validate_path(&e.path)?;
            if e.content.is_some() != e.kind.has_content() {
                return Err(SnapshotError::Manifest(format!(
                    "content presence mismatch for {:?}",
                    String::from_utf8_lossy(&e.path)
                )));
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        if let Some(w) = entries.windows(2).find(|w| w[0].path == w[1].path) {
            return Err(SnapshotError::Manifest(format!(
                "duplicate path {:?}",
                String::from_utf8_lossy(&w[0].path)
            )));
        }
        Ok(Self { entries })
    }

    /// The entries, in canonical (bytewise path) order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Look up an entry by exact path bytes.
    pub fn get(&self, path: &[u8]) -> Option<&Entry> {
        self.entries
            .binary_search_by(|e| e.path.as_slice().cmp(path))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// Serialise to canonical bytes. Deterministic for a given set of entries.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAGIC.len() + self.entries.len() * 96);
        out.extend_from_slice(MAGIC);
        for e in &self.entries {
            let content = match e.content {
                Some(d) => d.to_string(),
                None => "-".to_string(),
            };
            out.extend_from_slice(
                format!("{} {:o} {} {content} ", e.kind.token(), e.mode, e.size).as_bytes(),
            );
            out.extend_from_slice(&e.path);
            out.push(0);
        }
        out
    }

    /// Parse canonical bytes back into a manifest, re-validating every invariant.
    pub fn parse(bytes: &[u8]) -> Result<Self, SnapshotError> {
        let body = bytes
            .strip_prefix(MAGIC)
            .ok_or_else(|| SnapshotError::Manifest("bad manifest magic".into()))?;
        let mut entries = Vec::new();
        for record in split_records(body) {
            entries.push(parse_record(record)?);
        }
        Self::from_entries(entries)
    }

    /// The manifest (Merkle-root) digest.
    pub fn digest(&self) -> Digest {
        Digest::of(&self.serialize())
    }

    /// The snapshot id: the manifest digest formatted `blake3:<hex>`.
    pub fn id(&self) -> SnapshotId {
        SnapshotId(self.digest())
    }

    /// Total stored content bytes (files and symlink targets).
    pub fn content_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.content.is_some())
            .map(|e| e.size)
            .sum()
    }
}

/// Reject paths that are absolute, empty, contain a NUL, or contain a `..`
/// component. A name segment that merely *contains* `..` (e.g. `a..b`) is fine;
/// only a whole segment equal to `..` is a traversal.
pub(crate) fn validate_path(path: &[u8]) -> Result<(), SnapshotError> {
    if path.is_empty() {
        return Err(SnapshotError::UnsafePath("empty path".into()));
    }
    if path.first() == Some(&b'/') {
        return Err(SnapshotError::UnsafePath(format!(
            "absolute path {:?}",
            String::from_utf8_lossy(path)
        )));
    }
    if path.contains(&0) {
        return Err(SnapshotError::UnsafePath("NUL in path".into()));
    }
    for seg in path.split(|&b| b == b'/') {
        if seg == b".." {
            return Err(SnapshotError::UnsafePath(format!(
                "`..` component in {:?}",
                String::from_utf8_lossy(path)
            )));
        }
    }
    Ok(())
}

fn split_records(body: &[u8]) -> impl Iterator<Item = &[u8]> {
    body.split(|&b| b == 0).filter(|r| !r.is_empty())
}

fn parse_record(record: &[u8]) -> Result<Entry, SnapshotError> {
    // Four space-delimited head fields, then the raw path (which may contain spaces).
    let mut parts = record.splitn(5, |&b| b == b' ');
    let kind = parts.next().ok_or_else(bad_record)?;
    let mode = parts.next().ok_or_else(bad_record)?;
    let size = parts.next().ok_or_else(bad_record)?;
    let content = parts.next().ok_or_else(bad_record)?;
    let path = parts.next().ok_or_else(bad_record)?;

    let kind = EntryType::from_token(kind)?;
    let mode = u32::from_str_radix(str_field(mode)?, 8)
        .map_err(|_| SnapshotError::Manifest("bad mode".into()))?;
    let size: u64 = str_field(size)?
        .parse()
        .map_err(|_| SnapshotError::Manifest("bad size".into()))?;
    let content = if content == b"-" {
        None
    } else {
        Some(str_field(content)?.parse()?)
    };
    Ok(Entry {
        path: path.to_vec(),
        kind,
        mode,
        size,
        content,
    })
}

fn str_field(b: &[u8]) -> Result<&str, SnapshotError> {
    std::str::from_utf8(b).map_err(|_| SnapshotError::Manifest("non-utf8 header field".into()))
}

fn bad_record() -> SnapshotError {
    SnapshotError::Manifest("truncated manifest record".into())
}

/// The difference between two manifests, keyed by path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestDiff {
    /// Paths present in `b` but not `a`.
    pub added: Vec<Vec<u8>>,
    /// Paths present in `a` but not `b`.
    pub removed: Vec<Vec<u8>>,
    /// Paths in both whose type, mode, size, or content differ.
    pub changed: Vec<Vec<u8>>,
}

impl ManifestDiff {
    /// Compare two manifests (both already in canonical order).
    pub fn between(a: &Manifest, b: &Manifest) -> Self {
        let mut diff = Self::default();
        let (mut i, mut j) = (0, 0);
        let (ea, eb) = (a.entries(), b.entries());
        while i < ea.len() && j < eb.len() {
            match ea[i].path.cmp(&eb[j].path) {
                std::cmp::Ordering::Less => {
                    diff.removed.push(ea[i].path.clone());
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    diff.added.push(eb[j].path.clone());
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    if ea[i] != eb[j] {
                        diff.changed.push(ea[i].path.clone());
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
        diff.removed.extend(ea[i..].iter().map(|e| e.path.clone()));
        diff.added.extend(eb[j..].iter().map(|e| e.path.clone()));
        diff
    }

    /// Whether the two manifests were identical.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}
