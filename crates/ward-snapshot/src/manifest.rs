//! The canonical manifest and the snapshot identity.
//!
//! Format (`docs/snapshots-and-git.md` §3): one record per entry, records terminated by
//! a NUL byte, sorted bytewise by path, with no header and no trailer:
//!
//! ```text
//! <type> <mode> <size> <content-hash> <path-bytes>\0
//! ```
//!
//! * `type` is one of `file`, `dir`, `symlink`, `unsupported`. Submodule worktrees are
//!   recursed as ordinary files and directories (their `.git` is just bytes), so they
//!   need no separate type.
//! * `mode` is exactly four octal digits of permission bits (`0644`, `4755`), never type
//!   bits.
//! * `size` is the decimal byte count of the content: the file length, the symlink
//!   target length, and `0` for directories and unsupported entries.
//! * `content-hash` is 64 lowercase hex characters: BLAKE3 of the file bytes or of the
//!   symlink target; the all-zero [`ContentHash::NONE`] for directories and unsupported
//!   entries.
//! * `path-bytes` is the raw relative path (see [`RelPath`]); it may contain spaces and
//!   newlines but never NUL.
//!
//! The snapshot id is BLAKE3 over these bytes ([`Manifest::id`]). Parsing is strict: a
//! byte sequence that is not already canonical (unsorted, duplicate paths, malformed
//! fields) is rejected rather than repaired, so `parse(bytes).id()` always equals
//! `SnapshotId::of_manifest_bytes(bytes)`.

use crate::error::{Error, Result};
use crate::hash::{ContentHash, SnapshotId};
use crate::path::RelPath;

/// Maximum permission bits (setuid, setgid, sticky, rwxrwxrwx).
pub const MODE_MASK: u32 = 0o7777;

/// The kind of a manifest entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryKind {
    /// A regular file; content hashed.
    File,
    /// A directory (recorded so empty directories survive materialisation).
    Dir,
    /// A symbolic link; the *target bytes* are hashed, the target is never followed.
    Symlink,
    /// FIFO, socket, or device node: recorded by name only and flagged. Never created
    /// on materialisation.
    Unsupported,
}

impl EntryKind {
    /// The token used in the canonical encoding.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Dir => "dir",
            EntryKind::Symlink => "symlink",
            EntryKind::Unsupported => "unsupported",
        }
    }

    fn from_token(token: &[u8]) -> Option<Self> {
        match token {
            b"file" => Some(EntryKind::File),
            b"dir" => Some(EntryKind::Dir),
            b"symlink" => Some(EntryKind::Symlink),
            b"unsupported" => Some(EntryKind::Unsupported),
            _ => None,
        }
    }

    /// True for kinds that carry no content (directories, unsupported).
    #[must_use]
    pub fn is_contentless(self) -> bool {
        matches!(self, EntryKind::Dir | EntryKind::Unsupported)
    }
}

impl std::fmt::Display for EntryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// One manifest entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Entry {
    /// Entry kind.
    pub kind: EntryKind,
    /// Permission bits (`& 0o7777`).
    pub mode: u32,
    /// Content length in bytes (0 for contentless kinds).
    pub size: u64,
    /// Content hash ([`ContentHash::NONE`] for contentless kinds).
    pub hash: ContentHash,
    /// Relative path.
    pub path: RelPath,
}

impl Entry {
    /// A regular-file entry.
    #[must_use]
    pub fn file(path: RelPath, mode: u32, size: u64, hash: ContentHash) -> Self {
        Entry {
            kind: EntryKind::File,
            mode: mode & MODE_MASK,
            size,
            hash,
            path,
        }
    }

    /// A directory entry.
    #[must_use]
    pub fn dir(path: RelPath, mode: u32) -> Self {
        Entry {
            kind: EntryKind::Dir,
            mode: mode & MODE_MASK,
            size: 0,
            hash: ContentHash::NONE,
            path,
        }
    }

    /// A symlink entry; hashes and measures `target`.
    #[must_use]
    pub fn symlink(path: RelPath, target: &[u8]) -> Self {
        Entry {
            kind: EntryKind::Symlink,
            mode: 0o777,
            size: target.len() as u64,
            hash: ContentHash::of(target),
            path,
        }
    }

    /// An unsupported (FIFO/socket/device) entry.
    #[must_use]
    pub fn unsupported(path: RelPath, mode: u32) -> Self {
        Entry {
            kind: EntryKind::Unsupported,
            mode: mode & MODE_MASK,
            size: 0,
            hash: ContentHash::NONE,
            path,
        }
    }

    /// Append the canonical record (including the terminating NUL) to `out`.
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.kind.token().as_bytes());
        out.push(b' ');
        out.extend_from_slice(format!("{:04o}", self.mode & MODE_MASK).as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.size.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.hash.to_hex().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path.as_bytes());
        out.push(0);
    }

    fn validate(&self, index: usize) -> Result<()> {
        if self.mode > MODE_MASK {
            return Err(Error::ManifestParse {
                index,
                reason: format!("mode {:o} exceeds {MODE_MASK:o}", self.mode),
            });
        }
        if self.kind.is_contentless() && (self.size != 0 || !self.hash.is_none()) {
            return Err(Error::ManifestParse {
                index,
                reason: format!("{} entries must have size 0 and no content hash", self.kind),
            });
        }
        if !self.kind.is_contentless() && self.hash.is_none() {
            return Err(Error::ManifestParse {
                index,
                reason: format!("{} entries must carry a content hash", self.kind),
            });
        }
        Ok(())
    }

    fn parse_record(index: usize, record: &[u8]) -> Result<Entry> {
        let bad = |reason: String| Error::ManifestParse { index, reason };
        let mut fields = record.splitn(5, |b| *b == b' ');
        let kind_tok = fields.next().unwrap_or_default();
        let kind = EntryKind::from_token(kind_tok).ok_or_else(|| {
            bad(format!(
                "unknown entry type {:?}",
                String::from_utf8_lossy(kind_tok)
            ))
        })?;

        let mode_tok = fields.next().ok_or_else(|| bad("missing mode".into()))?;
        let mode = parse_mode(mode_tok).ok_or_else(|| bad("malformed mode".into()))?;

        let size_tok = fields.next().ok_or_else(|| bad("missing size".into()))?;
        let size = parse_size(size_tok).ok_or_else(|| bad("malformed size".into()))?;

        let hash_tok = fields
            .next()
            .ok_or_else(|| bad("missing content hash".into()))?;
        let hash_str =
            std::str::from_utf8(hash_tok).map_err(|_| bad("malformed content hash".into()))?;
        let hash: ContentHash = hash_str
            .parse()
            .map_err(|_| bad("malformed content hash".into()))?;

        let path_bytes = fields.next().ok_or_else(|| bad("missing path".into()))?;
        let path = RelPath::new(path_bytes.to_vec())?;

        let entry = Entry {
            kind,
            mode,
            size,
            hash,
            path,
        };
        entry.validate(index)?;
        Ok(entry)
    }
}

/// Exactly four octal digits.
fn parse_mode(tok: &[u8]) -> Option<u32> {
    if tok.len() != 4 {
        return None;
    }
    let mut mode = 0u32;
    for b in tok {
        if !(b'0'..=b'7').contains(b) {
            return None;
        }
        mode = (mode << 3) | u32::from(b - b'0');
    }
    Some(mode)
}

/// Decimal without leading zeros (except `0` itself), fitting in `u64`.
fn parse_size(tok: &[u8]) -> Option<u64> {
    if tok.is_empty() || (tok.len() > 1 && tok[0] == b'0') {
        return None;
    }
    let s = std::str::from_utf8(tok).ok()?;
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// A canonical, sorted, duplicate-free list of entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manifest {
    entries: Vec<Entry>,
}

impl Manifest {
    /// Build a manifest from entries in any order. Entries are sorted bytewise by path;
    /// modes are masked to permission bits.
    ///
    /// # Errors
    /// [`Error::DuplicatePath`] if two entries share a path; [`Error::ManifestParse`] if
    /// an entry is internally inconsistent (e.g. a directory with a content hash).
    pub fn from_entries(mut entries: Vec<Entry>) -> Result<Self> {
        for e in &mut entries {
            e.mode &= MODE_MASK;
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        for (i, e) in entries.iter().enumerate() {
            e.validate(i)?;
            if i > 0 && entries[i - 1].path == e.path {
                return Err(Error::DuplicatePath {
                    path: e.path.as_bytes().to_vec(),
                });
            }
        }
        Ok(Manifest { entries })
    }

    /// Entries in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up an entry by path (binary search).
    #[must_use]
    pub fn get(&self, path: &RelPath) -> Option<&Entry> {
        self.entries
            .binary_search_by(|e| e.path.cmp(path))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// Sum of file sizes (symlink targets and contentless entries excluded).
    #[must_use]
    pub fn total_file_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .map(|e| e.size)
            .sum()
    }

    /// The canonical encoding.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.entries.len() * 128);
        for e in &self.entries {
            e.write_canonical(&mut out);
        }
        out
    }

    /// The snapshot id: BLAKE3 over the canonical encoding.
    #[must_use]
    pub fn id(&self) -> SnapshotId {
        SnapshotId::of_manifest_bytes(&self.to_canonical_bytes())
    }

    /// Parse canonical bytes strictly.
    ///
    /// # Errors
    /// [`Error::ManifestParse`] for malformed records, unsorted input or a missing
    /// terminating NUL; [`Error::DuplicatePath`] for repeated paths;
    /// [`Error::InvalidPath`] for paths violating the [`RelPath`] rules (`..`, absolute,
    /// empty component).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut rest = bytes;
        let mut index = 0usize;
        while !rest.is_empty() {
            let Some(nul) = rest.iter().position(|b| *b == 0) else {
                return Err(Error::ManifestParse {
                    index,
                    reason: "record is not NUL-terminated".into(),
                });
            };
            let entry = Entry::parse_record(index, &rest[..nul])?;
            if let Some(prev) = entries.last() {
                match prev.path.cmp(&entry.path) {
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => {
                        return Err(Error::DuplicatePath {
                            path: entry.path.into_bytes(),
                        });
                    }
                    std::cmp::Ordering::Greater => {
                        return Err(Error::ManifestParse {
                            index,
                            reason: "entries are not in bytewise path order".into(),
                        });
                    }
                }
            }
            entries.push(entry);
            rest = &rest[nul + 1..];
            index += 1;
        }
        Ok(Manifest { entries })
    }

    /// Iterate over entries.
    pub fn iter(&self) -> std::slice::Iter<'_, Entry> {
        self.entries.iter()
    }
}

impl<'a> IntoIterator for &'a Manifest {
    type Item = &'a Entry;
    type IntoIter = std::slice::Iter<'a, Entry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(s: &str) -> RelPath {
        RelPath::new(s).unwrap_or_else(|_| unreachable!("test path"))
    }

    #[test]
    fn empty_manifest_has_stable_id() {
        let m = Manifest::default();
        assert!(m.to_canonical_bytes().is_empty());
        assert_eq!(m.id(), SnapshotId::of_manifest_bytes(b""));
        assert_eq!(Manifest::parse(b"").ok(), Some(m));
    }

    #[test]
    fn mode_and_size_parsing_is_strict() {
        assert_eq!(parse_mode(b"0644"), Some(0o644));
        assert_eq!(parse_mode(b"644"), None);
        assert_eq!(parse_mode(b"0648"), None);
        assert_eq!(parse_mode(b"07777"), None);
        assert_eq!(parse_size(b"0"), Some(0));
        assert_eq!(parse_size(b"010"), None);
        assert_eq!(parse_size(b""), None);
        assert_eq!(parse_size(b"1x"), None);
        assert_eq!(parse_size(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_size(b"18446744073709551616"), None);
    }

    #[test]
    fn from_entries_sorts_and_masks() {
        let m = Manifest::from_entries(vec![
            Entry::dir(rp("b"), 0o40755),
            Entry::file(rp("a"), 0o100_644, 0, ContentHash::of(b"")),
        ]);
        let m = m.unwrap_or_default();
        assert_eq!(m.entries()[0].path, rp("a"));
        assert_eq!(m.entries()[1].mode, 0o755);
        assert_eq!(m.entries()[0].mode, 0o644);
    }

    #[test]
    fn contentless_entries_are_validated() {
        let bad = Entry {
            kind: EntryKind::Dir,
            mode: 0o755,
            size: 1,
            hash: ContentHash::NONE,
            path: rp("d"),
        };
        assert!(Manifest::from_entries(vec![bad]).is_err());
        let bad = Entry {
            kind: EntryKind::File,
            mode: 0o644,
            size: 0,
            hash: ContentHash::NONE,
            path: rp("f"),
        };
        assert!(Manifest::from_entries(vec![bad]).is_err());
    }
}
