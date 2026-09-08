//! Bounded, sanitised text types (`event-model.md` §3, threat-model ST-020).
//!
//! Sanitisation happens **at construction** and is re-checked on deserialisation, so a
//! value of any type in this module is always safe to render in a terminal cell:
//!
//! * C0 and C1 control characters are removed. Line and paragraph separators (`\t`,
//!   `\n`, `\r`, VT, FF, NEL, U+2028, U+2029) are collapsed into a single ASCII space
//!   rather than dropped, so that stripping cannot join two words into a new token.
//! * Explicit bidirectional controls (U+202A–U+202E, U+2066–U+2069, U+200E/F, U+061C)
//!   and other invisible format characters (zero-width spaces and joiners, soft hyphen,
//!   BOM, word joiner, interlinear annotation, U+FFFE/U+FFFF) are removed.
//! * [`BoundedText`] values that still contain any non-ASCII character are wrapped in a
//!   first-strong isolate (U+2068 … U+2069) so their inherent direction cannot leak into
//!   the surrounding line. [`SandboxPath`] applies the isolate in its `Display` impl
//!   instead, so its stored form remains a usable relative path.
//! * Invalid UTF-8 in byte inputs is replaced with U+FFFD.
//! * Over-long input is truncated on a character boundary; the type records
//!   `truncated` and a `BLAKE3` hash of the original bytes so replay can prove truncation.
//!   The hash is also recorded whenever sanitisation altered the content.

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::ids::Blake3Hash;

/// First-strong isolate (FSI).
pub const FSI: char = '\u{2068}';
/// Pop directional isolate (PDI).
pub const PDI: char = '\u{2069}';
const ISOLATE_BYTES: usize = FSI.len_utf8() + PDI.len_utf8();

/// Errors from text validation (mostly surfaced through deserialisation).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TextError {
    /// The text is not in canonical sanitised form.
    #[error("text is not in sanitised canonical form")]
    NotSanitised,
    /// The text exceeds its byte cap.
    #[error("text longer than {max} bytes ({found})")]
    TooLong {
        /// Cap in bytes.
        max: usize,
        /// Length found.
        found: usize,
    },
    /// `truncated` was set without an original-content hash.
    #[error("truncated text must carry the hash of its original bytes")]
    TruncatedWithoutHash,
    /// Too many argv entries.
    #[error("argv has {found} entries, more than {max}")]
    TooManyArgs {
        /// Cap on entries.
        max: usize,
        /// Entries found.
        found: usize,
    },
}

/// Errors from [`SandboxPath`] construction.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PathError {
    /// The path was empty.
    #[error("path is empty")]
    Empty,
    /// The path contained a NUL byte.
    #[error("path contains a NUL byte")]
    Nul,
    /// The path was absolute (a host path, or otherwise not relative to the sandbox root).
    #[error("path is absolute; sandbox paths must be relative to /work or /env")]
    Absolute,
    /// The path contained a `..` component.
    #[error("path contains a `..` component")]
    ParentComponent,
    /// The path exceeded [`SandboxPath::MAX_BYTES`].
    #[error("path longer than {max} bytes ({found})")]
    TooLong {
        /// Cap in bytes.
        max: usize,
        /// Length found.
        found: usize,
    },
    /// A deserialised path was not in canonical form.
    #[error("path is not in canonical sanitised form")]
    NotCanonical,
}

/// Errors from [`HostName`] construction.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HostError {
    /// Empty host name.
    #[error("host name is empty")]
    Empty,
    /// Longer than 253 bytes.
    #[error("host name longer than {max} bytes ({found})")]
    TooLong {
        /// Cap in bytes.
        max: usize,
        /// Length found.
        found: usize,
    },
    /// A label was empty (consecutive dots or leading dot).
    #[error("host name has an empty label")]
    EmptyLabel,
    /// A label was longer than 63 bytes.
    #[error("host name label longer than 63 bytes")]
    LabelTooLong,
    /// A label started or ended with a hyphen.
    #[error("host name label starts or ends with a hyphen")]
    LabelHyphen,
    /// A character outside `[a-z0-9-.]` (after lowercasing) was found.
    #[error("host name contains an invalid character at byte {index}")]
    InvalidChar {
        /// Byte offset of the offending character.
        index: usize,
    },
}

// ---------------------------------------------------------------------------------------
// Core sanitiser
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Keep,
    Space,
    Drop,
}

fn classify(c: char) -> Class {
    match c {
        '\t' | '\n' | '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}' => {
            Class::Space
        }
        '\0'..='\u{1F}'
        | '\u{7F}'..='\u{9F}'
        | '\u{AD}'
        | '\u{61C}'
        | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{FFFE}'
        | '\u{FFFF}' => Class::Drop,
        _ => Class::Keep,
    }
}

/// Result of running the sanitiser over one string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sanitised {
    /// The sanitised, capped text.
    pub text: String,
    /// Whether characters were cut to respect the byte cap.
    pub truncated: bool,
    /// Whether any character was removed or replaced (independent of truncation and of
    /// the isolate wrapper, which is reversible).
    pub altered: bool,
}

/// Sanitises `input` to at most `max_bytes` bytes, as described in the module docs.
///
/// When `isolate` is set and the result contains any non-ASCII character it is wrapped
/// in FSI/PDI; the wrapper's six bytes count against `max_bytes`.
#[must_use]
pub fn sanitise(input: &str, max_bytes: usize, isolate: bool) -> Sanitised {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    let mut truncated = false;
    let mut altered = false;
    let mut last_synthetic_space = false;

    for c in input.chars() {
        let emit = match classify(c) {
            Class::Keep => {
                last_synthetic_space = false;
                Some(c)
            }
            Class::Space => {
                altered = true;
                if last_synthetic_space {
                    None
                } else {
                    last_synthetic_space = true;
                    Some(' ')
                }
            }
            Class::Drop => {
                altered = true;
                None
            }
        };
        if let Some(ch) = emit {
            if out.len() + ch.len_utf8() > max_bytes {
                truncated = true;
                break;
            }
            out.push(ch);
        }
    }

    if isolate && !out.is_ascii() {
        let cap = max_bytes.saturating_sub(ISOLATE_BYTES);
        if out.len() > cap {
            out.truncate(out.floor_char_boundary(cap));
            truncated = true;
        }
        if !out.is_ascii() {
            let mut wrapped = String::with_capacity(out.len() + ISOLATE_BYTES);
            wrapped.push(FSI);
            wrapped.push_str(&out);
            wrapped.push(PDI);
            out = wrapped;
        }
    }

    Sanitised {
        text: out,
        truncated,
        altered,
    }
}

fn lossy(bytes: &[u8]) -> (std::borrow::Cow<'_, str>, bool) {
    let cow = String::from_utf8_lossy(bytes);
    let was_lossy = matches!(cow, std::borrow::Cow::Owned(_));
    (cow, was_lossy)
}

// ---------------------------------------------------------------------------------------
// BoundedText
// ---------------------------------------------------------------------------------------

/// Sanitised text capped at `N` bytes (including the isolate wrapper when present).
///
/// `N` must be at least 8 so that the six-byte isolate wrapper leaves room for content.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BoundedText<const N: usize> {
    text: String,
    truncated: bool,
    original_hash: Option<Blake3Hash>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "BoundedText")]
struct RawText<'a> {
    #[serde(borrow)]
    text: std::borrow::Cow<'a, str>,
    truncated: bool,
    original_hash: Option<Blake3Hash>,
}

impl<const N: usize> BoundedText<N> {
    /// Byte cap of this type.
    pub const MAX_BYTES: usize = N;
    const MIN_CAP_OK: () = assert!(N >= 8, "BoundedText cap must be at least 8 bytes");

    /// Sanitises `input`.
    #[must_use]
    pub fn new(input: &str) -> Self {
        Self::build(input, input.as_bytes(), false)
    }

    /// Sanitises raw bytes, replacing invalid UTF-8 with U+FFFD.
    #[must_use]
    pub fn from_bytes(input: &[u8]) -> Self {
        let (text, was_lossy) = lossy(input);
        Self::build(&text, input, was_lossy)
    }

    fn build(text: &str, original: &[u8], was_lossy: bool) -> Self {
        let () = Self::MIN_CAP_OK;
        let s = sanitise(text, N, true);
        let changed = s.truncated || s.altered || was_lossy;
        Self {
            text: s.text,
            truncated: s.truncated,
            original_hash: changed.then(|| Blake3Hash::hash(original)),
        }
    }

    /// The stored, render-safe text (including the isolate wrapper when present).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The text without its isolate wrapper, for comparisons and matching.
    #[must_use]
    pub fn content(&self) -> &str {
        self.text
            .strip_prefix(FSI)
            .and_then(|s| s.strip_suffix(PDI))
            .unwrap_or(&self.text)
    }

    /// Whether the input was cut to fit.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// `BLAKE3` of the original input bytes, present iff sanitisation or truncation changed
    /// the content.
    #[must_use]
    pub const fn original_hash(&self) -> Option<Blake3Hash> {
        self.original_hash
    }

    /// Stored length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Whether the stored text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    fn validate(raw: RawText<'_>) -> Result<Self, TextError> {
        if raw.text.len() > N {
            return Err(TextError::TooLong {
                max: N,
                found: raw.text.len(),
            });
        }
        let canon = sanitise(&raw.text, N, true);
        if canon.truncated || canon.text != raw.text {
            return Err(TextError::NotSanitised);
        }
        if raw.truncated && raw.original_hash.is_none() {
            return Err(TextError::TruncatedWithoutHash);
        }
        Ok(Self {
            text: raw.text.into_owned(),
            truncated: raw.truncated,
            original_hash: raw.original_hash,
        })
    }
}

impl<const N: usize> Default for BoundedText<N> {
    fn default() -> Self {
        Self::new("")
    }
}

impl<const N: usize> fmt::Display for BoundedText<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl<const N: usize> fmt::Debug for BoundedText<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedText")
            .field("text", &self.text)
            .field("truncated", &self.truncated)
            .field("original_hash", &self.original_hash)
            .finish()
    }
}

impl<const N: usize> From<&str> for BoundedText<N> {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl<const N: usize> Serialize for BoundedText<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RawText {
            text: std::borrow::Cow::Borrowed(&self.text),
            truncated: self.truncated,
            original_hash: self.original_hash,
        }
        .serialize(serializer)
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedText<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawText::deserialize(deserializer)?;
        Self::validate(raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------------------
// BoundedArgv
// ---------------------------------------------------------------------------------------

/// One argv entry.
pub type Arg = BoundedText<{ BoundedArgv::MAX_ARG_BYTES }>;

/// A bounded, sanitised argument vector.
///
/// Caps: [`MAX_ARGS`](Self::MAX_ARGS) entries, [`MAX_ARG_BYTES`](Self::MAX_ARG_BYTES) per
/// entry, [`MAX_TOTAL_BYTES`](Self::MAX_TOTAL_BYTES) in total. Entries beyond the caps are
/// omitted (counted in [`omitted`](Self::omitted)); when anything was omitted, cut, or
/// altered, `original_hash` is the `BLAKE3` of the original entries each followed by a NUL
/// byte (the `/proc/<pid>/cmdline` layout).
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct BoundedArgv {
    args: Vec<Arg>,
    omitted: u32,
    truncated: bool,
    original_hash: Option<Blake3Hash>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "BoundedArgv")]
struct RawArgv {
    args: Vec<Arg>,
    omitted: u32,
    truncated: bool,
    original_hash: Option<Blake3Hash>,
}

impl BoundedArgv {
    /// Maximum number of stored entries.
    pub const MAX_ARGS: usize = 256;
    /// Byte cap per entry.
    pub const MAX_ARG_BYTES: usize = 4096;
    /// Byte cap for the sum of all stored entries.
    pub const MAX_TOTAL_BYTES: usize = 16 * 1024;

    /// Builds from raw byte arguments (e.g. as read from a tracepoint).
    #[must_use]
    pub fn from_bytes<'a, I>(argv: I) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let raw: Vec<&[u8]> = argv.into_iter().collect();
        let mut kept = Vec::with_capacity(raw.len().min(Self::MAX_ARGS));
        let mut total = 0usize;
        let mut truncated = false;
        let mut altered = false;
        let mut omitted = 0usize;

        for (i, bytes) in raw.iter().enumerate() {
            if i >= Self::MAX_ARGS {
                omitted = raw.len() - i;
                break;
            }
            let arg = Arg::from_bytes(bytes);
            if total + arg.len() > Self::MAX_TOTAL_BYTES {
                omitted = raw.len() - i;
                break;
            }
            total += arg.len();
            truncated |= arg.is_truncated();
            altered |= arg.original_hash().is_some();
            kept.push(arg);
        }

        let changed = truncated || altered || omitted > 0;
        let original_hash = changed.then(|| {
            let mut hasher = blake3::Hasher::new();
            for bytes in &raw {
                hasher.update(bytes);
                hasher.update(&[0u8]);
            }
            Blake3Hash::from(hasher.finalize())
        });

        Self {
            args: kept,
            omitted: u32::try_from(omitted).unwrap_or(u32::MAX),
            truncated: truncated || omitted > 0,
            original_hash,
        }
    }

    /// Builds from string arguments.
    #[must_use]
    pub fn from_strs<S: AsRef<str>>(argv: &[S]) -> Self {
        Self::from_bytes(argv.iter().map(|s| s.as_ref().as_bytes()))
    }

    /// Stored entries.
    #[must_use]
    pub fn args(&self) -> &[Arg] {
        &self.args
    }

    /// Number of entries that were dropped entirely because of the caps.
    #[must_use]
    pub const fn omitted(&self) -> u32 {
        self.omitted
    }

    /// Whether any entry was cut or omitted.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// `BLAKE3` of the original argv (see type docs), present iff anything changed.
    #[must_use]
    pub const fn original_hash(&self) -> Option<Blake3Hash> {
        self.original_hash
    }

    /// Number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.args.len()
    }

    /// Whether no entries are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.args.is_empty()
    }

    fn validate(raw: RawArgv) -> Result<Self, TextError> {
        if raw.args.len() > Self::MAX_ARGS {
            return Err(TextError::TooManyArgs {
                max: Self::MAX_ARGS,
                found: raw.args.len(),
            });
        }
        let total: usize = raw.args.iter().map(BoundedText::len).sum();
        if total > Self::MAX_TOTAL_BYTES {
            return Err(TextError::TooLong {
                max: Self::MAX_TOTAL_BYTES,
                found: total,
            });
        }
        let truncated = raw.truncated || raw.omitted > 0;
        if truncated && raw.original_hash.is_none() {
            return Err(TextError::TruncatedWithoutHash);
        }
        Ok(Self {
            args: raw.args,
            omitted: raw.omitted,
            truncated,
            original_hash: raw.original_hash,
        })
    }
}

impl fmt::Display for BoundedArgv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arg) in self.args.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(arg.as_str())?;
        }
        if self.omitted > 0 {
            write!(f, " …(+{} omitted)", self.omitted)?;
        }
        Ok(())
    }
}

impl fmt::Debug for BoundedArgv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedArgv")
            .field(
                "args",
                &self
                    .args
                    .iter()
                    .map(BoundedText::as_str)
                    .collect::<Vec<_>>(),
            )
            .field("omitted", &self.omitted)
            .field("truncated", &self.truncated)
            .field("original_hash", &self.original_hash)
            .finish()
    }
}

impl Serialize for BoundedArgv {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialise a borrowed view by cloning only the small header; args are cloned by
        // serde's `Vec` serialisation anyway.
        RawArgv {
            args: self.args.clone(),
            omitted: self.omitted,
            truncated: self.truncated,
            original_hash: self.original_hash,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BoundedArgv {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawArgv::deserialize(deserializer)?;
        Self::validate(raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------------------
// SandboxPath
// ---------------------------------------------------------------------------------------

/// The sandbox mount a [`SandboxPath`] is relative to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SandboxRoot {
    /// The project worktree, mounted at `/work`.
    Work,
    /// The persistent project environment, mounted at `/env`.
    Env,
}

impl SandboxRoot {
    /// Mount point inside the sandbox.
    #[must_use]
    pub const fn mount_point(self) -> &'static str {
        match self {
            SandboxRoot::Work => "/work",
            SandboxRoot::Env => "/env",
        }
    }
}

impl fmt::Display for SandboxRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mount_point())
    }
}

/// A path relative to a sandbox mount (`/work` or `/env`). Host paths never appear.
///
/// Invariants: relative; no empty, `.` or `..` components; no NUL; no control or
/// invisible format characters; at most [`MAX_BYTES`](Self::MAX_BYTES) bytes. An empty
/// relative part denotes the mount root itself (constructed from `.`).
///
/// The stored relative path is not wrapped in bidi isolates so it stays usable as a path;
/// the `Display` impl renders `<mount>/<rel>` and applies the isolate when the path
/// contains non-ASCII characters.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SandboxPath {
    root: SandboxRoot,
    rel: String,
    original_hash: Option<Blake3Hash>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "SandboxPath")]
struct RawPath<'a> {
    root: SandboxRoot,
    #[serde(borrow)]
    rel: std::borrow::Cow<'a, str>,
    original_hash: Option<Blake3Hash>,
}

impl SandboxPath {
    /// Byte cap for the relative part.
    pub const MAX_BYTES: usize = 4096;

    /// Validates and canonicalises `path` relative to `root`.
    ///
    /// # Errors
    /// See [`PathError`]. Absolute paths, `..` components, NUL bytes, empty input and
    /// over-long input are rejected rather than repaired.
    pub fn new(root: SandboxRoot, path: &str) -> Result<Self, PathError> {
        Self::build(root, path, path.as_bytes(), false)
    }

    /// Like [`new`](Self::new) but from raw bytes; invalid UTF-8 becomes U+FFFD.
    ///
    /// # Errors
    /// See [`PathError`].
    pub fn from_bytes(root: SandboxRoot, path: &[u8]) -> Result<Self, PathError> {
        if path.contains(&0) {
            return Err(PathError::Nul);
        }
        let (text, was_lossy) = lossy(path);
        Self::build(root, &text, path, was_lossy)
    }

    fn build(
        root: SandboxRoot,
        text: &str,
        original: &[u8],
        was_lossy: bool,
    ) -> Result<Self, PathError> {
        if text.is_empty() {
            return Err(PathError::Empty);
        }
        if text.contains('\0') {
            return Err(PathError::Nul);
        }
        if text.starts_with('/') {
            return Err(PathError::Absolute);
        }
        if text.len() > Self::MAX_BYTES {
            return Err(PathError::TooLong {
                max: Self::MAX_BYTES,
                found: text.len(),
            });
        }
        // Reject `..` before *and* after sanitisation: stripping a control character from
        // `.\u{1}.` must not manufacture a parent component.
        if text.split('/').any(|c| c == "..") {
            return Err(PathError::ParentComponent);
        }
        let s = sanitise(text, Self::MAX_BYTES, false);
        if s.truncated {
            return Err(PathError::TooLong {
                max: Self::MAX_BYTES,
                found: text.len(),
            });
        }
        let mut rel = String::with_capacity(s.text.len());
        for component in s.text.split('/') {
            match component {
                "" | "." => {}
                ".." => return Err(PathError::ParentComponent),
                c => {
                    if !rel.is_empty() {
                        rel.push('/');
                    }
                    rel.push_str(c);
                }
            }
        }
        let changed = was_lossy || s.altered || rel != text;
        Ok(Self {
            root,
            rel,
            original_hash: changed.then(|| Blake3Hash::hash(original)),
        })
    }

    /// The mount this path is relative to.
    #[must_use]
    pub const fn root(&self) -> SandboxRoot {
        self.root
    }

    /// The canonical relative path (empty for the mount root itself).
    #[must_use]
    pub fn relative(&self) -> &str {
        &self.rel
    }

    /// Path components in order.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.rel.split('/').filter(|c| !c.is_empty())
    }

    /// Whether this path denotes the mount root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.rel.is_empty()
    }

    /// `BLAKE3` of the original input bytes, present iff canonicalisation or sanitisation
    /// changed the representation.
    #[must_use]
    pub const fn original_hash(&self) -> Option<Blake3Hash> {
        self.original_hash
    }

    /// Full path inside the sandbox mount namespace, e.g. `/work/src/main.rs`.
    #[must_use]
    pub fn in_sandbox(&self) -> String {
        if self.rel.is_empty() {
            self.root.mount_point().to_owned()
        } else {
            format!("{}/{}", self.root.mount_point(), self.rel)
        }
    }

    fn validate(raw: RawPath<'_>) -> Result<Self, PathError> {
        let canon = if raw.rel.is_empty() {
            Self::new(raw.root, ".")?
        } else {
            Self::new(raw.root, &raw.rel)?
        };
        if canon.rel != raw.rel {
            return Err(PathError::NotCanonical);
        }
        Ok(Self {
            root: raw.root,
            rel: raw.rel.into_owned(),
            original_hash: raw.original_hash,
        })
    }
}

impl fmt::Display for SandboxPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let full = self.in_sandbox();
        if full.is_ascii() {
            f.write_str(&full)
        } else {
            write!(f, "{FSI}{full}{PDI}")
        }
    }
}

impl fmt::Debug for SandboxPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxPath")
            .field("root", &self.root)
            .field("rel", &self.rel)
            .field("original_hash", &self.original_hash)
            .finish()
    }
}

impl Serialize for SandboxPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RawPath {
            root: self.root,
            rel: std::borrow::Cow::Borrowed(&self.rel),
            original_hash: self.original_hash,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SandboxPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawPath::deserialize(deserializer)?;
        Self::validate(raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------------------
// HostName
// ---------------------------------------------------------------------------------------

/// A lowercase RFC 1123 host name (labels of `[a-z0-9-]`, 1–63 bytes each, no leading or
/// trailing hyphen, at most 253 bytes in total). A single trailing dot is accepted and
/// removed. Dotted-decimal IPv4 literals satisfy the grammar and are accepted;
/// internationalised names must already be in their `xn--` A-label form.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostName(String);

impl HostName {
    /// Maximum total length in bytes.
    pub const MAX_BYTES: usize = 253;
    /// Maximum label length in bytes.
    pub const MAX_LABEL_BYTES: usize = 63;

    /// Validates and lowercases a host name.
    ///
    /// # Errors
    /// See [`HostError`].
    pub fn new(input: &str) -> Result<Self, HostError> {
        let trimmed = input.strip_suffix('.').unwrap_or(input);
        if trimmed.is_empty() {
            return Err(HostError::Empty);
        }
        if trimmed.len() > Self::MAX_BYTES {
            return Err(HostError::TooLong {
                max: Self::MAX_BYTES,
                found: trimmed.len(),
            });
        }
        let mut lower = String::with_capacity(trimmed.len());
        let mut label_len = 0usize;
        let mut prev = b'.';
        for (index, &b) in trimmed.as_bytes().iter().enumerate() {
            let c = match b {
                b'A'..=b'Z' => b.to_ascii_lowercase(),
                b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' => b,
                _ => return Err(HostError::InvalidChar { index }),
            };
            if c == b'.' {
                if prev == b'.' {
                    return Err(HostError::EmptyLabel);
                }
                if prev == b'-' {
                    return Err(HostError::LabelHyphen);
                }
                label_len = 0;
            } else {
                if prev == b'.' && c == b'-' {
                    return Err(HostError::LabelHyphen);
                }
                label_len += 1;
                if label_len > Self::MAX_LABEL_BYTES {
                    return Err(HostError::LabelTooLong);
                }
            }
            lower.push(c as char);
            prev = c;
        }
        if prev == b'-' {
            return Err(HostError::LabelHyphen);
        }
        if prev == b'.' {
            return Err(HostError::EmptyLabel);
        }
        Ok(Self(lower))
    }

    /// The host name as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostName({:?})", self.0)
    }
}

impl core::str::FromStr for HostName {
    type Err = HostError;
    fn from_str(s: &str) -> Result<Self, HostError> {
        Self::new(s)
    }
}

impl TryFrom<String> for HostName {
    type Error = HostError;
    fn try_from(s: String) -> Result<Self, HostError> {
        Self::new(&s)
    }
}

impl From<HostName> for String {
    fn from(h: HostName) -> String {
        h.0
    }
}

impl AsRef<str> for HostName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    type T32 = BoundedText<32>;

    fn roundtrip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + fmt::Debug>(v: &T) {
        let bytes = postcard::to_allocvec(v).unwrap();
        let back: T = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(&back, v);
    }

    #[test]
    fn plain_ascii_is_untouched() {
        let t = T32::new("hello world");
        assert_eq!(t.as_str(), "hello world");
        assert!(!t.is_truncated());
        assert_eq!(t.original_hash(), None);
        roundtrip(&t);
    }

    #[test]
    fn c0_c1_and_del_controls_are_stripped_and_hashed() {
        let raw = "a\u{1}b\u{1b}[31mc\u{7f}d\u{80}e\u{9f}f";
        let t = T32::new(raw);
        assert_eq!(t.as_str(), "ab[31mcdef");
        assert!(!t.is_truncated());
        assert_eq!(t.original_hash(), Some(Blake3Hash::hash(raw.as_bytes())));
    }

    #[test]
    fn line_breaks_collapse_to_one_space() {
        let t = T32::new("one\r\n\ttwo\u{2028}three");
        assert_eq!(t.as_str(), "one two three");
        assert!(t.original_hash().is_some());
        // Idempotent: the result is its own canonical form.
        assert_eq!(T32::new(t.as_str()).as_str(), t.as_str());
    }

    #[test]
    fn bidi_overrides_are_stripped_and_non_ascii_is_isolated() {
        let raw = "abc\u{202e}fdp.exe";
        let t = T32::new(raw);
        assert_eq!(t.as_str(), "abcfdp.exe");
        assert!(t.original_hash().is_some());

        let t = T32::new("שלום");
        assert_eq!(t.as_str(), "\u{2068}שלום\u{2069}");
        assert_eq!(t.content(), "שלום");
        // Isolation is reversible, so no hash is recorded.
        assert_eq!(t.original_hash(), None);

        let t = T32::new("\u{2068}x\u{2069}");
        assert_eq!(t.as_str(), "x");
        let t = T32::new("a\u{200b}b\u{feff}c\u{ad}d");
        assert_eq!(t.as_str(), "abcd");
    }

    #[test]
    fn over_long_text_is_truncated_on_char_boundary_with_hash() {
        let raw = "x".repeat(40);
        let t = T32::new(&raw);
        assert_eq!(t.len(), 32);
        assert!(t.is_truncated());
        assert_eq!(t.original_hash(), Some(Blake3Hash::hash(raw.as_bytes())));

        // 31 ASCII bytes then a 2-byte char: the char does not fit → cut, still ASCII, no
        // isolate needed.
        let raw = format!("{}é", "y".repeat(31));
        let t = T32::new(&raw);
        assert_eq!(t.as_str(), "y".repeat(31));
        assert!(t.is_truncated());

        // Non-ASCII text at the cap: room is reserved for the isolate wrapper.
        let raw = "é".repeat(20); // 40 bytes
        let t = T32::new(&raw);
        assert!(t.len() <= 32);
        assert!(t.as_str().starts_with(FSI) && t.as_str().ends_with(PDI));
        assert_eq!(t.content().chars().count(), 13);
        assert!(t.is_truncated());
        roundtrip(&t);
    }

    #[test]
    fn invalid_utf8_is_replaced() {
        let t = T32::from_bytes(b"ok\xff\xfe!");
        assert_eq!(t.content(), "ok\u{fffd}\u{fffd}!");
        assert!(t.as_str().starts_with(FSI));
        assert_eq!(t.original_hash(), Some(Blake3Hash::hash(b"ok\xff\xfe!")));
        assert!(!t.is_truncated());
    }

    #[test]
    fn deserialisation_rejects_unsanitised_or_inconsistent_text() {
        fn raw(text: &str, truncated: bool, hash: Option<Blake3Hash>) -> Vec<u8> {
            postcard::to_allocvec(&RawText {
                text: std::borrow::Cow::Borrowed(text),
                truncated,
                original_hash: hash,
            })
            .unwrap()
        }
        assert!(postcard::from_bytes::<T32>(&raw("a\u{1b}b", false, None)).is_err());
        assert!(postcard::from_bytes::<T32>(&raw("שלום", false, None)).is_err());
        assert!(postcard::from_bytes::<T32>(&raw(&"a".repeat(33), false, None)).is_err());
        assert!(postcard::from_bytes::<T32>(&raw("cut", true, None)).is_err());
        let ok = postcard::from_bytes::<T32>(&raw("cut", true, Some(Blake3Hash::ZERO)));
        assert!(ok.is_ok());
        assert!(postcard::from_bytes::<T32>(&raw("\u{2068}é\u{2069}", false, None)).is_ok());
    }

    #[test]
    fn argv_caps_entries_and_hashes_original() {
        let a = BoundedArgv::from_strs(&["cargo", "test", "--", "--nocapture"]);
        assert_eq!(a.len(), 4);
        assert_eq!(a.to_string(), "cargo test -- --nocapture");
        assert!(!a.is_truncated());
        assert_eq!(a.original_hash(), None);
        roundtrip(&a);

        let many: Vec<String> = (0..300).map(|i| i.to_string()).collect();
        let a = BoundedArgv::from_strs(&many);
        assert_eq!(a.len(), BoundedArgv::MAX_ARGS);
        assert_eq!(a.omitted(), 44);
        assert!(a.is_truncated());
        let mut h = blake3::Hasher::new();
        for s in &many {
            h.update(s.as_bytes());
            h.update(&[0]);
        }
        assert_eq!(a.original_hash(), Some(Blake3Hash::from(h.finalize())));
        assert!(a.to_string().ends_with("…(+44 omitted)"));
        roundtrip(&a);

        let big = "z".repeat(5000);
        let a = BoundedArgv::from_strs(&[big.as_str(), "tail"]);
        assert_eq!(a.args()[0].len(), BoundedArgv::MAX_ARG_BYTES);
        assert!(a.args()[0].is_truncated());
        assert!(a.is_truncated());
        assert_eq!(a.omitted(), 0);

        let huge: Vec<String> = (0..10).map(|_| "q".repeat(4000)).collect();
        let a = BoundedArgv::from_strs(&huge);
        assert_eq!(a.len(), 4);
        assert_eq!(a.omitted(), 6);
    }

    #[test]
    fn argv_from_bytes_sanitises_each_entry() {
        let a = BoundedArgv::from_bytes([&b"ls"[..], &b"-l\x1b[0m"[..], &b"\xff"[..]]);
        assert_eq!(a.args()[1].as_str(), "-l[0m");
        assert_eq!(a.args()[2].content(), "\u{fffd}");
        assert!(a.original_hash().is_some());
        assert!(!a.is_truncated());
    }

    #[test]
    fn argv_deserialisation_enforces_caps() {
        let raw = RawArgv {
            args: (0..257).map(|_| Arg::new("x")).collect(),
            omitted: 0,
            truncated: false,
            original_hash: None,
        };
        let bytes = postcard::to_allocvec(&raw).unwrap();
        assert!(postcard::from_bytes::<BoundedArgv>(&bytes).is_err());

        let raw = RawArgv {
            args: vec![],
            omitted: 3,
            truncated: false,
            original_hash: None,
        };
        let bytes = postcard::to_allocvec(&raw).unwrap();
        assert!(postcard::from_bytes::<BoundedArgv>(&bytes).is_err());
    }

    #[test]
    fn sandbox_path_accepts_and_canonicalises_relative_paths() {
        let p = SandboxPath::new(SandboxRoot::Work, "src/main.rs").unwrap();
        assert_eq!(p.relative(), "src/main.rs");
        assert_eq!(p.in_sandbox(), "/work/src/main.rs");
        assert_eq!(p.to_string(), "/work/src/main.rs");
        assert_eq!(p.original_hash(), None);
        roundtrip(&p);

        let p = SandboxPath::new(SandboxRoot::Env, "./node_modules//.bin/./x/").unwrap();
        assert_eq!(p.relative(), "node_modules/.bin/x");
        assert!(p.original_hash().is_some());
        assert_eq!(
            p.components().collect::<Vec<_>>(),
            vec!["node_modules", ".bin", "x"]
        );
        roundtrip(&p);

        let root = SandboxPath::new(SandboxRoot::Work, ".").unwrap();
        assert!(root.is_root());
        assert_eq!(root.to_string(), "/work");
        roundtrip(&root);
    }

    #[test]
    fn sandbox_path_rejects_absolute_parent_nul_empty_and_long() {
        assert_eq!(
            SandboxPath::new(SandboxRoot::Work, "/etc/passwd"),
            Err(PathError::Absolute)
        );
        assert_eq!(
            SandboxPath::new(SandboxRoot::Work, "/"),
            Err(PathError::Absolute)
        );
        assert_eq!(
            SandboxPath::new(SandboxRoot::Work, "../x"),
            Err(PathError::ParentComponent)
        );
        assert_eq!(
            SandboxPath::new(SandboxRoot::Work, "a/../../etc"),
            Err(PathError::ParentComponent)
        );
        assert_eq!(
            SandboxPath::new(SandboxRoot::Work, ".."),
            Err(PathError::ParentComponent)
        );
        assert_eq!(
            SandboxPath::new(SandboxRoot::Work, "a\0b"),
            Err(PathError::Nul)
        );
        assert_eq!(
            SandboxPath::from_bytes(SandboxRoot::Work, b"a\0b"),
            Err(PathError::Nul)
        );
        assert_eq!(
            SandboxPath::new(SandboxRoot::Work, ""),
            Err(PathError::Empty)
        );
        let long = "a/".repeat(2100);
        assert!(matches!(
            SandboxPath::new(SandboxRoot::Work, &long),
            Err(PathError::TooLong { .. })
        ));
        // `..` manufactured by control-character stripping is still rejected.
        assert_eq!(
            SandboxPath::new(SandboxRoot::Work, "x/.\u{1}./y"),
            Err(PathError::ParentComponent)
        );
        // `...` is a legitimate file name.
        assert!(SandboxPath::new(SandboxRoot::Work, "...").is_ok());
    }

    #[test]
    fn sandbox_path_sanitises_and_isolates_display() {
        let p = SandboxPath::from_bytes(SandboxRoot::Work, b"dir/\xff\x1b[2Jname").unwrap();
        assert_eq!(p.relative(), "dir/\u{fffd}[2Jname");
        assert!(p.original_hash().is_some());
        assert!(p.to_string().starts_with(FSI));
        assert!(p.to_string().ends_with(PDI));
        roundtrip(&p);

        let p = SandboxPath::new(SandboxRoot::Work, "a\u{202e}b").unwrap();
        assert_eq!(p.relative(), "ab");
    }

    #[test]
    fn sandbox_path_deserialisation_rejects_non_canonical() {
        fn raw(root: SandboxRoot, rel: &str) -> Vec<u8> {
            postcard::to_allocvec(&RawPath {
                root,
                rel: std::borrow::Cow::Borrowed(rel),
                original_hash: None,
            })
            .unwrap()
        }
        for bad in ["/abs", "a/../b", "a//b", "./a", "a/", "a\u{1}b", "a\0"] {
            assert!(
                postcard::from_bytes::<SandboxPath>(&raw(SandboxRoot::Work, bad)).is_err(),
                "{bad:?}"
            );
        }
        assert!(postcard::from_bytes::<SandboxPath>(&raw(SandboxRoot::Env, "a/b")).is_ok());
        assert!(postcard::from_bytes::<SandboxPath>(&raw(SandboxRoot::Env, "")).is_ok());
    }

    #[test]
    fn host_name_validation_and_lowercasing() {
        assert_eq!(
            HostName::new("API.GitHub.com.").unwrap().as_str(),
            "api.github.com"
        );
        assert_eq!(HostName::new("1.2.3.4").unwrap().as_str(), "1.2.3.4");
        assert_eq!(
            HostName::new("xn--bcher-kva.example").unwrap().as_str(),
            "xn--bcher-kva.example"
        );
        assert_eq!(HostName::new(""), Err(HostError::Empty));
        assert_eq!(HostName::new("."), Err(HostError::Empty));
        assert_eq!(HostName::new("0.."), Err(HostError::EmptyLabel));
        assert_eq!(HostName::new("a.b.."), Err(HostError::EmptyLabel));
        assert_eq!(HostName::new("a..b"), Err(HostError::EmptyLabel));
        assert_eq!(HostName::new(".a"), Err(HostError::EmptyLabel));
        assert_eq!(HostName::new("-a.b"), Err(HostError::LabelHyphen));
        assert_eq!(HostName::new("a-.b"), Err(HostError::LabelHyphen));
        assert_eq!(HostName::new("a.b-"), Err(HostError::LabelHyphen));
        assert_eq!(
            HostName::new("a_b"),
            Err(HostError::InvalidChar { index: 1 })
        );
        assert_eq!(
            HostName::new("bücher.de"),
            Err(HostError::InvalidChar { index: 1 })
        );
        assert_eq!(
            HostName::new("a b"),
            Err(HostError::InvalidChar { index: 1 })
        );
        assert_eq!(HostName::new(&"a".repeat(64)), Err(HostError::LabelTooLong));
        let long = format!("{}.com", "a.".repeat(130));
        assert!(matches!(
            HostName::new(&long),
            Err(HostError::TooLong { .. })
        ));
        let bytes = postcard::to_allocvec("Bad_Host").unwrap();
        assert!(postcard::from_bytes::<HostName>(&bytes).is_err());
        let bytes = postcard::to_allocvec("Example.COM").unwrap();
        assert_eq!(
            postcard::from_bytes::<HostName>(&bytes).unwrap().as_str(),
            "example.com"
        );
    }
}
