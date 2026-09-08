//! Ingest sanitisers (threat-model row 19).
//!
//! Every human-facing string that enters the log from an untrusted source is normalised
//! here so the observer can never be driven by terminal escapes or Unicode bidi spoofing:
//! C0/C1 control characters and explicit bidirectional formatting characters are removed
//! (leaving the segment directionally isolated), invalid UTF-8 is replaced with U+FFFD,
//! and the length is capped. When a value is truncated by the length cap, a BLAKE3 hash of
//! the original bytes is retained so replay can prove the truncation.
//!
//! Sanitisation is idempotent: re-sanitising an already-sanitised string is a no-op, which
//! also lets the wire decoder re-run it on deserialisation without drift.

use serde::{Deserialize, Serialize};

use crate::hash::Blake3Hash;

/// Maximum retained characters for a single sanitised text value.
pub const MAX_TEXT_CHARS: usize = 4096;
/// Maximum retained arguments in a sanitised argv.
pub const MAX_ARGV_ARGS: usize = 1024;
/// Maximum retained characters for a host name.
pub const MAX_HOST_CHARS: usize = 253;

/// Explicit Unicode bidirectional formatting characters. Removing these isolates the
/// segment: it can no longer reorder the text around it.
fn is_bidi_control(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}' // LRE RLE PDF LRO RLO
        | '\u{2066}'..='\u{2069}' // LRI RLI FSI PDI
        | '\u{200E}' | '\u{200F}' // LRM RLM
        | '\u{061C}') // ALM
}

/// Drop control and bidi-formatting characters, then cap length. Returns the cleaned
/// string and whether the length cap truncated it.
fn clean(raw: &str, max_chars: usize) -> (String, bool) {
    let mut out = String::with_capacity(raw.len().min(max_chars));
    let mut count = 0;
    let mut truncated = false;
    for c in raw.chars() {
        if c.is_control() || is_bidi_control(c) {
            continue;
        }
        if count == max_chars {
            truncated = true;
            break;
        }
        out.push(c);
        count += 1;
    }
    (out, truncated)
}

/// A length-capped, sanitised text value (threat-model row 19).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawText", into = "RawText")]
pub struct BoundedText {
    text: String,
    original: Option<Blake3Hash>,
}

/// On-the-wire shape of [`BoundedText`]; deserialisation re-runs sanitisation through it.
#[derive(Serialize, Deserialize)]
struct RawText {
    text: String,
    original: Option<Blake3Hash>,
}

impl From<RawText> for BoundedText {
    fn from(raw: RawText) -> Self {
        // Re-sanitise on ingest from the wire; idempotence keeps trusted text stable.
        let (text, _) = clean(&raw.text, MAX_TEXT_CHARS);
        Self {
            text,
            original: raw.original,
        }
    }
}

impl From<BoundedText> for RawText {
    fn from(bt: BoundedText) -> Self {
        Self {
            text: bt.text,
            original: bt.original,
        }
    }
}

impl BoundedText {
    /// Sanitise a UTF-8 string.
    pub fn new(raw: &str) -> Self {
        Self::from_bytes(raw.as_bytes())
    }

    /// Sanitise raw bytes, replacing invalid UTF-8 with U+FFFD.
    pub fn from_bytes(raw: &[u8]) -> Self {
        let lossy = String::from_utf8_lossy(raw);
        let (text, truncated) = clean(&lossy, MAX_TEXT_CHARS);
        let original = truncated.then(|| Blake3Hash::hash(raw));
        Self { text, original }
    }

    /// The sanitised text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether the length cap truncated the original value.
    pub fn is_truncated(&self) -> bool {
        self.original.is_some()
    }

    /// BLAKE3 hash of the original bytes, present only when truncated.
    pub fn original_hash(&self) -> Option<&Blake3Hash> {
        self.original.as_ref()
    }
}

/// A sanitised, count-capped process argument vector. Each argument is a [`BoundedText`];
/// if arguments were dropped (or any argument truncated) a BLAKE3 hash of the original
/// argv is kept so replay can prove truncation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedArgv {
    args: Vec<BoundedText>,
    original: Option<Blake3Hash>,
}

impl BoundedArgv {
    /// Sanitise an argv from any sequence of byte-strings.
    pub fn new<I, S>(raw: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let originals: Vec<Vec<u8>> = raw.into_iter().map(|s| s.as_ref().to_vec()).collect();
        let mut truncated = originals.len() > MAX_ARGV_ARGS;
        let args: Vec<BoundedText> = originals
            .iter()
            .take(MAX_ARGV_ARGS)
            .map(|a| {
                let bt = BoundedText::from_bytes(a);
                truncated |= bt.is_truncated();
                bt
            })
            .collect();
        let original = truncated.then(|| {
            let mut h = blake3::Hasher::new();
            for a in &originals {
                h.update(a);
                h.update(&[0]); // NUL separates arguments in the proof.
            }
            Blake3Hash::from_bytes(*h.finalize().as_bytes())
        });
        Self { args, original }
    }

    /// The sanitised arguments.
    pub fn args(&self) -> &[BoundedText] {
        &self.args
    }

    /// Whether arguments were dropped or truncated.
    pub fn is_truncated(&self) -> bool {
        self.original.is_some()
    }

    /// BLAKE3 hash of the original argv, present only when truncated.
    pub fn original_hash(&self) -> Option<&Blake3Hash> {
        self.original.as_ref()
    }
}

/// Which sandbox root a [`SandboxPath`] is relative to. Host paths never appear in events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathRoot {
    /// The project worktree, mounted at `/work`.
    Work,
    /// The project environment, mounted at `/env`.
    Env,
}

impl PathRoot {
    fn as_str(self) -> &'static str {
        match self {
            PathRoot::Work => "work",
            PathRoot::Env => "env",
        }
    }
}

/// Why a path was rejected at ingest.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    /// The path is absolute and not under `/work` or `/env`, or otherwise escapes the roots.
    #[error("path is outside the sandbox roots /work and /env")]
    Outside,
    /// The path contains a `..` component.
    #[error("path contains a `..` component")]
    ParentTraversal,
}

/// A path confined to a sandbox root, relative and free of `..` traversal (threat-model
/// row 19 and the event-model "Type notes"). Rendered canonically as `/work/…` or `/env/…`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SandboxPath {
    root: PathRoot,
    rel: String,
}

impl SandboxPath {
    /// Build a path from a root and a relative path, rejecting absolute inputs and `..`.
    ///
    /// # Errors
    /// Returns [`PathError::Outside`] if `rel` is absolute, or [`PathError::ParentTraversal`]
    /// if any component is `..`.
    pub fn new(root: PathRoot, rel: &str) -> Result<Self, PathError> {
        if rel.starts_with('/') {
            return Err(PathError::Outside);
        }
        Ok(Self {
            root,
            rel: sanitise_rel(rel)?,
        })
    }

    /// Parse a full sandbox path such as `/work/src/main.rs`.
    ///
    /// # Errors
    /// Returns [`PathError::Outside`] if the path is not under `/work` or `/env`, or
    /// [`PathError::ParentTraversal`] on a `..` component.
    pub fn parse(full: &str) -> Result<Self, PathError> {
        for root in [PathRoot::Work, PathRoot::Env] {
            let prefix = format!("/{}", root.as_str());
            if full == prefix {
                return Ok(Self {
                    root,
                    rel: String::new(),
                });
            }
            if let Some(rest) = full.strip_prefix(&format!("{prefix}/")) {
                return Ok(Self {
                    root,
                    rel: sanitise_rel(rest)?,
                });
            }
        }
        Err(PathError::Outside)
    }

    /// The sandbox root.
    pub fn root(&self) -> PathRoot {
        self.root
    }

    /// The sanitised path relative to the root (empty for the root itself).
    pub fn rel(&self) -> &str {
        &self.rel
    }
}

/// Reject `..`, drop empty and `.` components, and sanitise each remaining component.
fn sanitise_rel(rel: &str) -> Result<String, PathError> {
    let mut parts: Vec<String> = Vec::new();
    for comp in rel.split('/') {
        match comp {
            "" | "." => {}
            ".." => return Err(PathError::ParentTraversal),
            other => {
                let (clean_comp, _) = clean(other, MAX_TEXT_CHARS);
                parts.push(clean_comp);
            }
        }
    }
    Ok(parts.join("/"))
}

impl std::fmt::Display for SandboxPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rel.is_empty() {
            write!(f, "/{}", self.root.as_str())
        } else {
            write!(f, "/{}/{}", self.root.as_str(), self.rel)
        }
    }
}

impl From<SandboxPath> for String {
    fn from(p: SandboxPath) -> Self {
        p.to_string()
    }
}

impl TryFrom<String> for SandboxPath {
    type Error = PathError;
    fn try_from(full: String) -> Result<Self, Self::Error> {
        Self::parse(&full)
    }
}

/// A sanitised, length-capped, lower-cased host name for display in events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct HostName {
    name: String,
}

impl HostName {
    /// Sanitise a host name: strip control/bidi characters, lower-case ASCII, cap length.
    pub fn new(raw: &str) -> Self {
        let (mut name, _) = clean(raw, MAX_HOST_CHARS);
        name.make_ascii_lowercase();
        Self { name }
    }

    /// The sanitised host name.
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl From<String> for HostName {
    fn from(raw: String) -> Self {
        Self::new(&raw)
    }
}

impl From<HostName> for String {
    fn from(h: HostName) -> Self {
        h.name
    }
}
