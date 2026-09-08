//! Credential service identifiers, credential scopes and observer step patterns.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

/// Maximum length of a service identifier.
pub const MAX_SERVICE_ID_LEN: usize = 64;

/// Maximum length of a scope item.
pub const MAX_SCOPE_ITEM_LEN: usize = 128;

/// Maximum length of a step pattern.
pub const MAX_STEP_PATTERN_LEN: usize = 512;

/// Identifier of a credential-broker service, optionally with `*` wildcards
/// (`github`, `npm-publish`, `cloud-*`).
///
/// Grammar: 1–64 characters from `[a-z0-9_.*-]`, not starting with `.` or `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceId(String);

impl ServiceId {
    /// Validates and wraps a service identifier or pattern.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidServiceId`] for anything outside the grammar.
    pub fn new(s: impl Into<String>) -> Result<Self, PolicyError> {
        let s = s.into();
        let reject = |reason| PolicyError::InvalidServiceId {
            value: s.clone(),
            reason,
        };
        if s.is_empty() {
            return Err(reject("must not be empty"));
        }
        if s.len() > MAX_SERVICE_ID_LEN {
            return Err(reject("too long"));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'*' | b'-')
        }) {
            return Err(reject("only `[a-z0-9_.*-]` are allowed"));
        }
        if s.starts_with('.') || s.starts_with('-') {
            return Err(reject("must not start with `.` or `-`"));
        }
        Ok(Self(s))
    }

    /// The identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` if the identifier contains a `*` wildcard.
    #[must_use]
    pub fn is_pattern(&self) -> bool {
        self.0.contains('*')
    }

    /// Whether this identifier (as a pattern) matches `name` taken literally.
    ///
    /// `*` matches any run of characters, including none. An identifier without `*`
    /// matches only itself.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        star_match(self.0.as_bytes(), name.as_bytes())
    }
}

/// Classic iterative `*`-only glob matcher.
fn star_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut backtrack: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            backtrack = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((bp, bt)) = backtrack {
            p = bp + 1;
            t = bt + 1;
            backtrack = Some((bp, bt + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

impl TryFrom<String> for ServiceId {
    type Error = PolicyError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl FromStr for ServiceId {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl From<ServiceId> for String {
    fn from(v: ServiceId) -> String {
        v.0
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One element of a credential scope (`repo:current`, `contents:read`, `per-host`).
///
/// Grammar: 1–128 characters from `[A-Za-z0-9_.:/*@-]`. Scope items are opaque to the
/// policy engine; service adapters interpret them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ScopeItem(String);

impl ScopeItem {
    /// Validates and wraps a scope item.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidScopeItem`] for anything outside the grammar.
    pub fn new(s: impl Into<String>) -> Result<Self, PolicyError> {
        let s = s.into();
        let reject = |reason| PolicyError::InvalidScopeItem {
            value: s.clone(),
            reason,
        };
        if s.is_empty() {
            return Err(reject("must not be empty"));
        }
        if s.len() > MAX_SCOPE_ITEM_LEN {
            return Err(reject("too long"));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'*' | b'@' | b'-')
        }) {
            return Err(reject("only `[A-Za-z0-9_.:/*@-]` are allowed"));
        }
        Ok(Self(s))
    }

    /// The item as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ScopeItem {
    type Error = PolicyError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl FromStr for ScopeItem {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl From<ScopeItem> for String {
    fn from(v: ScopeItem) -> String {
        v.0
    }
}

impl fmt::Display for ScopeItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated glob pattern naming actions the observer holds in step-through mode.
///
/// Patterns use `globset` syntax and are validated at parse time. They are matched
/// against sandbox-relative paths and command names by `wardd`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct StepPattern(String);

impl StepPattern {
    /// Validates and wraps a glob pattern.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidStepPattern`] if the pattern is empty, too long,
    /// or not a valid glob.
    pub fn new(s: impl Into<String>) -> Result<Self, PolicyError> {
        let s = s.into();
        if s.is_empty() {
            return Err(PolicyError::InvalidStepPattern {
                value: s,
                reason: "must not be empty".to_owned(),
            });
        }
        if s.len() > MAX_STEP_PATTERN_LEN {
            return Err(PolicyError::InvalidStepPattern {
                value: s,
                reason: "too long".to_owned(),
            });
        }
        globset::Glob::new(&s).map_err(|e| PolicyError::InvalidStepPattern {
            value: s.clone(),
            reason: e.kind().to_string(),
        })?;
        Ok(Self(s))
    }

    /// The pattern as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the pattern matches `candidate`.
    ///
    /// Fails closed: if the pattern cannot be compiled (which validation should make
    /// impossible), the result is `true` so the action is held.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        globset::Glob::new(&self.0).map_or(true, |g| g.compile_matcher().is_match(candidate))
    }
}

impl TryFrom<String> for StepPattern {
    type Error = PolicyError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl FromStr for StepPattern {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl From<StepPattern> for String {
    fn from(v: StepPattern) -> String {
        v.0
    }
}

impl fmt::Display for StepPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
