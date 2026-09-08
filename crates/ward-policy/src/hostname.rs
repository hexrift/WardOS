//! Validated hostnames and host patterns for network allowlists.
//!
//! An allowlist entry is either an exact hostname (`registry.npmjs.org`) or a
//! single-suffix wildcard (`*.githubusercontent.com`, matching one or more labels).
//! Hostnames are RFC 1123 host labels, ASCII only, lowercased on parse. IP literals are
//! rejected: allowlists are by name, and private-network destinations are always denied
//! regardless of policy.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

/// Maximum total length of a hostname (RFC 1123).
pub const MAX_HOSTNAME_LEN: usize = 253;

/// Maximum length of a single DNS label.
pub const MAX_LABEL_LEN: usize = 63;

/// A validated hostname or `*.suffix` wildcard pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostPattern {
    /// `true` when the pattern started with `*.`.
    wildcard: bool,
    /// The (lowercased) hostname, or the suffix after `*.` for wildcards.
    host: String,
}

fn validate_label(label: &str) -> Result<(), &'static str> {
    if label.is_empty() {
        return Err("empty label");
    }
    if label.len() > MAX_LABEL_LEN {
        return Err("label longer than 63 characters");
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("labels may only contain ASCII letters, digits and hyphens");
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err("labels may not start or end with a hyphen");
    }
    Ok(())
}

fn validate_hostname(host: &str) -> Result<(), &'static str> {
    if host.is_empty() {
        return Err("empty hostname");
    }
    if host.len() > MAX_HOSTNAME_LEN {
        return Err("hostname longer than 253 characters");
    }
    if !host.is_ascii() {
        return Err("hostname must be ASCII (IDNA is not supported)");
    }
    if IpAddr::from_str(host).is_ok() {
        return Err("IP literals are not accepted in allowlists");
    }
    for label in host.split('.') {
        validate_label(label)?;
    }
    // Reject all-numeric trailing labels (dotted quads with a trailing dot, etc.).
    if host
        .split('.')
        .all(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("hostname must contain a non-numeric label");
    }
    Ok(())
}

impl HostPattern {
    /// Parses and validates a hostname or `*.suffix` pattern.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidHostname`] for empty, over-long, non-ASCII, IP
    /// literal, or otherwise malformed values, and for wildcards anywhere but as the
    /// first label.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let reject = |reason| PolicyError::InvalidHostname {
            value: s.to_owned(),
            reason,
        };
        let trimmed = s.trim();
        if trimmed != s {
            return Err(reject("leading or trailing whitespace"));
        }
        let (wildcard, rest) = match trimmed.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, trimmed),
        };
        if rest.contains('*') {
            return Err(reject(
                "`*` is only allowed as the leading label (`*.example.com`)",
            ));
        }
        if rest.ends_with('.') {
            return Err(reject("trailing dot is not allowed"));
        }
        validate_hostname(rest).map_err(reject)?;
        if wildcard && !rest.contains('.') {
            return Err(reject("wildcard suffix must contain at least two labels"));
        }
        Ok(Self {
            wildcard,
            host: rest.to_ascii_lowercase(),
        })
    }

    /// `true` for `*.suffix` patterns.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// The hostname, or the suffix after `*.` for a wildcard.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether this pattern matches a concrete hostname.
    ///
    /// Comparison is ASCII case-insensitive. A wildcard matches any name with at least
    /// one label before the suffix; it does not match the bare suffix.
    #[must_use]
    pub fn matches_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.wildcard {
            host.len() > self.host.len() + 1
                && host.ends_with(&self.host)
                && host.as_bytes()[host.len() - self.host.len() - 1] == b'.'
        } else {
            host == self.host
        }
    }

    /// Whether every host matched by `other` is also matched by `self`.
    #[must_use]
    pub fn covers(&self, other: &HostPattern) -> bool {
        if self == other {
            return true;
        }
        if !self.wildcard {
            return false;
        }
        // `*.D` covers `x.D` and `*.x.D` for any non-empty `x`.
        other.host.len() > self.host.len() + 1
            && other.host.ends_with(&self.host)
            && other.host.as_bytes()[other.host.len() - self.host.len() - 1] == b'.'
    }
}

impl Ord for HostPattern {
    /// Orders by hostname first, then exact before wildcard, so related patterns sort
    /// together and the order does not depend on the `*.` prefix.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.host, self.wildcard).cmp(&(&other.host, other.wildcard))
    }
}

impl PartialOrd for HostPattern {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            write!(f, "*.{}", self.host)
        } else {
            f.write_str(&self.host)
        }
    }
}

impl FromStr for HostPattern {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for HostPattern {
    type Error = PolicyError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<HostPattern> for String {
    fn from(p: HostPattern) -> String {
        p.to_string()
    }
}

/// A set of host patterns.
pub type HostSet = BTreeSet<HostPattern>;

/// Whether some pattern in `set` covers `pattern`.
#[must_use]
pub fn set_covers(set: &HostSet, pattern: &HostPattern) -> bool {
    set.iter().any(|p| p.covers(pattern))
}

/// Whether every host matched by some pattern in `a` is matched by some pattern in `b`.
#[must_use]
pub fn is_subset(a: &HostSet, b: &HostSet) -> bool {
    a.iter().all(|p| set_covers(b, p))
}

/// The intersection of two host sets.
///
/// With exact names and single-suffix wildcards, the set of hosts matched by both `a` and
/// `b` is exactly described by the patterns of either side that are covered by some
/// pattern on the other side.
#[must_use]
pub fn intersect(a: &HostSet, b: &HostSet) -> HostSet {
    a.iter()
        .filter(|p| set_covers(b, p))
        .chain(b.iter().filter(|p| set_covers(a, p)))
        .cloned()
        .collect()
}

/// Whether a concrete hostname is matched by any pattern in `set`.
#[must_use]
pub fn set_matches_host(set: &HostSet, host: &str) -> bool {
    set.iter().any(|p| p.matches_host(host))
}
