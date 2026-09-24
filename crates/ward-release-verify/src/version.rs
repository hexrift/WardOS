//! A minimal `SemVer` parser and comparator.
//!
//! This exists only so [`crate::rollback::check_anti_rollback`] can order two version
//! strings without pulling in a dependency. The accepted grammar mirrors the tag
//! grammar already used by `scripts/release/check-version.sh` and
//! `scripts/release/generate-manifest.sh`:
//!
//! ```text
//! [vV]?<major>.<minor>.<patch>(-<pre-release>)?(+<build>)?
//! ```
//!
//! where `<major>`/`<minor>`/`<patch>` are non-negative integers and `<pre-release>`/
//! `<build>` are dot-separated runs of `[0-9A-Za-z-]+`. Build metadata is parsed (so a
//! malformed one is still rejected) but never affects ordering, per SemVer 2.0.0 §10.
//! Precedence otherwise follows SemVer 2.0.0 §11: a release outranks any pre-release of
//! the same `major.minor.patch`, numeric pre-release identifiers are compared
//! numerically and always rank below alphanumeric ones, and when one pre-release's
//! identifiers are a prefix of another's, the longer one ranks higher.

use std::cmp::Ordering;
use std::fmt;

/// A parsed `major.minor.patch[-pre-release]` version, ignoring build metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// The `X` in `X.Y.Z`.
    pub major: u64,
    /// The `Y` in `X.Y.Z`.
    pub minor: u64,
    /// The `Z` in `X.Y.Z`.
    pub patch: u64,
    /// Dot-separated pre-release identifiers, in order, or empty for a release version.
    pub pre: Vec<Identifier>,
}

/// One dot-separated pre-release identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identifier {
    /// An identifier made only of ASCII digits, compared numerically.
    Numeric(u64),
    /// Any other identifier, compared as an ASCII string.
    Alphanumeric(String),
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Identifier::Numeric(a), Identifier::Numeric(b)) => a.cmp(b),
            (Identifier::Alphanumeric(a), Identifier::Alphanumeric(b)) => a.cmp(b),
            // SemVer 2.0.0 §11.4.3: numeric identifiers always have lower precedence
            // than alphanumeric identifiers.
            (Identifier::Numeric(_), Identifier::Alphanumeric(_)) => Ordering::Less,
            (Identifier::Alphanumeric(_), Identifier::Numeric(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A release (no pre-release) outranks any pre-release of the same core.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                // `Vec<Identifier>`'s own lexicographic `Ord` already implements SemVer's
                // "compare identifier by identifier; a strict prefix ranks lower" rule.
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Why a version string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionParseError {
    /// The input was empty (after stripping an optional leading `v`/`V`).
    #[error("version string '{0}' is empty")]
    Empty(String),
    /// The `major.minor.patch` core was missing a component, had too many, or a
    /// component was not a plain non-negative integer.
    #[error("version '{0}' does not have the form <major>.<minor>.<patch>: bad component '{1}'")]
    BadCore(String, String),
    /// A pre-release or build-metadata identifier used a character outside
    /// `[0-9A-Za-z-]`, or was empty.
    #[error("version '{0}' has an invalid pre-release/build identifier '{1}'")]
    BadIdentifier(String, String),
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, id) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match id {
                Identifier::Numeric(n) => write!(f, "{n}")?,
                Identifier::Alphanumeric(s) => f.write_str(s)?,
            }
        }
        Ok(())
    }
}

fn split_once_char(s: &str, c: char) -> (&str, Option<&str>) {
    match s.find(c) {
        Some(i) => (&s[..i], Some(&s[i + c.len_utf8()..])),
        None => (s, None),
    }
}

fn is_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

fn parse_dotted_identifiers(
    original: &str,
    field: &str,
) -> Result<Vec<Identifier>, VersionParseError> {
    let mut ids = Vec::new();
    for part in field.split('.') {
        if part.is_empty() || !part.chars().all(is_id_char) {
            return Err(VersionParseError::BadIdentifier(
                original.to_string(),
                part.to_string(),
            ));
        }
        if part.bytes().all(|b| b.is_ascii_digit()) {
            let Ok(n) = part.parse::<u64>() else {
                return Err(VersionParseError::BadIdentifier(
                    original.to_string(),
                    part.to_string(),
                ));
            };
            ids.push(Identifier::Numeric(n));
        } else {
            ids.push(Identifier::Alphanumeric(part.to_string()));
        }
    }
    Ok(ids)
}

/// Parses a `[v]major.minor.patch[-pre-release][+build]` version string.
///
/// A leading `v`/`V` is optional and stripped so this accepts both a release tag
/// (`v1.2.3`) and a bare workspace/manifest version (`1.2.3`).
///
/// # Errors
///
/// Returns [`VersionParseError`] if the input is empty, the `major.minor.patch` core
/// is missing a component, has extra components, or a component is not a plain
/// non-negative integer, or a pre-release/build identifier is empty or uses a
/// character outside `[0-9A-Za-z-]`.
pub fn parse(input: &str) -> Result<Version, VersionParseError> {
    let original = input.to_string();
    let stripped = input.strip_prefix(['v', 'V']).unwrap_or(input);
    if stripped.is_empty() {
        return Err(VersionParseError::Empty(original));
    }

    let (core_and_pre, build) = split_once_char(stripped, '+');
    if let Some(build) = build {
        if build.is_empty() {
            return Err(VersionParseError::BadIdentifier(
                original,
                build.to_string(),
            ));
        }
        parse_dotted_identifiers(&original, build)?;
    }

    let (core, pre) = split_once_char(core_and_pre, '-');
    let mut parts = core.split('.');
    let (Some(maj), Some(min), Some(pat), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VersionParseError::BadCore(original, core.to_string()));
    };

    let parse_component = |p: &str| -> Result<u64, VersionParseError> {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(VersionParseError::BadCore(original.clone(), p.to_string()));
        }
        p.parse::<u64>()
            .map_err(|_| VersionParseError::BadCore(original.clone(), p.to_string()))
    };
    let major = parse_component(maj)?;
    let minor = parse_component(min)?;
    let patch = parse_component(pat)?;

    let pre = match pre {
        None => Vec::new(),
        Some(p) if p.is_empty() => {
            return Err(VersionParseError::BadIdentifier(original, p.to_string()));
        }
        Some(p) => parse_dotted_identifiers(&original, p)?,
    };

    Ok(Version {
        major,
        minor,
        patch,
        pre,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_plain_release() {
        let v = parse("v1.2.3").unwrap();
        assert_eq!(
            v,
            Version {
                major: 1,
                minor: 2,
                patch: 3,
                pre: vec![]
            }
        );
    }

    #[test]
    fn parses_without_leading_v() {
        assert_eq!(parse("0.18.0").unwrap(), parse("v0.18.0").unwrap());
    }

    #[test]
    fn parses_prerelease_and_build() {
        let v = parse("v1.2.3-rc.1+build.5").unwrap();
        assert_eq!(
            v.pre,
            vec![
                Identifier::Alphanumeric("rc".into()),
                Identifier::Numeric(1)
            ]
        );
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(parse("v"), Err(VersionParseError::Empty(_))));
    }

    #[test]
    fn rejects_short_core() {
        assert!(matches!(
            parse("v1.2"),
            Err(VersionParseError::BadCore(_, _))
        ));
    }

    #[test]
    fn rejects_non_numeric_core_component() {
        assert!(matches!(
            parse("v1.x.3"),
            Err(VersionParseError::BadCore(_, _))
        ));
    }

    #[test]
    fn rejects_bad_prerelease_char() {
        assert!(matches!(
            parse("v1.2.3-rc_1"),
            Err(VersionParseError::BadIdentifier(_, _))
        ));
    }

    #[test]
    fn release_outranks_prerelease_of_same_core() {
        assert!(parse("v1.0.0").unwrap() > parse("v1.0.0-rc.1").unwrap());
    }

    #[test]
    fn numeric_prerelease_ranks_below_alphanumeric() {
        assert!(parse("v1.0.0-1").unwrap() < parse("v1.0.0-alpha").unwrap());
    }

    #[test]
    fn shorter_prerelease_prefix_ranks_lower() {
        assert!(parse("v1.0.0-alpha").unwrap() < parse("v1.0.0-alpha.1").unwrap());
    }

    #[test]
    fn patch_orders_before_minor_before_major() {
        assert!(parse("v1.2.3").unwrap() < parse("v1.2.4").unwrap());
        assert!(parse("v1.2.9").unwrap() < parse("v1.3.0").unwrap());
        assert!(parse("v1.9.9").unwrap() < parse("v2.0.0").unwrap());
    }

    #[test]
    fn display_round_trips_core_and_prerelease() {
        assert_eq!(parse("v1.2.3").unwrap().to_string(), "1.2.3");
        assert_eq!(parse("v1.2.3-rc.1").unwrap().to_string(), "1.2.3-rc.1");
    }
}
