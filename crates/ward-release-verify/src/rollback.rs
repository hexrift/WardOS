//! The anti-rollback floor (ADR-0028 §5 / the verification contract's step 5).
//!
//! "An update whose version is lower than the currently committed one is refused even
//! when its signature and identity are valid, unless the user explicitly overrides it
//! — a validly signed older release still carries whatever was fixed since." This
//! module is that one decision, taken in isolation from everything else the ADR's
//! verifier does: it does not check a signature, an identity, or a digest, and it does
//! not know what "committed" means operationally (that is the update state machine's
//! job) — it only compares two version strings.

use crate::version::{self, VersionParseError};

/// Why [`check_anti_rollback`] refused an update, or could not evaluate it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RollbackFailure {
    /// The candidate version is lower than the committed version and no override was
    /// given.
    #[error(
        "downgrade refused: candidate version '{candidate}' is lower than the committed \
         version '{committed}'; pass an explicit override to accept it anyway"
    )]
    DowngradeRefused {
        /// The candidate update's version string, as given.
        candidate: String,
        /// The currently committed version string, as given.
        committed: String,
    },
    /// The candidate version string could not be parsed as a version.
    #[error("candidate version is not a valid version: {0}")]
    InvalidCandidate(VersionParseError),
    /// The committed version string could not be parsed as a version.
    #[error("committed version is not a valid version: {0}")]
    InvalidCommitted(VersionParseError),
}

/// Decides whether a candidate update must be refused by the anti-rollback floor.
///
/// Returns `Ok(())` when `candidate >= committed`, or when `candidate < committed` and
/// `override_downgrade` is `true`. Returns
/// [`RollbackFailure::DowngradeRefused`] when `candidate < committed` and
/// `override_downgrade` is `false`.
///
/// # Errors
///
/// Returns [`RollbackFailure::InvalidCandidate`] or [`RollbackFailure::InvalidCommitted`]
/// if either version string fails to parse (see [`crate::version::parse`]).
pub fn check_anti_rollback(
    candidate: &str,
    committed: &str,
    override_downgrade: bool,
) -> Result<(), RollbackFailure> {
    let candidate_version = version::parse(candidate).map_err(RollbackFailure::InvalidCandidate)?;
    let committed_version = version::parse(committed).map_err(RollbackFailure::InvalidCommitted)?;

    if candidate_version < committed_version && !override_downgrade {
        return Err(RollbackFailure::DowngradeRefused {
            candidate: candidate.to_string(),
            committed: committed.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn refuses_lower_candidate_without_override() {
        assert!(matches!(
            check_anti_rollback("v1.0.0", "v1.2.0", false),
            Err(RollbackFailure::DowngradeRefused { .. })
        ));
    }

    #[test]
    fn accepts_equal_candidate() {
        check_anti_rollback("v1.2.0", "v1.2.0", false).unwrap();
    }

    #[test]
    fn accepts_higher_candidate() {
        check_anti_rollback("v1.3.0", "v1.2.0", false).unwrap();
    }

    #[test]
    fn accepts_lower_candidate_with_explicit_override() {
        check_anti_rollback("v1.0.0", "v1.2.0", true).unwrap();
    }

    #[test]
    fn override_is_a_no_op_when_not_a_downgrade() {
        // The override flag must never turn a legitimate upgrade into a rejection, and
        // must never itself be required for a non-downgrade to succeed.
        check_anti_rollback("v1.3.0", "v1.2.0", true).unwrap();
    }

    #[test]
    fn accepts_bare_versions_without_v_prefix() {
        // The committed version comes from `workspace.package.version` in Cargo.toml,
        // which has no leading `v`.
        check_anti_rollback("v0.19.0", "0.18.0", false).unwrap();
    }

    #[test]
    fn prerelease_candidate_is_a_downgrade_from_its_own_release() {
        assert!(matches!(
            check_anti_rollback("v1.2.0-rc.1", "v1.2.0", false),
            Err(RollbackFailure::DowngradeRefused { .. })
        ));
    }

    #[test]
    fn rejects_unparseable_candidate() {
        assert!(matches!(
            check_anti_rollback("not-a-version", "v1.2.0", false),
            Err(RollbackFailure::InvalidCandidate(_))
        ));
    }

    #[test]
    fn rejects_unparseable_committed() {
        assert!(matches!(
            check_anti_rollback("v1.2.0", "not-a-version", false),
            Err(RollbackFailure::InvalidCommitted(_))
        ));
    }
}
