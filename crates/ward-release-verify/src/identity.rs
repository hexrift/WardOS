//! ADR-0028 §2's pinned identity policy.
//!
//! The verifier this module belongs to is not a general Sigstore/`GitHub`-attestation
//! policy engine: it enforces one pinned identity, `WardOS`'s own release workflow, and
//! rejects everything else. Per the ADR, "any valid signature" is never an acceptable
//! policy — a cryptographically valid attestation from the wrong repository, workflow,
//! ref, or issuer must still be rejected, with a reason specific enough to act on.
//!
//! [`AttestationClaims`] is this module's whole input: plain, already-extracted values
//! that some other, not-yet-written component is responsible for retrieving and
//! cryptographically verifying (a `GitHub` attestation lookup, or a Sigstore bundle
//! check against a trusted root). This module never performs that verification itself
//! and never makes a network call; it only decides whether already-trustworthy claims
//! satisfy WardOS's policy.

/// Already-extracted, already-cryptographically-verified attestation claims.
///
/// Real `GitHub`/Sigstore attestations carry both a single Fulcio certificate SAN
/// (`signing_identity`) *and* separate structured provenance-predicate fields
/// (`repository`, `workflow`, `source_ref`) that are expected to agree with it. This
/// type keeps them as independent fields — and [`evaluate_identity`] checks all of
/// them independently — precisely so a decoder bug or a forged predicate that gets one
/// of them right but not the others is still caught, rather than trusting whichever
/// field happens to be checked first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationClaims<'a> {
    /// The OIDC token issuer claim, e.g. `https://token.actions.githubusercontent.com`.
    pub issuer: &'a str,
    /// The Fulcio certificate's SAN (Subject Alternative Name) URI, e.g.
    /// `https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/v1.2.3`.
    pub signing_identity: &'a str,
    /// The `owner/repo` claim from the provenance predicate, e.g. `hexrift/WardOS`.
    pub repository: &'a str,
    /// The workflow file claim, e.g. `release.yml` (just the file name, not a path).
    pub workflow: &'a str,
    /// The full source ref actually being verified, e.g. `refs/tags/v1.2.3`. Never a
    /// branch (`refs/heads/...`) or pull-request (`refs/pull/.../merge`) ref for a
    /// release.
    pub source_ref: &'a str,
}

/// The result of a passing [`evaluate_identity`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The release tag named by `source_ref`, without its `refs/tags/` prefix, e.g.
    /// `v1.2.3`. Convenient for chaining into [`crate::rollback::check_anti_rollback`].
    pub tag: String,
}

/// The pinned OIDC issuer (ADR-0028 §2).
pub const PINNED_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The pinned source repository (ADR-0028 §2).
pub const PINNED_REPOSITORY: &str = "hexrift/WardOS";
/// The pinned release workflow file (ADR-0028 §2).
pub const PINNED_WORKFLOW: &str = "release.yml";
/// The `refs/tags/` prefix a release ref must carry.
const RELEASE_REF_PREFIX: &str = "refs/tags/";

/// Why [`evaluate_identity`] rejected a set of claims. Each variant is a distinct,
/// actionable reason per the ADR's verification contract — never a single generic
/// "verification failed".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityFailure {
    /// The OIDC issuer did not match [`PINNED_ISSUER`].
    #[error("OIDC issuer mismatch: expected '{expected}', got '{actual}'")]
    IssuerMismatch {
        /// The pinned issuer.
        expected: &'static str,
        /// The issuer the claims actually carried.
        actual: String,
    },
    /// The source repository did not match [`PINNED_REPOSITORY`].
    #[error("source repository mismatch: expected '{expected}', got '{actual}'")]
    RepositoryMismatch {
        /// The pinned repository.
        expected: &'static str,
        /// The repository the claims actually carried.
        actual: String,
    },
    /// The workflow file did not match [`PINNED_WORKFLOW`] — a different, possibly
    /// still-legitimate, workflow in the same repository is not acceptable.
    #[error(
        "workflow mismatch: expected '{expected}', got '{actual}' (provenance must come \
         from the pinned release workflow, not another workflow in the same repository)"
    )]
    WorkflowMismatch {
        /// The pinned workflow file.
        expected: &'static str,
        /// The workflow file the claims actually carried.
        actual: String,
    },
    /// The source ref was not a `refs/tags/v<semver>` release tag — a branch or a
    /// pull-request ref is never accepted.
    #[error("source ref '{source_ref}' is not an acceptable release ref: {reason}")]
    InvalidSourceRef {
        /// The ref the claims actually carried.
        source_ref: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The signing identity (SAN) did not equal the pinned identity reconstructed for
    /// the actual source ref. This is checked in addition to, not instead of, the
    /// `repository`/`workflow` field checks above: an attacker able to spoof the
    /// structured claims but not the certificate SAN is still caught here.
    #[error("signing identity mismatch: expected '{expected}', got '{actual}'")]
    SigningIdentityMismatch {
        /// The SAN [`evaluate_identity`] expected, given the pinned policy and the
        /// actual source ref.
        expected: String,
        /// The SAN the claims actually carried.
        actual: String,
    },
}

/// Mirrors the tag grammar in `scripts/release/check-version.sh` and
/// `scripts/release/generate-manifest.sh`:
/// `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`.
fn is_meta_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-'
}

fn is_release_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix('v') else {
        return false;
    };

    let (rest, build) = match rest.find('+') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    if let Some(build) = build
        && (build.is_empty() || !build.chars().all(is_meta_char))
    {
        return false;
    }

    let (core, pre) = match rest.find('-') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    if let Some(pre) = pre
        && (pre.is_empty() || !pre.chars().all(is_meta_char))
    {
        return false;
    }

    let mut parts = core.split('.');
    let (Some(maj), Some(min), Some(pat), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    [maj, min, pat]
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn validate_source_ref(source_ref: &str) -> Result<(), IdentityFailure> {
    match source_ref.strip_prefix(RELEASE_REF_PREFIX) {
        Some(tag) if is_release_tag(tag) => Ok(()),
        Some(tag) => Err(IdentityFailure::InvalidSourceRef {
            source_ref: source_ref.to_string(),
            reason: format!("'{tag}' is not a v<semver> release tag"),
        }),
        None => Err(IdentityFailure::InvalidSourceRef {
            source_ref: source_ref.to_string(),
            reason: "not a tag ref under refs/tags/ -- a branch or pull-request ref is \
                      never accepted for a release"
                .to_string(),
        }),
    }
}

/// Decides whether `claims` satisfy `WardOS`'s pinned release identity policy
/// (ADR-0028 §2).
///
/// Checks, in order, that the issuer, repository, workflow, source ref (a
/// `refs/tags/v<semver>` release tag) and signing identity (SAN) each independently
/// match the pinned policy, returning the first mismatch found. The signing-identity
/// check is evaluated last and is reconstructed from the pinned repository/workflow
/// and the claims' own (already-validated) source ref, so it also catches a SAN that
/// was forged to point at a different tag or workflow than the one actually attested.
///
/// This function performs no cryptographic verification and no I/O: `claims` must
/// already be the output of verifying a real attestation elsewhere.
///
/// # Errors
///
/// Returns the specific [`IdentityFailure`] variant for whichever check failed first.
pub fn evaluate_identity(
    claims: &AttestationClaims<'_>,
) -> Result<VerifiedIdentity, IdentityFailure> {
    if claims.issuer != PINNED_ISSUER {
        return Err(IdentityFailure::IssuerMismatch {
            expected: PINNED_ISSUER,
            actual: claims.issuer.to_string(),
        });
    }
    if claims.repository != PINNED_REPOSITORY {
        return Err(IdentityFailure::RepositoryMismatch {
            expected: PINNED_REPOSITORY,
            actual: claims.repository.to_string(),
        });
    }
    if claims.workflow != PINNED_WORKFLOW {
        return Err(IdentityFailure::WorkflowMismatch {
            expected: PINNED_WORKFLOW,
            actual: claims.workflow.to_string(),
        });
    }
    validate_source_ref(claims.source_ref)?;

    let expected_identity = format!(
        "https://github.com/{PINNED_REPOSITORY}/.github/workflows/{PINNED_WORKFLOW}@{}",
        claims.source_ref
    );
    if claims.signing_identity != expected_identity {
        return Err(IdentityFailure::SigningIdentityMismatch {
            expected: expected_identity,
            actual: claims.signing_identity.to_string(),
        });
    }

    let tag = claims
        .source_ref
        .strip_prefix(RELEASE_REF_PREFIX)
        .unwrap_or(claims.source_ref)
        .to_string();
    Ok(VerifiedIdentity { tag })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn valid_claims() -> AttestationClaims<'static> {
        AttestationClaims {
            issuer: PINNED_ISSUER,
            signing_identity: "https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/v1.2.3",
            repository: PINNED_REPOSITORY,
            workflow: PINNED_WORKFLOW,
            source_ref: "refs/tags/v1.2.3",
        }
    }

    #[test]
    fn accepts_matching_policy() {
        let verified = evaluate_identity(&valid_claims()).unwrap();
        assert_eq!(verified.tag, "v1.2.3");
    }

    #[test]
    fn accepts_prerelease_tag() {
        let mut claims = valid_claims();
        claims.source_ref = "refs/tags/v1.2.3-rc.1";
        claims.signing_identity =
            "https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/v1.2.3-rc.1";
        let verified = evaluate_identity(&claims).unwrap();
        assert_eq!(verified.tag, "v1.2.3-rc.1");
    }

    #[test]
    fn rejects_wrong_issuer() {
        let mut claims = valid_claims();
        claims.issuer = "https://attacker.example/oidc";
        assert!(matches!(
            evaluate_identity(&claims),
            Err(IdentityFailure::IssuerMismatch { .. })
        ));
    }

    #[test]
    fn rejects_wrong_repository() {
        let mut claims = valid_claims();
        claims.repository = "attacker/WardOS";
        assert!(matches!(
            evaluate_identity(&claims),
            Err(IdentityFailure::RepositoryMismatch { .. })
        ));
    }

    #[test]
    fn rejects_wrong_workflow_file() {
        let mut claims = valid_claims();
        claims.workflow = "deploy.yml";
        assert!(matches!(
            evaluate_identity(&claims),
            Err(IdentityFailure::WorkflowMismatch { .. })
        ));
    }

    #[test]
    fn rejects_branch_ref() {
        let mut claims = valid_claims();
        claims.source_ref = "refs/heads/main";
        claims.signing_identity =
            "https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/heads/main";
        assert!(matches!(
            evaluate_identity(&claims),
            Err(IdentityFailure::InvalidSourceRef { .. })
        ));
    }

    #[test]
    fn rejects_pull_request_ref() {
        let mut claims = valid_claims();
        claims.source_ref = "refs/pull/42/merge";
        claims.signing_identity =
            "https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/pull/42/merge";
        assert!(matches!(
            evaluate_identity(&claims),
            Err(IdentityFailure::InvalidSourceRef { .. })
        ));
    }

    #[test]
    fn rejects_non_semver_tag() {
        let mut claims = valid_claims();
        claims.source_ref = "refs/tags/not-a-version";
        claims.signing_identity = "https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/not-a-version";
        assert!(matches!(
            evaluate_identity(&claims),
            Err(IdentityFailure::InvalidSourceRef { .. })
        ));
    }

    #[test]
    fn rejects_signing_identity_for_another_tag() {
        // Every structured claim is correct, but the certificate SAN itself names a
        // different tag than the one actually being verified -- the acceptance-case
        // table's "valid signature from another repository/workflow" row, generalised
        // to "another ref".
        let mut claims = valid_claims();
        claims.signing_identity =
            "https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/v9.9.9";
        assert!(matches!(
            evaluate_identity(&claims),
            Err(IdentityFailure::SigningIdentityMismatch { .. })
        ));
    }

    #[test]
    fn rejects_signing_identity_for_another_repository() {
        let mut claims = valid_claims();
        claims.signing_identity =
            "https://github.com/attacker/WardOS/.github/workflows/release.yml@refs/tags/v1.2.3";
        assert!(matches!(
            evaluate_identity(&claims),
            Err(IdentityFailure::SigningIdentityMismatch { .. })
        ));
    }

    #[test]
    fn wildcard_in_policy_is_not_matched_as_a_literal_asterisk() {
        // The ADR's `v*` is a description of "the actual tag", not a literal
        // wildcard character the SAN could contain.
        let mut claims = valid_claims();
        claims.signing_identity =
            "https://github.com/hexrift/WardOS/.github/workflows/release.yml@refs/tags/v*";
        assert!(matches!(
            evaluate_identity(&claims),
            Err(IdentityFailure::SigningIdentityMismatch { .. })
        ));
    }
}
