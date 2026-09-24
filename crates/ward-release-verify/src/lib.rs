//! `ward-release-verify` — offline decision logic for `WardOS`'s release-trust policy.
//!
//! This crate implements exactly two pure, offline decisions carved out of
//! [ADR-0028](https://github.com/hexrift/WardOS/blob/main/docs/decisions/ADR-0028-release-provenance-and-trusted-updates.md)
//! (`docs/decisions/ADR-0028-release-provenance-and-trusted-updates.md`), tracked by
//! issue #148:
//!
//! - §2's pinned identity policy ([`identity::evaluate_identity`]): given claims that
//!   some other, not-yet-written component has already cryptographically verified and
//!   extracted from a `GitHub` attestation or Sigstore bundle, decide whether the OIDC
//!   issuer, signing identity (SAN), source ref, repository and workflow match `WardOS`'s
//!   pinned policy — with a distinct, actionable reason for each independent way they
//!   can fail to, never one generic "verification failed".
//! - The verification contract's step 5 / §5's anti-rollback floor
//!   ([`rollback::check_anti_rollback`]): decide, from two already-parsed semver
//!   strings alone, whether a candidate update must be refused as a downgrade absent an
//!   explicit override.
//!
//! Both decisions are total functions over plain data: no I/O, no network access, and
//! no randomness, which is what makes them exhaustively unit-testable without a live
//! CI/OIDC round-trip or a real Sigstore toolchain.
//!
//! ## What this is not
//!
//! This crate performs **no** cryptographic signature verification and makes **no**
//! Sigstore/cosign/Fulcio/Rekor call, OIDC token exchange, or network access of any
//! kind. It does not retrieve an attestation or a Sigstore bundle, and it is not wired
//! into `.github/workflows/release.yml`, `install.sh`, or `desktop/bin/wardos-update`.
//! Its job starts *after* some other, not-yet-written component has already
//! cryptographically verified a real attestation and turned it into the plain
//! [`identity::AttestationClaims`] this crate consumes. Building that
//! retrieval-and-verification component, wiring these two decisions into the update
//! state machine (`downloaded` → `digest-checked` → `provenance-verified` → `staged` →
//! `booted` → `health-checked` → `committed`/`rolled-back`), digest/checksum
//! verification, and the boot-chain/Secure Boot work (ADR-0028 §6) all remain open —
//! see ADR-0028's own "Scope of the implementation" section. Nothing in this crate, or
//! its documentation, should be read as a claim that `WardOS` releases are signed or
//! verified end-to-end; that remains false until the deferred pieces above land too.

#![allow(clippy::module_name_repetitions, clippy::doc_markdown)]

pub mod identity;
pub mod rollback;
pub mod version;

pub use identity::{AttestationClaims, IdentityFailure, VerifiedIdentity, evaluate_identity};
pub use rollback::{RollbackFailure, check_anti_rollback};
pub use version::{Identifier, Version, VersionParseError};
