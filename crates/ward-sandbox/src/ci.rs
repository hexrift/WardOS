//! Isolation execution gate for CI (issue #124).
//!
//! The bubblewrap/namespace, verifier and egress tests skip when their
//! prerequisites are missing, so a developer laptop that cannot create a user
//! namespace still runs the rest of the suite. That same skip is a hole in CI: a
//! runner whose isolation regressed would report a *green* required job with the
//! security assertions silently skipped ("unavailable (guarded tests will skip)").
//!
//! [`REQUIRE_ISOLATION_ENV`] closes the hole. When it is set to a non-empty value
//! — CI sets it in `.github/workflows/verify.yml` — a missing prerequisite becomes
//! a hard failure instead of a skip, so the required job turns red. Unset (the
//! local default), the convenient skip is preserved unchanged.

/// Environment variable that turns a missing isolation prerequisite from a test
/// skip into a hard failure. Set by the required CI job so a runner that cannot
/// enforce isolation cannot report a successful security verification (#124).
pub const REQUIRE_ISOLATION_ENV: &str = "WARD_REQUIRE_ISOLATION";

/// Whether isolation execution is mandatory on this host, i.e.
/// [`REQUIRE_ISOLATION_ENV`] is set to a non-empty value.
#[must_use]
pub fn isolation_required() -> bool {
    std::env::var_os(REQUIRE_ISOLATION_ENV).is_some_and(|v| !v.is_empty())
}

/// Gate a test body on an isolation prerequisite.
///
/// Returns `true` when `present`, so the caller runs the test. When the
/// prerequisite is absent it prints a skip note and returns `false` — unless
/// require-mode is on ([`isolation_required`]), in which case it panics so the
/// test, and the required CI job, fails rather than passing with the security
/// assertion silently skipped (issue #124). `prerequisite` names the missing
/// capability for both messages.
#[must_use]
#[track_caller]
pub fn isolation_ready(present: bool, prerequisite: &str) -> bool {
    gate(present, isolation_required(), prerequisite)
}

/// The pure decision behind [`isolation_ready`], with `required` passed in so the
/// negative CI-gate test can exercise the red path without mutating the process
/// environment (which would race parallel tests).
#[must_use]
#[track_caller]
fn gate(present: bool, required: bool, prerequisite: &str) -> bool {
    if present {
        return true;
    }
    assert!(
        !required,
        "{REQUIRE_ISOLATION_ENV} is set but the isolation prerequisite is unavailable: \
         {prerequisite}. CI (issue #124) requires the isolation tests to run for real; a \
         runner that cannot enforce isolation must fail the required job, not skip it."
    );
    eprintln!("skipping: {prerequisite} not available");
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_prerequisite_runs_in_either_mode() {
        assert!(gate(true, false, "bubblewrap"));
        assert!(gate(true, true, "bubblewrap"));
    }

    #[test]
    fn absent_prerequisite_skips_when_not_required() {
        assert!(!gate(false, false, "bubblewrap"));
    }

    /// The negative CI-gate: with prerequisites unavailable and require-mode on,
    /// the gate is red (issue #124 acceptance).
    #[test]
    #[should_panic(expected = "WARD_REQUIRE_ISOLATION")]
    fn absent_prerequisite_is_red_when_required() {
        let _ = gate(false, true, "bubblewrap");
    }
}
