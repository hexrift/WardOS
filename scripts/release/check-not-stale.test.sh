#!/usr/bin/env bash
# Regressions for check-not-stale.sh (issue #149, acceptance: "overlapping
# runs finishing out of order" and "retry of an already-published commit"
# are covered): an older, slower manifest job must never promote `latest`
# over a newer commit's already-promoted one.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/check-not-stale.sh"

# The commit being built is still main's tip: safe to promote.
expect_status 0 "still the tip promotes" bash "$sut" abc123 abc123

# A newer commit landed on main while this run's builds were still going:
# this run must stand down rather than overwrite the newer promotion.
expect_status 1 "superseded by a newer commit skips" bash "$sut" abc123 def456

# Retrying a run for a commit that is *still* the tip (nothing else landed
# meanwhile) is a no-op re-promotion of the same content -- also safe, and
# distinct from the superseded case above.
expect_status 0 "retry of the still-current tip promotes" bash "$sut" abc123 abc123

echo "PASS check-not-stale.test.sh"
