#!/usr/bin/env bash
# Regressions for check-not-stale.sh (issue #149, acceptance: "overlapping
# runs finishing out of order" is covered here): an older, slower manifest
# job must never promote `latest` over a newer commit's already-promoted
# one. This only tests the ordering decision (is this run's commit still
# main's tip?) -- promote-latest.test.sh covers the other half of "retry of
# an already-published commit", that a retry re-promotes the exact digest
# this run captured rather than assuming any tag is unwritable.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/check-not-stale.sh"

# The commit being built is still main's tip: safe to promote.
expect_status 0 "still the tip promotes" bash "$sut" abc123 abc123

# A newer commit landed on main while this run's builds were still going:
# this run must stand down rather than overwrite the newer promotion.
expect_status 1 "superseded by a newer commit skips" bash "$sut" abc123 def456

# Retrying a run for a commit that is *still* the tip (nothing else landed
# meanwhile) is still an ordering pass -- same input, same result.
expect_status 0 "retry of the still-current tip passes the ordering check" bash "$sut" abc123 abc123

echo "PASS check-not-stale.test.sh"
