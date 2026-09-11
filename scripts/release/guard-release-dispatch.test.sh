#!/usr/bin/env bash
# Regressions for guard-release-dispatch.sh (issue #126, ADR-0027): the release
# disk dispatch must never request a dev-seed `user` account. A non-blank user=
# field is refused; the real release.yml dispatch is asserted clean.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/guard-release-dispatch.sh"

# The unprovisioned production dispatch (no user field) is accepted.
expect_status 0 "dispatch without a user field is allowed" \
  bash "$sut" disk.yml --ref v1.2.3 -f type=both -f source=release \
  -f release=v1.2.3 -f arch=both -f luks=false

# An explicitly blank user field is the same as omitting it -> allowed.
expect_status 0 "blank user field is allowed" \
  bash "$sut" disk.yml --ref v1.2.3 -f source=release -f user= -f luks=false

# A dev-seed account (the exact regression from the blocker) is refused.
expect_status 1 "user=wardos dev seed is refused" \
  bash "$sut" disk.yml --ref v1.2.3 -f type=both -f source=release \
  -f release=v1.2.3 -f arch=both -f user=wardos -f luks=false

# Any non-blank user, not just wardos, is refused.
expect_status 1 "any non-blank user is refused" \
  bash "$sut" disk.yml -f source=release -f user=alice

# No arguments is an error, not a silent pass.
expect_status 1 "no arguments rejected" bash "$sut"

# Regression against the real workflow: the release job's disk dispatch must
# carry no literal user account. Matching a `user=<alphanumeric>` value catches a
# re-added dev seed (e.g. user=wardos) while ignoring the prose/placeholder
# `user=...` in the explanatory comment. This keeps the fix from silently
# regressing if the dispatch is edited later.
release_yml="$RELEASE_DIR/../../.github/workflows/release.yml"
[[ -f "$release_yml" ]] || fail "release.yml not found at $release_yml"
if grep -nE 'user=[A-Za-z0-9]' "$release_yml"; then
  fail "release.yml dispatch still requests a non-blank user account"
fi
echo "ok   release.yml requests no user account"

echo "PASS guard-release-dispatch.test.sh"
