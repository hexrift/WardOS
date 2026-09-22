#!/usr/bin/env bash
# Regression coverage for image/dnf-retry.sh (issue #198). Pure bash against fixtures and
# a counter-file-driven fake command; no docker/podman/network needed, so this runs in
# the "image lint" CI job alongside the shellcheck/dry-run checks, not just inside the
# docker-backed "image packages"/"hyprland config" jobs where the real dnf calls live.
set -euo pipefail
here=$(dirname "$0")
lib="$here/dnf-retry.sh"
# shellcheck source=image/dnf-retry.sh
source "$lib"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# retry: succeeds once the underlying command stops failing, within the attempt budget.
counter="$tmp/count"
echo 0 >"$counter"
flaky_then_ok() {
  local n
  n=$(<"$counter")
  n=$((n + 1))
  echo "$n" >"$counter"
  [[ $n -ge 3 ]]
}
retry 5 0 flaky_then_ok || fail "retry gave up before the command started succeeding"
[[ $(<"$counter") -eq 3 ]] || fail "expected exactly 3 attempts, got $(<"$counter")"

# retry: gives up and returns the underlying failure's exit status once the attempt
# budget is exhausted, and never calls the command more times than the budget allows.
echo 0 >"$counter"
always_fails() {
  local n
  n=$(<"$counter")
  n=$((n + 1))
  echo "$n" >"$counter"
  return 7
}
rc=0
retry 3 0 always_fails || rc=$?
[[ $rc -eq 7 ]] || fail "expected the underlying exit status 7, got $rc"
[[ $(<"$counter") -eq 3 ]] || fail "expected exactly 3 attempts (the budget), got $(<"$counter")"

# classify_dnf_failure: a mirror/network hiccup reads as transient.
transient_log="$tmp/transient.log"
cat >"$transient_log" <<'EOF'
Errors during downloading metadata for repository 'copr:copr.fedorainfracloud.org:mineiro:hyprland':
  - Curl error (6): Couldn't resolve host name for https://download.copr.fedorainfracloud.org/... [Could not resolve host: download.copr.fedorainfracloud.org]
Failed to synchronize cache for repo 'copr:copr.fedorainfracloud.org:mineiro:hyprland', ignoring this repo.
EOF
[[ $(classify_dnf_failure "$transient_log") == transient ]] \
  || fail "a mirror-resolution failure should classify as transient"

# classify_dnf_failure: a genuinely missing/renamed package reads as genuine, not transient.
genuine_log="$tmp/genuine.log"
cat >"$genuine_log" <<'EOF'
Failed to resolve the transaction:
No match for argument: hyprland-nonexistent
EOF
[[ $(classify_dnf_failure "$genuine_log") == genuine ]] \
  || fail "a 'no match for argument' failure should classify as genuine, not transient"

# classify_dnf_failure: no captured output at all is never mistaken for transient.
[[ $(classify_dnf_failure "$tmp/does-not-exist.log") == genuine ]] \
  || fail "a missing log file should classify as genuine (the safe default), not transient"

# last_step_tail: no marker at all -- falls back to the whole file (never narrower than
# classifying everything, when no step boundary is known).
no_marker_log="$tmp/no-marker.log"
printf 'one\ntwo\nthree\n' >"$no_marker_log"
[[ "$(last_step_tail "$no_marker_log")" == "$(cat "$no_marker_log")" ]] \
  || fail "with no marker, last_step_tail should return the whole file"

# last_step_tail: called as a bare standalone command under `set -euo pipefail` -- exactly
# how check-packages.sh/check-hyprland.sh actually call it (`last_step_tail FILE >OUT`),
# never inside a `[[ ... ]]` or other errexit-suppressing context. A log with no marker
# must not abort the caller (review on #201: grep finding nothing makes the internal
# `grep | tail | cut` pipeline exit non-zero under pipefail, and a plain assignment
# statement is not otherwise exempt from errexit). Run in a nested bash so a regression
# here aborts only that nested process, not this whole test script, and reports cleanly.
standalone_out="$tmp/standalone-out"
if ! bash -euo pipefail -c 'source "$1"; last_step_tail "$2" >"$3"' \
  _ "$lib" "$no_marker_log" "$standalone_out"; then
  fail "last_step_tail as a standalone command under set -e must not abort the caller when the file has no marker"
fi
[[ "$(cat "$standalone_out")" == "$(cat "$no_marker_log")" ]] \
  || fail "the standalone call's fallback output should be the whole file"

# last_step_tail: returns only what follows the LAST marker, discarding earlier steps.
multi_step_log="$tmp/multi-step.log"
{
  echo "before any marker, should never appear in the tail"
  echo "$DNF_RETRY_STEP_MARK"
  echo "first step's own output"
  echo "$DNF_RETRY_STEP_MARK"
  echo "second (last) step's own output"
} >"$multi_step_log"
tail_out=$(last_step_tail "$multi_step_log")
[[ "$tail_out" == "second (last) step's own output" ]] \
  || fail "last_step_tail should return only the last step's own output, got: $tail_out"

# Mixed-sequence regressions (review on #201): an earlier step's transient hiccup that
# already recovered on its own retry must never paint a later, unrelated failure -- itself
# genuine, or itself a fresh transient one -- as belonging to that earlier outage.

# transient attempt -> recovery -> a later, unrelated step's genuine failure: classifying
# the WHOLE log would wrongly say "transient" (the earlier Could-not-resolve-host text is
# still in the file); classifying last_step_tail's output must say "genuine".
mixed_genuine_log="$tmp/mixed-genuine.log"
{
  echo "$DNF_RETRY_STEP_MARK"
  echo "retry: attempt 1/3 failed (exit 1), retrying in 5s: dnf -y -q copr enable mineiro/hyprland"
  echo "Could not resolve host: download.copr.fedorainfracloud.org"
  echo "(recovered on attempt 2)"
  echo "$DNF_RETRY_STEP_MARK"
  echo "Failed to resolve the transaction:"
  echo "No match for argument: nope-not-a-package"
} >"$mixed_genuine_log"
[[ $(classify_dnf_failure "$mixed_genuine_log") == transient ]] \
  || fail "sanity check: the unscoped whole-file classification should still read transient here"
last_step_tail "$mixed_genuine_log" >"$mixed_genuine_log.tail"
[[ $(classify_dnf_failure "$mixed_genuine_log.tail") == genuine ]] \
  || fail "an earlier recovered transient hiccup must not mask a later step's genuine failure"

# transient earlier attempt (recovers) -> the final step's OWN retries are exhausted on a
# genuine (non-network) error: still genuine, not transient, even though the file as a
# whole contains transient-looking text from the earlier, already-recovered step.
mixed_final_retry_log="$tmp/mixed-final-retry.log"
{
  echo "$DNF_RETRY_STEP_MARK"
  echo "retry: attempt 1/3 failed (exit 1), retrying in 5s: dnf -y -q install dnf5-plugins"
  echo "Could not resolve host: mirrors.fedoraproject.org"
  echo "(recovered on attempt 2)"
  echo "$DNF_RETRY_STEP_MARK"
  echo "retry: attempt 1/3 failed (exit 1), retrying in 5s: dnf -q repoquery nope-not-a-package"
  echo "No match for argument: nope-not-a-package"
  echo "retry: attempt 2/3 failed (exit 1), retrying in 10s: dnf -q repoquery nope-not-a-package"
  echo "No match for argument: nope-not-a-package"
  echo "No match for argument: nope-not-a-package"
} >"$mixed_final_retry_log"
last_step_tail "$mixed_final_retry_log" >"$mixed_final_retry_log.tail"
[[ $(classify_dnf_failure "$mixed_final_retry_log.tail") == genuine ]] \
  || fail "a genuine failure that itself exhausted retries must stay genuine, not inherit an earlier step's transient wording"

echo "ok   image/dnf-retry.test.sh"
