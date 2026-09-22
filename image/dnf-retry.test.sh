#!/usr/bin/env bash
# Regression coverage for image/dnf-retry.sh (issue #198). Pure bash against fixtures and
# a counter-file-driven fake command; no docker/podman/network needed, so this runs in
# the "image lint" CI job alongside the shellcheck/dry-run checks, not just inside the
# docker-backed "image packages"/"hyprland config" jobs where the real dnf calls live.
set -euo pipefail
# shellcheck source=image/dnf-retry.sh
source "$(dirname "$0")/dnf-retry.sh"

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

echo "ok   image/dnf-retry.test.sh"
