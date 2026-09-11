#!/usr/bin/env bash
# Guard the production release's disk dispatch (issue #126, ADR-0027 / #119).
#
# Usage: guard-release-dispatch.sh <gh-workflow-run-args...>
#
# A production release disk must ship UNPROVISIONED: the disk workflow's blank
# `user` default leaves no account, and the real user is created at first boot.
# Requesting the `wardos` dev-seed account from the release path (`-f user=wardos`)
# would ship a pre-provisioned login on every published disk -- exactly what
# ADR-0027 forbids. This guard inspects the actual `gh workflow run` arguments
# the release job is about to dispatch and fails if any set a non-blank `user`
# field, so a re-added dev seed cannot slip through unnoticed.
#
# A blank `user=` (the field present but empty) is allowed -- it is the same as
# omitting it. Anything non-blank is refused.
#
# Exit codes:
#   0   no non-blank `user` field in the dispatch args -> safe to run.
#   1   a non-blank `user=<value>` field is present -> refuse to dispatch.
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "guard-release-dispatch: no dispatch arguments given" >&2
  exit 1
fi

for arg in "$@"; do
  # gh passes each field as its own `key=value` token (after `-f`/--field`). The
  # release disk dispatch must never carry a non-blank `user` field.
  if [[ "$arg" == user=* ]]; then
    value="${arg#user=}"
    if [[ -n "$value" ]]; then
      echo "guard-release-dispatch: refusing release dispatch with a dev-seed account: 'user=$value'" >&2
      echo "guard-release-dispatch: production release disks must be unprovisioned (ADR-0027); omit -f user=..." >&2
      exit 1
    fi
  fi
done

echo "guard-release-dispatch: OK -- release disk dispatch requests no user account."
