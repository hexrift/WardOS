#!/usr/bin/env bash
# Refuse to promote `latest` for a commit that is no longer main's tip
# (issue #149): a manifest job for an older commit can finish its builds
# after a newer commit's job has already promoted `latest`. Comparing the
# commit this job is building against main's current tip, immediately
# before promotion, is what stops that -- not `needs:`, and not the
# workflow's `concurrency` group alone, which only bounds how many manifest
# jobs run at once and does not order them by commit.
#
# Usage: check-not-stale.sh <building-sha> <main-tip-sha>
# Exit 0 (not stale -- promote) when they match, 1 (stale -- skip) otherwise.
set -euo pipefail

building="${1:?usage: check-not-stale.sh <building-sha> <main-tip-sha>}"
tip="${2:?usage: check-not-stale.sh <building-sha> <main-tip-sha>}"

if [[ "$building" != "$tip" ]]; then
  echo "check-not-stale: main is now at $tip, not $building; leaving latest for that commit's own manifest job to promote." >&2
  exit 1
fi

echo "check-not-stale: OK -- $building is still main's tip"
