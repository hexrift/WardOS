#!/usr/bin/env bash
# Determine whether a GitHub Release exists for a tag, failing closed (issue #126).
#
# Usage: release-exists.sh <tag>
#   requires GITHUB_REPOSITORY in the environment (owner/repo).
#
# The release job must not conflate "there is no release yet" with "we could not
# read whether a release exists". A blind `gh release view "$TAG"` treats any
# failure -- auth, API, network -- as "does not exist" and takes the create path,
# which would clobber under a tag the run could not actually inspect. So probe
# the release with the API and map the outcomes precisely: a clean HTTP 404 is a
# genuine "not found" (the caller may create), a success is "exists" (the caller
# reconciles/uploads), and ANY other failure is a hard error the caller must fail
# on -- never a create.
#
# `gh` is invoked through $GH (default: gh) so the probe can be stubbed in tests.
#
# Exit codes:
#   0   a release exists for the tag  -> caller takes the reconcile/upload path.
#   2   a clean 404: no release exists -> caller may create it.
#   1   any other lookup failure (non-404 HTTP, auth, network) -> caller must
#       fail the job; the create path is NOT authorized.
set -euo pipefail

GH="${GH:-gh}"

tag="${1:?usage: release-exists.sh <tag>}"
: "${GITHUB_REPOSITORY:?release-exists: GITHUB_REPOSITORY must be set}"

# Probe the release endpoint. Capture stderr (stdout is discarded) and the exit
# status without tripping set -e, so a 404 can be told apart from other errors.
set +e
err="$("$GH" api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}" 2>&1 >/dev/null)"
status=$?
set -e

if [[ "$status" -eq 0 ]]; then
  echo "release-exists: a release for '$tag' exists."
  exit 0
fi

# gh reports HTTP failures as "... (HTTP <code>)"; a clean 404 is the only
# outcome that means "no release yet". Every other error is fatal.
if grep -qiE 'HTTP[[:space:]]+404' <<<"$err"; then
  echo "release-exists: no release for '$tag' (HTTP 404)."
  exit 2
fi

echo "release-exists: could not determine whether a release for '$tag' exists (non-404 lookup error):" >&2
echo "$err" >&2
exit 1
