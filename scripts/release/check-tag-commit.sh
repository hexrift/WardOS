#!/usr/bin/env bash
# Bind a release tag to the exact source commit before publishing (issue #126).
#
# Usage: check-tag-commit.sh <tag> <expected-commit-sha>
#   requires GITHUB_REPOSITORY in the environment (owner/repo).
#
# A published release's tag must name exactly the commit this run built. The
# existing-release path already enforced this, but a git TAG can exist while no
# GitHub Release does yet -- and the create path would then bind a NEW release to
# a tag that already points at unrelated source. So verify the tag's commit here,
# INDEPENDENTLY of whether a release exists, before either the create or the
# upload branch runs.
#
# The tag ref is resolved to a commit -- an annotated tag object is dereferenced
# through git/tags/<sha> to the commit it wraps -- and compared to the expected
# build commit. A tag that does not exist yet is fine: the caller's create path
# binds it to the build commit. A non-404 lookup error fails closed.
#
# `gh` is invoked through $GH (default: gh) so the lookups can be stubbed.
#
# Exit codes:
#   0   the tag does not exist yet, or it resolves to <expected-commit-sha>
#       -> safe to proceed (create may bind it, or the retry is legitimate).
#   1   the tag resolves to a DIFFERENT commit, or its lookup failed for any
#       non-404 reason -> the caller must fail before publishing.
set -euo pipefail

GH="${GH:-gh}"

tag="${1:?usage: check-tag-commit.sh <tag> <expected-commit-sha>}"
expected="${2:?usage: check-tag-commit.sh <tag> <expected-commit-sha>}"
: "${GITHUB_REPOSITORY:?check-tag-commit: GITHUB_REPOSITORY must be set}"

ref="repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}"

# Look up the tag ref's object sha. A clean 404 means the tag is absent (fine);
# any other failure is fatal, never silently "absent".
errf="$(mktemp)"
trap 'rm -f "$errf"' EXIT
set +e
obj_sha="$("$GH" api "$ref" --jq '.object.sha' 2>"$errf")"
status=$?
set -e
err="$(cat "$errf")"

if [[ "$status" -ne 0 ]]; then
  if grep -qiE 'HTTP[[:space:]]+404' <<<"$err"; then
    echo "check-tag-commit: tag '$tag' does not exist yet; create may bind it to $expected."
    exit 0
  fi
  echo "check-tag-commit: could not read tag '$tag' (non-404 lookup error):" >&2
  echo "$err" >&2
  exit 1
fi

# An annotated tag object must be dereferenced to the commit it wraps.
obj_type="$("$GH" api "$ref" --jq '.object.type')"
if [[ "$obj_type" == "tag" ]]; then
  obj_sha="$("$GH" api "repos/${GITHUB_REPOSITORY}/git/tags/${obj_sha}" --jq '.object.sha')"
fi

if [[ "$obj_sha" != "$expected" ]]; then
  echo "check-tag-commit: refusing to publish: tag $tag points at $obj_sha, not the build commit $expected" >&2
  exit 1
fi

echo "check-tag-commit: tag $tag resolves to the build commit $expected."
exit 0
