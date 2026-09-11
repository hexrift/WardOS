#!/usr/bin/env bash
# Bind a release tag to the exact source commit before publishing (issue #126).
#
# Usage: check-tag-commit.sh <tag> <expected-commit-sha> <release-exists:true|false>
#   requires GITHUB_REPOSITORY in the environment (owner/repo).
#
# A published release's tag must name exactly the commit this run built. Whether
# an absent tag ref (a clean 404) is acceptable depends on whether a GitHub
# Release already exists -- so that state is passed in, making the tag decision
# JOINT with the release-existence decision instead of an independent guess:
#
#   * release-exists=true  -- a Release already exists, so its tag MUST still
#     exist and resolve to the build commit before any asset is replaced/added.
#     A 404 tag ref here is fatal: a Release whose tag was deleted (or repointed)
#     no longer provably binds its assets to this source. This is the state the
#     round-4 review flagged.
#   * release-exists=false -- no Release yet. A 404 tag is fine: the caller's
#     create path binds a fresh tag to the build commit.
#
# In BOTH cases a tag that DOES exist must resolve to the expected commit -- an
# annotated tag object is dereferenced through git/tags/<sha> to the commit it
# wraps. A non-404 lookup error always fails closed.
#
# `gh` is invoked through $GH (default: gh) so the lookups can be stubbed.
#
# Exit codes:
#   0   safe to proceed: the tag resolves to <expected-commit-sha>, or the tag is
#       absent AND no Release exists yet (the create path may bind it).
#   1   must fail before publishing: the tag resolves to a DIFFERENT commit; the
#       tag ref is missing while a Release already exists; or the lookup failed
#       for any non-404 reason.
set -euo pipefail

GH="${GH:-gh}"

tag="${1:?usage: check-tag-commit.sh <tag> <expected-commit-sha> <release-exists:true|false>}"
expected="${2:?usage: check-tag-commit.sh <tag> <expected-commit-sha> <release-exists:true|false>}"
release_exists="${3:?usage: check-tag-commit.sh <tag> <expected-commit-sha> <release-exists:true|false>}"
: "${GITHUB_REPOSITORY:?check-tag-commit: GITHUB_REPOSITORY must be set}"

case "$release_exists" in
  true | false) ;;
  *) echo "check-tag-commit: <release-exists> must be 'true' or 'false', got '$release_exists'" >&2
     exit 1 ;;
esac

ref="repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}"

# Look up the tag ref's object sha. Capture stderr and status without tripping
# set -e so a clean 404 can be told apart from any other failure.
errf="$(mktemp)"
trap 'rm -f "$errf"' EXIT
set +e
obj_sha="$("$GH" api "$ref" --jq '.object.sha' 2>"$errf")"
status=$?
set -e
err="$(cat "$errf")"

if [[ "$status" -ne 0 ]]; then
  if grep -qiE 'HTTP[[:space:]]+404' <<<"$err"; then
    # The tag ref does not exist. Acceptable only if no Release exists yet.
    if [[ "$release_exists" == "true" ]]; then
      echo "check-tag-commit: refusing to publish: a release for $tag exists but its tag ref is gone; nothing binds those assets to the build commit $expected" >&2
      exit 1
    fi
    echo "check-tag-commit: tag '$tag' does not exist yet and no release exists; create may bind it to $expected."
    exit 0
  fi
  echo "check-tag-commit: could not read tag '$tag' (non-404 lookup error):" >&2
  echo "$err" >&2
  exit 1
fi

# The tag exists: it must resolve to the build commit, whether or not a Release
# exists. An annotated tag object is dereferenced to the commit it wraps.
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
