#!/usr/bin/env bash
# Bind a release tag to the workspace source it is cut from (issue #126).
#
# Usage: check-version.sh <tag> [cargo-toml]
#
# Validates that <tag> is a v<...> release tag and that it names exactly the
# workspace.package.version in the checked-out Cargo.toml (default ./Cargo.toml).
# A mistyped tag, or a build dispatched from a ref whose Cargo version does not
# match the tag, is rejected here -- before anything is built or published.
set -euo pipefail

tag="${1:?usage: check-version.sh <tag> [cargo-toml]}"
cargo_toml="${2:-Cargo.toml}"

# Strict tag grammar: v<major>.<minor>.<patch> with optional SemVer prerelease
# (-rc.1) and build metadata (+meta). Anchored end-to-end so a value carrying
# shell metacharacters (e.g. 'v1.2.3; touch pwned' or 'v1.2.3$(...)') is rejected
# here rather than treated as a tag -- the workflow reads this value from a
# dispatch input, so the grammar is the gate that keeps junk out of the release.
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "check-version: not a valid v<semver> release tag: '$tag'" >&2
  exit 1
fi

if [[ ! -f "$cargo_toml" ]]; then
  echo "check-version: no such Cargo.toml: '$cargo_toml'" >&2
  exit 1
fi

# The first `version = "..."` inside the [workspace.package] table.
version="$(
  awk -F'"' '
    /^\[workspace\.package\]/ { in_wp = 1; next }
    /^\[/                     { in_wp = 0 }
    in_wp && /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }
  ' "$cargo_toml"
)"

if [[ -z "$version" ]]; then
  echo "check-version: no workspace.package.version found in '$cargo_toml'" >&2
  exit 1
fi

if [[ "$tag" != "v$version" ]]; then
  echo "check-version: tag '$tag' does not match workspace version 'v$version' in '$cargo_toml'" >&2
  echo "check-version: refusing to build or publish a mislabelled release." >&2
  exit 1
fi

echo "check-version: OK -- tag '$tag' matches workspace version 'v$version'."
