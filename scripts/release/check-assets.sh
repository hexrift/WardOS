#!/usr/bin/env bash
# Bind a release's published assets to the source they were built from (issue #126).
#
# Usage: check-assets.sh <local-dir> <published-dir>
#
#   <local-dir>      the tarballs and .sha256 checksums this run built and is
#                    about to upload.
#   <published-dir>  the release's already-published assets, downloaded by the
#                    caller (an empty directory if the release has none yet).
#
# On an idempotent retry -- the tag already resolves to this build's commit -- a
# rebuild must reproduce the published bytes exactly. For every *.tar.gz and
# *.tar.gz.sha256 in <local-dir> that also exists in <published-dir>, the two
# must be byte-identical. If any published counterpart differs, `gh release
# upload --clobber` would silently replace a published artifact (and its
# checksum) with different bytes -- refuse before the caller uploads anything.
# Published assets the run is NOT replacing (e.g. a disk image, or another
# architecture's tarball built by an earlier run) are left untouched.
#
# Exit codes:
#   0   every local artifact is already published byte-identical -> the caller
#       should skip the upload (a clean idempotent no-op).
#   10  one or more local artifacts are not yet published, and none that are
#       published conflict -> the caller should upload.
#   1   a published artifact differs from the rebuilt one, or the inputs are
#       unusable -> the caller must fail before uploading.
set -euo pipefail

local_dir="${1:?usage: check-assets.sh <local-dir> <published-dir>}"
published_dir="${2:?usage: check-assets.sh <local-dir> <published-dir>}"

for d in "$local_dir" "$published_dir"; do
  if [[ ! -d "$d" ]]; then
    echo "check-assets: no such directory: '$d'" >&2
    exit 1
  fi
done

shopt -s nullglob
local_assets=("$local_dir"/*.tar.gz "$local_dir"/*.tar.gz.sha256)
shopt -u nullglob

if [[ ${#local_assets[@]} -eq 0 ]]; then
  echo "check-assets: no artifacts to publish in '$local_dir'" >&2
  exit 1
fi

missing=0
identical=0
conflict=0
for path in "${local_assets[@]}"; do
  name="$(basename "$path")"
  pub="$published_dir/$name"
  if [[ ! -e "$pub" ]]; then
    echo "check-assets: '$name' is not yet published"
    missing=$((missing + 1))
  elif cmp -s "$path" "$pub"; then
    echo "check-assets: '$name' already published, byte-identical"
    identical=$((identical + 1))
  else
    echo "check-assets: CONFLICT -- published '$name' differs from the rebuilt artifact" >&2
    conflict=$((conflict + 1))
  fi
done

if [[ "$conflict" -gt 0 ]]; then
  echo "check-assets: refusing to overwrite $conflict published artifact(s) with different bytes." >&2
  exit 1
fi

if [[ "$missing" -eq 0 ]]; then
  echo "check-assets: OK -- all $identical artifact(s) already published byte-identical; skip upload."
  exit 0
fi

echo "check-assets: $missing new artifact(s) to upload, $identical already byte-identical."
exit 10
