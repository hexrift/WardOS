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
# *.tar.gz.sha256, and the release manifest *-manifest.json with its .sha256
# (generate-manifest.sh), in <local-dir> that also exists in <published-dir>,
# the two must be byte-identical. If any published counterpart differs, `gh release
# upload --clobber` would silently replace a published artifact (and its
# checksum) with different bytes -- refuse before the caller uploads anything.
# Published assets the run is NOT replacing (e.g. a disk image, or another
# architecture's tarball built by an earlier run) are left untouched.
#
# The manifest's Sigstore bundle, *-manifest.json.sigstore.json (issue #148), is
# the one asset that is never byte-compared: a keyless signature differs on
# every run that signs (its own Fulcio certificate, Rekor entry and timestamp)
# even over identical manifest bytes, so a differing published bundle is not a
# conflict. The rule is: a local bundle is uploaded (with --clobber) exactly when
# its manifest is published byte-identical or not yet published; when the
# manifest's bytes differ the whole run is refused, bundle included, by the
# manifest's own conflict; a published bundle with no local counterpart (a run
# that did not sign) is left untouched. A local bundle therefore always counts
# as "to upload", never as "identical" -- a retry that re-signs an identical
# manifest exits 10 so the fresh bundle replaces the published one, which is
# harmless: it is a second valid signature over the same bytes.
#
# Exit codes:
#   0   every local artifact is already published byte-identical and the run
#       carries no bundle -> the caller should skip the upload (a clean
#       idempotent no-op).
#   10  one or more local artifacts are not yet published, or the run carries a
#       bundle, and none that are published conflict -> the caller should
#       upload (--clobber).
#   1   a published artifact differs from the rebuilt one, a bundle has no
#       manifest beside it, or the inputs are unusable -> the caller must fail
#       before uploading.
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
local_assets=("$local_dir"/*.tar.gz "$local_dir"/*.tar.gz.sha256
  "$local_dir"/*-manifest.json "$local_dir"/*-manifest.json.sha256
  "$local_dir"/*-manifest.json.sigstore.json)
shopt -u nullglob

if [[ ${#local_assets[@]} -eq 0 ]]; then
  echo "check-assets: no artifacts to publish in '$local_dir'" >&2
  exit 1
fi

missing=0
identical=0
conflict=0
bundles=0
for path in "${local_assets[@]}"; do
  name="$(basename "$path")"
  pub="$published_dir/$name"
  if [[ "$name" == *-manifest.json.sigstore.json ]]; then
    # Never byte-compared (see the header). Its manifest must be in this run's
    # set, so the manifest's own identical/new/conflict verdict governs it.
    manifest_name="${name%.sigstore.json}"
    if [[ ! -e "$local_dir/$manifest_name" ]]; then
      echo "check-assets: bundle '$name' has no manifest '$manifest_name' beside it in '$local_dir'" >&2
      exit 1
    fi
    echo "check-assets: '$name' is this run's signature bundle; uploaded with its manifest, never byte-compared"
    bundles=$((bundles + 1))
  elif [[ ! -e "$pub" ]]; then
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

if [[ "$missing" -eq 0 && "$bundles" -eq 0 ]]; then
  echo "check-assets: OK -- all $identical artifact(s) already published byte-identical; skip upload."
  exit 0
fi

echo "check-assets: $missing new artifact(s) and $bundles signature bundle(s) to upload, $identical already byte-identical."
exit 10
