#!/usr/bin/env bash
# Fail-closed download of a release's already-published assets (issue #126).
#
# Usage: download-published.sh <tag> <local-dir> <published-dir>
#
#   <tag>            the release tag whose assets are being reconciled.
#   <local-dir>      the tarballs and .sha256 checksums this run built.
#   <published-dir>  where the matching already-published assets are written for
#                    check-assets.sh to compare (created if absent).
#
# On an idempotent retry the caller compares the rebuilt artifacts against the
# release's published bytes before clobbering. That comparison is only safe if a
# missing published file reliably means "this artifact was never published"
# (upload it) rather than "we failed to read the release" (which must never
# authorize a clobber). A blind `gh release download ... || true` erases that
# distinction: any auth/API/network/storage failure leaves <published-dir> empty
# and looks identical to a release with no assets, so check-assets would report
# "upload" and the caller would overwrite an existing release it could not read.
#
# So enumerate the release's real assets first, then download only the expected
# ones, failing the whole operation if either step fails:
#   * enumeration failure (`gh release view` non-zero) is fatal -- we cannot read
#     the release, so we refuse to proceed rather than treat it as empty;
#   * for each local artifact, if the release actually lists that asset we
#     download exactly it, and a failed download of a listed asset is fatal;
#   * a local artifact absent from the remote list is genuinely new -- it is left
#     out of <published-dir> so check-assets counts it as an upload.
#
# `gh` is invoked through $GH (default: gh) so the enumeration and download can be
# exercised in isolation by the tests.
#
# Exit codes:
#   0   the release's assets were enumerated and every published counterpart of a
#       local artifact was downloaded; the caller runs check-assets.sh next.
#   1   enumeration failed, a listed asset failed to download, or the inputs are
#       unusable -> the caller must fail the job, never fall through to upload.
set -euo pipefail

GH="${GH:-gh}"

# Names of the assets the release currently has attached, one per line. Exits
# non-zero (propagated) if the release cannot be read.
remote_asset_names() {
  "$GH" release view "$1" --json assets --jq '.assets[].name'
}

# Download exactly the named asset into the given directory. The name is used as
# the download pattern so only that one asset is fetched.
download_asset() {
  "$GH" release download "$1" --dir "$3" --clobber --pattern "$2"
}

main() {
  local tag="${1:?usage: download-published.sh <tag> <local-dir> <published-dir>}"
  local local_dir="${2:?usage: download-published.sh <tag> <local-dir> <published-dir>}"
  local published_dir="${3:?usage: download-published.sh <tag> <local-dir> <published-dir>}"

  if [[ ! -d "$local_dir" ]]; then
    echo "download-published: no such directory: '$local_dir'" >&2
    return 1
  fi
  mkdir -p "$published_dir"

  # Enumerate first. A failure here means we could not read the release; it is
  # NOT the same as "the release has no assets" and must not authorize a clobber.
  local remote
  if ! remote="$(remote_asset_names "$tag")"; then
    echo "download-published: could not enumerate assets for '$tag' (auth/API/network failure); refusing to proceed." >&2
    return 1
  fi

  shopt -s nullglob
  local locals=("$local_dir"/*.tar.gz "$local_dir"/*.tar.gz.sha256)
  shopt -u nullglob
  if [[ ${#locals[@]} -eq 0 ]]; then
    echo "download-published: no local artifacts in '$local_dir'" >&2
    return 1
  fi

  local path name
  for path in "${locals[@]}"; do
    name="$(basename "$path")"
    if ! printf '%s\n' "$remote" | grep -Fxq -- "$name"; then
      echo "download-published: '$name' is not published yet (new artifact)."
      continue
    fi
    if ! download_asset "$tag" "$name" "$published_dir"; then
      echo "download-published: '$name' is a published asset but its download failed; refusing to proceed." >&2
      return 1
    fi
    # A listed asset must actually land -- a silent no-download would masquerade
    # as "new" and let the caller clobber it.
    if [[ ! -e "$published_dir/$name" ]]; then
      echo "download-published: '$name' was listed but did not download; refusing to proceed." >&2
      return 1
    fi
    echo "download-published: pulled published '$name' for comparison."
  done
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
