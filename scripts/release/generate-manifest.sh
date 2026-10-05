#!/usr/bin/env bash
# Generate a release's machine-readable manifest (ADR-0028 §4, issue #148).
#
# Usage: generate-manifest.sh <tag> <commit> <dist-dir> [image-ref]
#
#   <tag>        the release tag, e.g. v1.2.3 (same grammar as check-version.sh).
#   <commit>     the full 40-hex-character source commit the release was built
#                from (what check-tag-commit.sh already binds the tag to).
#   <dist-dir>   the directory holding this release's *.tar.gz artifacts and
#                their *.tar.gz.sha256 sidecars (what check-assets.sh already
#                validated before upload).
#   [image-ref]  optional OCI/bootc image reference for this release, e.g.
#                quay.io/hexrift/wardos:v1.2.3. Omit when this release has no
#                image counterpart (or the image workflow publishes its own).
#
# Prints the manifest as JSON on stdout. Nothing is written or uploaded here;
# the caller decides where the manifest is published (the release workflow
# attaches it as wardos-<version>-manifest.json with a .sha256 sidecar).
#
# The manifest also records the node protocol window this release serves
# (issue #275): the `<!-- protocol-window: M.a-M.b -->` marker of
# docs/compatibility.md, which scripts/security-check/protocol-window.py holds
# equal to the WARD_NODE_PROTOCOL constant on every pull request. The marker is
# parsed here with the same grammar as that check (exactly one marker, one
# major, a non-inverted minor range) so the manifest can never state a window
# the compatibility document does not. The document is found relative to this
# script; GENERATE_MANIFEST_COMPATIBILITY_DOC overrides the path (tests).
#
# This does NOT sign or attest anything. The release workflow signs the printed
# manifest afterwards, keyless with its own identity, into the sibling asset
# wardos-<version>-manifest.json.sigstore.json (issue #148; verified offline by
# verify-manifest.sh) -- a signature over these bytes, which is why nothing in
# them can reference it. The `provenance` object below is about the SLSA
# provenance attestation of ADR-0028 §4, which does not exist yet: it is an
# explicit, honest placeholder, `status: "unavailable"` and a note saying what
# does exist, and a caller must not post-process this manifest to claim
# otherwise until a real attestation exists.
#
# Every input is validated before any JSON is produced -- a malformed tag or
# commit, a missing/extra/mismatched artifact, or a digest that doesn't match
# its own sidecar is refused with an actionable message, never silently
# dropped or guessed at.
#
# Exit codes:
#   0   the manifest was generated and printed.
#   1   an input was missing, malformed, incomplete or inconsistent, or the
#       protocol-window marker is absent, duplicated or malformed.
set -euo pipefail

tag="${1:?usage: generate-manifest.sh <tag> <commit> <dist-dir> [image-ref]}"
commit="${2:?usage: generate-manifest.sh <tag> <commit> <dist-dir> [image-ref]}"
dist_dir="${3:?usage: generate-manifest.sh <tag> <commit> <dist-dir> [image-ref]}"
image_ref="${4:-}"

die() {
  echo "generate-manifest: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

# Same strict tag grammar as check-version.sh: v<major>.<minor>.<patch> with
# optional SemVer prerelease/build metadata, anchored end-to-end.
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  die "not a valid v<semver> release tag: '$tag'"
fi
version="${tag#v}"

# A full, lowercase git commit object id. A short hash or a symbolic ref
# (HEAD, a branch name) is refused: the manifest must bind to the exact
# immutable commit ADR-0028 §4 requires, not to something that can move.
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  die "not a full 40-character lowercase commit sha: '$commit'"
fi

[[ -d "$dist_dir" ]] || die "no such directory: '$dist_dir'"

if [[ -n "$image_ref" ]] && [[ "$image_ref" =~ [[:space:]] ]]; then
  die "image reference must not contain whitespace: '$image_ref'"
fi

# The node protocol window, read from the compatibility document's single
# machine-readable marker. Newlines are flattened first so a marker (or a
# window) wrapped over lines parses the way protocol-window.py's DOTALL and \s
# read it; the content of a well-formed marker never contains '>'.
compat_doc="${GENERATE_MANIFEST_COMPATIBILITY_DOC:-$(dirname "${BASH_SOURCE[0]}")/../../docs/compatibility.md}"
[[ -f "$compat_doc" ]] || die "compatibility document not found: '$compat_doc'"
markers="$(tr '\n' ' ' <"$compat_doc" | grep -o -E '<!--[[:space:]]*protocol-window:[^>]*-->' || true)"
marker_count="$(printf '%s\n' "$markers" | grep -c . || true)"
if [[ "$marker_count" -eq 0 ]]; then
  die "$compat_doc: no protocol-window marker found; state the window as '<!-- protocol-window: M.a-M.b -->'"
elif [[ "$marker_count" -gt 1 ]]; then
  die "$compat_doc: more than one protocol-window marker; keep exactly one"
fi
window="${markers#*protocol-window:}"
window="${window%-->}"
window="$(printf '%s' "$window" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
if [[ ! "$window" =~ ^([0-9]+)\.([0-9]+)-([0-9]+)\.([0-9]+)$ ]]; then
  die "$compat_doc: malformed protocol-window marker '$window': expected 'M.a-M.b'"
fi
window_major="${BASH_REMATCH[1]}"
window_min_minor="${BASH_REMATCH[2]}"
window_max_minor="${BASH_REMATCH[4]}"
if [[ "$window_major" != "${BASH_REMATCH[3]}" ]]; then
  die "$compat_doc: malformed protocol-window marker '$window': a window spans one major"
fi
if ((10#$window_min_minor > 10#$window_max_minor)); then
  die "$compat_doc: malformed protocol-window marker '$window': inverted range"
fi

shopt -s nullglob
tarballs=("$dist_dir"/*.tar.gz)
sidecars=("$dist_dir"/*.tar.gz.sha256)
shopt -u nullglob

[[ ${#tarballs[@]} -gt 0 ]] || die "no artifacts (*.tar.gz) found in '$dist_dir'; refusing to generate an incomplete manifest"

# Every sidecar must name a tarball this run is actually describing -- an
# orphaned checksum (stale build, wrong directory) is flagged rather than
# silently ignored.
declare -A have_tarball=()
for path in "${tarballs[@]}"; do
  have_tarball["$(basename "$path")"]=1
done
for path in "${sidecars[@]}"; do
  name="$(basename "$path")"
  tarball_name="${name%.sha256}"
  [[ -n "${have_tarball[$tarball_name]:-}" ]] || die "checksum sidecar '$name' has no matching artifact in '$dist_dir'"
done

artifacts_json="[]"
for path in "${tarballs[@]}"; do
  name="$(basename "$path")"

  # Artifact names are produced by scripts/release/package.sh as
  # <component>-<version>-<arch>-linux.tar.gz, one component per release train
  # (issue #275): `wardos` is the runtime tarball, `ward-node` the node's.
  # Matched by literal prefix/suffix (not a single regex split) so a version
  # containing its own hyphens (a SemVer prerelease like "1.2.3-rc.1") can
  # never be ambiguous with the arch segment. An artifact whose name doesn't
  # carry *this* manifest's version at all -- left over from a different
  # release in the same directory -- is a real hazard, not a cosmetic mismatch.
  suffix="-linux.tar.gz"
  component=""
  for candidate in wardos ward-node; do
    prefix="${candidate}-${version}-"
    if [[ "$name" == "$prefix"*"$suffix" ]]; then
      component="$candidate"
      break
    fi
  done
  if [[ -z "$component" ]]; then
    die "artifact name does not match the expected {wardos,ward-node}-${version}-<arch>-linux.tar.gz pattern: '$name'"
  fi
  arch="${name#"$prefix"}"
  arch="${arch%"$suffix"}"
  if [[ -z "$arch" || ! "$arch" =~ ^[A-Za-z0-9_]+$ ]]; then
    die "artifact '$name' has an empty or invalid architecture segment"
  fi

  sidecar="$dist_dir/$name.sha256"
  [[ -f "$sidecar" ]] || die "missing checksum sidecar for artifact '$name' (expected '$name.sha256')"

  # sha256sum's own line format is "<hex>  <name>" (or "<hex> *<name>" in
  # binary mode); only the first whitespace-separated field is the digest.
  recorded_digest="$(awk '{print $1; exit}' "$sidecar")"
  if [[ ! "$recorded_digest" =~ ^[0-9a-f]{64}$ ]]; then
    die "checksum sidecar '$name.sha256' does not contain a valid sha256 hex digest"
  fi

  actual_digest="$(sha256sum "$path" | awk '{print $1}')"
  if [[ "$actual_digest" != "$recorded_digest" ]]; then
    die "digest mismatch for artifact '$name': sidecar says $recorded_digest, bytes hash to $actual_digest"
  fi

  size_bytes="$(wc -c <"$path" | tr -d '[:space:]')"

  artifact_json="$(
    jq -n \
      --arg name "$name" \
      --arg component "$component" \
      --arg arch "$arch" \
      --arg digest "sha256:$actual_digest" \
      --argjson size "$size_bytes" \
      '{name: $name, component: $component, architecture: $arch, digest: $digest, size_bytes: $size}'
  )"
  artifacts_json="$(jq -c --argjson a "$artifact_json" '. + [$a]' <<<"$artifacts_json")"
done

# Stable ordering regardless of glob/filesystem order, so two runs over the
# same inputs produce byte-identical manifests.
artifacts_json="$(jq -c 'sort_by(.name)' <<<"$artifacts_json")"

generated_at="${GENERATE_MANIFEST_NOW:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

jq -n \
  --arg schema_version "1" \
  --arg tag "$tag" \
  --arg version "$version" \
  --arg commit "$commit" \
  --arg generated_at "$generated_at" \
  --argjson artifacts "$artifacts_json" \
  --arg image_ref "$image_ref" \
  --argjson window_major "$((10#$window_major))" \
  --argjson window_min_minor "$((10#$window_min_minor))" \
  --argjson window_max_minor "$((10#$window_max_minor))" \
  '{
    schema_version: ($schema_version | tonumber),
    tag: $tag,
    version: $version,
    source_commit: $commit,
    generated_at: $generated_at,
    artifacts: $artifacts,
    node_protocol_window: {
      major: $window_major,
      min_minor: $window_min_minor,
      max_minor: $window_max_minor
    },
    image: {
      bootc_reference: (if $image_ref == "" then null else $image_ref end)
    },
    provenance: {
      status: "unavailable",
      attestation_ref: null,
      builder: null,
      note: "No SLSA provenance attestation is generated or verified yet (ADR-0028, issue #148). The release workflow signs this manifest keyless after generating it, when its run is on the release tag; the Sigstore bundle is the sibling asset wardos-\($version)-manifest.json.sigstore.json, verified offline by scripts/release/verify-manifest.sh (docs/release-manifest.md). The tarballs are bound to this manifest by digest only."
    },
    compatibility: {
      rollback_supported: true,
      min_upgrade_from: null,
      notes: "The anti-rollback floor (ADR-0028 §5) is enforced by the update verifier at install/update time, not recorded per-release here."
    }
  }'
