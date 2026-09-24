#!/usr/bin/env bash
# Regressions for generate-manifest.sh (ADR-0028 §4, issue #148): a correct
# manifest is produced from a valid fixture release, and every kind of
# incomplete/incorrect input is refused with a non-zero exit rather than
# silently producing a manifest that overstates what is actually known.
#
# Two of the ADR's acceptance-case table rows apply directly to a manifest
# generator (the rest are verifier-side, out of scope for this script):
#   - "One byte changed after download"      -> here: digest mismatch is
#                                                caught before the manifest
#                                                ships, not just at install.
#   - "Missing or incomplete artifact set"    -> here: a missing sidecar, an
#                                                orphaned sidecar, an empty
#                                                dist dir, or a mismatched
#                                                version-in-filename are all
#                                                refused, not silently
#                                                dropped from the manifest.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/generate-manifest.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

commit="0123456789abcdef0123456789abcdef01234567"
tag="v1.2.3"
version="1.2.3"

# fresh_case NAME -> makes $work/NAME/dist and echoes the case dir.
fresh_case() {
  local dir="$work/$1"
  mkdir -p "$dir/dist"
  printf '%s' "$dir"
}

# add_artifact DIST ARCH [BYTES] -> writes a valid tarball+sidecar pair for
# $version/$ARCH into DIST, with real matching bytes/digest.
add_artifact() {
  local dist="$1" arch="$2"
  local bytes="${3:-payload-$arch}"
  local name="wardos-${version}-${arch}-linux.tar.gz"
  printf '%s' "$bytes" >"$dist/$name"
  (cd "$dist" && sha256sum "$name" >"$name.sha256")
}

### Happy path ################################################################

c="$(fresh_case valid)"
add_artifact "$c/dist" x86_64
add_artifact "$c/dist" aarch64
out="$(GENERATE_MANIFEST_NOW=2026-01-01T00:00:00Z bash "$sut" "$tag" "$commit" "$c/dist")"
echo "$out" | jq -e . >/dev/null || fail "valid case: output is not valid JSON"
[[ "$(jq -r .tag <<<"$out")" == "$tag" ]] || fail "valid case: wrong tag"
[[ "$(jq -r .version <<<"$out")" == "$version" ]] || fail "valid case: wrong version"
[[ "$(jq -r .source_commit <<<"$out")" == "$commit" ]] || fail "valid case: wrong commit"
[[ "$(jq -r '.artifacts | length' <<<"$out")" == "2" ]] || fail "valid case: expected 2 artifacts"
[[ "$(jq -r '.artifacts[0].name' <<<"$out")" == "wardos-1.2.3-aarch64-linux.tar.gz" ]] ||
  fail "valid case: artifacts are not sorted by name"
[[ "$(jq -r '.artifacts[] | select(.architecture == "x86_64") | .digest' <<<"$out")" \
  == "sha256:$(sha256sum "$c/dist/wardos-1.2.3-x86_64-linux.tar.gz" | awk '{print $1}')" ]] ||
  fail "valid case: x86_64 digest does not match the artifact's actual bytes"
[[ "$(jq -r '.provenance.status' <<<"$out")" == "unavailable" ]] ||
  fail "valid case: provenance.status must stay 'unavailable' until real attestation exists"
[[ "$(jq -r '.provenance.attestation_ref' <<<"$out")" == "null" ]] ||
  fail "valid case: provenance.attestation_ref must be null, not fabricated"
[[ "$(jq -r '.compatibility.rollback_supported' <<<"$out")" == "true" ]] ||
  fail "valid case: rollback_supported should default true"
[[ "$(jq -r '.image.bootc_reference' <<<"$out")" == "null" ]] ||
  fail "valid case: image.bootc_reference should be null when not given"
echo "ok   valid fixture release produces a correct manifest"

# Determinism: the same inputs, generated twice, produce byte-identical JSON
# (modulo generated_at, pinned above) -- glob/filesystem order must not leak in.
out2="$(GENERATE_MANIFEST_NOW=2026-01-01T00:00:00Z bash "$sut" "$tag" "$commit" "$c/dist")"
[[ "$out" == "$out2" ]] || fail "valid case: two runs over identical inputs produced different manifests"
echo "ok   generation is deterministic across repeated runs"

# Optional image reference is carried through untouched.
c="$(fresh_case with-image-ref)"
add_artifact "$c/dist" x86_64
out="$(bash "$sut" "$tag" "$commit" "$c/dist" "quay.io/hexrift/wardos:$tag")"
[[ "$(jq -r '.image.bootc_reference' <<<"$out")" == "quay.io/hexrift/wardos:$tag" ]] ||
  fail "image-ref case: bootc_reference not carried through"
echo "ok   an explicit image reference is recorded"

### Rejections #################################################################

# Empty dist dir: no artifacts at all -> completeness failure.
c="$(fresh_case empty)"
expect_status 1 "empty dist dir is refused" bash "$sut" "$tag" "$commit" "$c/dist"

# Missing dist dir entirely.
expect_status 1 "missing dist dir is refused" bash "$sut" "$tag" "$commit" "$work/does-not-exist"

# Malformed tag (not v<semver>).
c="$(fresh_case bad-tag)"
add_artifact "$c/dist" x86_64
expect_status 1 "malformed tag is refused" bash "$sut" "1.2.3" "$commit" "$c/dist"
expect_status 1 "tag with shell metacharacters is refused" \
  bash "$sut" 'v1.2.3; touch pwned' "$commit" "$c/dist"

# Malformed / short / symbolic commit.
expect_status 1 "short commit sha is refused" bash "$sut" "$tag" "abc123" "$c/dist"
expect_status 1 "symbolic ref instead of a commit sha is refused" bash "$sut" "$tag" "HEAD" "$c/dist"

# Artifact whose filename's version segment doesn't match the tag: a
# leftover artifact from a different release must not be folded in.
c="$(fresh_case wrong-version)"
printf 'BYTES\n' >"$c/dist/wardos-9.9.9-x86_64-linux.tar.gz"
(cd "$c/dist" && sha256sum wardos-9.9.9-x86_64-linux.tar.gz >wardos-9.9.9-x86_64-linux.tar.gz.sha256)
expect_status 1 "artifact naming a different version is refused" bash "$sut" "$tag" "$commit" "$c/dist"

# Missing checksum sidecar for an otherwise-valid tarball.
c="$(fresh_case missing-sidecar)"
printf 'BYTES\n' >"$c/dist/wardos-${version}-x86_64-linux.tar.gz"
expect_status 1 "artifact with no checksum sidecar is refused" bash "$sut" "$tag" "$commit" "$c/dist"

# Orphaned sidecar with no matching tarball.
c="$(fresh_case orphan-sidecar)"
add_artifact "$c/dist" x86_64
echo "deadbeef  wardos-${version}-aarch64-linux.tar.gz" >"$c/dist/wardos-${version}-aarch64-linux.tar.gz.sha256"
expect_status 1 "a checksum sidecar with no matching artifact is refused" bash "$sut" "$tag" "$commit" "$c/dist"

# Digest mismatch: the sidecar was not regenerated after the bytes changed --
# exactly the "one byte changed after download" acceptance case, but caught
# here at manifest-generation time against the sidecar the build itself wrote.
c="$(fresh_case digest-mismatch)"
add_artifact "$c/dist" x86_64
printf 'TAMPERED-BYTES\n' >"$c/dist/wardos-${version}-x86_64-linux.tar.gz"
expect_status 1 "a tarball that no longer matches its own sidecar is refused" bash "$sut" "$tag" "$commit" "$c/dist"

# Corrupt sidecar contents (not a valid hex digest).
c="$(fresh_case corrupt-sidecar)"
printf 'BYTES\n' >"$c/dist/wardos-${version}-x86_64-linux.tar.gz"
echo "not-a-digest" >"$c/dist/wardos-${version}-x86_64-linux.tar.gz.sha256"
expect_status 1 "a sidecar without a valid sha256 hex digest is refused" bash "$sut" "$tag" "$commit" "$c/dist"

# Image reference with embedded whitespace (would otherwise corrupt the field).
c="$(fresh_case bad-image-ref)"
add_artifact "$c/dist" x86_64
expect_status 1 "an image reference containing whitespace is refused" \
  bash "$sut" "$tag" "$commit" "$c/dist" "quay.io/hexrift/wardos:$tag extra"

echo "PASS generate-manifest.test.sh"
