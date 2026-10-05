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
node_version="0.3.0"

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

# add_node_artifact DIST ARCH -> the node train's tarball+sidecar pair for
# $version/$ARCH (issue #275).
add_node_artifact() {
  local dist="$1" arch="$2"
  local name="ward-node-${node_version}-${arch}-linux.tar.gz"
  printf '%s' "node-payload-$arch" >"$dist/$name"
  (cd "$dist" && sha256sum "$name" >"$name.sha256")
}

### Happy path ################################################################

c="$(fresh_case valid)"
add_artifact "$c/dist" x86_64
add_artifact "$c/dist" aarch64
out="$(GENERATE_MANIFEST_NOW=2026-01-01T00:00:00Z bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist")"
echo "$out" | jq -e . >/dev/null || fail "valid case: output is not valid JSON"
[[ "$(jq -r .tag <<<"$out")" == "$tag" ]] || fail "valid case: wrong tag"
[[ "$(jq -r .version <<<"$out")" == "$version" ]] || fail "valid case: wrong version"
[[ "$(jq -r .source_commit <<<"$out")" == "$commit" ]] || fail "valid case: wrong commit"
[[ "$(jq -r '.artifacts | length' <<<"$out")" == "2" ]] || fail "valid case: expected 2 artifacts"
[[ "$(jq -r '.artifacts[0].name' <<<"$out")" == "wardos-1.2.3-aarch64-linux.tar.gz" ]] ||
  fail "valid case: artifacts are not sorted by name"
[[ "$(jq -r '.artifacts[0].component' <<<"$out")" == "wardos" ]] ||
  fail "valid case: the runtime tarball's component is not wardos"
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
# The window comes from the repository's own compatibility document (issue
# #275): the same marker protocol-window.py holds equal to WARD_NODE_PROTOCOL.
repo_marker="$(grep -o -E '<!--[[:space:]]*protocol-window:[^>]*-->' "$RELEASE_DIR/../../docs/compatibility.md")"
[[ "$repo_marker" =~ ([0-9]+)\.([0-9]+)-([0-9]+)\.([0-9]+) ]] || fail "valid case: could not read the repository's protocol-window marker"
[[ "$(jq -c '.node_protocol_window' <<<"$out")" \
  == "{\"major\":${BASH_REMATCH[1]},\"min_minor\":${BASH_REMATCH[2]},\"max_minor\":${BASH_REMATCH[4]}}" ]] ||
  fail "valid case: node_protocol_window does not restate docs/compatibility.md's marker"
echo "ok   valid fixture release produces a correct manifest"

# Determinism: the same inputs, generated twice, produce byte-identical JSON
# (modulo generated_at, pinned above) -- glob/filesystem order must not leak in.
out2="$(GENERATE_MANIFEST_NOW=2026-01-01T00:00:00Z bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist")"
[[ "$out" == "$out2" ]] || fail "valid case: two runs over identical inputs produced different manifests"
echo "ok   generation is deterministic across repeated runs"

# Optional image reference is carried through untouched.
c="$(fresh_case with-image-ref)"
add_artifact "$c/dist" x86_64
out="$(bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist" "quay.io/hexrift/wardos:$tag")"
[[ "$(jq -r '.image.bootc_reference' <<<"$out")" == "quay.io/hexrift/wardos:$tag" ]] ||
  fail "image-ref case: bootc_reference not carried through"
echo "ok   an explicit image reference is recorded"

### The node protocol window (issue #275) ####################################

# The window is read from the compatibility document's marker with the grammar
# of scripts/security-check/protocol-window.py: exactly one marker, one major,
# a non-inverted minor range, whitespace and line wrapping tolerated.
# write_doc NAME MARKER... -> a stand-in compatibility document holding the
# given marker text(s); echoes its path.
write_doc() {
  local path="$work/$1.md"
  shift
  { echo "# Compatibility"; echo; printf '%s\n' "$@"; echo; echo "Body."; } >"$path"
  printf '%s' "$path"
}
c="$(fresh_case window)"
add_artifact "$c/dist" x86_64
doc="$(write_doc window-plain '<!-- protocol-window: 2.1-2.4 -->')"
out="$(GENERATE_MANIFEST_COMPATIBILITY_DOC="$doc" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist")"
[[ "$(jq -c '.node_protocol_window' <<<"$out")" == '{"major":2,"min_minor":1,"max_minor":4}' ]] ||
  fail "window case: marker 2.1-2.4 not recorded as major 2, minors 1-4"
echo "ok   the protocol window is read from the compatibility document's marker"

doc="$(write_doc window-wrapped '<!--protocol-window:' '  1.0-1.3' '-->')"
out="$(GENERATE_MANIFEST_COMPATIBILITY_DOC="$doc" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist")"
[[ "$(jq -c '.node_protocol_window' <<<"$out")" == '{"major":1,"min_minor":0,"max_minor":3}' ]] ||
  fail "window case: a marker wrapped over lines is not read like protocol-window.py reads it"
echo "ok   a line-wrapped marker parses the way protocol-window.py reads it"

doc="$(write_doc window-single-minor '<!-- protocol-window: 1.3-1.3 -->')"
out="$(GENERATE_MANIFEST_COMPATIBILITY_DOC="$doc" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist")"
[[ "$(jq -c '.node_protocol_window' <<<"$out")" == '{"major":1,"min_minor":3,"max_minor":3}' ]] ||
  fail "window case: a one-minor window is not recorded"
echo "ok   a one-minor window is recorded"

# Anything protocol-window.py would refuse is refused here too, with no
# manifest produced: the field is never guessed or defaulted.
doc="$(write_doc window-absent 'No marker in this document.')"
expect_status 1 "a compatibility document without a marker is refused" \
  env GENERATE_MANIFEST_COMPATIBILITY_DOC="$doc" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"
doc="$(write_doc window-duplicate '<!-- protocol-window: 1.0-1.3 -->' '<!-- protocol-window: 1.0-1.3 -->')"
expect_status 1 "two markers are refused" \
  env GENERATE_MANIFEST_COMPATIBILITY_DOC="$doc" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"
doc="$(write_doc window-malformed '<!-- protocol-window: 1.0 to 1.3 -->')"
expect_status 1 "a marker that is not M.a-M.b is refused" \
  env GENERATE_MANIFEST_COMPATIBILITY_DOC="$doc" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"
doc="$(write_doc window-cross-major '<!-- protocol-window: 1.0-2.3 -->')"
expect_status 1 "a window spanning two majors is refused" \
  env GENERATE_MANIFEST_COMPATIBILITY_DOC="$doc" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"
doc="$(write_doc window-inverted '<!-- protocol-window: 1.3-1.0 -->')"
expect_status 1 "an inverted window is refused" \
  env GENERATE_MANIFEST_COMPATIBILITY_DOC="$doc" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"
expect_status 1 "a missing compatibility document is refused" \
  env GENERATE_MANIFEST_COMPATIBILITY_DOC="$work/no-such-doc.md" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"
out="$(GENERATE_MANIFEST_COMPATIBILITY_DOC="$(write_doc window-absent-again 'No marker.')" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist" 2>/dev/null || true)"
[[ -z "$out" ]] || fail "window case: a refused run must print no manifest at all"
echo "ok   a refused window produces no manifest"

# The node train (issue #275): ward-node-<version>-<arch>-linux.tar.gz is an
# artifact of the same release, recorded under its own component next to the
# runtime tarball's, with the same digest and architecture validation.
c="$(fresh_case node-train)"
add_artifact "$c/dist" x86_64
add_node_artifact "$c/dist" x86_64
out="$(bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist")"
[[ "$(jq -r '.artifacts | length' <<<"$out")" == "2" ]] || fail "node-train case: expected 2 artifacts"
node_entry="$(jq -c '.artifacts[] | select(.name == "ward-node-0.3.0-x86_64-linux.tar.gz")' <<<"$out")"
[[ -n "$node_entry" ]] || fail "node-train case: the node tarball is not in the manifest"
[[ "$(jq -r .component <<<"$node_entry")" == "ward-node" ]] || fail "node-train case: wrong component for the node tarball"
[[ "$(jq -r .architecture <<<"$node_entry")" == "x86_64" ]] || fail "node-train case: wrong architecture for the node tarball"
[[ "$(jq -r .digest <<<"$node_entry")" \
  == "sha256:$(sha256sum "$c/dist/ward-node-0.3.0-x86_64-linux.tar.gz" | awk '{print $1}')" ]] ||
  fail "node-train case: the node tarball's digest does not match its bytes"
[[ "$(jq -r '.artifacts[] | select(.name == "wardos-1.2.3-x86_64-linux.tar.gz") | .component' <<<"$out")" == "wardos" ]] ||
  fail "node-train case: the runtime tarball's component is not wardos"
[[ "$(jq -r .version <<<"$node_entry")" == "$node_version" ]] || fail "node-train case: the node tarball's version is not the node version"
[[ "$(jq -r '.artifacts[] | select(.name == "wardos-1.2.3-x86_64-linux.tar.gz") | .version' <<<"$out")" == "$version" ]] ||
  fail "node-train case: the runtime tarball's version is not the release version"
[[ "$(jq -c .components <<<"$out")" == "{\"wardos\":{\"version\":\"$version\"},\"ward-node\":{\"version\":\"$node_version\"}}" ]] ||
  fail "node-train case: components does not name both trains' versions"
echo "ok   the node tarball is recorded as its own component"

# The node train's version is its own (issue #275): a node tarball named by the
# release version is a leftover or a mislabelled build, and the node version must
# always be given and be SemVer.
c="$(fresh_case node-under-release-version)"
add_artifact "$c/dist" x86_64
printf 'node' >"$c/dist/ward-node-${version}-x86_64-linux.tar.gz"
(cd "$c/dist" && sha256sum "ward-node-${version}-x86_64-linux.tar.gz" >"ward-node-${version}-x86_64-linux.tar.gz.sha256")
expect_status 1 "a node tarball named by the release version is refused" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"
c="$(fresh_case node-version-default)"
add_artifact "$c/dist" x86_64
out="$(bash "$sut" "$tag" "$commit" "$c/dist")" || fail "node-version-default: refused"
[[ "$(jq -r '.components["ward-node"].version' <<<"$out")" == "$(bash "$RELEASE_DIR/node-version.sh" --root "$RELEASE_DIR/../..")" ]] ||
  fail "node-version-default: without --node-version the checkout's node version is not used"
echo "ok   without --node-version the checkout's node version is recorded"
expect_status 1 "a node version that is not SemVer is refused" bash "$sut" --node-version "v0.3.0" "$tag" "$commit" "$c/dist"

# A node tarball that no longer matches its sidecar is refused like any other.
c="$(fresh_case node-digest-mismatch)"
add_artifact "$c/dist" x86_64
add_node_artifact "$c/dist" x86_64
printf 'TAMPERED-NODE\n' >"$c/dist/ward-node-${node_version}-x86_64-linux.tar.gz"
expect_status 1 "a node tarball that no longer matches its own sidecar is refused" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"

### Rejections #################################################################

# Empty dist dir: no artifacts at all -> completeness failure.
c="$(fresh_case empty)"
expect_status 1 "empty dist dir is refused" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"

# Missing dist dir entirely.
expect_status 1 "missing dist dir is refused" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$work/does-not-exist"

# Malformed tag (not v<semver>).
c="$(fresh_case bad-tag)"
add_artifact "$c/dist" x86_64
expect_status 1 "malformed tag is refused" bash "$sut" --node-version "$node_version" "1.2.3" "$commit" "$c/dist"
expect_status 1 "tag with shell metacharacters is refused" \
  bash "$sut" --node-version "$node_version" 'v1.2.3; touch pwned' "$commit" "$c/dist"

# Malformed / short / symbolic commit.
expect_status 1 "short commit sha is refused" bash "$sut" --node-version "$node_version" "$tag" "abc123" "$c/dist"
expect_status 1 "symbolic ref instead of a commit sha is refused" bash "$sut" --node-version "$node_version" "$tag" "HEAD" "$c/dist"

# Artifact whose filename's version segment doesn't match the tag: a
# leftover artifact from a different release must not be folded in.
c="$(fresh_case wrong-version)"
printf 'BYTES\n' >"$c/dist/wardos-9.9.9-x86_64-linux.tar.gz"
(cd "$c/dist" && sha256sum wardos-9.9.9-x86_64-linux.tar.gz >wardos-9.9.9-x86_64-linux.tar.gz.sha256)
expect_status 1 "artifact naming a different version is refused" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"

# Missing checksum sidecar for an otherwise-valid tarball.
c="$(fresh_case missing-sidecar)"
printf 'BYTES\n' >"$c/dist/wardos-${version}-x86_64-linux.tar.gz"
expect_status 1 "artifact with no checksum sidecar is refused" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"

# Orphaned sidecar with no matching tarball.
c="$(fresh_case orphan-sidecar)"
add_artifact "$c/dist" x86_64
echo "deadbeef  wardos-${version}-aarch64-linux.tar.gz" >"$c/dist/wardos-${version}-aarch64-linux.tar.gz.sha256"
expect_status 1 "a checksum sidecar with no matching artifact is refused" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"

# Digest mismatch: the sidecar was not regenerated after the bytes changed --
# exactly the "one byte changed after download" acceptance case, but caught
# here at manifest-generation time against the sidecar the build itself wrote.
c="$(fresh_case digest-mismatch)"
add_artifact "$c/dist" x86_64
printf 'TAMPERED-BYTES\n' >"$c/dist/wardos-${version}-x86_64-linux.tar.gz"
expect_status 1 "a tarball that no longer matches its own sidecar is refused" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"

# Corrupt sidecar contents (not a valid hex digest).
c="$(fresh_case corrupt-sidecar)"
printf 'BYTES\n' >"$c/dist/wardos-${version}-x86_64-linux.tar.gz"
echo "not-a-digest" >"$c/dist/wardos-${version}-x86_64-linux.tar.gz.sha256"
expect_status 1 "a sidecar without a valid sha256 hex digest is refused" bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist"

# Image reference with embedded whitespace (would otherwise corrupt the field).
c="$(fresh_case bad-image-ref)"
add_artifact "$c/dist" x86_64
expect_status 1 "an image reference containing whitespace is refused" \
  bash "$sut" --node-version "$node_version" "$tag" "$commit" "$c/dist" "quay.io/hexrift/wardos:$tag extra"

echo "PASS generate-manifest.test.sh"
