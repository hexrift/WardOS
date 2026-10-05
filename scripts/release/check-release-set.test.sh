#!/usr/bin/env bash
# Regressions for check-release-set.sh (issue #275): a release is published only
# with the complete set of both trains for every architecture it carries. A
# missing or misnamed node tarball, a missing or wrong sidecar, and a leftover
# from another version are each refused before `gh release create` runs.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/check-release-set.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

version="1.2.3"
node_version="0.3.0"

# fresh_case NAME -> makes $work/NAME/dist and echoes the case dir.
fresh_case() {
  local dir="$work/$1"
  mkdir -p "$dir/dist"
  printf '%s' "$dir"
}

# add_asset DIST NAME [BYTES] -> a tarball NAME.tar.gz with its matching sidecar.
add_asset() {
  local dist="$1" name="$2" bytes="${3:-payload-$2}"
  printf '%s' "$bytes" >"$dist/$name.tar.gz"
  (cd "$dist" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
}

# add_arch DIST ARCH -> both trains for one architecture.
add_arch() {
  add_asset "$1" "wardos-${version}-$2-linux"
  add_asset "$1" "ward-node-${node_version}-$2-linux"
}

### Complete sets ###############################################################

c="$(fresh_case one-arch)"
add_arch "$c/dist" x86_64
expect_status 0 "both trains for the required arch pass" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

c="$(fresh_case two-arches)"
add_arch "$c/dist" x86_64
add_arch "$c/dist" aarch64
expect_status 0 "a second complete arch beyond the required one passes" bash "$sut" "$c/dist" "$version" "$node_version" x86_64
expect_status 0 "both arches may be required" bash "$sut" "$c/dist" "$version" "$node_version" x86_64 aarch64

# The accepted set is reported by train and arch, so the release log says what shipped.
out="$(bash "$sut" "$c/dist" "$version" "$node_version" x86_64)"
grep -q "ward-node-${node_version}-aarch64-linux.tar.gz" <<<"$out" || fail "two-arches: the node tarball is not reported"
grep -q "wardos-${version}-x86_64-linux.tar.gz" <<<"$out" || fail "two-arches: the runtime tarball is not reported"
echo "ok   the accepted set is reported"

### The node train is required, not optional ####################################

c="$(fresh_case node-missing)"
add_asset "$c/dist" "wardos-${version}-x86_64-linux"
expect_status 1 "a runtime tarball without its node tarball is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

c="$(fresh_case runtime-missing)"
add_asset "$c/dist" "ward-node-${node_version}-x86_64-linux"
expect_status 1 "a node tarball without its runtime tarball is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

# A second arch that built only one train is incomplete even though it is not required.
c="$(fresh_case aarch64-partial)"
add_arch "$c/dist" x86_64
add_asset "$c/dist" "wardos-${version}-aarch64-linux"
expect_status 1 "an optional arch with only the runtime tarball is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

c="$(fresh_case required-arch-absent)"
add_arch "$c/dist" aarch64
expect_status 1 "a required arch with no assets at all is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

### Names ######################################################################

c="$(fresh_case misnamed-node)"
add_asset "$c/dist" "wardos-${version}-x86_64-linux"
add_asset "$c/dist" "wardnode-${version}-x86_64-linux"
expect_status 1 "a node tarball under another prefix is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

c="$(fresh_case node-without-linux-suffix)"
add_asset "$c/dist" "wardos-${version}-x86_64-linux"
add_asset "$c/dist" "ward-node-${node_version}-x86_64"
expect_status 1 "a node tarball without the -linux suffix is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

c="$(fresh_case other-version)"
add_arch "$c/dist" x86_64
add_asset "$c/dist" "ward-node-9.9.9-x86_64-linux"
expect_status 1 "an artifact of another version in dist is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

c="$(fresh_case prerelease)"
add_asset "$c/dist" "wardos-1.2.3-rc.1-x86_64-linux"
add_asset "$c/dist" "ward-node-0.3.0-rc.1-x86_64-linux"
expect_status 0 "a prerelease version with its own hyphen is parsed by prefix" bash "$sut" "$c/dist" "1.2.3-rc.1" "0.3.0-rc.1" x86_64

# The node train has its own version (issue #275): a node tarball named with the
# release version is not this release's node tarball.
c="$(fresh_case node-under-release-version)"
add_asset "$c/dist" "wardos-${version}-x86_64-linux"
add_asset "$c/dist" "ward-node-${version}-x86_64-linux"
expect_status 1 "a node tarball named by the release version instead of the node version is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64
expect_status 1 "a node version that is not SemVer is a usage error" bash "$sut" "$c/dist" "$version" "v0.3.0" x86_64

### Sidecars ####################################################################

c="$(fresh_case node-sidecar-missing)"
add_arch "$c/dist" x86_64
rm "$c/dist/ward-node-${node_version}-x86_64-linux.tar.gz.sha256"
expect_status 1 "a node tarball without its sidecar is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

c="$(fresh_case orphan-sidecar)"
add_arch "$c/dist" x86_64
echo "deadbeef  ward-node-${node_version}-aarch64-linux.tar.gz" >"$c/dist/ward-node-${node_version}-aarch64-linux.tar.gz.sha256"
expect_status 1 "a sidecar without its tarball is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

c="$(fresh_case digest-mismatch)"
add_arch "$c/dist" x86_64
printf 'OTHER-BYTES' >"$c/dist/ward-node-${node_version}-x86_64-linux.tar.gz"
expect_status 1 "a node tarball that does not match its sidecar is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

c="$(fresh_case sidecar-names-other-file)"
add_arch "$c/dist" x86_64
cp "$c/dist/wardos-${version}-x86_64-linux.tar.gz.sha256" "$c/dist/ward-node-${node_version}-x86_64-linux.tar.gz.sha256"
expect_status 1 "a sidecar that names another tarball is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64

### Guardrails ##################################################################

c="$(fresh_case empty)"
expect_status 1 "an empty dist dir is refused" bash "$sut" "$c/dist" "$version" "$node_version" x86_64
expect_status 1 "a missing dist dir is refused" bash "$sut" "$work/does-not-exist" "$version" "$node_version" x86_64
expect_status 1 "no required arch is a usage error" bash "$sut" "$c/dist" "$version" "$node_version"

echo "PASS check-release-set.test.sh"
