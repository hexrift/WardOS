#!/usr/bin/env bash
# Regressions for package.sh (issue #275): one release build packages two trains,
# the runtime tarball (what install.sh and the image's release stage expect) and
# the node tarball, each with the sidecar check-assets.sh and check-release-set.sh
# bind to its bytes; a missing binary fails the step instead of shipping a tarball
# without it.
# shellcheck source=scripts/release/testlib.sh
source "$(dirname "$0")/testlib.sh"

sut="$RELEASE_DIR/package.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

version="1.2.3"
node_version="0.3.0"
arch="x86_64"
runtime="wardos-${version}-${arch}-linux"
node="ward-node-${node_version}-${arch}-linux"

# fresh_case NAME -> a case dir with a complete fake build: every binary the two
# trains ship under bin/, and the repository files the tarballs carry under src/.
fresh_case() {
  local dir="$work/$1" bin
  mkdir -p "$dir/bin" "$dir/src/docs/decisions" "$dir/dist"
  for bin in ward wardd ward-agent ward-shell wardos-theme-render ward-node ward-node-adapter; do
    printf '#!/bin/sh\necho %s\n' "$bin" >"$dir/bin/$bin"
    chmod +x "$dir/bin/$bin"
  done
  printf 'installer\n' >"$dir/src/install.sh"
  printf 'readme\n' >"$dir/src/README.md"
  printf 'license\n' >"$dir/src/LICENSE"
  printf 'guide\n' >"$dir/src/docs/node-integration-guide.md"
  printf 'adr\n' >"$dir/src/docs/decisions/ADR-0001.md"
  printf '%s' "$dir"
}

# listing TARBALL -> the sorted member paths of a tarball.
listing() { tar -tzf "$1" | sed 's#/$##' | sort; }

### Both trains are packaged from one build #####################################

c="$(fresh_case complete)"
expect_status 0 "a complete build packages both trains" \
  bash "$sut" "$version" "$node_version" "$arch" "$c/bin" "$c/dist" "$c/src"

for name in "$runtime" "$node"; do
  [[ -f "$c/dist/$name.tar.gz" ]] || fail "complete: $name.tar.gz was not written"
  [[ -f "$c/dist/$name.tar.gz.sha256" ]] || fail "complete: $name.tar.gz.sha256 was not written"
  [[ -d "$c/dist/$name" ]] || fail "complete: the unpacked $name directory the smoke step runs is missing"
  # The sidecar is sha256sum's own line for exactly that tarball, verifiable where
  # the release's consumers verify it: next to the tarball, by name.
  (cd "$c/dist" && sha256sum -c --status "$name.tar.gz.sha256") || fail "complete: $name.tar.gz.sha256 does not verify"
  [[ "$(awk '{print $2}' "$c/dist/$name.tar.gz.sha256")" == "$name.tar.gz" ]] ||
    fail "complete: $name.tar.gz.sha256 names something other than its tarball"
done
echo "ok   both tarballs carry a verifiable sidecar"

# The runtime tarball: the five binaries the image's release stage expects, the
# installer, README, LICENSE and docs/ -- exactly what release.yml shipped before.
want="$(printf '%s\n' \
  "$runtime" "$runtime/ward" "$runtime/wardd" "$runtime/ward-agent" "$runtime/ward-shell" \
  "$runtime/wardos-theme-render" "$runtime/install.sh" "$runtime/README.md" "$runtime/LICENSE" \
  "$runtime/docs" "$runtime/docs/node-integration-guide.md" "$runtime/docs/decisions" \
  "$runtime/docs/decisions/ADR-0001.md" | sort)"
[[ "$(listing "$c/dist/$runtime.tar.gz")" == "$want" ]] ||
  fail "runtime tarball layout differs:
$(diff <(printf '%s\n' "$want") <(listing "$c/dist/$runtime.tar.gz") || true)"
echo "ok   the runtime tarball carries the five binaries, install.sh, README.md, LICENSE and docs/"

# The node tarball: the node, the adapter, the ward-agent shim a node names with
# --agent-shim (issue #427, ADR-0037), LICENSE and docs/ -- no installer (the node is
# an operator install, node-integration-guide.md §1) and no other runtime binary.
want="$(printf '%s\n' \
  "$node" "$node/ward-node" "$node/ward-node-adapter" "$node/ward-agent" "$node/LICENSE" \
  "$node/docs" "$node/docs/node-integration-guide.md" "$node/docs/decisions" \
  "$node/docs/decisions/ADR-0001.md" | sort)"
[[ "$(listing "$c/dist/$node.tar.gz")" == "$want" ]] ||
  fail "node tarball layout differs:
$(diff <(printf '%s\n' "$want") <(listing "$c/dist/$node.tar.gz") || true)"
echo "ok   the node tarball carries ward-node, ward-node-adapter, ward-agent, LICENSE and docs/"

# The packaged binaries are the built ones, executable, under their own names.
mkdir -p "$c/unpack" && tar -C "$c/unpack" -xzf "$c/dist/$node.tar.gz"
[[ "$("$c/unpack/$node/ward-node-adapter")" == "ward-node-adapter" ]] ||
  fail "node tarball: ward-node-adapter is not the built binary"
cmp -s "$c/bin/ward-node" "$c/unpack/$node/ward-node" || fail "node tarball: ward-node differs from the built binary"
# The shim is the same build the runtime tarball carries, executable as shipped: the
# node refuses a shim its owner may not execute.
cmp -s "$c/bin/ward-agent" "$c/unpack/$node/ward-agent" || fail "node tarball: ward-agent differs from the built binary"
[[ -f "$c/unpack/$node/ward-agent" && ! -L "$c/unpack/$node/ward-agent" && -x "$c/unpack/$node/ward-agent" ]] ||
  fail "node tarball: ward-agent is not an executable regular file"
echo "ok   the node tarball's binaries are the built ones"

# The two trains carry their own versions (issue #275): the node tarball is named by
# the node version, never by the release's.
[[ ! -e "$c/dist/ward-node-${version}-${arch}-linux.tar.gz" ]] ||
  fail "complete: a node tarball was written under the release version"
echo "ok   the node tarball is named by the node version"

# The two trains together are exactly what check-release-set.sh accepts for the arch.
expect_status 0 "the packaged set satisfies check-release-set.sh" \
  bash "$RELEASE_DIR/check-release-set.sh" "$c/dist" "$version" "$node_version" "$arch"

### A build missing a binary fails before any tarball is written ################

c="$(fresh_case no-node)"
rm "$c/bin/ward-node"
expect_status 1 "a build without ward-node is refused" \
  bash "$sut" "$version" "$node_version" "$arch" "$c/bin" "$c/dist" "$c/src"
[[ -z "$(ls -A "$c/dist")" ]] || fail "no-node: something was written to dist despite the refusal"

c="$(fresh_case no-adapter)"
rm "$c/bin/ward-node-adapter"
expect_status 1 "a build without ward-node-adapter is refused" \
  bash "$sut" "$version" "$node_version" "$arch" "$c/bin" "$c/dist" "$c/src"

# The shim is part of the node train (issue #427): a build without it ships neither.
c="$(fresh_case no-shim)"
rm "$c/bin/ward-agent"
expect_status 1 "a build without ward-agent is refused" \
  bash "$sut" "$version" "$node_version" "$arch" "$c/bin" "$c/dist" "$c/src"
[[ -z "$(ls -A "$c/dist")" ]] || fail "no-shim: something was written to dist despite the refusal"

c="$(fresh_case no-ward)"
rm "$c/bin/ward"
expect_status 1 "a build without ward is refused" \
  bash "$sut" "$version" "$node_version" "$arch" "$c/bin" "$c/dist" "$c/src"
[[ -z "$(ls -A "$c/dist")" ]] || fail "no-ward: something was written to dist despite the refusal"

c="$(fresh_case no-license)"
rm "$c/src/LICENSE"
expect_status 1 "a source tree without LICENSE is refused" \
  bash "$sut" "$version" "$node_version" "$arch" "$c/bin" "$c/dist" "$c/src"

# Guardrails: a malformed version or arch never becomes part of an asset name.
c="$(fresh_case bad-version)"
expect_status 1 "a non-semver version is refused" \
  bash "$sut" "v1.2.3" "$node_version" "$arch" "$c/bin" "$c/dist" "$c/src"
expect_status 1 "a non-semver node version is refused" \
  bash "$sut" "$version" "v0.3.0" "$arch" "$c/bin" "$c/dist" "$c/src"
expect_status 1 "an arch with path characters is refused" \
  bash "$sut" "$version" "$node_version" "../x" "$c/bin" "$c/dist" "$c/src"
expect_status 1 "a missing bin dir is refused" \
  bash "$sut" "$version" "$node_version" "$arch" "$work/does-not-exist" "$c/dist" "$c/src"

echo "PASS package.test.sh"
