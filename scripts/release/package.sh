#!/usr/bin/env bash
# Package one architecture's release build into its two trains (issue #275).
#
# Usage: package.sh <version> <arch> <bin-dir> <dist-dir> [source-root]
#
#   <version>      the release version without the leading v (what check-version.sh
#                  bound the tag to).
#   <arch>         the runner's `uname -m`; install.sh and the image's release stage
#                  pick a tarball by it.
#   <bin-dir>      where cargo put the release binaries (target/release).
#   <dist-dir>     where the tarballs, their .sha256 sidecars and the unpacked
#                  directories the smoke step runs are written.
#   [source-root]  the checkout the installer, README, LICENSE and docs/ come from
#                  (default: the current directory).
#
# Two tarballs, one checksum sidecar each, both named <train>-<version>-<arch>-linux:
#
#   wardos-…     the runtime: ward, wardd, ward-agent, ward-shell and
#                wardos-theme-render (the five the image's release stage expects,
#                image/Containerfile; tarballs before v0.2 carried only the first
#                three), install.sh, README.md, LICENSE and a copy of docs/.
#   ward-node-…  the node: ward-node and ward-node-adapter, LICENSE and the same
#                copy of docs/. No installer: the node is an operator install
#                (docs/node-integration-guide.md §1), not part of install.sh; the
#                image's release stage installs the two binaries from this tarball.
#
# The sidecar is sha256sum's own line for the tarball, written next to it, so
# `sha256sum -c <name>.tar.gz.sha256` verifies it wherever both are downloaded.
# Every input file is checked before anything is written: a build that lacks a
# binary fails here, with the name, instead of shipping a tarball without it.
set -euo pipefail

version="${1:?usage: package.sh <version> <arch> <bin-dir> <dist-dir> [source-root]}"
arch="${2:?usage: package.sh <version> <arch> <bin-dir> <dist-dir> [source-root]}"
bin_dir="${3:?usage: package.sh <version> <arch> <bin-dir> <dist-dir> [source-root]}"
dist_dir="${4:?usage: package.sh <version> <arch> <bin-dir> <dist-dir> [source-root]}"
source_root="${5:-.}"

die() {
  echo "package: $*" >&2
  exit 1
}

# The same SemVer grammar as check-version.sh, without the leading v: the version
# becomes part of two asset names and must never carry a path or shell character.
semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
[[ "$version" =~ $semver_re ]] || die "not a SemVer version (without the leading v): '$version'"
[[ "$arch" =~ ^[A-Za-z0-9_]+$ ]] || die "not an architecture name: '$arch'"
[[ -d "$bin_dir" ]] || die "no such binary directory: '$bin_dir'"
[[ -d "$source_root" ]] || die "no such source root: '$source_root'"

runtime_binaries=(ward wardd ward-agent ward-shell wardos-theme-render)
node_binaries=(ward-node ward-node-adapter)
runtime_files=(install.sh README.md LICENSE)
node_files=(LICENSE)

for bin in "${runtime_binaries[@]}" "${node_binaries[@]}"; do
  [[ -f "$bin_dir/$bin" ]] || die "the build has no '$bin' in '$bin_dir'; refusing to package without it"
done
for f in "${runtime_files[@]}" "${node_files[@]}"; do
  [[ -f "$source_root/$f" ]] || die "no '$f' in '$source_root'"
done
[[ -d "$source_root/docs" ]] || die "no 'docs/' in '$source_root'"

# package_train NAME BINARIES... -- FILES...
# Stages NAME/ under dist, tars it, and writes the sidecar in dist by name.
package_train() {
  local name="$1"
  shift
  local stage="$dist_dir/$name"
  mkdir -p "$stage"
  while [[ $# -gt 0 && "$1" != "--" ]]; do
    cp "$bin_dir/$1" "$stage/"
    shift
  done
  shift
  for f in "$@"; do
    cp "$source_root/$f" "$stage/"
  done
  cp -r "$source_root/docs" "$stage/docs"
  tar -C "$dist_dir" -czf "$dist_dir/$name.tar.gz" "$name"
  (cd "$dist_dir" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
  echo "package: wrote $name.tar.gz and its .sha256"
}

mkdir -p "$dist_dir"
package_train "wardos-${version}-${arch}-linux" "${runtime_binaries[@]}" -- "${runtime_files[@]}"
package_train "ward-node-${version}-${arch}-linux" "${node_binaries[@]}" -- "${node_files[@]}"
