#!/usr/bin/env bash
# Refuse to publish an incomplete release (issue #275, ADR-0028 verification
# contract step 1: "the complete artifact set").
#
# Usage: check-release-set.sh <dist-dir> <version> <node-version> <required-arch>...
#
#   <dist-dir>        the assets this run is about to publish: every tarball and
#                     .sha256 sidecar the build jobs uploaded.
#   <version>         the release version without the leading v.
#   <node-version>    the node train's own version (node-version.sh), which names
#                     the node tarball.
#   <required-arch>   an architecture the release must carry; any further
#                     architecture found in <dist-dir> is accepted as long as its
#                     set is complete.
#
# A release carries two trains per architecture, each a tarball with its sidecar:
#
#   wardos-<version>-<arch>-linux.tar.gz           the runtime (package.sh)
#   ward-node-<node-version>-<arch>-linux.tar.gz   the node
#
# For every architecture that has any asset at all, both tarballs and both
# sidecars must be present; a build job that packaged one train and lost the
# other, or an upload that dropped a sidecar, would otherwise publish a release
# that install.sh or an operator cannot verify. Every *.tar.gz must match one of
# the two names above for this release (a misnamed artifact, a node tarball under
# the release version rather than the node's, or a leftover from another release
# is refused, never silently attached), every sidecar must name
# its own tarball and verify against its bytes, and every required architecture
# must be present.
#
# Exit codes:
#   0   the set is complete; what it holds is printed per architecture.
#   1   something is missing, misnamed, orphaned or does not verify.
set -euo pipefail

usage="usage: check-release-set.sh <dist-dir> <version> <node-version> <required-arch>..."
dist_dir="${1:?$usage}"
version="${2:?$usage}"
node_version="${3:?$usage}"
shift 3
[[ $# -ge 1 ]] || { echo "check-release-set: $usage" >&2; exit 1; }
required=("$@")

semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
[[ "$version" =~ $semver_re ]] || { echo "check-release-set: not a SemVer version: '$version'" >&2; exit 1; }
[[ "$node_version" =~ $semver_re ]] || { echo "check-release-set: not a SemVer node version: '$node_version'" >&2; exit 1; }

# Each train is named by its own version (issue #275).
trains=(wardos ward-node)
declare -A train_version=([wardos]="$version" [ward-node]="$node_version")
suffix="-linux.tar.gz"

[[ -d "$dist_dir" ]] || { echo "check-release-set: no such directory: '$dist_dir'" >&2; exit 1; }

shopt -s nullglob
tarballs=("$dist_dir"/*.tar.gz)
sidecars=("$dist_dir"/*.tar.gz.sha256)
shopt -u nullglob

problems=0
problem() {
  echo "check-release-set: $*" >&2
  problems=$((problems + 1))
}

[[ ${#tarballs[@]} -gt 0 ]] || problem "no tarball in '$dist_dir'"

# arches[ARCH]=1 for every architecture any asset names; have[NAME]=1 per tarball.
declare -A arches=() have=()
for path in "${tarballs[@]}"; do
  name="$(basename "$path")"
  have["$name"]=1
  # Matched by literal prefix and suffix, never a regex split: a prerelease
  # version carries hyphens of its own, so only the fixed prefix can delimit it.
  arch=""
  for train in "${trains[@]}"; do
    prefix="${train}-${train_version[$train]}-"
    if [[ "$name" == "$prefix"*"$suffix" ]]; then
      arch="${name#"$prefix"}"
      arch="${arch%"$suffix"}"
      break
    fi
  done
  if [[ -z "$arch" || ! "$arch" =~ ^[A-Za-z0-9_]+$ ]]; then
    problem "'$name' is not a tarball of this release (wardos-${version}-<arch>${suffix} or ward-node-${node_version}-<arch>${suffix})"
    continue
  fi
  arches["$arch"]=1
done

for path in "${sidecars[@]}"; do
  name="$(basename "$path")"
  tarball="${name%.sha256}"
  if [[ -z "${have[$tarball]:-}" ]]; then
    problem "sidecar '$name' has no tarball"
    continue
  fi
  # The second field is the file sha256sum will check; it must be this tarball,
  # not another one that happens to be present.
  named="$(awk '{print $2; exit}' "$path")"
  named="${named#\*}"
  if [[ "$named" != "$tarball" ]]; then
    problem "sidecar '$name' names '$named', not its own tarball"
    continue
  fi
  if ! (cd "$dist_dir" && sha256sum -c --status "$name"); then
    problem "'$tarball' does not match its sidecar"
  fi
done

for arch in "${required[@]}"; do
  [[ -n "${arches[$arch]:-}" ]] || problem "no asset for required architecture '$arch'"
done

for arch in $(printf '%s\n' "${!arches[@]}" | sort); do
  for train in "${trains[@]}"; do
    name="${train}-${train_version[$train]}-${arch}${suffix}"
    [[ -n "${have[$name]:-}" ]] || problem "architecture '$arch' has no '$name'"
    [[ -f "$dist_dir/$name.sha256" ]] || problem "architecture '$arch' has no '$name.sha256'"
  done
done

if [[ "$problems" -gt 0 ]]; then
  echo "check-release-set: refusing to publish an incomplete release ($problems problem(s))." >&2
  exit 1
fi

for arch in $(printf '%s\n' "${!arches[@]}" | sort); do
  for train in "${trains[@]}"; do
    echo "check-release-set: $arch: ${train}-${train_version[$train]}-${arch}${suffix} (+ .sha256)"
  done
done
echo "check-release-set: OK -- ${#arches[@]} architecture(s), both trains each (wardos ${version}, ward-node ${node_version}), every sidecar verified."
