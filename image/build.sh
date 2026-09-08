#!/usr/bin/env bash
# Build the WardOS host image (image/Containerfile) with podman.
#
#   image/build.sh [--tag NAME] [--version V] [--dry-run] [-- extra podman build args]
#
# Defaults: tag localhost/wardos:<git describe --tags --always>, version = the same
# describe string, passed in as --build-arg WARDOS_VERSION so the image carries it in
# its org.wardos.version label. Run it as root (sudo) when the image is going to feed
# image/disk.sh, because bootc-image-builder reads root's container storage.
# See image/README.md.
set -euo pipefail

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

podman_bin=${PODMAN:-podman}
tag=""
version=""
dry_run=0
extra=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag=$2; shift 2 ;;
    --tag=*) tag=${1#--tag=}; shift ;;
    --version) version=$2; shift 2 ;;
    --version=*) version=${1#--version=}; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    --) shift; extra=("$@"); break ;;
    *) echo "build.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$version" ]]; then
  version=$(git describe --tags --always 2>/dev/null || echo dev)
fi
if [[ -z "$tag" ]]; then
  tag="localhost/wardos:${version}"
fi

if [[ ! -f image/Containerfile ]]; then
  echo "build.sh: image/Containerfile not found under $repo_root" >&2
  exit 1
fi

cmd=("$podman_bin" build
  --tag "$tag"
  --file image/Containerfile
  --build-arg "WARDOS_VERSION=${version}")
if [[ ${#extra[@]} -gt 0 ]]; then
  cmd+=("${extra[@]}")
fi
cmd+=(.)

printf 'build.sh: would run (from %s):\n  ' "$repo_root"
printf '%q ' "${cmd[@]}"
printf '\n'

if [[ $dry_run -eq 1 ]]; then
  exit 0
fi

if ! command -v "$podman_bin" >/dev/null 2>&1; then
  echo "build.sh: $podman_bin is not installed; install podman or re-run with --dry-run" >&2
  exit 1
fi

exec "${cmd[@]}"
