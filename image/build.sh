#!/usr/bin/env bash
# Build the WardOS host image (image/Containerfile) with podman.
#
#   image/build.sh [--source release|checkout] [--release vX.Y.Z] [--tag NAME]
#                  [--version V] [--dry-run] [-- extra podman build args]
#
# Defaults: --source release (the published tarball of --release, default the newest
# tag reachable from HEAD, checksum fetched from the release and verified in the build);
# --source checkout compiles this working tree instead. Tag localhost/wardos:<git
# describe --tags --always>, version = the same describe string, passed in as
# --build-arg WARDOS_VERSION for the org.wardos.version label. Run it as root (sudo)
# when the image is going to feed image/disk.sh, because bootc-image-builder reads
# root's container storage. See image/README.md.
set -euo pipefail

usage() {
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

podman_bin=${PODMAN:-podman}
tag=""
version=""
source="release"
release=""
dry_run=0
extra=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag=$2; shift 2 ;;
    --tag=*) tag=${1#--tag=}; shift ;;
    --version) version=$2; shift 2 ;;
    --version=*) version=${1#--version=}; shift ;;
    --source) source=$2; shift 2 ;;
    --source=*) source=${1#--source=}; shift ;;
    --release) release=$2; shift 2 ;;
    --release=*) release=${1#--release=}; shift ;;
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
case "$source" in
  release)
    if [[ -z "$release" ]]; then
      release=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)
    fi
    if [[ -z "$release" ]]; then
      echo "build.sh: no v* tag reachable; pass --release vX.Y.Z or --source checkout" >&2
      exit 1
    fi
    asset="wardos-${release#v}-x86_64-linux.tar.gz.sha256"
    sha=$(curl -fsSL "https://github.com/hexrift/WardOS/releases/download/${release}/${asset}" | awk '{print $1}') || true
    if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
      echo "build.sh: could not fetch the checksum for release ${release}" >&2
      exit 1
    fi
    cmd+=(--build-arg "WARDOS_SOURCE=release"
      --build-arg "WARDOS_RELEASE=${release}"
      --build-arg "WARDOS_SHA256=${sha}")
    ;;
  checkout)
    cmd+=(--build-arg "WARDOS_SOURCE=builder")
    ;;
  *)
    echo "build.sh: --source must be release or checkout" >&2
    exit 2
    ;;
esac
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
