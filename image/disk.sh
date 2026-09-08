#!/usr/bin/env bash
# Turn a built WardOS image into a bootable disk with bootc-image-builder.
#
#   image/disk.sh --type qcow2|iso [--image NAME] [--output DIR] [--rootfs FS]
#                 [--config FILE] [--dry-run]
#
# Defaults: image localhost/wardos:<git describe --tags --always>, output ./image/out,
# rootfs btrfs (ADR-0001). --config passes a bootc-image-builder TOML (users, disk
# layout) into the builder. Must run as root: the builder is a privileged container that
# reads root's container storage and writes the disk image. See image/README.md.
set -euo pipefail

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

podman_bin=${PODMAN:-podman}
# Pinned builder image; bump deliberately (image/README.md, "bootc-image-builder").
builder=${BOOTC_IMAGE_BUILDER:-quay.io/centos-bootc/bootc-image-builder:latest}
type=""
image=""
output="$repo_root/image/out"
rootfs="btrfs"
config=""
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type) type=$2; shift 2 ;;
    --type=*) type=${1#--type=}; shift ;;
    --image) image=$2; shift 2 ;;
    --image=*) image=${1#--image=}; shift ;;
    --output) output=$2; shift 2 ;;
    --output=*) output=${1#--output=}; shift ;;
    --rootfs) rootfs=$2; shift 2 ;;
    --rootfs=*) rootfs=${1#--rootfs=}; shift ;;
    --config) config=$2; shift 2 ;;
    --config=*) config=${1#--config=}; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "disk.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$type" in
  qcow2 | iso) ;;
  "") echo "disk.sh: --type qcow2|iso is required" >&2; exit 2 ;;
  *) echo "disk.sh: unsupported --type '$type' (qcow2 or iso)" >&2; exit 2 ;;
esac

if [[ -z "$image" ]]; then
  image="localhost/wardos:$(git describe --tags --always 2>/dev/null || echo dev)"
fi

if [[ -n "$config" && ! -f "$config" ]]; then
  echo "disk.sh: config file not found: $config" >&2
  exit 1
fi

cmd=("$podman_bin" run --rm -it
  --privileged
  --security-opt label=type:unconfined_t
  --volume "${output}:/output"
  --volume /var/lib/containers/storage:/var/lib/containers/storage)
if [[ -n "$config" ]]; then
  cmd+=(--volume "$(realpath "$config"):/config.toml:ro")
fi
cmd+=("$builder"
  --type "$type"
  --rootfs "$rootfs")
if [[ -n "$config" ]]; then
  cmd+=(--config /config.toml)
fi
cmd+=("$image")

printf 'disk.sh: would run (output in %s):\n  mkdir -p %q\n  ' "$output" "$output"
printf '%q ' "${cmd[@]}"
printf '\n'

if [[ $dry_run -eq 1 ]]; then
  exit 0
fi

if ! command -v "$podman_bin" >/dev/null 2>&1; then
  echo "disk.sh: $podman_bin is not installed; install podman or re-run with --dry-run" >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "disk.sh: bootc-image-builder needs root (sudo $0 ...)" >&2
  exit 1
fi
if ! "$podman_bin" image exists "$image"; then
  echo "disk.sh: image $image is not in root's container storage; run sudo image/build.sh first" >&2
  exit 1
fi

mkdir -p "$output"
exec "${cmd[@]}"
