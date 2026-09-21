#!/usr/bin/env bash
# Build the WardOS host image (image/Containerfile) with podman.
#
#   image/build.sh [--source release|checkout] [--release vX.Y.Z] [--arch x86_64|aarch64]
#                  [--tag NAME] [--version V] [--dev-seed-user NAME] [--dry-run]
#                  [-- extra podman build args]
#
# Defaults: --source release (the published tarball of --release, default the newest
# tag reachable from HEAD, else the Containerfile default; checksum fetched from the
# release and verified in the build);
# --source checkout compiles this working tree instead. --arch builds for another
# architecture (podman --platform, and the release tarball and checksum of that
# architecture; aarch64 tarballs exist from v0.3), the default being this machine's.
# Tag localhost/wardos:<git describe --tags --always>, version = the same describe
# string, passed in as --build-arg WARDOS_VERSION for the org.wardos.version label.
# --dev-seed-user NAME is the ONE development escape hatch (ADR-0027, NON-PRODUCTION): it
# passes --build-arg WARDOS_DEV_SEED_USER=NAME so wardos-dev-seed seeds that account (and
# marks the machine provisioned) at first boot; the password, if any, is delivered as a
# first-boot systemd credential, never baked in. Omit it for a production image, which
# ships unprovisioned. Run it as root (sudo) when the image is going to feed image/disk.sh,
# because bootc-image-builder reads root's container storage. See image/README.md.
set -euo pipefail

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

podman_bin=${PODMAN:-podman}
tag=""
version=""
source="release"
release=""
arch=""
dev_seed_user=""
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
    --arch) arch=$2; shift 2 ;;
    --arch=*) arch=${1#--arch=}; shift ;;
    --dev-seed-user) dev_seed_user=$2; shift 2 ;;
    --dev-seed-user=*) dev_seed_user=${1#--dev-seed-user=}; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    --) shift; extra=("$@"); break ;;
    *) echo "build.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# The dev-seed username (NON-PRODUCTION escape hatch) is baked into the image as the
# wardos-dev-seed flag file, so validate it here against the SAME conservative policy
# wardos-provisiond / wardos-dev-seed enforce, and refuse a reserved name — a build-time
# failure beats an image that quietly seeds nothing (or the wrong identity) at first boot.
if [[ -n "$dev_seed_user" ]]; then
  if [[ ! "$dev_seed_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    echo "build.sh: --dev-seed-user '$dev_seed_user' is not a valid username" >&2
    exit 2
  fi
  case "$dev_seed_user" in
    root | daemon | bin | sys | adm | nobody | nogroup | greeter | ward-provision)
      echo "build.sh: --dev-seed-user '$dev_seed_user' is a reserved name" >&2
      exit 2
      ;;
  esac
fi

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

# The architecture decides the platform podman builds for and which release tarball
# (and checksum build arg) the Containerfile's release stage takes. Without --arch the
# build is native and no --platform is passed: podman uses this machine's, and the
# Containerfile picks the tarball from TARGETARCH.
platform=()
case "$arch" in
  "") arch=$(uname -m) ;;
  x86_64) platform=(--platform linux/amd64) ;;
  aarch64) platform=(--platform linux/arm64) ;;
  *) echo "build.sh: --arch must be x86_64 or aarch64 (got '$arch')" >&2; exit 2 ;;
esac
sha_arg="WARDOS_SHA256"
if [[ "$arch" == aarch64 ]]; then sha_arg="WARDOS_SHA256_AARCH64"; fi

# --format docker: the Containerfile's SHELL (pipefail) is honoured; the OCI format
# ignores it, and bootc is happy with either.
cmd=("$podman_bin" build
  --format docker
  "${platform[@]}"
  --tag "$tag"
  --file image/Containerfile
  --build-arg "WARDOS_VERSION=${version}")
# NON-PRODUCTION dev escape hatch (ADR-0027): only when asked. Stage 2 of the Containerfile
# reads this regardless of --source, so it works for both checkout and release binaries.
if [[ -n "$dev_seed_user" ]]; then
  cmd+=(--build-arg "WARDOS_DEV_SEED_USER=${dev_seed_user}")
fi
case "$source" in
  release)
    if [[ -z "$release" ]]; then
      release=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)
    fi
    if [[ -z "$release" ]]; then
      # No tag reachable (shallow clone, fork without tags): fall back to the
      # Containerfile's own default, which is the release the image was last verified with.
      release=$(sed -n 's/^ARG WARDOS_RELEASE=\(v[0-9][^ ]*\)$/\1/p' image/Containerfile | head -n 1)
    fi
    if [[ -z "$release" ]]; then
      echo "build.sh: no release known; pass --release vX.Y.Z or --source checkout" >&2
      exit 1
    fi
    asset="wardos-${release#v}-${arch}-linux.tar.gz.sha256"
    sha=$(curl -fsSL "https://github.com/hexrift/WardOS/releases/download/${release}/${asset}" | awk '{print $1}') || true
    if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
      echo "build.sh: could not fetch the checksum for release ${release} (${asset})" >&2
      if [[ "$arch" == aarch64 ]]; then
        echo "build.sh: aarch64 tarballs ship from v0.3; for an older release use --source checkout" >&2
      fi
      exit 1
    fi
    cmd+=(--build-arg "WARDOS_SOURCE=release"
      --build-arg "WARDOS_RELEASE=${release}"
      --build-arg "${sha_arg}=${sha}")
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
