#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is unavailable; start Docker Desktop and retry." >&2
  exit 1
fi

image="ward-node-docker-preflight:$(date +%s)-$$"
context="$(mktemp -d)"
cleanup() {
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf -- "$context"
}
trap cleanup EXIT

cat >"$context/Dockerfile" <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bubblewrap \
  && useradd --create-home ward \
  && rm -rf /var/lib/apt/lists/*
USER ward
CMD ["bwrap", "--unshare-all", "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--", "/bin/true"]
DOCKERFILE

docker build --tag "$image" "$context"
docker run --rm "$image"
echo "container Bubblewrap preflight: PASS"
