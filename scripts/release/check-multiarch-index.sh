#!/usr/bin/env bash
# Validate that an image index actually names both platforms WardOS publishes
# for (issue #149): `needs: [build, build-aarch64]` only proves both jobs
# succeeded, not that `docker buildx imagetools create` actually wove both
# children into the index it just built -- this reads the index's own
# manifest list instead of trusting that.
#
# Usage: check-multiarch-index.sh <raw-index-json>
set -euo pipefail

index="${1:?usage: check-multiarch-index.sh <raw-index-json>}"
if [[ ! -f "$index" ]]; then
  echo "check-multiarch-index: no such file: '$index'" >&2
  exit 1
fi

has_platform() {
  jq -e --arg arch "$1" \
    '[.manifests[]? | select(.platform.os == "linux" and .platform.architecture == $arch)] | length >= 1' \
    "$index" >/dev/null
}

ok=1
has_platform amd64 || { echo "check-multiarch-index: no linux/amd64 manifest in the index" >&2; ok=0; }
has_platform arm64 || { echo "check-multiarch-index: no linux/arm64 manifest in the index" >&2; ok=0; }

if [[ "$ok" != 1 ]]; then
  exit 1
fi
echo "check-multiarch-index: OK -- both linux/amd64 and linux/arm64 present"
