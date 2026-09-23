#!/usr/bin/env bash
# Promote a validated, digest-addressed image index to `latest`, unless a
# newer commit has already landed on main (issue #149). This is the only
# place in the manifest job that ever writes the shared `latest` tag, and it
# writes it exactly once, as its last action: a run whose commit has been
# superseded returns before invoking docker at all, so `latest` is either
# written once, correctly, or not touched. Promoting by digest
# (`repo@sha256:...`), rather than by re-deriving from the mutable
# per-architecture tags or even the mutable `<sha>` tag, means a retry that
# rebuilds and republishes those tags under the hood can never make this
# promote a different index than the one this run actually validated
# earlier in the same job.
#
# Usage: promote-latest.sh <repo> <digest> <building-sha> <main-tip-sha>
# The DOCKER environment variable names the docker binary to invoke (tests
# override it with a stub); it defaults to "docker".
#
# PROMOTE_LATEST_BARRIER_DIR is a test-only seam (never set by the real
# workflow): if set, this script signals readiness by creating
# "$dir/ready" and then blocks reading "$dir/go" immediately before the one
# command that can write `latest`. A test can therefore start this script,
# wait for "$dir/ready" to exist -- a deterministic rendezvous, not a sleep
# race -- kill it while it is blocked there, and know with certainty that
# no promotion command ran. This is #149's "cancellation before promotion"
# acceptance case made concrete rather than just structurally argued.
set -euo pipefail

repo="${1:?usage: promote-latest.sh <repo> <digest> <building-sha> <main-tip-sha>}"
digest="${2:?usage: promote-latest.sh <repo> <digest> <building-sha> <main-tip-sha>}"
building="${3:?usage: promote-latest.sh <repo> <digest> <building-sha> <main-tip-sha>}"
tip="${4:?usage: promote-latest.sh <repo> <digest> <building-sha> <main-tip-sha>}"
docker_bin="${DOCKER:-docker}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! bash "$script_dir/check-not-stale.sh" "$building" "$tip"; then
  echo "promote-latest: skipping promotion (see above)."
  exit 0
fi

if [ -n "${PROMOTE_LATEST_BARRIER_DIR:-}" ]; then
  : >"$PROMOTE_LATEST_BARRIER_DIR/ready"
  read -r _ <"$PROMOTE_LATEST_BARRIER_DIR/go" || true
fi

"$docker_bin" buildx imagetools create -t "$repo:latest" "$repo@$digest"
"$docker_bin" buildx imagetools inspect "$repo:latest"
