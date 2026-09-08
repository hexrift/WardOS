#!/usr/bin/env bash
# E-02: run the snapshot performance harness and keep the raw output out of git.
# Usage: experiments/E-02/run.sh [harness args...]   (see the example's doc comment)
set -euo pipefail

cd "$(dirname "$0")/../.."

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p experiments/E-02/results
exec cargo run --release -p ward-snapshot --example e02_snapshot_perf -- \
  --dir "${TMPDIR:-/tmp}/ward-e02" \
  --out "experiments/E-02/results/run-${stamp}.raw" \
  "$@"
