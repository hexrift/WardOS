#!/usr/bin/env bash
# Protected verification entry point for the WardOS repository.
# Deliberately boring. Every step is a plain, well-known command.
# See docs/development-under-tamperward.md.
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ -f Cargo.toml ]]; then
  # A clean checkout must be buildable with --locked. Ordinary cargo fmt/clippy/test
  # may update a stale lockfile in the writable CI checkout and hide a workspace
  # version mismatch (issue #281), so make lock consistency an explicit merge gate.
  cargo metadata --locked --no-deps --format-version 1 >/dev/null

  cargo fmt --all -- --check

  cargo clippy \
    --workspace \
    --all-targets \
    --all-features \
    -- \
    -D warnings

  cargo test \
    --workspace \
    --all-targets \
    --all-features
else
  echo "verify: no Cargo workspace yet (Phase 0); skipping Rust checks"
fi

./scripts/security-check/static.sh
./scripts/security-check/tamperward-integration.sh
