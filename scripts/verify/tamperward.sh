#!/usr/bin/env bash
# Protected verification entry point for the WardOS repository.
# Deliberately boring. Every step is a plain, well-known command.
# See docs/development-under-tamperward.md.
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ -f Cargo.toml ]]; then
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
