#!/usr/bin/env bash
# TamperWard integration check.
# Phase 0: confirms the repository TamperWard configuration exists and is well-formed
# enough to parse as YAML. From Phase 3 this runs integration/tamperward/tests.
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ ! -s .tamperward.yml ]]; then
  echo "tamperward-integration: .tamperward.yml missing" >&2
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY'
import sys
try:
    import yaml  # type: ignore
except ImportError:
    print("tamperward-integration: PyYAML not available; syntax check skipped")
    sys.exit(0)
with open(".tamperward.yml", "r", encoding="utf-8") as fh:
    data = yaml.safe_load(fh)
for key in ("version", "protected", "rules", "verify"):
    if key not in data:
        print(f"tamperward-integration: missing top-level key {key!r}", file=sys.stderr)
        sys.exit(1)
print("tamperward-integration: PASS")
PY
else
  echo "tamperward-integration: python3 not available; syntax check skipped"
fi

if [[ -d integration/tamperward/tests ]]; then
  echo "tamperward-integration: integration tests present; run them via cargo test (Phase 3+)"
fi
