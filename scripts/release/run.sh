#!/usr/bin/env bash
# Release-helper test runner: syntax-check and shellcheck every script under
# scripts/release, then run every *.test.sh here. Mirrors desktop/tests/run.sh.
# Each test is a bash script that exits non-zero on failure.
set -euo pipefail

cd "$(dirname "$0")/../.."

scripts=()
for f in scripts/release/*.sh; do
  [[ -f "$f" ]] && scripts+=("$f")
done
if [[ ${#scripts[@]} -gt 0 ]]; then
  bash -n "${scripts[@]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck --severity=style "${scripts[@]}"
  else
    echo "run.sh: shellcheck not installed; syntax check only" >&2
  fi
fi

status=0
for t in scripts/release/*.test.sh; do
  [[ -f "$t" ]] || continue
  if bash "$t"; then
    echo "ok   $t"
  else
    echo "FAIL $t"
    status=1
  fi
done
exit $status
