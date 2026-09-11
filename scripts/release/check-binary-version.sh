#!/usr/bin/env bash
# Assert a packaged binary reports the version the release claims (issue #126).
#
# Usage: check-binary-version.sh <expected-version> <command> [args...]
#
# Runs `<command> [args...] --version` and fails unless its output carries the
# expected version as a whole token (clap prints "<name> <version>"). A binary
# compiled from source other than the release tag claims is rejected here --
# before its asset is packaged and uploaded.
set -euo pipefail

expected="${1:?usage: check-binary-version.sh <expected-version> <command> [args...]}"
shift
[[ $# -ge 1 ]] || { echo "check-binary-version: no command given" >&2; exit 1; }

out="$("$@" --version)"

# clap prints "<name> <version>". Compare the version token literally (string
# equality, not a regex) so every valid Cargo SemVer matches -- including build
# metadata like 1.2.3+meta, where '+' would otherwise be an ERE operator. The
# whole-token match keeps 0.6.0 from matching 10.6.0 or substring-matching
# 0.6.00: only a field that equals "$expected" exactly counts.
matched=0
while read -r -a tokens; do
  for tok in "${tokens[@]}"; do
    if [[ "$tok" == "$expected" ]]; then
      matched=1
      break 2
    fi
  done
done <<<"$out"

if [[ "$matched" -ne 1 ]]; then
  echo "check-binary-version: '$*' reports '$out', expected version '$expected'" >&2
  exit 1
fi

echo "check-binary-version: OK -- '$*' reports version '$expected'."
