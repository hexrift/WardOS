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

esc="${expected//./\\.}"
if ! grep -Eq "(^|[[:space:]])${esc}([[:space:]]|\$)" <<<"$out"; then
  echo "check-binary-version: '$*' reports '$out', expected version '$expected'" >&2
  exit 1
fi

echo "check-binary-version: OK -- '$*' reports version '$expected'."
