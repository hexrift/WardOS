#!/usr/bin/env bash
# Shared helpers for scripts/release/*.test.sh. Source this from a test.
#
#   RELEASE_DIR        absolute path of scripts/release
#   expect_status N D  run a command, fail unless it exits N (D describes the case)
#   fail MSG           print FAIL and exit 1
set -euo pipefail

RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RELEASE_DIR

fail() { echo "FAIL: $*" >&2; exit 1; }

# expect_status EXPECTED DESC CMD...
# Runs CMD in a subshell (so its `exit` never trips the caller's `set -e`) and
# asserts the exit status equals EXPECTED.
expect_status() {
  local want=$1 desc=$2
  shift 2
  local got=0
  "$@" >/dev/null 2>&1 || got=$?
  [[ "$got" == "$want" ]] || fail "$desc: expected exit $want, got $got"
  echo "ok   $desc"
}
