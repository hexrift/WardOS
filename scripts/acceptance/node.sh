#!/usr/bin/env bash
# Runs the ward-node cross-system acceptance suite (docs/node-acceptance.md) against a
# real node, with isolation required rather than skipped, and prints one verdict line per
# case and a summary table. The cases are the #[test]s of
# crates/ward-node-client/tests/acceptance.rs and, for the network allowlist and result
# return, crates/ward-node-client/tests/acceptance_network.rs and
# crates/ward-node-client/tests/acceptance_output.rs; each writes its verdict as
#   acceptance <case>: PASS in <ms> ms -- <criterion>
# The cargo test output goes to stderr and only the table to stdout, so the table can be
# captured on its own. After the table, the Node.js reference control plane's acceptance
# (scripts/acceptance/node-js.sh, docs/node-integration-from-nodejs.md) runs against a
# real node under the same isolation requirement and adds its verdict lines. Exit status:
# 0 when every case of both passed, 1 otherwise.
#
#   scripts/acceptance/node.sh            run the suite and print the table
#   scripts/acceptance/node.sh --render F render the table from a saved cargo test log F
#                                         (the Node.js acceptance is not run)
set -euo pipefail

cd "$(dirname "$0")/../.."

render() {
  local log=$1
  local status=0
  local name verdict ms
  echo
  echo "ward-node cross-system acceptance (docs/node-acceptance.md)"
  echo
  printf '%-70s %-6s %s\n' "case" "result" "time"
  printf '%-70s %-6s %s\n' "----" "------" "----"
  local passed=0 failed=0 listing=0
  while IFS= read -r line; do
    if [[ "$line" =~ acceptance\ ([a-z_]+):\ PASS\ in\ ([0-9]+)\ ms ]]; then
      name=${BASH_REMATCH[1]}
      ms=${BASH_REMATCH[2]}
      printf '%-70s %-6s %s ms\n' "$name" "PASS" "$ms"
      passed=$((passed + 1))
    fi
  done <"$log"
  while IFS= read -r line; do
    if [[ "$line" == "failures:" ]]; then
      listing=1
    elif [[ $listing -eq 1 && "$line" =~ ^\ \ \ \ ([a-z_]+)$ ]]; then
      printf '%-70s %-6s %s\n' "${BASH_REMATCH[1]}" "FAIL" "-"
      failed=$((failed + 1))
      status=1
    elif [[ $listing -eq 1 && -n "$line" && ! "$line" =~ ^\ \ \ \  ]]; then
      listing=0
    fi
  done <"$log"
  echo
  if ! grep -q '^test result: ok\.' "$log"; then
    status=1
  fi
  if [[ "$passed" -eq 0 ]]; then
    echo "no acceptance case ran (bubblewrap missing, or the suite did not build)"
    status=1
  fi
  echo "acceptance: $passed passed, $failed failed"
  if [[ $status -eq 0 ]]; then
    verdict=PASS
  else
    verdict=FAIL
  fi
  echo "acceptance: $verdict"
  return "$status"
}

if [[ "${1:-}" == "--render" ]]; then
  [[ -n "${2:-}" ]] || { echo "usage: $0 --render <log>" >&2; exit 2; }
  render "$2"
  exit $?
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

export WARD_REQUIRE_ISOLATION=1
set +e
cargo test -p ward-node-client --test acceptance --test acceptance_network --test acceptance_output -- --test-threads=1 --nocapture 2>&1 | tee "$log" >&2
set -e

status=0
render "$log" || status=$?
echo
bash scripts/acceptance/node-js.sh || status=1
exit "$status"
