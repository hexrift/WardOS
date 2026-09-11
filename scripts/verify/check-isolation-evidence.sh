#!/usr/bin/env bash
# Machine-checkable evidence that the mandatory isolation regressions actually
# ran under WARD_REQUIRE_ISOLATION=1 (issue #124).
#
# A green required job must never hide a namespace/verifier/egress assertion that
# was deleted, renamed, returned early, or dropped from the suite. Grepping the
# aggregate `test result: ok.` line cannot prove that: the count stays green when
# a required test disappears. This checker instead holds an explicit inventory of
# the mandatory `#[test]` names and proves each one appears exactly once with an
# `ok` result in the captured per-test output, and it ties the ST-029 corpus to
# its fixed row catalogue so dropping a corpus row also turns the gate red.
#
# Usage:
#   check-isolation-evidence.sh <e2e-test-log> [verifier_corpus.rs]
#
#   <e2e-test-log>       Captured stdout of `cargo test -p ward-daemon --test e2e`
#                        (default libtest terminal format: `test <name> ... ok`).
#   [verifier_corpus.rs] Source that defines the ST-029 `CORPUS` catalogue.
#                        Defaults to the in-tree path relative to this script.
#
# Exits non-zero (gate red) if any mandatory test is missing, not `ok`, or
# duplicated; if a `skipping:` prerequisite line is present; or if the ST-029
# corpus catalogue no longer holds exactly its expected rows. On success it writes
# the mandatory names plus expected-vs-observed counts to $GITHUB_STEP_SUMMARY
# when that variable is set.
set -euo pipefail

# --- Mandatory isolation regressions (issue #124 acceptance) -----------------
# The exact integration-test function names in crates/ward-daemon/tests/e2e.rs
# that must run under WARD_REQUIRE_ISOLATION=1. Each name maps to one of the
# three regression families #124 names: namespace, verifier-corpus, egress.
MANDATORY_TESTS=(
  "selftest_blocks_every_probe"            # namespace escape containment: ST-013/014/015
  "hostile_verifier_corpus_is_contained"   # verifier corpus: ST-029
  "egress_and_surface_probes_never_reach"  # egress + surface: ST-022/026/027/028
)

# The fixed ST-029 corpus row catalogue, in run order. Kept here independently of
# the Rust source so that dropping or renaming a row in the source turns the gate
# red even if the in-tree test is edited to match the reduced catalogue.
EXPECTED_CORPUS_ROWS=(
  "ST-029 network-egress"
  "ST-029 read-host-path"
  "ST-029 write-outside-scratch"
  "ST-029 no-persistence"
  "ST-029 runaway-budget"
  "ST-029 resource-cgroup"
  "ST-029 protected-test-overlay"
  "ST-029 exit-code-authority"
  "ST-029 symlink-host-escape"
)

die() {
  echo "::error::$*" >&2
  exit 1
}

main() {
  local log="${1:-}"
  local script_dir
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  local corpus_src="${2:-$script_dir/../../crates/ward-daemon/src/selftest/verifier_corpus.rs}"

  [ -n "$log" ] || die "usage: check-isolation-evidence.sh <e2e-test-log> [verifier_corpus.rs]"
  [ -f "$log" ] || die "isolation evidence log not found: $log"
  [ -f "$corpus_src" ] || die "ST-029 corpus source not found: $corpus_src"

  # A skipped prerequisite must never appear under require-mode; it means an
  # isolation assertion did not run for real (crates/ward-sandbox/src/ci.rs).
  if grep -Eq '^skipping: ' "$log"; then
    grep -E '^skipping: ' "$log" >&2 || true
    die "an isolation prerequisite was skipped under WARD_REQUIRE_ISOLATION (issue #124)"
  fi

  # Each mandatory test must appear exactly once with an `ok` result.
  local name count ok_count failures=()
  for name in "${MANDATORY_TESTS[@]}"; do
    # libtest prints one line per test: `test <name> ... ok` (or ... FAILED / ignored).
    count="$(grep -Ec "^test ${name} \.\.\. " "$log" || true)"
    ok_count="$(grep -Ec "^test ${name} \.\.\. ok$" "$log" || true)"
    if [ "$count" -eq 0 ]; then
      failures+=("$name: MISSING (no 'test ${name} ... <result>' line — deleted, renamed, or filtered out?)")
    elif [ "$count" -gt 1 ]; then
      failures+=("$name: DUPLICATED ($count result lines; expected exactly 1)")
    elif [ "$ok_count" -ne 1 ]; then
      failures+=("$name: NOT OK ($(grep -E "^test ${name} \.\.\. " "$log" | head -n1))")
    fi
  done

  # Tie the ST-029 corpus to its fixed catalogue: the source must define exactly
  # the expected rows, in order. A dropped/renamed/added row is a red gate.
  local observed_rows=()
  local row
  while IFS= read -r row; do
    observed_rows+=("$row")
  done < <(extract_corpus_rows "$corpus_src")

  local corpus_ok=1
  if [ "${#observed_rows[@]}" -ne "${#EXPECTED_CORPUS_ROWS[@]}" ]; then
    corpus_ok=0
    failures+=("ST-029 corpus catalogue: ${#observed_rows[@]} rows in $corpus_src, expected ${#EXPECTED_CORPUS_ROWS[@]}")
  else
    local i
    for i in "${!EXPECTED_CORPUS_ROWS[@]}"; do
      if [ "${observed_rows[$i]}" != "${EXPECTED_CORPUS_ROWS[$i]}" ]; then
        corpus_ok=0
        failures+=("ST-029 corpus row $((i + 1)): got '${observed_rows[$i]}', expected '${EXPECTED_CORPUS_ROWS[$i]}'")
      fi
    done
  fi

  write_summary "$corpus_ok"

  if [ "${#failures[@]}" -ne 0 ]; then
    for row in "${failures[@]}"; do
      echo "::error::isolation evidence: $row" >&2
    done
    die "mandatory isolation regressions are not proven to have run (issue #124)"
  fi

  echo "isolation evidence OK: ${#MANDATORY_TESTS[@]} mandatory tests ran, ${#EXPECTED_CORPUS_ROWS[@]} ST-029 corpus rows present"
}

# Print the ST-029 corpus row names, one per line, in source order, from the
# `CORPUS` const array in the given Rust source.
extract_corpus_rows() {
  local src="$1"
  awk '
    /pub const CORPUS/ { collecting = 1 }
    collecting {
      if (match($0, /"ST-029 [^"]+"/)) {
        s = substr($0, RSTART + 1, RLENGTH - 2)
        print s
      }
      if (index($0, "];")) { exit }
    }
  ' "$src"
}

write_summary() {
  local corpus_ok="$1"
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  {
    echo "### Isolation regressions executed (issue #124)"
    echo ""
    echo "Each mandatory test ran under \`WARD_REQUIRE_ISOLATION=1\`, where a missing"
    echo "prerequisite is a hard failure rather than a skip."
    echo ""
    echo "| Mandatory test | Family | Expected | Observed (\`ok\`) |"
    echo "| --- | --- | --- | --- |"
    local name family ok_count
    for name in "${MANDATORY_TESTS[@]}"; do
      family="$(family_of "$name")"
      ok_count="$(grep -Ec "^test ${name} \.\.\. ok$" "$log" || true)"
      echo "| \`$name\` | $family | 1 | $ok_count |"
    done
    echo ""
    echo "ST-029 verifier corpus catalogue: ${#EXPECTED_CORPUS_ROWS[@]} rows expected, $(if [ "$corpus_ok" -eq 1 ]; then echo "all present"; else echo "MISMATCH"; fi)."
  } >> "$GITHUB_STEP_SUMMARY"
}

family_of() {
  case "$1" in
    selftest_blocks_every_probe) echo "namespace (ST-013/014/015)" ;;
    hostile_verifier_corpus_is_contained) echo "verifier corpus (ST-029)" ;;
    egress_and_surface_probes_never_reach) echo "egress + surface (ST-022/026/027/028)" ;;
    *) echo "isolation" ;;
  esac
}

main "$@"
