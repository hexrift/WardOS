#!/usr/bin/env bash
# Regression for the isolation-evidence checker itself (issue #124): the gate must
# go GREEN only when every mandatory test ran `ok` and the ST-029 corpus catalogue
# is intact, and RED whenever any expected evidence is absent. Without this, a
# checker that silently stopped enforcing would leave the required job green.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
checker="$here/check-isolation-evidence.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# A well-formed captured e2e log: every mandatory test present, exactly once, ok.
good_log() {
  cat <<'EOF'
running 3 tests
test egress_and_surface_probes_never_reach ... ok
test selftest_blocks_every_probe ... ok
test hostile_verifier_corpus_is_contained ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 1.26s
EOF
}

# A corpus source with exactly the fixed ST-029 catalogue.
good_corpus() {
  cat <<'EOF'
pub const CORPUS: &[&str] = &[
    "ST-029 network-egress",
    "ST-029 read-host-path",
    "ST-029 write-outside-scratch",
    "ST-029 no-persistence",
    "ST-029 runaway-budget",
    "ST-029 resource-cgroup",
    "ST-029 protected-test-overlay",
    "ST-029 exit-code-authority",
    "ST-029 symlink-host-escape",
];
EOF
}

# expect_exit <expected-code> <description> -- <checker args...>
expect_exit() {
  local want="$1" desc="$2"
  shift 2
  [ "$1" = "--" ] && shift
  local got=0
  # GITHUB_STEP_SUMMARY intentionally unset: the checker must decide the exit
  # code from the evidence alone, not from being able to publish a summary.
  "$checker" "$@" >/dev/null 2>&1 || got=$?
  if [ "$got" -eq "$want" ]; then
    echo "ok   - $desc (exit $got)"
    pass=$((pass + 1))
  else
    echo "FAIL - $desc (want exit $want, got $got)"
    fail=$((fail + 1))
  fi
}

corpus="$tmp/corpus.rs"
good_corpus > "$corpus"

# --- GREEN: all evidence present --------------------------------------------
good_log > "$tmp/good.log"
expect_exit 0 "all evidence present -> green" -- "$tmp/good.log" "$corpus"

# --- RED: a mandatory test line is missing ----------------------------------
good_log | grep -v 'hostile_verifier_corpus_is_contained' > "$tmp/missing.log"
expect_exit 1 "missing verifier-corpus test -> red" -- "$tmp/missing.log" "$corpus"

# --- RED: a mandatory test did not pass -------------------------------------
good_log | sed 's/test selftest_blocks_every_probe ... ok/test selftest_blocks_every_probe ... FAILED/' > "$tmp/failed.log"
expect_exit 1 "mandatory test FAILED -> red" -- "$tmp/failed.log" "$corpus"

# --- RED: a prerequisite was skipped under require-mode ---------------------
{ good_log; echo "skipping: bubblewrap not available"; } > "$tmp/skip.log"
expect_exit 1 "skipping: line present -> red" -- "$tmp/skip.log" "$corpus"

# --- RED: a mandatory test line is duplicated -------------------------------
{ good_log; echo "test egress_and_surface_probes_never_reach ... ok"; } > "$tmp/dup.log"
expect_exit 1 "duplicated test line -> red" -- "$tmp/dup.log" "$corpus"

# --- RED: an ST-029 corpus row was dropped from the catalogue ---------------
good_corpus | grep -v 'ST-029 no-persistence' > "$tmp/corpus-short.rs"
expect_exit 1 "dropped ST-029 corpus row -> red" -- "$tmp/good.log" "$tmp/corpus-short.rs"

# --- RED: an ST-029 corpus row was renamed ----------------------------------
good_corpus | sed 's/ST-029 runaway-budget/ST-029 runaway-budgetX/' > "$tmp/corpus-renamed.rs"
expect_exit 1 "renamed ST-029 corpus row -> red" -- "$tmp/good.log" "$tmp/corpus-renamed.rs"

# --- RED: the log file does not exist ---------------------------------------
expect_exit 1 "missing log file -> red" -- "$tmp/does-not-exist.log" "$corpus"

echo ""
echo "checker self-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
