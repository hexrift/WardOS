#!/usr/bin/env bash
# Regressions for node.sh's rendering: a log in which every case passed renders a PASS
# table and exits 0; a skipped case is shown with its reason and fails nothing; a failed
# case, a failed suite and a log with no case at all each exit 1 and name the failure.
set -euo pipefail

sut="$(cd "$(dirname "$0")" && pwd)/node.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

expect() {
  local want=$1 desc=$2 log=$3
  local got=0 out
  out=$(bash "$sut" --render "$log" 2>&1) || got=$?
  [[ "$got" == "$want" ]] || fail "$desc: expected exit $want, got $got: $out"
  printf '%s' "$out" >"$work/last"
  echo "ok   $desc"
}

cat >"$work/pass.log" <<'EOF'
running 3 tests
test every_acceptance_case_is_documented ... ok
test bounded_execution_kills_at_the_budget_and_completes_within_bounds ... acceptance bounded_execution_kills_at_the_budget_and_completes_within_bounds: PASS in 2345 ms -- a criterion
ok
test isolation_holds_against_an_in_sandbox_probe ... isolation: the workload's environment keys are HOME,PATH,PWD,TERM
acceptance isolation_holds_against_an_in_sandbox_probe: PASS in 223 ms -- a criterion
ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.40s
EOF
expect 0 "a passing log renders PASS" "$work/pass.log"
grep -q 'bounded_execution_kills_at_the_budget_and_completes_within_bounds *PASS *2345 ms' "$work/last" \
  || fail "the table lacks the passing case: $(cat "$work/last")"
grep -q 'isolation_holds_against_an_in_sandbox_probe *PASS *223 ms' "$work/last" \
  || fail "the table lacks the case whose verdict started a new line: $(cat "$work/last")"
grep -q '^acceptance: 2 passed, 0 failed$' "$work/last" || fail "wrong summary: $(cat "$work/last")"
grep -q '^acceptance: PASS$' "$work/last" || fail "no PASS verdict: $(cat "$work/last")"

cat >"$work/fail.log" <<'EOF'
running 2 tests
test isolation_holds_against_an_in_sandbox_probe ... acceptance isolation_holds_against_an_in_sandbox_probe: PASS in 900 ms -- a criterion
ok
test durable_records_survive_a_node_restart ... 
thread 'durable_records_survive_a_node_restart' panicked at crates/ward-node-client/tests/acceptance.rs:1:1:
assertion failed
FAILED

failures:

---- durable_records_survive_a_node_restart stdout ----
    something the test printed

failures:
    durable_records_survive_a_node_restart

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.00s
EOF
expect 1 "a failed case exits 1" "$work/fail.log"
grep -q 'durable_records_survive_a_node_restart *FAIL' "$work/last" || fail "the failed case is not named: $(cat "$work/last")"
grep -q '^acceptance: 1 passed, 1 failed$' "$work/last" || fail "wrong summary: $(cat "$work/last")"
grep -q '^acceptance: FAIL$' "$work/last" || fail "no FAIL verdict: $(cat "$work/last")"

cat >"$work/skipped.log" <<'EOF'
running 1 test
test every_acceptance_case_is_documented ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
EOF
expect 1 "a log with no acceptance case exits 1" "$work/skipped.log"
grep -q 'no acceptance case ran' "$work/last" || fail "the empty run is not explained: $(cat "$work/last")"

cat >"$work/skip.log" <<'EOF'
running 2 tests
test capacity_cgroup_limits_hold_and_usage_is_recorded ... acceptance capacity_cgroup_limits_hold_and_usage_is_recorded: SKIP -- no cgroup v2 directory delegated to this test
ok
test isolation_holds_against_an_in_sandbox_probe ... acceptance isolation_holds_against_an_in_sandbox_probe: PASS in 223 ms -- a criterion
ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.40s
EOF
expect 0 "a skipped case beside a passing one renders SKIP and still passes" "$work/skip.log"
grep -q 'capacity_cgroup_limits_hold_and_usage_is_recorded *SKIP *no cgroup v2 directory delegated to this test' "$work/last" \
  || fail "the skipped case is not shown with its reason: $(cat "$work/last")"
grep -q '^acceptance: 1 passed, 0 failed, 1 skipped$' "$work/last" || fail "wrong summary: $(cat "$work/last")"
grep -q '^acceptance: PASS$' "$work/last" || fail "no PASS verdict: $(cat "$work/last")"

printf 'error: could not compile\n' >"$work/broken.log"
expect 1 "a build failure exits 1" "$work/broken.log"

echo "node.test.sh: PASS"
