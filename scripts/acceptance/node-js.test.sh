#!/usr/bin/env bash
# Regressions for node-js.sh's gates, none of which needs a sandbox: a Node.js below 22
# is refused with the version named; a host whose bubblewrap cannot sandbox is skipped
# loudly, or fails when WARD_REQUIRE_ISOLATION=1; `--probe` reports either way; a
# binary that is not there is named before anything is started; and a test-loopback
# ward-node given as WARD_NODE_BIN, or a shipped one given as WARD_NODE_LOOPBACK_BIN, is
# refused by what its --version says before anything is started.
set -euo pipefail

sut="$(cd "$(dirname "$0")" && pwd)/node-js.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# A PATH whose `bwrap` exits as told and whose `node` is the real one or a fake.
fake_bin() {
  local dir=$1 bwrap_status=$2 node_version=$3
  mkdir -p "$dir"
  printf '#!/bin/sh\nexit %s\n' "$bwrap_status" >"$dir/bwrap"
  if [[ -n "$node_version" ]]; then
    printf '#!/bin/sh\necho %s\n' "$node_version" >"$dir/node"
  else
    ln -s "$(command -v node)" "$dir/node"
  fi
  chmod +x "$dir/bwrap" "$dir/node" 2>/dev/null || true
  # Everything else the script needs (timeout, mktemp, …) stays reachable.
  for tool in timeout mktemp chmod seq sleep stat cat tr wc grep pgrep cp date dirname bash sh tee; do
    [[ -e "$dir/$tool" ]] || ln -s "$(command -v "$tool")" "$dir/$tool"
  done
}

expect() {
  local want=$1 desc=$2
  shift 2
  local got=0 out
  out=$("$@" 2>&1) || got=$?
  [[ "$got" == "$want" ]] || fail "$desc: expected exit $want, got $got: $out"
  printf '%s' "$out" >"$work/last"
  echo "ok   $desc"
}

fake_bin "$work/old-node" 0 "v20.19.0"
expect 1 "a Node.js below 22 is refused" env PATH="$work/old-node" bash "$sut"
grep -q 'Node.js >= 22 is required' "$work/last" || fail "the requirement is not named: $(cat "$work/last")"
grep -q 'v20.19.0' "$work/last" || fail "the found version is not named: $(cat "$work/last")"

fake_bin "$work/no-sandbox" 1 ""
expect 1 "--probe reports an unavailable sandbox" env PATH="$work/no-sandbox" bash "$sut" --probe
grep -q '^isolation: unavailable$' "$work/last" || fail "wrong probe output: $(cat "$work/last")"

expect 0 "without a sandbox and without WARD_REQUIRE_ISOLATION the run is skipped" \
  env PATH="$work/no-sandbox" WARD_REQUIRE_ISOLATION= bash "$sut"
grep -q 'node-js acceptance: SKIPPED' "$work/last" || fail "the skip is not announced: $(cat "$work/last")"
grep -q 'WARD_REQUIRE_ISOLATION=1' "$work/last" || fail "the skip does not say how to make it fail: $(cat "$work/last")"

expect 1 "without a sandbox and with WARD_REQUIRE_ISOLATION=1 the run fails" \
  env PATH="$work/no-sandbox" WARD_REQUIRE_ISOLATION=1 bash "$sut"
grep -q 'WARD_REQUIRE_ISOLATION is set but the isolation prerequisite is unavailable' "$work/last" \
  || fail "the failure is not explained: $(cat "$work/last")"
grep -q 'SKIPPED' "$work/last" && fail "a required run must not read as skipped: $(cat "$work/last")"

fake_bin "$work/sandbox" 0 ""
expect 0 "--probe reports a ready sandbox" env PATH="$work/sandbox" bash "$sut" --probe
grep -q '^isolation: ready$' "$work/last" || fail "wrong probe output: $(cat "$work/last")"

expect 1 "a missing ward-node binary is named before anything starts" \
  env PATH="$work/sandbox" WARD_NODE_BIN="$work/absent/ward-node" WARD_NODE_ADAPTER_BIN="$work/absent/ward-node-adapter" bash "$sut"
grep -q "ward-node binary is not executable: $work/absent/ward-node" "$work/last" \
  || fail "the missing binary is not named: $(cat "$work/last")"

# fake_node <path> <version>: a ward-node whose --version prints `ward-node <version>`.
fake_node() {
  mkdir -p "$(dirname "$1")"
  printf '#!/bin/sh\necho "ward-node %s"\n' "$2" >"$1"
  chmod +x "$1"
}
fake_node "$work/shipped/ward-node" "0.1.0"
fake_node "$work/loopback/ward-node" "0.1.0 (test-loopback)"
fake_node "$work/shipped/ward-node-adapter" "0.1.0"

expect 1 "a test-loopback ward-node as WARD_NODE_BIN is refused before anything starts" \
  env PATH="$work/sandbox" WARD_NODE_BIN="$work/loopback/ward-node" \
  WARD_NODE_ADAPTER_BIN="$work/shipped/ward-node-adapter" \
  WARD_NODE_LOOPBACK_BIN="$work/loopback/ward-node" bash "$sut"
grep -q "WARD_NODE_BIN is a test-loopback build of ward-node ($work/loopback/ward-node)" "$work/last" \
  || fail "the test-loopback build is not refused by name: $(cat "$work/last")"
grep -q 'node-js acceptance' "$work/last" && fail "a case ran against the test-loopback build: $(cat "$work/last")"

expect 1 "a shipped ward-node as WARD_NODE_LOOPBACK_BIN is refused before anything starts" \
  env PATH="$work/sandbox" WARD_NODE_BIN="$work/shipped/ward-node" \
  WARD_NODE_ADAPTER_BIN="$work/shipped/ward-node-adapter" \
  WARD_NODE_LOOPBACK_BIN="$work/shipped/ward-node" bash "$sut"
grep -q "WARD_NODE_LOOPBACK_BIN is not a test-loopback build of ward-node ($work/shipped/ward-node)" "$work/last" \
  || fail "the shipped build is not refused as the loopback node: $(cat "$work/last")"
grep -q 'node-js acceptance' "$work/last" && fail "a case ran against the wrong build: $(cat "$work/last")"

echo "node-js.test.sh: PASS"
