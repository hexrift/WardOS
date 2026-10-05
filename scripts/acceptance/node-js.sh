#!/usr/bin/env bash
# Acceptance of the Node.js reference control plane (examples/node-control-plane,
# docs/node-integration-from-nodejs.md) against a real `ward-node`: the client generates
# its issuer key, the node is started with that key in its trust store and a task root,
# and every byte the client sends is validated by the node itself. One verdict line per
# case on stdout,
#   node-js acceptance <case>: PASS|FAIL -- <what it proves>
# then a summary; everything else goes to stderr. Exit status: 0 when every case passed
# (or isolation is unavailable and not required, which prints SKIPPED), 1 otherwise.
#
#   scripts/acceptance/node-js.sh           run the cases
#   scripts/acceptance/node-js.sh --probe   print whether isolation is available and exit
#
# Environment: WARD_NODE_BIN and WARD_NODE_ADAPTER_BIN name the binaries (default: build
# them with cargo into ${CARGO_TARGET_DIR:-target}/debug); WARD_REQUIRE_ISOLATION=1 makes
# a host without a working bubblewrap fail instead of skipping, as the Rust suites do.
set -euo pipefail

cd "$(dirname "$0")/../.."

client=examples/node-control-plane/control-plane.mjs

die() { echo "node-js: $*" >&2; exit 1; }

require_node() {
  local version major
  command -v node >/dev/null 2>&1 || die "Node.js >= 22 is required and no \`node\` is on PATH"
  version="$(node -v 2>/dev/null || true)"
  major="${version#v}"
  major="${major%%.*}"
  if ! [[ "$major" =~ ^[0-9]+$ && "$major" -ge 22 ]]; then
    die "Node.js >= 22 is required (found \`node -v\` = ${version:-nothing})"
  fi
}

# The same probe as ward-launch's `available()`: a minimal real sandbox must exit cleanly.
isolation_ready() {
  command -v bwrap >/dev/null 2>&1 || return 1
  timeout 5 bwrap --unshare-all --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib \
    --ro-bind-try /lib64 /lib64 --proc /proc --dev /dev -- /bin/true >/dev/null 2>&1
}

require_node

if [[ "${1:-}" == "--probe" ]]; then
  if isolation_ready; then
    echo "isolation: ready"
    exit 0
  fi
  echo "isolation: unavailable"
  exit 1
fi

if ! isolation_ready; then
  if [[ "${WARD_REQUIRE_ISOLATION:-}" == "1" ]]; then
    die "WARD_REQUIRE_ISOLATION is set but the isolation prerequisite is unavailable: bubblewrap cannot create a user namespace here. A runner that cannot enforce isolation must fail, not skip."
  fi
  echo "node-js acceptance: SKIPPED -- bubblewrap cannot create a user namespace here; set WARD_REQUIRE_ISOLATION=1 to fail instead" | tee /dev/stderr
  exit 0
fi

if [[ -z "${WARD_NODE_BIN:-}" || -z "${WARD_NODE_ADAPTER_BIN:-}" ]]; then
  target="${CARGO_TARGET_DIR:-target}"
  if [[ ! -x "$target/debug/ward-node" || ! -x "$target/debug/ward-node-adapter" ]]; then
    echo "node-js: building ward-node and ward-node-adapter" >&2
    cargo build -p ward-node -p ward-node-client >&2
  fi
  WARD_NODE_BIN="${WARD_NODE_BIN:-$target/debug/ward-node}"
  WARD_NODE_ADAPTER_BIN="${WARD_NODE_ADAPTER_BIN:-$target/debug/ward-node-adapter}"
fi
[[ -x "$WARD_NODE_BIN" ]] || die "ward-node binary is not executable: $WARD_NODE_BIN"
[[ -x "$WARD_NODE_ADAPTER_BIN" ]] || die "ward-node-adapter binary is not executable: $WARD_NODE_ADAPTER_BIN"

work="$(mktemp -d)"
chmod 700 "$work"
node_pid=""
# shellcheck disable=SC2317  # reached through the EXIT trap
cleanup() {
  if [[ -n "$node_pid" ]]; then
    kill "$node_pid" 2>/dev/null || true
    wait "$node_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

passed=0
failed=0
pass() { printf 'node-js acceptance %s: PASS -- %s\n' "$1" "$2"; passed=$((passed + 1)); }
fail() { printf 'node-js acceptance %s: FAIL -- %s\n' "$1" "$2"; failed=$((failed + 1)); }

# field <json-file> <js-expression-on-o>: one JSON value from a one-line JSON file.
field() {
  node -e 'const o = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); const v = eval(process.argv[2]); process.stdout.write(v === undefined ? "undefined" : JSON.stringify(v));' "$1" "$2"
}

# ---- the host: key, trust store, snapshot, node --------------------------------------------

mkdir -p "$work/cp"
principal="$(node "$client" derive-id prn acceptance-issuer)"
trust_line="$(node "$client" keygen --key "$work/cp/issuer.pem" --principal acceptance-issuer)"
[[ "$(stat -c %a "$work/cp/issuer.pem")" == "600" ]] || die "the issuer key was not written mode 0600"
[[ "$trust_line" == *" $principal" ]] || die "the trust-store line does not end in the principal: $trust_line"
# The node's own derivation of the key id must agree with the client's.
public_key="${trust_line%% *}"
key_id="$("$WARD_NODE_BIN" issuer-key-id "$public_key")"
[[ "$trust_line" == "$public_key $key_id $principal" ]] || die "the client's key id differs from ward-node issuer-key-id: $trust_line vs $key_id"
printf '# written by scripts/acceptance/node-js.sh\n%s\n' "$trust_line" >"$work/trusted-issuers"
chmod 600 "$work/trusted-issuers"

node_id="$(node "$client" derive-id node acceptance-host)"
mkdir -p "$work/project/src"
echo "from the snapshot" >"$work/project/src/input.txt"
snapshot="$("$WARD_NODE_BIN" snapshot import --state-dir "$work/state" "$work/project")"
[[ "$snapshot" =~ ^[0-9a-f]{64}$ ]] || die "snapshot import printed no id: $snapshot"

"$WARD_NODE_BIN" --socket "$work/node.sock" --state-dir "$work/state" --node-id "$node_id" \
  --trusted-issuers "$work/trusted-issuers" --task-root "$work/tasks" >"$work/node.log" 2>&1 &
node_pid=$!
for _ in $(seq 1 100); do
  [[ -S "$work/node.sock" ]] && break
  kill -0 "$node_pid" 2>/dev/null || { cat "$work/node.log" >&2; die "ward-node exited before serving"; }
  sleep 0.1
done
[[ -S "$work/node.sock" ]] || die "ward-node did not bind its socket within 10 s"

common=(--socket "$work/node.sock" --adapter "$WARD_NODE_ADAPTER_BIN")
node "$client" capabilities "${common[@]}" >"$work/capabilities.json"
[[ "$(field "$work/capabilities.json" 'o.lifecycle.start')" == "true" ]] \
  || die "the node does not execute here (lifecycle.start is not true): $(cat "$work/capabilities.json")"

run_common=("${common[@]}" --key "$work/cp/issuer.pem" --principal acceptance-issuer --node "$node_id"
  --state-dir "$work/cp" --snapshot "$snapshot" --task-root "$work/tasks" --timeout-ms 90000)

# run <out-file> <args…>: the client's exit status in $status, its outcome JSON in the file.
run() {
  local out=$1
  shift
  status=0
  node "$client" run "${run_common[@]}" "$@" >"$out" 2>>"$work/client.log" || status=$?
}

check() {
  # check <case> <out-file> <expression> <expected-json> <what>: accumulate a failure message.
  local got
  got="$(field "$2" "$3")"
  if [[ "$got" != "$4" ]]; then
    problems+="$5: $3 is $got, expected $4; "
  fi
}

audit_json() {
  "$WARD_NODE_BIN" audit --state-dir "$work/state" --task-root "$work/tasks" --json "$1"
}

verify_log() {
  # The node's own verifier (node-integration.md §2.6 and §6.5): the log must verify, be
  # sealed and agree with the task record. `ward replay --verify` is run too when a `ward`
  # binary is at hand (WARD_BIN or on PATH).
  local task=$1 log=$2
  audit_json "$task" >"$work/audit.json" || return 1
  [[ "$(field "$work/audit.json" 'o.evidence.verified.sealed')" == "true" ]] || return 1
  [[ "$(field "$work/audit.json" 'o.evidence.disagreement')" == "null" ]] || return 1
  local ward="${WARD_BIN:-}"
  if [[ -z "$ward" ]] && command -v ward >/dev/null 2>&1; then ward="$(command -v ward)"; fi
  if [[ -n "$ward" ]]; then
    "$ward" replay --verify "$log" >/dev/null 2>&1 || return 1
  fi
}

# ---- case 1: a workload that exits 0 completes and seals a verifying log ------------------

problems=""
run "$work/run1.json" --task acc-task-1 --attempt acc-attempt-1a --budget-ms 60000 -- sh -c 'echo acceptance >> out.txt'
[[ "$status" == "0" ]] || problems+="exit status $status; "
check 1 "$work/run1.json" 'o.outcome' '"completed"' "outcome"
check 1 "$work/run1.json" 'o.certain' 'true' "certainty"
check 1 "$work/run1.json" 'o.exitStatus' '0' "exit status"
check 1 "$work/run1.json" 'o.receipt' '"completed"' "receipt"
check 1 "$work/run1.json" 'o.finalState' '"sealed"' "final state"
check 1 "$work/run1.json" 'o.sealed' 'true' "sealed"
check 1 "$work/run1.json" 'o.cancelled' 'false' "cancelled"
check 1 "$work/run1.json" 'o.version' '1' "first version"
check 1 "$work/run1.json" 'o.operations.map(x => x.verb).join()' '"create,admit,start,seal"' "operations"
task1="$(field "$work/run1.json" 'o.binding.task' | tr -d '"')"
attempt1="$(field "$work/run1.json" 'o.binding.attempt' | tr -d '"')"
head1="$(field "$work/run1.json" 'o.evidenceHead' | tr -d '"')"
log1="$(field "$work/run1.json" 'o.evidenceLog' | tr -d '"')"
[[ "$task1" == "$(node "$client" derive-id task acc-task-1)" ]] || problems+="task id not derived from the caller id; "
[[ "$head1" =~ ^[0-9a-f]{64}$ ]] || problems+="no sealed evidence head; "
[[ "$log1" == "$work/tasks/$task1/$attempt1.evidence/events.log" ]] || problems+="evidence log path $log1; "
[[ "$(wc -l <"$work/tasks/$task1/$attempt1/out.txt" 2>/dev/null)" == "1" ]] || problems+="the workload did not write out.txt once; "
if verify_log "$task1" "$log1"; then
  [[ "$(field "$work/audit.json" 'o.evidence.verified.head')" == "\"$head1\"" ]] || problems+="audit head differs from the report's; "
  [[ "$(field "$work/audit.json" 'o.receipt')" == '"completed"' ]] || problems+="audit receipt; "
  [[ "$(field "$work/audit.json" 'o.admitted.authority.lease.issuer')" == "\"$principal\"" ]] || problems+="audit issuer principal; "
  [[ "$(field "$work/audit.json" 'o.admitted.issuer_key')" == "\"$key_id\"" ]] || problems+="audit key id; "
else
  problems+="the evidence log does not verify sealed with the node's audit; "
fi
if [[ -z "$problems" ]]; then
  pass completes_and_seals "an exit-0 workload ends completed with exit status 0, version 1 and a sealed evidence log the node's own audit verifies and binds to the client's issuer"
else
  fail completes_and_seals "$problems"
fi

# ---- case 2: a non-zero exit is failed with its exit status ------------------------------

problems=""
run "$work/run2.json" --task acc-task-2 --attempt acc-attempt-2a --budget-ms 60000 -- sh -c 'exit 3'
[[ "$status" == "1" ]] || problems+="exit status $status, expected 1; "
check 2 "$work/run2.json" 'o.outcome' '"failed"' "outcome"
check 2 "$work/run2.json" 'o.certain' 'true' "certainty"
check 2 "$work/run2.json" 'o.exitStatus' '3' "exit status"
check 2 "$work/run2.json" 'o.finalState' '"sealed"' "final state"
check 2 "$work/run2.json" 'o.sealed' 'true' "sealed"
task2="$(field "$work/run2.json" 'o.binding.task' | tr -d '"')"
verify_log "$task2" "$(field "$work/run2.json" 'o.evidenceLog' | tr -d '"')" || problems+="the evidence log does not verify; "
if [[ -z "$problems" ]]; then
  pass fails_with_exit_status "an exit-3 workload ends failed, certain, with exit status 3 from the evidence log, and seals"
else
  fail fails_with_exit_status "$problems"
fi

# ---- case 3: cancellation is revoke, then seal ---------------------------------------------

problems=""
marker="ward-node-js-cancel-$$-$(date +%s%N)"
run "$work/run3.json" --task acc-task-3 --attempt acc-attempt-3a --budget-ms 600000 --cancel-after 1000 -- sh -c "sleep 300; echo $marker"
[[ "$status" == "1" ]] || problems+="exit status $status, expected 1; "
check 3 "$work/run3.json" 'o.cancelled' 'true' "cancelled"
check 3 "$work/run3.json" 'o.finalState' '"sealed"' "final state"
check 3 "$work/run3.json" 'o.sealed' 'true' "sealed"
check 3 "$work/run3.json" 'o.operations.map(x => x.verb).join()' '"create,admit,start,revoke,seal"' "operations"
check 3 "$work/run3.json" 'o.exitStatus' 'undefined' "no exit status"
outcome3="$(field "$work/run3.json" 'o.outcome')"
[[ "$outcome3" == '"failed"' || "$outcome3" == '"unknown"' ]] || problems+="outcome $outcome3; "
lease3="$(field "$work/run3.json" 'o.binding.lease' | tr -d '"')"
grep -q "\"$lease3\"" "$work/state/revocations.json" 2>/dev/null || problems+="the lease is not in revocations.json; "
for _ in $(seq 1 150); do
  pgrep -f "$marker" >/dev/null 2>&1 || break
  sleep 0.1
done
pgrep -f "$marker" >/dev/null 2>&1 && problems+="a workload process outlived the revocation; "
task3="$(field "$work/run3.json" 'o.binding.task' | tr -d '"')"
verify_log "$task3" "$(field "$work/run3.json" 'o.evidenceLog' | tr -d '"')" || problems+="the evidence log does not verify; "
if [[ -z "$problems" ]]; then
  pass cancel_is_revoke_then_seal "cancelling a running attempt revokes it (never stop), kills the workload, records the lease in revocations.json and seals a verifying log"
else
  fail cancel_is_revoke_then_seal "$problems"
fi

# ---- case 4: a replay after a control-plane restart acts on nothing ------------------------

problems=""
status=0
node "$client" replay "${common[@]}" --state-dir "$work/cp" --attempt "$attempt1" >"$work/replay1.json" 2>>"$work/client.log" || status=$?
[[ "$status" == "0" ]] || problems+="exit status $status; "
check 4 "$work/replay1.json" 'o.replayed' 'true' "replayed"
check 4 "$work/replay1.json" 'o.outcome' '"completed"' "outcome"
check 4 "$work/replay1.json" 'o.finalState' '"sealed"' "final state"
check 4 "$work/replay1.json" 'o.operations.map(x => x.verb).join()' '"create,admit,seal"' "no start on replay"
check 4 "$work/replay1.json" 'o.operations.map(x => x.state).join()' '"sealed,sealed,sealed"' "every replayed id answers sealed"
check 4 "$work/replay1.json" 'o.evidenceHead' "\"$head1\"" "same evidence head"
[[ "$(wc -l <"$work/tasks/$task1/$attempt1/out.txt" 2>/dev/null)" == "1" ]] || problems+="the workload ran again; "
if [[ -z "$problems" ]]; then
  pass replay_acts_on_nothing "a new client process replaying the recorded bytes and operation ids is answered sealed for create, admit and seal, sends no start, and the workload's output and evidence head are unchanged"
else
  fail replay_acts_on_nothing "$problems"
fi

# ---- case 5: the node holds the version strictly increasing; the counter satisfies it ------

problems=""
# A control plane that lost its counter would reissue version 1; the node refuses it.
cp "$work/cp/admission-versions.json" "$work/cp/admission-versions.backup"
node -e 'const fs = require("fs"); const p = process.argv[1]; const f = JSON.parse(fs.readFileSync(p, "utf8")); delete f.versions[process.argv[2]]; fs.writeFileSync(p, JSON.stringify(f));' "$work/cp/admission-versions.json" "$task1"
run "$work/run5a.json" --task acc-task-1 --attempt acc-attempt-1b --budget-ms 60000 -- sh -c 'true'
[[ "$status" == "1" ]] || problems+="stale exit status $status, expected 1; "
check 5 "$work/run5a.json" 'o.outcome' '"refused"' "stale outcome"
check 5 "$work/run5a.json" 'o.refused' '{"verb":"admit","reason":"stale_operation"}' "stale refusal"
check 5 "$work/run5a.json" 'o.version' '1' "stale version"
check 5 "$work/run5a.json" 'o.finalState' '"created"' "task left created"
# With the counter restored the retry is version 2, admitted and completed; the create of
# the attempt the refusal left `created` is replayed under the same operation id.
cp "$work/cp/admission-versions.backup" "$work/cp/admission-versions.json"
run "$work/run5b.json" --task acc-task-1 --attempt acc-attempt-1b --budget-ms 60000 -- sh -c 'true'
[[ "$status" == "0" ]] || problems+="retry exit status $status; "
check 5 "$work/run5b.json" 'o.outcome' '"completed"' "retry outcome"
check 5 "$work/run5b.json" 'o.version' '2' "retry version"
check 5 "$work/run5b.json" 'o.finalState' '"sealed"' "retry final state"
check 5 "$work/run5b.json" 'o.binding.task' "\"$task1\"" "same task"
[[ "$(field "$work/run5b.json" 'o.binding.attempt')" != "\"$attempt1\"" ]] || problems+="the retry reused the attempt id; "
verify_log "$task1" "$(field "$work/run5b.json" 'o.evidenceLog' | tr -d '"')" || problems+="the retry's evidence log does not verify; "
if [[ -z "$problems" ]]; then
  pass version_is_held_strictly_increasing "a new attempt of a task under a reissued version 1 is refused stale_operation by the node with nothing run; with the durable counter it is admitted as version 2 and completes"
else
  fail version_is_held_strictly_increasing "$problems"
fi

echo
echo "node-js acceptance: $passed passed, $failed failed"
if [[ "$failed" -eq 0 ]]; then
  echo "node-js acceptance: PASS"
  exit 0
fi
echo "node-js acceptance: FAIL"
echo "--- client log ---" >&2
cat "$work/client.log" >&2 2>/dev/null || true
echo "--- node log ---" >&2
cat "$work/node.log" >&2
exit 1
