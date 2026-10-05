#!/usr/bin/env bash
# Acceptance of the Node.js reference control plane (examples/node-control-plane,
# docs/node-integration-from-nodejs.md) against a real `ward-node`: the client generates
# its issuer key, the node is started with that key in its trust store, a task root and
# --output-return, and every byte the client sends is validated by the node itself. A
# second node without --output-return proves the refusal of an output grant. One verdict
# line per case on stdout,
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
plain_pid=""
# shellcheck disable=SC2317  # reached through the EXIT trap
cleanup() {
  local pid
  for pid in "$node_pid" "$plain_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
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

# host_digest <file>: BLAKE3-256 of a file on the host, with the client's own BLAKE3, to
# compare against the digest the node returned for the same file.
host_digest() {
  node --input-type=module -e 'import { readFileSync } from "node:fs"; import { blake3Hex } from "./examples/node-control-plane/blake3.mjs"; process.stdout.write(blake3Hex(readFileSync(process.argv[1])));' -- "$1"
}

# log_holds_digest <log> <hex>: whether the evidence log's bytes contain the 32-byte digest.
log_holds_digest() {
  node -e 'const fs = require("fs"); process.exit(fs.readFileSync(process.argv[1]).includes(Buffer.from(process.argv[2], "hex")) ? 0 : 1);' "$1" "$2" 2>/dev/null
}

# start_node <socket> <state-dir> <task-root> [flags…]: start a node, wait for its socket, print its pid.
start_node() {
  local socket=$1 state=$2 tasks=$3 pid
  shift 3
  "$WARD_NODE_BIN" --socket "$socket" --state-dir "$state" --node-id "$node_id" \
    --trusted-issuers "$work/trusted-issuers" --task-root "$tasks" "$@" >>"$work/node.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 100); do
    [[ -S "$socket" ]] && break
    kill -0 "$pid" 2>/dev/null || { cat "$work/node.log" >&2; die "ward-node exited before serving"; }
    sleep 0.1
  done
  [[ -S "$socket" ]] || die "ward-node did not bind its socket within 10 s"
  echo "$pid"
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

node_pid="$(start_node "$work/node.sock" "$work/state" "$work/tasks" --output-return)"

common=(--socket "$work/node.sock" --adapter "$WARD_NODE_ADAPTER_BIN")
node "$client" capabilities "${common[@]}" >"$work/capabilities.json"
[[ "$(field "$work/capabilities.json" 'o.lifecycle.start')" == "true" ]] \
  || die "the node does not execute here (lifecycle.start is not true): $(cat "$work/capabilities.json")"
[[ "$(field "$work/capabilities.json" 'o.output?.stdio === true && o.output?.files === true')" == "true" ]] \
  || die "a node started with --output-return does not report output.stdio and output.files: $(cat "$work/capabilities.json")"

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

# ---- case 6: a declared result comes back exactly, with digests the host agrees with ----

problems=""
run "$work/run6.json" --task acc-task-6 --attempt acc-attempt-6a --budget-ms 60000 \
  --stdio-bytes 4096 --files out/report.json,copy.txt --files missing.txt --files-bytes 2048 --out-dir "$work/out6" \
  -- sh -c 'printf "hello stdout\n"; printf "hello stderr\n" >&2; mkdir -p out; printf "{\"ok\":true}" > out/report.json; cat src/input.txt > copy.txt'
[[ "$status" == "0" ]] || problems+="exit status $status; "
check 6 "$work/run6.json" 'o.outcome' '"completed"' "outcome"
check 6 "$work/run6.json" 'o.exitStatus' '0' "exit status"
check 6 "$work/run6.json" 'o.output.stdout' '{"bytes":13,"truncated":false,"dropped":0,"content_base64":"aGVsbG8gc3Rkb3V0Cg=="}' "stdout"
check 6 "$work/run6.json" 'o.output.stderr' '{"bytes":13,"truncated":false,"dropped":0,"content_base64":"aGVsbG8gc3RkZXJyCg=="}' "stderr"
check 6 "$work/run6.json" 'o.output.truncated' 'false' "nothing truncated"
check 6 "$work/run6.json" 'o.outputMissing' 'false' "the granted output came back"
check 6 "$work/run6.json" 'o.output.files.map(f => f.path).join()' '"out/report.json,copy.txt,missing.txt"' "files in declaration order"
check 6 "$work/run6.json" 'o.output.files[2]' '{"path":"missing.txt","skipped":"missing"}' "missing file"
check 6 "$work/run6.json" 'o.output.files[0].size' '11' "report size"
check 6 "$work/run6.json" 'o.output.files[0].truncated' 'false' "report returned whole"
check 6 "$work/run6.json" 'o.output.files[0].content_base64' 'undefined' "content written, not printed"
check 6 "$work/run6.json" 'o.output.files[0].written' "\"$work/out6/out/report.json\"" "report written under --out-dir"
check 6 "$work/run6.json" 'o.output.files[1].written' "\"$work/out6/copy.txt\"" "copy written under --out-dir"
task6="$(field "$work/run6.json" 'o.binding.task' | tr -d '"')"
attempt6="$(field "$work/run6.json" 'o.binding.attempt' | tr -d '"')"
workspace6="$work/tasks/$task6/$attempt6"
for path in out/report.json copy.txt; do
  if [[ -f "$workspace6/$path" && -f "$work/out6/$path" ]]; then
    cmp -s "$workspace6/$path" "$work/out6/$path" || problems+="$path written differs from the workspace file; "
    [[ "$(stat -c %a "$work/out6/$path")" == "600" ]] || problems+="$path written with mode $(stat -c %a "$work/out6/$path"); "
    expected6="$(host_digest "$workspace6/$path")"
    check 6 "$work/run6.json" "o.output.files.find(f => f.path === \"$path\").digest" "\"$expected6\"" "$path digest equals the host file's"
  else
    problems+="$path is not both in the workspace and under --out-dir; "
  fi
done
[[ "$(cat "$work/out6/copy.txt" 2>/dev/null)" == "from the snapshot" ]] || problems+="copy.txt is not the snapshot's input; "
[[ ! -e "$work/out6/missing.txt" ]] || problems+="a skipped file was written; "
log6="$(field "$work/run6.json" 'o.evidenceLog' | tr -d '"')"
digest6="$(field "$work/run6.json" 'o.output.files[0].digest' | tr -d '"')"
# The NodeAttemptOutputCollected record carries the digest's 32 bytes (never the content).
log_holds_digest "$log6" "$digest6" || problems+="the node's evidence log does not record the returned digest; "
grep -q 'hello stdout' "$log6" 2>/dev/null && problems+="the evidence log carries output bytes; "
verify_log "$task6" "$log6" || problems+="the evidence log does not verify; "
# Reading the result again answers the same bytes, verified the same way.
status=0
node "$client" result "${common[@]}" --task "$task6" --attempt "$attempt6" \
  --lease "$(field "$work/run6.json" 'o.binding.lease' | tr -d '"')" >"$work/result6.json" 2>>"$work/client.log" || status=$?
[[ "$status" == "0" ]] || problems+="result exit status $status; "
check 6 "$work/result6.json" 'o.state' '"sealed"' "result state"
check 6 "$work/result6.json" 'o.output.stdout' "$(field "$work/run6.json" 'o.output.stdout')" "result stdout equals the run's"
check 6 "$work/result6.json" 'o.output.files.map(f => f.digest ?? f.skipped).join()' "$(field "$work/run6.json" 'o.output.files.map(f => f.digest ?? f.skipped).join()')" "result digests equal the run's"
if [[ -z "$problems" ]]; then
  pass output_returns_declared_content_with_matching_digests "a workload printing to both streams and writing two declared files returns exactly those bytes with dropped 0, each file's content equal to the file in the workspace on the host and its digest equal to the host file's BLAKE3-256 and recorded in the sealed log (which carries no output bytes), a missing path skipped, --out-dir holding the returned files mode 0600, and a later result answering the same bytes"
else
  fail output_returns_declared_content_with_matching_digests "$problems"
fi

# ---- case 7: past the budgets the heads come back with truncation marks -----------------

problems=""
run "$work/run7.json" --task acc-task-7 --attempt acc-attempt-7a --budget-ms 60000 \
  --stdio-bytes 1000 --files large.bin --files-bytes 100 \
  -- sh -c 'head -c 10000 /dev/zero | tr "\0" a; head -c 5000 /dev/zero | tr "\0" e >&2; head -c 4000 /dev/zero | tr "\0" f > large.bin'
[[ "$status" == "0" ]] || problems+="exit status $status; "
check 7 "$work/run7.json" 'o.outcome' '"completed"' "outcome"
check 7 "$work/run7.json" 'o.output.stdout.bytes' '1000' "stdout head"
check 7 "$work/run7.json" 'o.output.stdout.dropped' '9000' "stdout dropped"
check 7 "$work/run7.json" 'o.output.stdout.truncated' 'true' "stdout truncated"
check 7 "$work/run7.json" 'Buffer.from(o.output.stdout.content_base64, "base64").equals(Buffer.alloc(1000, "a"))' 'true' "stdout is the first 1000 bytes"
check 7 "$work/run7.json" 'o.output.stderr.bytes' '1000' "stderr head"
check 7 "$work/run7.json" 'o.output.stderr.dropped' '4000' "stderr dropped"
check 7 "$work/run7.json" 'Buffer.from(o.output.stderr.content_base64, "base64").equals(Buffer.alloc(1000, "e"))' 'true' "stderr is the first 1000 bytes"
check 7 "$work/run7.json" 'o.output.truncated' 'true' "result marked truncated"
task7="$(field "$work/run7.json" 'o.binding.task' | tr -d '"')"
attempt7="$(field "$work/run7.json" 'o.binding.attempt' | tr -d '"')"
if [[ -f "$work/tasks/$task7/$attempt7/large.bin" ]]; then
  expected7="$(host_digest "$work/tasks/$task7/$attempt7/large.bin")"
  check 7 "$work/run7.json" 'o.output.files[0]' "{\"path\":\"large.bin\",\"size\":4000,\"digest\":\"$expected7\",\"truncated\":true}" "large.bin digest-only with its true size and the host file's digest"
else
  problems+="large.bin is not in the workspace; "
fi
verify_log "$task7" "$(field "$work/run7.json" 'o.evidenceLog' | tr -d '"')" || problems+="the evidence log does not verify; "
if [[ -z "$problems" ]]; then
  pass output_marks_truncation_past_the_budgets "a workload writing 10000 bytes to stdout, 5000 to stderr and a 4000-byte file under a grant of 1000 stream bytes and 100 file bytes gets exactly the first 1000 bytes of each stream with truncated true and dropped 9000 and 4000, and the file digest-only with its true size and the host file's digest"
else
  fail output_marks_truncation_past_the_budgets "$problems"
fi

# ---- case 8: without --output-return the grant is refused, and the client says so ------

problems=""
plain_snapshot="$("$WARD_NODE_BIN" snapshot import --state-dir "$work/plain-state" "$work/project")"
plain_pid="$(start_node "$work/plain.sock" "$work/plain-state" "$work/plain-tasks")"
plain_common=(--socket "$work/plain.sock" --adapter "$WARD_NODE_ADAPTER_BIN")
node "$client" capabilities "${plain_common[@]}" >"$work/plain-capabilities.json"
[[ "$(field "$work/plain-capabilities.json" 'o.output')" == "undefined" ]] || problems+="a node without the flag reports an output section; "
status=0
node "$client" run "${plain_common[@]}" --key "$work/cp/issuer.pem" --principal acceptance-issuer --node "$node_id" \
  --state-dir "$work/cp" --snapshot "$plain_snapshot" --task-root "$work/plain-tasks" --timeout-ms 90000 \
  --task acc-task-8 --attempt acc-attempt-8a --budget-ms 60000 --stdio-bytes 16 --files x --files-bytes 16 \
  -- sh -c 'echo never' >"$work/run8.json" 2>>"$work/client.log" || status=$?
[[ "$status" == "1" ]] || problems+="exit status $status, expected 1; "
check 8 "$work/run8.json" 'o.outcome' '"refused"' "outcome"
check 8 "$work/run8.json" 'o.certain' 'true' "a refusal is certain"
check 8 "$work/run8.json" 'o.refused' '{"verb":"admit","reason":"unsupported_grant"}' "refusal"
check 8 "$work/run8.json" 'o.finalState' '"created"' "task left created"
check 8 "$work/run8.json" 'o.output' 'null' "no output"
check 8 "$work/run8.json" 'o.outputMissing' 'true' "the granted output is missing"
check 8 "$work/run8.json" 'o.operations.map(x => x.verb).join()' '"create,admit"' "nothing sent after the refusal"
task8="$(field "$work/run8.json" 'o.binding.task' | tr -d '"')"
[[ ! -e "$work/plain-tasks/$task8" ]] || problems+="a refused grant materialised a task directory; "
status=0
node "$client" result "${plain_common[@]}" --task "$task8" --attempt "$(field "$work/run8.json" 'o.binding.attempt' | tr -d '"')" \
  --lease "$(field "$work/run8.json" 'o.binding.lease' | tr -d '"')" >"$work/result8.json" 2>>"$work/client.log" || status=$?
[[ "$status" == "1" ]] || problems+="result exit status $status, expected 1; "
check 8 "$work/result8.json" 'o.rejected' '"unsupported_operation"' "result refused on a node without the flag"
# A grant above every node's ceilings is refused by the client before anything is signed or sent.
status=0
node "$client" run "${run_common[@]}" --task acc-task-8 --attempt acc-attempt-8b --budget-ms 60000 --stdio-bytes 1048577 \
  -- sh -c 'echo never' >"$work/run8b.json" 2>"$work/run8b.err" || status=$?
[[ "$status" == "2" ]] || problems+="over-ceiling exit status $status, expected 2; "
grep -q 'unsupported_grant' "$work/run8b.err" || problems+="the client's refusal does not name unsupported_grant: $(cat "$work/run8b.err"); "
[[ ! -s "$work/run8b.json" ]] || problems+="an over-ceiling grant printed an outcome; "
[[ ! -e "$work/cp/runs/$(node "$client" derive-id exec acc-attempt-8b).json" ]] || problems+="an over-ceiling grant was recorded as a run; "
if [[ -z "$problems" ]]; then
  pass output_grant_is_refused_without_the_flag "a node started without --output-return reports no output capability and refuses an output grant unsupported_grant at admit with nothing run or materialised, which the client reports as refused (certain, not unknown) and exits 1; its result is unsupported_operation; and a grant above the ceilings is refused by the client before signing"
else
  fail output_grant_is_refused_without_the_flag "$problems"
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
