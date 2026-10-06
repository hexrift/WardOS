#!/usr/bin/env bash
# Acceptance of the Node.js reference control plane (examples/node-control-plane,
# docs/node-integration-from-nodejs.md) against a real `ward-node`: the client generates
# its issuer key, the node is started with that key in its trust store, a task root,
# --output-return and --action-channel, and every byte the client sends is validated by the
# node itself. A second node without either flag proves the refusal of an output grant and
# of an actions grant. The action-channel cases run a Python agent in the sandbox that asks
# through /run/ward/actions.sock and proceeds only on an approval, and read the sealed
# evidence log's action records back byte for byte. One verdict line per case on stdout,
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
background=()
# shellcheck disable=SC2317  # reached through the EXIT trap
cleanup() {
  local pid
  for pid in "${background[@]}" "$node_pid" "$plain_pid"; do
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

# text_digest <text>: BLAKE3-256 of the UTF-8 bytes of a text, as the node digests a summary,
# detail or note (node-integration.md §6.7).
text_digest() {
  node --input-type=module -e 'import { blake3Hex } from "./examples/node-control-plane/blake3.mjs"; process.stdout.write(blake3Hex(Buffer.from(process.argv[1], "utf8")));' -- "$1"
}

# action_records <log> <out>: the evidence log's records as one JSON line, read from the raw
# bytes: every frame (`WE`, version 1, kind 1, u32 length, the postcard record) is walked,
# each record's event named by its variant, and the three action records decoded field by
# field (ward-events' NodeActionRequested, NodeActionAnswered, NodeActionRefused; ADR-0031
# §4). A record that does not decode exactly up to its own hash fails the read.
action_records() {
  # shellcheck disable=SC2016  # JavaScript, not shell: its ${…} are template literals
  node --input-type=module -e '
    import { readFileSync, writeFileSync } from "node:fs";
    const NAMES = { 40: "NodeAttemptAdmitted", 41: "NodeAttemptLaunched", 42: "NodeAttemptIntervened", 43: "NodeAttemptEnded", 44: "NodeAttemptRecovered", 45: "NodeAttemptSealed", 46: "NodeAttemptOutputCollected", 47: "NodeAttemptResourceUsage", 48: "NodeActionRequested", 49: "NodeActionAnswered", 50: "NodeActionRefused" };
    const KINDS = ["approval", "decision"];
    const DECISIONS = ["approved", "denied", "expired", "cancelled"];
    const REFUSALS = ["oversized", "malformed", "control_request", "kind_not_granted", "duplicate_id", "too_many_pending", "too_many_requests"];
    const bytes = readFileSync(process.argv[1]);
    const records = [];
    let at = 0;
    while (at < bytes.length) {
      if (bytes.toString("latin1", at, at + 2) !== "WE" || bytes[at + 2] !== 1 || bytes[at + 3] !== 1) throw new Error(`no record frame at byte ${at}`);
      const payload = bytes.subarray(at + 8, at + 8 + bytes.readUInt32LE(at + 4));
      at += 8 + payload.length;
      let p = 16;
      const varint = () => {
        let value = 0;
        for (let shift = 0; ; shift += 7) {
          const byte = payload[p++];
          value += (byte & 0x7f) * 2 ** shift;
          if ((byte & 0x80) === 0) return value;
        }
      };
      const hash = () => payload.subarray(p, (p += 32)).toString("hex");
      const seq = varint();
      varint(); varint();
      if (payload[p++] === 1) { varint(); varint(); }
      varint();
      p += 32;
      const variant = varint();
      const record = { seq, event: NAMES[variant] ?? `event ${variant}` };
      if (variant === 48) Object.assign(record, { action: varint(), kind: KINDS[varint()], summary_bytes: varint(), summary: hash(), detail_bytes: varint(), detail: hash() });
      if (variant === 49) Object.assign(record, { action: varint(), decision: DECISIONS[varint()], operation: payload[p++] === 1 ? varint() : null, note_bytes: varint(), note: payload[p++] === 1 ? hash() : null });
      if (variant === 50) Object.assign(record, { reason: REFUSALS[varint()], bytes: varint() });
      if (variant >= 48 && variant <= 50 && p + 32 !== payload.length) throw new Error(`record ${seq} does not decode as ${record.event}`);
      records.push(record);
    }
    writeFileSync(process.argv[2], JSON.stringify(records));
  ' -- "$1" "$2"
}

# wait_listing <attempt> <expression> <expected-json> <out>: poll the client's own `actions`
# (from the run record) until the expression on the listing has the expected value; 60 s at
# most. A condition, not a fixed sleep.
wait_listing() {
  local attempt=$1 expression=$2 expected=$3 out=$4
  for _ in $(seq 1 600); do
    if node "$client" actions "${common[@]}" --state-dir "$work/cp" --attempt "$attempt" >"$out" 2>/dev/null \
      && [[ "$(field "$out" "$expression")" == "$expected" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
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
# The action-channel workload (node-integration.md §6.7): asks each id given on its command
# line in turn, on one connection, records every reply, and proceeds (writes `proceeded`,
# exits 0) only when every answer was `approved`; denied, expired and cancelled exit 3, 4
# and 5, a missing channel 8 and an end of file without a reply 6.
cat >"$work/project/agent.py" <<'AGENT'
import json
import os
import socket
import sys

SUMMARY = "deploy to staging"
DETAIL = "plan: rotate 3 services"
EXIT = {"denied": 3, "expired": 4, "cancelled": 5}

path = os.environ.get("WARD_ACTION_SOCKET")
if path != "/run/ward/actions.sock":
    sys.exit(8)
peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
peer.settimeout(900)
peer.connect(path)
replies = []
for rid in sys.argv[1:]:
    line = json.dumps({"id": rid, "kind": "approval", "summary": SUMMARY, "detail": DETAIL})
    peer.sendall((line + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = peer.recv(4096)
        if not chunk:
            break
        data += chunk
    reply = json.loads(data) if data.endswith(b"\n") else None
    replies.append(reply)
    with open("replies.json", "w") as out:
        json.dump(replies, out)
    if reply is None:
        sys.exit(6)
    if reply.get("id") != rid or reply.get("decision") != "approved":
        sys.exit(EXIT.get(reply.get("decision"), 7))
with open("proceeded", "w") as out:
    out.write("yes")
AGENT
snapshot="$("$WARD_NODE_BIN" snapshot import --state-dir "$work/state" "$work/project")"
[[ "$snapshot" =~ ^[0-9a-f]{64}$ ]] || die "snapshot import printed no id: $snapshot"

node_pid="$(start_node "$work/node.sock" "$work/state" "$work/tasks" --output-return --action-channel)"

common=(--socket "$work/node.sock" --adapter "$WARD_NODE_ADAPTER_BIN")
node "$client" capabilities "${common[@]}" >"$work/capabilities.json"
[[ "$(field "$work/capabilities.json" 'o.lifecycle.start')" == "true" ]] \
  || die "the node does not execute here (lifecycle.start is not true): $(cat "$work/capabilities.json")"
[[ "$(field "$work/capabilities.json" 'o.output?.stdio === true && o.output?.files === true')" == "true" ]] \
  || die "a node started with --output-return does not report output.stdio and output.files: $(cat "$work/capabilities.json")"
[[ "$(field "$work/capabilities.json" 'o.actions')" == '{"approval":true,"decision":true,"max_pending":8,"max_total":64,"max_wait_secs":3600}' ]] \
  || die "a node started with --action-channel does not report the actions section with the ceilings: $(cat "$work/capabilities.json")"

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
  got="$(field "$2" "$3" 2>/dev/null)" || got="<unreadable>"
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

# ---- the action channel (node-integration.md §6.7, ADR-0031) ------------------------------

summary_digest="$(text_digest "deploy to staging")"
detail_digest="$(text_digest "plan: rotate 3 services")"

# requested_ok <case> <records> <action>: the request is recorded with the summary's and the
# detail's sizes and digests, never their text.
requested_ok() {
  check "$1" "$2" "o.filter(r => r.event === \"NodeActionRequested\" && r.action === $3).map(r => [r.kind, r.summary_bytes, r.summary, r.detail_bytes, r.detail])" \
    "[[\"approval\",17,\"$summary_digest\",23,\"$detail_digest\"]]" "request $3 recorded with its digests"
}

# answered_before_end <case> <records> <action> <decision> <operation|null> <note|"">: the
# one answer to the request is recorded as given, before NodeAttemptEnded.
answered_before_end() {
  local note_json='[0,null]'
  if [[ -n "$6" ]]; then
    note_json="[${#6},\"$(text_digest "$6")\"]"
  fi
  check "$1" "$2" "o.filter(r => r.event === \"NodeActionAnswered\" && r.action === $3).map(r => [r.decision, r.operation, [r.note_bytes, r.note]])" \
    "[[\"$4\",$5,$note_json]]" "the answer to request $3 recorded once"
  check "$1" "$2" 'o.findIndex(r => r.event === "NodeActionAnswered" && r.action === '"$3"') < o.findIndex(r => r.event === "NodeAttemptEnded")' 'true' "answer recorded before the end"
}

# log_free_of_text <log>: the sealed log carries no summary, detail or note text.
log_free_of_text() {
  ! grep -aq -e 'deploy to staging' -e 'rotate 3 services' -e 'by acceptance' -e 'second process' "$1"
}

# ---- case 9: an approval lets the workload proceed --------------------------------------

problems=""
run "$work/run9.json" --task acc-task-9 --attempt acc-attempt-9a --budget-ms 120000 \
  --actions approval --actions-wait-secs 120 --approve-all --note "approved by acceptance" \
  -- python3 agent.py deploy-9
[[ "$status" == "0" ]] || problems+="exit status $status; "
check 9 "$work/run9.json" 'o.outcome' '"completed"' "outcome"
check 9 "$work/run9.json" 'o.exitStatus' '0' "exit status"
check 9 "$work/run9.json" 'o.actions' '[{"request":1,"id":"deploy-9","kind":"approval","summary":"deploy to staging","decision":"approved","note":"approved by acceptance","operation_id":263,"result":"answered","replayed":false}]' "the request and its answer"
task9="$(field "$work/run9.json" 'o.binding.task' | tr -d '"')"
attempt9="$(field "$work/run9.json" 'o.binding.attempt' | tr -d '"')"
workspace9="$work/tasks/$task9/$attempt9"
check 9 "$workspace9/replies.json" 'o' '[{"id":"deploy-9","decision":"approved","note":"approved by acceptance"}]' "the workload received the approval with the note"
[[ -f "$workspace9/proceeded" ]] || problems+="the workload did not proceed; "
check 9 "$work/cp/runs/$attempt9.json" 'o.answers' '[{"request":1,"id":"deploy-9","kind":"approval","decision":"approved","note":"approved by acceptance","operation_id":263}]' "the answer in the run record"
grep -q 'request 1 (approval, id deploy-9): deploy to staging' "$work/client.log" || problems+="the request was not printed; "
grep -q 'request 1 answered approved (operation 263)' "$work/client.log" || problems+="the answer was not printed; "
[[ ! -e "$work/tasks/$task9/$attempt9.actions/actions.sock" ]] || problems+="the channel socket outlived the attempt; "
log9="$(field "$work/run9.json" 'o.evidenceLog' | tr -d '"')"
if action_records "$log9" "$work/records9.json"; then
  requested_ok 9 "$work/records9.json" 1
  answered_before_end 9 "$work/records9.json" 1 approved 263 "approved by acceptance"
else
  problems+="the evidence log's records do not decode; "
fi
log_free_of_text "$log9" || problems+="the evidence log carries request or note text; "
verify_log "$task9" "$log9" || problems+="the evidence log does not verify; "
if [[ -z "$problems" ]]; then
  pass actions_approval_lets_the_workload_proceed "a workload granted the channel on a node started with --action-channel asks through /run/ward/actions.sock; run --approve-all lists the request, records the answer in the run record under operation 263 of its scheme, answers it approved with the note from a second adapter, the workload receives exactly that and exits 0, and the sealed log records the request's summary and detail digests and the approval with that operation id and the note's digest before the attempt's end, never the text"
else
  fail actions_approval_lets_the_workload_proceed "$problems"
fi

# ---- case 10: a denial stops it -----------------------------------------------------------

problems=""
run "$work/run10.json" --task acc-task-10 --attempt acc-attempt-10a --budget-ms 120000 \
  --actions approval --actions-wait-secs 120 --deny-all --note "denied by acceptance" \
  -- python3 agent.py deploy-10
[[ "$status" == "1" ]] || problems+="exit status $status, expected 1; "
check 10 "$work/run10.json" 'o.outcome' '"failed"' "outcome"
check 10 "$work/run10.json" 'o.exitStatus' '3' "the workload's denied exit status"
check 10 "$work/run10.json" 'o.actions.map(a => [a.request, a.decision, a.operation_id, a.result])' '[[1,"denied",263,"answered"]]' "the answer"
task10="$(field "$work/run10.json" 'o.binding.task' | tr -d '"')"
attempt10="$(field "$work/run10.json" 'o.binding.attempt' | tr -d '"')"
check 10 "$work/tasks/$task10/$attempt10/replies.json" 'o' '[{"id":"deploy-10","decision":"denied","note":"denied by acceptance"}]' "the workload received the denial"
[[ ! -e "$work/tasks/$task10/$attempt10/proceeded" ]] || problems+="the workload proceeded on a denial; "
log10="$(field "$work/run10.json" 'o.evidenceLog' | tr -d '"')"
if action_records "$log10" "$work/records10.json"; then
  requested_ok 10 "$work/records10.json" 1
  answered_before_end 10 "$work/records10.json" 1 denied 263 "denied by acceptance"
else
  problems+="the evidence log's records do not decode; "
fi
log_free_of_text "$log10" || problems+="the evidence log carries request or note text; "
verify_log "$task10" "$log10" || problems+="the evidence log does not verify; "
if [[ -z "$problems" ]]; then
  pass actions_denial_stops_the_workload "run --deny-all answers the request denied; the workload receives the denial, does not proceed and exits 3, the run ends failed and exits 1, and the sealed log records the denial under operation 263 with the note's digest before the end"
else
  fail actions_denial_stops_the_workload "$problems"
fi

# ---- case 11: a request nobody answers expires ---------------------------------------------

problems=""
run "$work/run11.json" --task acc-task-11 --attempt acc-attempt-11a --budget-ms 120000 \
  --actions approval --actions-wait-secs 2 -- python3 agent.py deploy-11
[[ "$status" == "1" ]] || problems+="exit status $status, expected 1; "
check 11 "$work/run11.json" 'o.outcome' '"failed"' "outcome"
check 11 "$work/run11.json" 'o.exitStatus' '4' "the workload's expired exit status"
check 11 "$work/run11.json" 'o.actions' '[]' "nobody here answered"
task11="$(field "$work/run11.json" 'o.binding.task' | tr -d '"')"
attempt11="$(field "$work/run11.json" 'o.binding.attempt' | tr -d '"')"
check 11 "$work/tasks/$task11/$attempt11/replies.json" 'o' '[{"id":"deploy-11","decision":"expired"}]' "the workload received expired"
log11="$(field "$work/run11.json" 'o.evidenceLog' | tr -d '"')"
if action_records "$log11" "$work/records11.json"; then
  requested_ok 11 "$work/records11.json" 1
  answered_before_end 11 "$work/records11.json" 1 expired null ""
else
  problems+="the evidence log's records do not decode; "
fi
verify_log "$task11" "$log11" || problems+="the evidence log does not verify; "
# A late answer, from the run record, is refused: the attempt has ended.
status=0
node "$client" answer "${common[@]}" --state-dir "$work/cp" --attempt "$attempt11" --request 1 --decision approved \
  >"$work/answer11.json" 2>>"$work/client.log" || status=$?
[[ "$status" == "1" ]] || problems+="late answer exit status $status, expected 1; "
check 11 "$work/answer11.json" 'o' '{"result":"rejected","reason":"invalid_state","operation_id":263}' "late answer"
status=0
node "$client" actions "${common[@]}" --state-dir "$work/cp" --attempt "$attempt11" >"$work/actions11.json" 2>>"$work/client.log" || status=$?
[[ "$status" == "0" ]] || problems+="actions exit status $status; "
check 11 "$work/actions11.json" 'o' '{"state":"sealed","pending":[]}' "nothing pending once sealed"
if [[ -z "$problems" ]]; then
  pass actions_unanswered_request_expires "a request nobody answers is answered expired by the node once the grant's wait_secs (2) ran out; the workload fails closed with exit 4, the sealed log records the expiry with no operation id and no note before the end, a late answer from the run record is refused invalid_state and the listing of the sealed attempt is empty"
else
  fail actions_unanswered_request_expires "$problems"
fi

# ---- case 12: cancelling while a request is pending answers it cancelled ------------------

problems=""
marker12="cancel-12-$$-$(date +%s%N)"
attempt12="$(node "$client" derive-id exec acc-attempt-12a)"
node "$client" run "${run_common[@]}" --task acc-task-12 --attempt acc-attempt-12a --budget-ms 600000 \
  --actions approval --actions-wait-secs 600 -- python3 agent.py "$marker12" >"$work/run12.json" 2>>"$work/client.log" &
run12_pid=$!
background+=("$run12_pid")
if wait_listing "$attempt12" 'o.pending.length' '1' "$work/actions12.json"; then
  check 12 "$work/actions12.json" 'o.state' '"running"' "listed running"
  check 12 "$work/actions12.json" 'o.pending.map(p => [p.action, p.id, p.kind, p.summary, p.detail])' "[[1,\"$marker12\",\"approval\",\"deploy to staging\",\"plan: rotate 3 services\"]]" "the pending request"
  check 12 "$work/actions12.json" 'o.pending[0].expires_in_ms > 0 && o.pending[0].expires_in_ms <= 600000' 'true' "its wait"
else
  problems+="the request was never listed; "
fi
kill -TERM "$run12_pid" 2>/dev/null || true
status=0
wait "$run12_pid" || status=$?
[[ "$status" == "1" ]] || problems+="exit status $status, expected 1; "
check 12 "$work/run12.json" 'o.cancelled' 'true' "cancelled"
check 12 "$work/run12.json" 'o.finalState' '"sealed"' "final state"
check 12 "$work/run12.json" 'o.operations.map(x => x.verb).join()' '"create,admit,start,revoke,seal"' "revoke, then seal"
for _ in $(seq 1 150); do
  pgrep -f "$marker12" >/dev/null 2>&1 || break
  sleep 0.1
done
pgrep -f "$marker12" >/dev/null 2>&1 && problems+="a workload process outlived the cancellation; "
task12="$(field "$work/run12.json" 'o.binding.task' | tr -d '"')"
log12="$(field "$work/run12.json" 'o.evidenceLog' | tr -d '"')"
if action_records "$log12" "$work/records12.json"; then
  requested_ok 12 "$work/records12.json" 1
  answered_before_end 12 "$work/records12.json" 1 cancelled null ""
else
  problems+="the evidence log's records do not decode; "
fi
verify_log "$task12" "$log12" || problems+="the evidence log does not verify; "
status=0
node "$client" answer "${common[@]}" --state-dir "$work/cp" --attempt "$attempt12" --request 1 --decision approved \
  >"$work/answer12.json" 2>>"$work/client.log" || status=$?
check 12 "$work/answer12.json" 'o.reason' '"invalid_state"' "a late answer"
node "$client" actions "${common[@]}" --state-dir "$work/cp" --attempt "$attempt12" >"$work/actions12-end.json" 2>>"$work/client.log" || true
check 12 "$work/actions12-end.json" 'o' '{"state":"sealed","pending":[]}' "nothing pending once sealed"
if [[ -z "$problems" ]]; then
  pass actions_cancel_while_pending_answers_cancelled "while the workload waits on a request the client's actions lists it with its id, kind, summary, detail and wait; cancelling the run (SIGTERM: revoke, then seal) kills the workload, the node answers the request cancelled and the sealed log records that with no operation id before the end, a late answer is refused invalid_state and nothing is pending"
else
  fail actions_cancel_while_pending_answers_cancelled "$problems"
fi

# ---- case 13: answered from a second process, idempotently, with each refusal ------------

problems=""
attempt13="$(node "$client" derive-id exec acc-attempt-13a)"
node "$client" run "${run_common[@]}" --task acc-task-13 --attempt acc-attempt-13a --budget-ms 300000 \
  --actions approval --actions-wait-secs 300 -- python3 agent.py second-13a second-13b >"$work/run13.json" 2>>"$work/client.log" &
run13_pid=$!
background+=("$run13_pid")
answer13() {
  local out=$1
  shift
  status=0
  node "$client" answer "${common[@]}" "$@" >"$out" 2>>"$work/client.log" || status=$?
}
wait_listing "$attempt13" 'o.pending.length' '1' "$work/actions13a.json" || problems+="the first request was never listed; "
check 13 "$work/actions13a.json" 'o.pending.map(p => [p.action, p.id])' '[[1,"second-13a"]]' "the first request"
answer13 "$work/answer13a.json" --state-dir "$work/cp" --attempt "$attempt13" --request 1 --decision approved --note "from a second process"
[[ "$status" == "0" ]] || problems+="first answer exit status $status; "
check 13 "$work/answer13a.json" 'o' '{"result":"answered","request":1,"decision":"approved","operation_id":263}' "first answer"
# The workload received it and asks again; while it waits, the first request is answered.
wait_listing "$attempt13" 'o.pending.map(p => p.action).join()' '"2"' "$work/actions13b.json" || problems+="the second request was never listed; "
check 13 "$work/actions13b.json" 'o.pending.map(p => [p.action, p.id])' '[[2,"second-13b"]]' "the second request, after the approval"
answer13 "$work/answer13-replay.json" --state-dir "$work/cp" --attempt "$attempt13" --request 1 --decision approved --note "from a second process"
[[ "$status" == "0" ]] || problems+="replay exit status $status; "
check 13 "$work/answer13-replay.json" 'o' '{"result":"answered","request":1,"decision":"approved","operation_id":263}' "the replay is answered again"
binding13=(--task "$(node "$client" derive-id task acc-task-13)" --attempt "$attempt13" --lease "$(node "$client" derive-id lease acc-attempt-13a)")
answer13 "$work/answer13-stale.json" "${binding13[@]}" --operation-id 263 --request 1 --decision denied
[[ "$status" == "1" ]] || problems+="stale exit status $status; "
check 13 "$work/answer13-stale.json" 'o' '{"result":"rejected","reason":"stale_operation","operation_id":263}' "the same id with another answer"
answer13 "$work/answer13-again.json" "${binding13[@]}" --operation-id 300 --request 1 --decision denied
check 13 "$work/answer13-again.json" 'o' '{"result":"rejected","reason":"already_answered","operation_id":300}' "another answer to an answered request"
answer13 "$work/answer13-unknown.json" "${binding13[@]}" --operation-id 301 --request 9 --decision denied
check 13 "$work/answer13-unknown.json" 'o' '{"result":"rejected","reason":"unknown_request","operation_id":301}' "a request number never recorded"
answer13 "$work/answer13b.json" --state-dir "$work/cp" --attempt "$attempt13" --request 2 --decision approved
check 13 "$work/answer13b.json" 'o' '{"result":"answered","request":2,"decision":"approved","operation_id":264}' "second answer"
status=0
wait "$run13_pid" || status=$?
[[ "$status" == "0" ]] || problems+="run exit status $status; "
check 13 "$work/run13.json" 'o.outcome' '"completed"' "outcome"
check 13 "$work/run13.json" 'o.actions' '[]' "the run itself answered nothing"
task13="$(field "$work/run13.json" 'o.binding.task' | tr -d '"')"
check 13 "$work/tasks/$task13/$attempt13/replies.json" 'o.map(r => r.decision).join()' '"approved,approved"' "the workload's replies"
[[ -f "$work/tasks/$task13/$attempt13/proceeded" ]] || problems+="the workload did not proceed; "
check 13 "$work/cp/runs/$attempt13.json" 'o.answers.map(a => [a.request, a.decision, a.operation_id])' '[[1,"approved",263],[2,"approved",264]]' "the run record"
log13="$(field "$work/run13.json" 'o.evidenceLog' | tr -d '"')"
if action_records "$log13" "$work/records13.json"; then
  check 13 "$work/records13.json" 'o.filter(r => r.event === "NodeActionAnswered").map(r => [r.action, r.decision, r.operation])' '[[1,"approved",263],[2,"approved",264]]' "exactly the two applied answers, nothing for the replay or the refusals"
  answered_before_end 13 "$work/records13.json" 1 approved 263 "from a second process"
else
  problems+="the evidence log's records do not decode; "
fi
log_free_of_text "$log13" || problems+="the evidence log carries request or note text; "
verify_log "$task13" "$log13" || problems+="the evidence log does not verify; "
if [[ -z "$problems" ]]; then
  pass actions_answered_from_a_second_process "a run granted the channel without a policy is answered from separate actions and answer processes through the run record: the answer takes operation 263 of the record's scheme, replaying it is answered again, the same id with another answer is stale_operation, another answer to the request already_answered and an unknown number unknown_request; the workload proceeds after both approvals and the sealed log holds exactly the two applied answers"
else
  fail actions_answered_from_a_second_process "$problems"
fi

# ---- case 14: a node without the flag, or a grant above the ceilings, is refused ---------

problems=""
[[ "$(field "$work/plain-capabilities.json" 'o.actions')" == "undefined" ]] || problems+="a node without the flag reports an actions section; "
status=0
node "$client" run "${plain_common[@]}" --key "$work/cp/issuer.pem" --principal acceptance-issuer --node "$node_id" \
  --state-dir "$work/cp" --snapshot "$plain_snapshot" --task-root "$work/plain-tasks" --timeout-ms 90000 \
  --task acc-task-14 --attempt acc-attempt-14a --budget-ms 60000 --actions approval --approve-all \
  -- python3 agent.py never-14 >"$work/run14.json" 2>>"$work/client.log" || status=$?
[[ "$status" == "1" ]] || problems+="exit status $status, expected 1; "
check 14 "$work/run14.json" 'o.outcome' '"refused"' "outcome"
check 14 "$work/run14.json" 'o.refused' '{"verb":"admit","reason":"unsupported_grant"}' "refusal"
check 14 "$work/run14.json" 'o.actions' '[]' "nothing answered"
task14="$(field "$work/run14.json" 'o.binding.task' | tr -d '"')"
[[ ! -e "$work/plain-tasks/$task14" ]] || problems+="a refused grant materialised a task directory; "
status=0
node "$client" actions "${plain_common[@]}" --state-dir "$work/cp" --attempt "$(node "$client" derive-id exec acc-attempt-14a)" \
  >"$work/actions14.json" 2>>"$work/client.log" || status=$?
[[ "$status" == "1" ]] || problems+="actions exit status $status, expected 1; "
check 14 "$work/actions14.json" 'o' '{"rejected":"unsupported_operation"}' "actions on a node without the flag"
status=0
node "$client" run "${run_common[@]}" --task acc-task-14 --attempt acc-attempt-14b --budget-ms 60000 \
  --actions approval --actions-max-pending 9 --actions-max-total 9 --approve-all \
  -- python3 agent.py never-14 >"$work/run14b.json" 2>"$work/run14b.err" || status=$?
[[ "$status" == "2" ]] || problems+="over-ceiling exit status $status, expected 2; "
grep -q 'unsupported_grant' "$work/run14b.err" || problems+="the client's refusal does not name unsupported_grant: $(cat "$work/run14b.err"); "
[[ ! -s "$work/run14b.json" ]] || problems+="an over-ceiling grant printed an outcome; "
[[ ! -e "$work/cp/runs/$(node "$client" derive-id exec acc-attempt-14b).json" ]] || problems+="an over-ceiling grant was recorded as a run; "
status=0
node "$client" run "${run_common[@]}" --task acc-task-14 --attempt acc-attempt-14c --budget-ms 60000 \
  --actions credential -- python3 agent.py never-14 >"$work/run14c.json" 2>"$work/run14c.err" || status=$?
[[ "$status" == "2" ]] || problems+="unknown kind exit status $status, expected 2; "
grep -q 'credential' "$work/run14c.err" || problems+="the client's refusal does not name the kind: $(cat "$work/run14c.err"); "
if [[ -z "$problems" ]]; then
  pass actions_grant_is_refused_without_the_flag_or_outside_the_grammar "a node started without --action-channel reports no actions section and refuses an actions grant unsupported_grant at admit with nothing materialised, which the client reports refused and exits 1, and answers actions unsupported_operation; a grant above the ceilings or with an unknown kind is refused by the client before signing or recording"
else
  fail actions_grant_is_refused_without_the_flag_or_outside_the_grammar "$problems"
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
