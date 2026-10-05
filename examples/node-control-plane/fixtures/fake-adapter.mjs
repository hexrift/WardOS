// A stand-in for `ward-node-adapter` (node-integration.md §11.4) for the framing tests:
// it speaks the adapter's JSON-lines protocol on stdin/stdout, records every line it
// received in FAKE_ADAPTER_LOG, and never touches a node. With FAKE_ADAPTER_HOLD=1 a
// run stays `running` until SIGTERM, which it answers the way the real adapter does: the
// attempt is revoked and sealed, `done` is written, and the process exits.
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const log = process.env.FAKE_ADAPTER_LOG;
const hold = process.env.FAKE_ADAPTER_HOLD === "1";
const socketFlag = process.argv.indexOf("--socket");
const socket = socketFlag >= 0 ? process.argv[socketFlag + 1] : null;

function emit(event) {
  process.stdout.write(`${JSON.stringify({ ...event, schema: 1 })}\n`);
}

const CAPABILITIES = {
  protocol: { major: 1, minor: 3 },
  architecture: "x86_64",
  capacity: { logical_cpus: 2, memory_bytes: 4294967296 },
  isolation: { namespaces: { sandbox: true, user_namespace: true }, backends: { container: false, microvm: false, vm: false } },
  network: { offline: true, proxy_allowlist: false },
  credentials: { proxy_injection: false, scoped_http_gateway: false },
  snapshots: { content_addressed: true, diff: false, read: false },
  verifier: { isolated: false },
  lifecycle: { pause: true, stop: true, revoke: true, admit: true, start: true },
};

let failed = false;
let running = null;

function finish(binding, ids, state, outcome, cancelled, operations, evidence) {
  emit({ event: "receipt", state, outcome });
  operations.push({ verb: "seal", operation_id: ids.seal, state: "sealed", reason: null });
  emit({ event: "state", verb: "seal", operation_id: ids.seal, state: "sealed" });
  if (evidence) emit({ event: "evidence", path: evidence });
  emit({
    event: "done",
    report: {
      binding,
      final_state: "sealed",
      outcome: outcome === "completed" ? "completed" : outcome === "failed" ? "failed" : "unknown",
      outcome_certain: outcome !== "unknown",
      receipt: outcome,
      cause: cancelled ? "Killed" : outcome === "completed" ? { Exited: { code: 0 } } : { Exited: { code: 3 } },
      sealed: true,
      cancelled,
      deadline_exceeded: false,
      evidence_log: evidence,
      evidence_head: evidence ? "3ac2d55f".padEnd(64, "0") : null,
      operations,
      transport_error: null,
    },
  });
}

process.on("SIGTERM", () => {
  if (running === null) process.exit(0);
  const { binding, ids, operations, evidence } = running;
  operations.push({ verb: "revoke", operation_id: ids.revoke, state: "revoked", reason: null });
  emit({ event: "state", verb: "revoke", operation_id: ids.revoke, state: "revoked" });
  finish(binding, ids, "revoked", "failed", true, operations, evidence);
  process.exit(0);
});

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", (line) => {
  if (log) appendFileSync(log, `${line}\n`);
  if (line.trim() === "") return;
  let command;
  try {
    command = JSON.parse(line);
  } catch {
    failed = true;
    emit({ event: "error", error: "command line is not a JSON object with a `cmd` string" });
    return;
  }
  switch (command.cmd) {
    case "capabilities":
      emit({ event: "capabilities", protocol: { major: 1, minor: 3 }, capabilities: { ...CAPABILITIES, socket } });
      return;
    case "inspect":
      emit({ event: "inspected", state: "sealed", outcome: "completed" });
      return;
    case "revoke":
      emit({ event: "verb", verb: "revoke", operation_id: command.operation_id, result: "accepted", state: "revoked" });
      return;
    case "run": {
      if (typeof command.envelope_json !== "string" || typeof command.proof?.signature !== "string") {
        failed = true;
        emit({ event: "error", error: "run takes envelope_json and proof" });
        return;
      }
      let envelope;
      try {
        envelope = JSON.parse(command.envelope_json);
      } catch {
        failed = true;
        emit({ event: "error", error: "envelope_json is not a valid envelope" });
        return;
      }
      const startAt = command.operation_ids?.start_at ?? 1;
      const ids = { create: startAt, admit: startAt + 1, start: startAt + 2, stop: startAt + 3, revoke: startAt + 4, seal: startAt + 5 };
      const binding = envelope.binding;
      const evidence = command.task_root ? `${command.task_root}/${binding.task}/${binding.attempt}.evidence/events.log` : null;
      const operations = [];
      for (const [verb, state] of [["create", "created"], ["admit", "ready"]]) {
        operations.push({ verb, operation_id: ids[verb], state, reason: null });
        emit({ event: "state", verb, operation_id: ids[verb], state });
      }
      emit({ event: "admitted", envelope_json: command.envelope_json, proof: command.proof });
      operations.push({ verb: "start", operation_id: ids.start, state: "running", reason: null });
      emit({ event: "state", verb: "start", operation_id: ids.start, state: "running" });
      if (hold) {
        running = { binding, ids, operations, evidence };
        return;
      }
      const exitStatus = envelope.workload.argv.at(-1) === "exit 3" ? 3 : 0;
      finish(binding, ids, "exited", exitStatus === 0 ? "completed" : "failed", false, operations, evidence);
      return;
    }
    default:
      failed = true;
      emit({ event: "error", error: `unknown command \`${command.cmd}\`` });
  }
});
lines.on("close", () => process.exit(failed ? 1 : 0));
