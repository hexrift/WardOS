// A stand-in for `ward-node-adapter` (node-integration.md §11.4) for the framing tests:
// it speaks the adapter's JSON-lines protocol on stdin/stdout, records every line it
// received in FAKE_ADAPTER_LOG, and never touches a node. With FAKE_ADAPTER_HOLD=1 a
// run stays `running` until SIGTERM, which it answers the way the real adapter does: the
// attempt is revoked and sealed, `done` is written, and the process exits. A manifest
// with an `output` grant gets a canned result (§6.6) in `done` and through `result`;
// FAKE_ADAPTER_CORRUPT_DIGEST=1 serves the first returned file with a digest that is not
// its content's, and FAKE_ADAPTER_RESULT_REJECT=<reason> refuses `result` with it.
//
// FAKE_ADAPTER_ACTIONS names a JSON file that scripts the attempt's action channel (§6.7)
// and holds the node's side of it, so that several adapter processes in turn (a run and an
// answering loop, or a control plane before and after a restart) see one channel:
//
//   requests          the requests the workload makes, each a §6.7 pending entry, plus
//                     `after: N` to appear only from the (N+1)th `actions` on
//   state             the attempt's state (default `running`); `end_after: N` makes it
//                     `exited` from the (N+1)th `actions` on; `missing_until: N` refuses the
//                     first N `actions` task_not_found (the run has not created the task)
//   reject_actions    refuse every `actions` with this reason
//   answer_reject     {request: [reason, …]}: refuse that many answers to the request, in turn
//   answer_override   fields merged into the next answer event (a node that answers wrong)
//   die_on_answer     exit without answering the next `answer` (a crash before delivery)
//   keep_listing_answered  keep answered requests in the listing (a stale read)
//   applied, answered the node's own record: operation id → answer, request → operation id
//
// `answer` is refused as the node refuses it, in the node's order: a replayed operation id
// is answered again (or stale_operation for another answer), then invalid_state off a live
// attempt, unknown_request, already_answered. A `run` whose manifest grants `actions`
// marks the attempt running in `<file>.run`, waits until every request is answered, exits 0
// only if all were approved (3 otherwise), and marks it sealed.
import { appendFileSync, existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";

import { blake3Hex } from "../blake3.mjs";

const log = process.env.FAKE_ADAPTER_LOG;
const hold = process.env.FAKE_ADAPTER_HOLD === "1";
const corruptDigest = process.env.FAKE_ADAPTER_CORRUPT_DIGEST === "1";
const resultReject = process.env.FAKE_ADAPTER_RESULT_REJECT;
const channelFile = process.env.FAKE_ADAPTER_ACTIONS;
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

/** The canned §6.6 result for a grant: both streams printed once, every declared file but `missing.txt` returned. */
function cannedOutput(grant) {
  const stream = (text) => {
    const content = Buffer.from(text);
    return { bytes: content.length, truncated: false, dropped: 0, content_base64: content.toString("base64") };
  };
  let corrupted = !corruptDigest;
  const files = grant.files.map((path) => {
    if (path === "missing.txt") return { path, skipped: "missing" };
    const content = Buffer.from(`content of ${path}\n`);
    let digest = blake3Hex(content);
    if (!corrupted) {
      digest = blake3Hex(Buffer.from(`not ${path}`));
      corrupted = true;
    }
    return { path, size: content.length, digest, truncated: false, content_base64: content.toString("base64") };
  });
  return { stdout: stream("hello stdout\n"), stderr: stream("hello stderr\n"), files };
}

function manifestOf(envelope) {
  const bytes = envelope.workload?.capability_manifest?.bytes;
  if (typeof bytes !== "string") return {};
  return JSON.parse(Buffer.from(bytes, "hex").toString("utf8"));
}

function grantOf(envelope) {
  return manifestOf(envelope).output ?? null;
}

// ---- the scripted action channel -------------------------------------------------------

const LIVE = ["running", "paused"];

function readChannel() {
  const channel = JSON.parse(readFileSync(channelFile, "utf8"));
  channel.polls ??= 0;
  channel.applied ??= {};
  channel.answered ??= {};
  return channel;
}

// Written to a temporary file and renamed, so a run polling the channel from another
// process never reads it half written.
function writeChannel(channel) {
  writeFileSync(`${channelFile}.${process.pid}`, JSON.stringify(channel));
  renameSync(`${channelFile}.${process.pid}`, channelFile);
}

/** The attempt's state: the run's own when one is driving it, else the script's. */
function channelState(channel) {
  if (existsSync(`${channelFile}.run`)) return readFileSync(`${channelFile}.run`, "utf8");
  if (channel.end_after !== undefined && channel.polls > channel.end_after) return "exited";
  return channel.state ?? "running";
}

function listActions(binding) {
  const channel = readChannel();
  channel.polls += 1;
  writeChannel(channel);
  if (channel.reject_actions || channel.polls <= (channel.missing_until ?? 0)) {
    emit({ event: "rejected", verb: "actions", operation_id: null, reason: channel.reject_actions ?? "task_not_found" });
    return;
  }
  const state = channelState(channel);
  const pending = LIVE.includes(state)
    ? channel.requests
        .filter((request) => channel.polls > (request.after ?? 0))
        .filter((request) => channel.keep_listing_answered || channel.answered[request.action] === undefined)
        .map(({ after, ...request }) => request)
    : [];
  void binding;
  emit({ event: "actions", state, pending });
}

function sameAnswer(applied, command) {
  return applied.request === command.request && applied.decision === command.decision && (applied.note ?? null) === (command.note ?? null);
}

function answerAction(command) {
  const channel = readChannel();
  if (channel.die_on_answer) {
    channel.die_on_answer = false;
    writeChannel(channel);
    process.exit(1);
  }
  const reply = (event) => {
    const override = channel.answer_override;
    delete channel.answer_override;
    writeChannel(channel);
    emit({ ...event, ...override });
  };
  const rejected = (reason) => reply({ event: "rejected", verb: "answer", operation_id: command.operation_id, reason });
  const scripted = channel.answer_reject?.[command.request];
  if (Array.isArray(scripted) && scripted.length > 0) {
    const reason = scripted.shift();
    if (reason === "already_answered") channel.answered[command.request] ??= "expired";
    return rejected(reason);
  }
  const applied = channel.applied[command.operation_id];
  if (applied) {
    if (!sameAnswer(applied, command)) return rejected("stale_operation");
    return reply({ event: "answered", operation_id: command.operation_id, request: command.request, decision: applied.decision });
  }
  if (!LIVE.includes(channelState(channel))) return rejected("invalid_state");
  if (!channel.requests.some((request) => request.action === command.request)) return rejected("unknown_request");
  if (channel.answered[command.request] !== undefined) return rejected("already_answered");
  channel.applied[command.operation_id] = { request: command.request, decision: command.decision, note: command.note ?? null };
  channel.answered[command.request] = command.operation_id;
  return reply({ event: "answered", operation_id: command.operation_id, request: command.request, decision: command.decision });
}

function writeRunState(state) {
  writeFileSync(`${channelFile}.run.${process.pid}`, state);
  renameSync(`${channelFile}.run.${process.pid}`, `${channelFile}.run`);
}

/** Hold a run whose manifest grants `actions` until every request is answered. */
function waitForAnswers(done) {
  writeRunState("running");
  const deadline = Date.now() + 20_000;
  const timer = setInterval(() => {
    const channel = readChannel();
    const decisions = channel.requests.map((request) => channel.applied[channel.answered[request.action]]?.decision ?? channel.answered[request.action]);
    if (decisions.every((decision) => decision !== undefined) || Date.now() > deadline) {
      clearInterval(timer);
      writeRunState("sealed");
      done(decisions.every((decision) => decision === "approved") ? 0 : 3);
    }
  }, 10);
}

function finish(binding, ids, state, outcome, cancelled, operations, evidence, grant = null) {
  emit({ event: "receipt", state, outcome });
  operations.push({ verb: "seal", operation_id: ids.seal, state: "sealed", reason: null });
  emit({ event: "state", verb: "seal", operation_id: ids.seal, state: "sealed" });
  if (evidence) emit({ event: "evidence", path: evidence });
  const output = grant ? cannedOutput(grant) : null;
  if (output) {
    emit({ event: "output", stdout_bytes: output.stdout.bytes, stderr_bytes: output.stderr.bytes, files: output.files.length, truncated: false });
  }
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
      output,
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
    case "actions":
      listActions(command.binding);
      return;
    case "answer":
      answerAction(command);
      return;
    case "result":
      if (resultReject) {
        emit({ event: "rejected", verb: "result", operation_id: null, reason: resultReject });
        return;
      }
      emit({ event: "result", state: "sealed", output: cannedOutput({ files: ["out/report.json", "missing.txt"] }) });
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
      if (channelFile && manifestOf(envelope).actions) {
        running = { binding, ids, operations, evidence };
        waitForAnswers((exitStatus) => {
          running = null;
          finish(binding, ids, "exited", exitStatus === 0 ? "completed" : "failed", false, operations, evidence, grantOf(envelope));
        });
        return;
      }
      const exitStatus = envelope.workload.argv.at(-1) === "exit 3" ? 3 : 0;
      finish(binding, ids, "exited", exitStatus === 0 ? "completed" : "failed", false, operations, evidence, grantOf(envelope));
      return;
    }
    default:
      failed = true;
      emit({ event: "error", error: `unknown command \`${command.cmd}\`; the commands are capabilities, run, revoke, inspect, result, actions and answer` });
  }
});
lines.on("close", () => process.exit(failed ? 1 : 0));
