// The JSON-lines framing towards `ward-node-adapter` (node-integration.md §11.4), against
// a fake adapter that records every line: one JSON object per line, the pre-signed bytes
// and proof passed through unchanged, the event stream collected to `done`, cancellation
// as revoke-and-seal, and the receipt mapped to an outcome.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  Adapter,
  blake3Hex,
  buildEnvelope,
  issuerFromSeed,
  operationIds,
  outcomeOf,
  outputGrantOf,
  rootLease,
  signEnvelope,
} from "../ward-node.mjs";

const FAKE = fileURLToPath(new URL("../fixtures/fake-adapter.mjs", import.meta.url));
const BINDING = {
  task: "task_01M45YYRG00001249248SK6H24",
  attempt: "exec_01M45YYRG00005ANB6CSVQF248",
  lease: "lease_01M45YYRG00009K6DANAXVQK6C",
};

function signed(argvTail = "true", manifest = undefined) {
  const now = Date.now();
  const envelope = buildEnvelope({
    binding: BINDING,
    agent: "agent_01M43CJ1G0000DVQFEXVZZY001",
    node: "node_01M3KY5QG0000028T5CY4TQKFF",
    session: "sess_01M45YYRG0000FXQ5TK1V58CGG",
    lease: rootLease({
      id: BINDING.lease,
      delegationId: "deleg_01M45YYRG000016NWVVWJ6HB70",
      issuer: "prn_01M1RQ16G00000Y3RF1W7GY3RF",
      subject: "agent_01M43CJ1G0000DVQFEXVZZY001",
      task: BINDING.task,
      grants: [{ capability: "repo.read", resource: "repo:example/project", delegable: false }],
      issuedAtUnixMs: now - 60_000,
      expiresAtUnixMs: now + 600_000,
    }),
    workload: {
      argv: ["sh", "-c", argvTail],
      manifest,
      snapshot: "c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b",
      wallClockBudgetMs: 60_000,
    },
    issuedAtUnixMs: now - 60_000,
    expiresAtUnixMs: now + 600_000,
    version: 1,
  });
  return signEnvelope(issuerFromSeed(Buffer.alloc(32, 7)), envelope);
}

function fakeAdapter(extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), "ward-adapter-"));
  const log = join(dir, "received.jsonl");
  const adapter = new Adapter({
    command: [process.execPath, FAKE],
    socket: "/run/ward-node/node.sock",
    env: { ...process.env, FAKE_ADAPTER_LOG: log, ...extraEnv },
  });
  return { dir, log, adapter, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function receivedLines(log) {
  const text = readFileSync(log, "utf8");
  assert.ok(text.endsWith("\n"), "every command line ends with a newline");
  return text.slice(0, -1).split("\n").map((line) => {
    assert.ok(!line.includes("\n"));
    return JSON.parse(line);
  });
}

test("capabilities is one command line and one event, with the socket passed as a flag", async () => {
  const { log, adapter, cleanup } = fakeAdapter();
  try {
    const capabilities = await adapter.capabilities();
    assert.deepEqual(capabilities.protocol, { major: 1, minor: 3 });
    assert.equal(capabilities.lifecycle.start, true);
    assert.equal(capabilities.socket, "/run/ward-node/node.sock");
    assert.equal(await adapter.close(), 0);
    assert.deepEqual(receivedLines(log), [{ cmd: "capabilities" }]);
  } finally {
    cleanup();
  }
});

test("run sends the pre-signed bytes unchanged and collects the stream to done", async () => {
  const { log, adapter, cleanup } = fakeAdapter();
  try {
    const request = signed();
    const seen = [];
    const { events, report } = await adapter.run(request, {
      operationIds: operationIds(20),
      taskRoot: "/var/lib/ward-node/tasks",
      onEvent: (event) => seen.push(event.event),
    });
    assert.deepEqual(seen, ["state", "state", "admitted", "state", "receipt", "state", "evidence", "done"]);
    assert.equal(events.length, 8);
    assert.ok(events.every((event) => event.schema === 1));
    assert.equal(report.final_state, "sealed");
    assert.equal(report.outcome, "completed");
    assert.deepEqual(
      report.operations.map((operation) => [operation.verb, operation.operation_id]),
      [["create", 20], ["admit", 21], ["start", 22], ["seal", 25]],
    );
    const admitted = events.find((event) => event.event === "admitted");
    assert.equal(admitted.envelope_json, request.envelope_json);
    assert.deepEqual(admitted.proof, request.proof);
    assert.equal(await adapter.close(), 0);
    const [command] = receivedLines(log);
    assert.equal(command.cmd, "run");
    assert.equal(command.envelope_json, request.envelope_json, "the signed bytes travel as one JSON string");
    assert.deepEqual(command.proof, request.proof);
    assert.deepEqual(command.operation_ids, { start_at: 20 });
    assert.equal(command.task_root, "/var/lib/ward-node/tasks");
    assert.equal(command.envelope, undefined, "never the unsigned form");
    assert.equal(command.issuer_seed_file, undefined, "the key never leaves the control plane");
    const outcome = outcomeOf(report);
    assert.equal(outcome.outcome, "completed");
    assert.equal(outcome.certain, true);
    assert.equal(outcome.exitStatus, 0);
    assert.equal(outcome.cancelled, false);
    assert.equal(outcome.evidenceLog, "/var/lib/ward-node/tasks/task_01M45YYRG00001249248SK6H24/exec_01M45YYRG00005ANB6CSVQF248.evidence/events.log");
  } finally {
    cleanup();
  }
});

test("a failed receipt maps to failed with the exit status from the cause", async () => {
  const { adapter, cleanup } = fakeAdapter();
  try {
    const { report } = await adapter.run(signed("exit 3"), {});
    const outcome = outcomeOf(report);
    assert.equal(outcome.outcome, "failed");
    assert.equal(outcome.certain, true);
    assert.equal(outcome.exitStatus, 3);
    assert.equal(outcome.receipt, "failed");
    assert.equal(outcome.finalState, "sealed");
    assert.equal(await adapter.close(), 0);
  } finally {
    cleanup();
  }
});

test("cancel is revoke then seal, and the run still ends in done", async () => {
  const { log, adapter, cleanup } = fakeAdapter({ FAKE_ADAPTER_HOLD: "1" });
  try {
    const { report } = await adapter.run(signed("sleep 300"), {
      onEvent: (event) => {
        if (event.event === "state" && event.state === "running") adapter.cancel();
      },
    });
    assert.equal(report.cancelled, true);
    assert.equal(report.final_state, "sealed");
    const verbs = report.operations.map((operation) => operation.verb);
    assert.deepEqual(verbs, ["create", "admit", "start", "revoke", "seal"]);
    assert.ok(!verbs.includes("stop"), "cancellation is never stop");
    const outcome = outcomeOf(report);
    assert.equal(outcome.outcome, "failed");
    assert.equal(outcome.cancelled, true);
    assert.equal(outcome.exitStatus, undefined);
    assert.equal(await adapter.close(), 0);
    assert.equal(receivedLines(log).length, 1, "cancellation is a signal, not a command on the busy stdin");
  } finally {
    cleanup();
  }
});

test("inspect and revoke are their own commands", async () => {
  const { log, adapter, cleanup } = fakeAdapter();
  try {
    assert.deepEqual(await adapter.inspect(BINDING), { state: "sealed", outcome: "completed" });
    const revoked = await adapter.revoke(BINDING, 24);
    assert.deepEqual(revoked, { result: "accepted", state: "revoked", operation_id: 24 });
    assert.equal(await adapter.close(), 0);
    assert.deepEqual(receivedLines(log), [
      { cmd: "inspect", binding: BINDING },
      { cmd: "revoke", operation_id: 24, binding: BINDING },
    ]);
  } finally {
    cleanup();
  }
});

test("an error event fails the command and the adapter exits 1", async () => {
  const { adapter, cleanup } = fakeAdapter();
  try {
    await assert.rejects(
      adapter.run({ envelope_json: "{not json", proof: { issuer_key_id: "0".repeat(64), signature: "0".repeat(128) }, binding: BINDING }, {}),
      /not a valid envelope/,
    );
    assert.equal(await adapter.close(), 1);
  } finally {
    cleanup();
  }
});

test("outcomeOf maps every report shape and never infers success from unknown", () => {
  const base = { binding: BINDING, final_state: "sealed", sealed: true, cancelled: false, deadline_exceeded: false, evidence_log: null, evidence_head: null, operations: [], transport_error: null };
  assert.deepEqual(
    outcomeOf({ ...base, outcome: "unknown", outcome_certain: false, receipt: "unknown", cause: "Ambiguous" }),
    { outcome: "unknown", certain: false, receipt: "unknown", cause: "Ambiguous", exitStatus: undefined, finalState: "sealed", sealed: true, cancelled: false, deadlineExceeded: false, evidenceLog: null, evidenceHead: null, refused: undefined, transportError: null, output: null, outputMissing: false, binding: BINDING },
  );
  const refused = outcomeOf({ ...base, final_state: "created", sealed: false, outcome: { refused: { verb: "admit", reason: "authority_denied" } }, outcome_certain: true, receipt: null, cause: null });
  assert.equal(refused.outcome, "refused");
  assert.deepEqual(refused.refused, { verb: "admit", reason: "authority_denied" });
  assert.equal(refused.exitStatus, undefined);
  const budget = outcomeOf({ ...base, outcome: "failed", outcome_certain: true, receipt: "failed", cause: "BudgetExceeded" });
  assert.equal(budget.outcome, "failed");
  assert.equal(budget.cause, "BudgetExceeded");
  assert.equal(budget.exitStatus, undefined);
  const lost = outcomeOf({ ...base, final_state: "running", sealed: false, outcome: "unknown", outcome_certain: false, receipt: null, cause: null, transport_error: "connection closed without a response" });
  assert.equal(lost.outcome, "unknown");
  assert.equal(lost.transportError, "connection closed without a response");
  assert.throws(() => outcomeOf({ ...base, outcome: "completed", outcome_certain: false, receipt: "completed", cause: null }), /certain/);
});

const OUTPUT_MANIFEST = { network: "offline", output: { stdio_bytes: 4096, files: ["out/report.json", "missing.txt"], files_bytes: 2048 } };

test("a run under an output grant carries the result in done, decoded with its digests verified", async () => {
  const request = signed("make test", OUTPUT_MANIFEST);
  const { adapter, cleanup } = fakeAdapter();
  try {
    const seen = [];
    const { report } = await adapter.run(request, { onEvent: (event) => seen.push(event.event) });
    assert.deepEqual(seen, ["state", "state", "admitted", "state", "receipt", "state", "output", "done"]);
    assert.equal(report.output.stdout.content_base64, Buffer.from("hello stdout\n").toString("base64"), "the report carries the wire form");
    const outcome = outcomeOf(report, { grant: outputGrantOf(request.envelope_json) });
    assert.equal(outcome.outcome, "completed");
    assert.equal(outcome.outputMissing, false);
    assert.deepEqual(outcome.output.stdout.content, Buffer.from("hello stdout\n"));
    assert.deepEqual(outcome.output.stderr.content, Buffer.from("hello stderr\n"));
    assert.equal(outcome.output.truncated, false);
    assert.deepEqual(outcome.output.files.map((file) => file.path), ["out/report.json", "missing.txt"]);
    assert.equal(outcome.output.files[0].content.toString(), "content of out/report.json\n");
    assert.equal(outcome.output.files[0].digest, blake3Hex(outcome.output.files[0].content));
    assert.deepEqual(outcome.output.files[1], { path: "missing.txt", skipped: "missing" });
    assert.equal(await adapter.close(), 0);
  } finally {
    cleanup();
  }
});

test("a run without the grant has no output, and the adapter is never asked for one", async () => {
  const { log, adapter, cleanup } = fakeAdapter();
  try {
    const request = signed();
    const { events, report } = await adapter.run(request, {});
    assert.ok(!events.some((event) => event.event === "output"));
    assert.equal(outputGrantOf(request.envelope_json), null);
    const outcome = outcomeOf(report, { grant: outputGrantOf(request.envelope_json) });
    assert.equal(outcome.output, null);
    assert.equal(outcome.outputMissing, false, "no grant, nothing missing");
    assert.equal(await adapter.close(), 0);
    assert.equal(receivedLines(log).length, 1, "result is the adapter's to ask, after seal, never a second command here");
  } finally {
    cleanup();
  }
});

test("a returned file whose digest disagrees with its content is refused, not reported", async () => {
  const request = signed("make test", OUTPUT_MANIFEST);
  const { adapter, cleanup } = fakeAdapter({ FAKE_ADAPTER_CORRUPT_DIGEST: "1" });
  try {
    const { report } = await adapter.run(request, {});
    assert.equal(report.outcome, "completed", "the wire report arrived");
    assert.throws(() => outcomeOf(report), /digest/);
    await assert.rejects(adapter.result(BINDING), /digest/);
    assert.equal(await adapter.close(), 0);
  } finally {
    cleanup();
  }
});

test("result is its own command, answered with the decoded output or a rejection", async () => {
  const { log, adapter, cleanup } = fakeAdapter();
  try {
    const resulted = await adapter.result(BINDING);
    assert.equal(resulted.state, "sealed");
    assert.deepEqual(resulted.output.stdout.content, Buffer.from("hello stdout\n"));
    assert.equal(resulted.output.files[0].content.toString(), "content of out/report.json\n");
    assert.deepEqual(resulted.output.files[1], { path: "missing.txt", skipped: "missing" });
    assert.equal(await adapter.close(), 0);
    assert.deepEqual(receivedLines(log), [{ cmd: "result", binding: BINDING }]);
  } finally {
    cleanup();
  }
  const refused = fakeAdapter({ FAKE_ADAPTER_RESULT_REJECT: "resource_unavailable" });
  try {
    assert.deepEqual(await refused.adapter.result(BINDING), { rejected: "resource_unavailable" });
    assert.equal(await refused.adapter.close(), 0);
  } finally {
    refused.cleanup();
  }
});
