// The action channel on the control-plane side (node-integration.md §6.7, §7.5, §11.4;
// ADR-0031): the `actions` grant is held to the manifest grammar and the node's ceilings
// before anything is signed, `actions` and `answer` speak the adapter's commands and
// refuse an answer that does not match what was asked, and the answer loop answers by a
// policy with operation ids from the run record's scheme, persisting each answer before
// it is sent, so a restarted control plane replays an answer rather than giving another.
// The node is `fixtures/fake-adapter.mjs` with a scripted channel (FAKE_ADAPTER_ACTIONS).
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  ACTION_CEILINGS,
  ACTION_KINDS,
  Adapter,
  actionsGrant,
  actionsGrantOf,
  answerOperationId,
  blake3Hex,
  buildEnvelope,
  decodeActions,
  issuerFromSeed,
  loadRunRecord,
  manifest,
  operationIds,
  recordAnswer,
  rootLease,
  saveRunRecord,
  signEnvelope,
} from "../ward-node.mjs";

const FAKE = fileURLToPath(new URL("../fixtures/fake-adapter.mjs", import.meta.url));
const BINDING = {
  task: "task_01M45YYRG00001249248SK6H24",
  attempt: "exec_01M45YYRG00005ANB6CSVQF248",
  lease: "lease_01M45YYRG00009K6DANAXVQK6C",
};
const GRANT = { kinds: ["approval"], max_pending: 2, max_total: 8, wait_secs: 300 };

function envelopeInput(actions) {
  const now = 1_791_201_600_000;
  return {
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
      grants: [{ capability: "workload.run", resource: `task:${BINDING.task}`, delegable: false }],
      issuedAtUnixMs: now,
      expiresAtUnixMs: now + 3_600_000,
    }),
    workload: {
      argv: ["python3", "agent.py"],
      manifest: actions === undefined ? undefined : { network: "offline", actions },
      snapshot: "c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b",
      wallClockBudgetMs: 600_000,
    },
    issuedAtUnixMs: now,
    expiresAtUnixMs: now + 900_000,
    version: 1,
  };
}

function signedWith(actions) {
  return signEnvelope(issuerFromSeed(Buffer.alloc(32, 7)), buildEnvelope(envelopeInput(actions)));
}

function pendingEntry(action, extra = {}) {
  return { action, id: `ask-${action}`, kind: "approval", summary: `step ${action}`, detail: `detail of step ${action}`, expires_in_ms: 290_000, ...extra };
}

/** A scratch directory with a fake adapter whose channel is the script `channel`. */
function scripted(channel) {
  const dir = mkdtempSync(join(tmpdir(), "ward-actions-"));
  const log = join(dir, "received.jsonl");
  const state = join(dir, "channel.json");
  writeFileSync(state, JSON.stringify(channel));
  const env = { ...process.env, FAKE_ADAPTER_LOG: log, FAKE_ADAPTER_ACTIONS: state };
  const spawnAdapter = () => new Adapter({ command: [process.execPath, FAKE], socket: "/run/ward-node/node.sock", env });
  return {
    dir,
    log,
    state,
    runs: join(dir, "runs"),
    spawnAdapter,
    channel: () => JSON.parse(readFileSync(state, "utf8")),
    received: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : []),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** The run record a control plane writes before its first send, under `runs`. */
function recordRun(runs, actions = GRANT, startAt = 1) {
  const signed = signedWith(actions);
  saveRunRecord(runs, {
    binding: BINDING,
    version: 1,
    envelope_json: signed.envelope_json,
    proof: signed.proof,
    operation_ids: { start_at: startAt },
    task_root: null,
  });
  return signed;
}

// ---- the grant -------------------------------------------------------------------------

test("the kinds and ceilings are the node's: approval and decision, 8 pending, 64 in all, 3600 seconds", () => {
  assert.deepEqual(ACTION_KINDS, ["approval", "decision"]);
  assert.deepEqual(ACTION_CEILINGS, { maxPending: 8, maxTotal: 64, waitSecs: 3600 });
  assert.ok(Object.isFrozen(ACTION_KINDS));
  assert.ok(Object.isFrozen(ACTION_CEILINGS));
});

test("an actions grant is built in wire spelling, and the §7.5 example is signed byte for byte", () => {
  assert.deepEqual(actionsGrant({ kinds: ["approval"], maxPending: 2, maxTotal: 8, waitSecs: 300 }), GRANT);
  assert.deepEqual(actionsGrant({ kinds: ["decision", "approval"], maxPending: 8, maxTotal: 64, waitSecs: 3600 }), {
    kinds: ["decision", "approval"],
    max_pending: 8,
    max_total: 64,
    wait_secs: 3600,
  });
  const json = '{"network":"offline","actions":{"kinds":["approval"],"max_pending":2,"max_total":8,"wait_secs":300}}';
  const built = manifest({ network: "offline", actions: GRANT });
  assert.equal(Buffer.from(built.bytes, "hex").toString("utf8"), json);
  assert.equal(built.hash, blake3Hex(Buffer.from(json)));
  // The caller's key order changes nothing; the grant follows `output` when both are granted.
  assert.deepEqual(manifest({ actions: { wait_secs: 300, max_total: 8, kinds: ["approval"], max_pending: 2 }, network: "offline" }), built);
  const both = manifest({ actions: GRANT, output: { stdio_bytes: 1, files: [], files_bytes: 0 }, network: "offline" });
  assert.equal(
    Buffer.from(both.bytes, "hex").toString("utf8"),
    '{"network":"offline","output":{"stdio_bytes":1,"files":[],"files_bytes":0},"actions":{"kinds":["approval"],"max_pending":2,"max_total":8,"wait_secs":300}}',
  );
});

test("a grant outside ADR-0031's grammar is refused before signing, naming the field", () => {
  const refuses = (actions, pattern) => assert.throws(() => manifest({ network: "offline", actions }), pattern);
  refuses(null, /actions/);
  refuses([], /actions/);
  refuses({ ...GRANT, extra: 1 }, /kinds, max_pending, max_total, wait_secs/);
  refuses({ kinds: ["approval"], max_pending: 1, max_total: 1 }, /kinds, max_pending, max_total, wait_secs/);
  refuses({ ...GRANT, kinds: [] }, /kinds/);
  refuses({ ...GRANT, kinds: "approval" }, /kinds/);
  refuses({ ...GRANT, kinds: ["approval", "approval"] }, /repeats/);
  refuses({ ...GRANT, kinds: ["credential"] }, /credential/);
  refuses({ ...GRANT, kinds: ["Approval"] }, /kind/);
  refuses({ ...GRANT, kinds: ["approval", "decision", "approval"] }, /kinds/);
  for (const field of ["max_pending", "max_total", "wait_secs"]) {
    refuses({ ...GRANT, [field]: 0 }, new RegExp(field));
    refuses({ ...GRANT, [field]: -1 }, new RegExp(field));
    refuses({ ...GRANT, [field]: 1.5 }, new RegExp(field));
    refuses({ ...GRANT, [field]: "2" }, new RegExp(field));
    refuses({ ...GRANT, [field]: null }, new RegExp(field));
  }
  refuses({ ...GRANT, max_pending: 3, max_total: 2 }, /max_pending.*max_total/);
  assert.ok(manifest({ network: "offline", actions: { ...GRANT, max_pending: 1, max_total: 1, wait_secs: 1 } }).hash, "the smallest grant");
  assert.throws(() => actionsGrant({ kinds: [], maxPending: 1, maxTotal: 1, waitSecs: 1 }), /kinds/);
});

test("a grant above the node's ceilings is refused here, not by the node as unsupported_grant", () => {
  const refuses = (actions, pattern) => assert.throws(() => manifest({ network: "offline", actions }), pattern);
  refuses({ ...GRANT, max_pending: 9, max_total: 9 }, /max_pending` 9 is above the 8 .*unsupported_grant/);
  refuses({ ...GRANT, max_total: 65 }, /max_total` 65 is above the 64 .*unsupported_grant/);
  refuses({ ...GRANT, wait_secs: 3601 }, /wait_secs` 3601 is above the 3600 .*unsupported_grant/);
  refuses({ ...GRANT, wait_secs: 2 ** 53 }, /wait_secs/);
  assert.ok(manifest({ network: "offline", actions: { kinds: ["approval", "decision"], max_pending: 8, max_total: 64, wait_secs: 3600 } }).hash);
  assert.throws(() => actionsGrant({ kinds: ["approval"], maxPending: 9, maxTotal: 64, waitSecs: 1 }), /unsupported_grant/);
});

test("buildEnvelope refuses a bad grant before signing, and actionsGrantOf reads the signed one back", () => {
  assert.throws(() => buildEnvelope(envelopeInput({ ...GRANT, kinds: ["credential"] })), /credential/);
  assert.throws(() => buildEnvelope(envelopeInput({ ...GRANT, max_pending: 9 })), /unsupported_grant/);
  const signed = signedWith(GRANT);
  assert.deepEqual(actionsGrantOf(signed.envelope_json), GRANT);
  assert.equal(actionsGrantOf(signedWith(undefined).envelope_json), null, "no grant, no channel");
  assert.throws(() => actionsGrantOf("{not json"), /JSON/);
});

// ---- operation ids -----------------------------------------------------------------------

test("answers take operation ids from the run record's scheme: one per request number, past pause and resume", () => {
  const ids = operationIds(1);
  // create..seal are 1..6, pause and resume count up from 7 for at most 128 each (§6.3).
  assert.equal(ids.first_answer, 1 + 6 + 256);
  assert.equal(answerOperationId(ids, 1), 263);
  assert.equal(answerOperationId(ids, 64), 326);
  assert.equal(answerOperationId(operationIds(20), 1), 282);
  assert.equal(answerOperationId({ start_at: 20 }, 2), 283, "a recorded scheme of start_at alone");
  for (const request of [0, -1, 65, 1.5, "1"]) assert.throws(() => answerOperationId(ids, request), /request/);
});

test("recordAnswer persists one answer per request durably and returns the recorded one on a second call", () => {
  const dir = mkdtempSync(join(tmpdir(), "ward-record-"));
  try {
    recordRun(dir);
    const first = recordAnswer(dir, BINDING.attempt, { request: 1, id: "ask-1", kind: "approval", decision: "denied", note: "no", operation_id: 263 });
    assert.deepEqual(first, { request: 1, id: "ask-1", kind: "approval", decision: "denied", note: "no", operation_id: 263 });
    const again = recordAnswer(dir, BINDING.attempt, { request: 1, id: "ask-1", kind: "approval", decision: "approved", operation_id: 263 });
    assert.deepEqual(again, first, "the record holds the first answer; a second is never written");
    assert.deepEqual(loadRunRecord(dir, BINDING.attempt).answers, [first]);
    assert.throws(() => recordAnswer(dir, BINDING.attempt, { request: 2, decision: "expired", operation_id: 264 }), /approved or denied/);
    assert.throws(() => recordAnswer(dir, BINDING.attempt, { request: 2, decision: "approved", operation_id: 999 }), /operation id/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- actions ---------------------------------------------------------------------------

test("actions is one command and one event, decoded oldest first", async () => {
  const fake = scripted({ requests: [pendingEntry(1), pendingEntry(2, { kind: "decision" })] });
  const adapter = fake.spawnAdapter();
  try {
    const listed = await adapter.actions(BINDING);
    assert.equal(listed.state, "running");
    assert.deepEqual(listed.pending, [pendingEntry(1), pendingEntry(2, { kind: "decision" })]);
    assert.equal(await adapter.close(), 0);
    assert.deepEqual(fake.received(), [{ cmd: "actions", binding: BINDING }]);
  } finally {
    fake.cleanup();
  }
  const refused = scripted({ requests: [], reject_actions: "unsupported_operation" });
  try {
    const adapter = refused.spawnAdapter();
    assert.deepEqual(await adapter.actions(BINDING), { rejected: "unsupported_operation" });
    assert.equal(await adapter.close(), 0);
  } finally {
    refused.cleanup();
  }
});

test("a listing outside §6.7 is refused, not acted on", () => {
  const ok = { state: "running", pending: [pendingEntry(1), pendingEntry(2)] };
  assert.deepEqual(decodeActions(ok), ok);
  assert.deepEqual(decodeActions({ state: "sealed", pending: [] }), { state: "sealed", pending: [] });
  const refuses = (listing, pattern, grant) => assert.throws(() => decodeActions(listing, grant), pattern);
  refuses({ state: "running" }, /pending/);
  refuses({ state: "launched", pending: [] }, /state/);
  refuses({ state: "sealed", pending: [pendingEntry(1)] }, /running or paused/);
  refuses({ state: "running", pending: [pendingEntry(2), pendingEntry(1)] }, /oldest first/);
  refuses({ state: "running", pending: [pendingEntry(1), pendingEntry(1)] }, /oldest first/);
  refuses({ state: "running", pending: [pendingEntry(1), pendingEntry(2, { id: "ask-1" })] }, /repeats/);
  refuses({ state: "running", pending: [pendingEntry(0)] }, /action/);
  refuses({ state: "running", pending: [pendingEntry(2 ** 32)] }, /action/);
  refuses({ state: "running", pending: [{ ...pendingEntry(1), extra: true }] }, /action, id, kind, summary, detail, expires_in_ms/);
  for (const id of ["", "a b", "x".repeat(65), "ä", "a/b", 7]) refuses({ state: "running", pending: [pendingEntry(1, { id })] }, /id/);
  for (const id of ["a", "A.b_c:d-9", "x".repeat(64)]) assert.ok(decodeActions({ state: "running", pending: [pendingEntry(1, { id })] }));
  refuses({ state: "running", pending: [pendingEntry(1, { kind: "credential" })] }, /kind/);
  refuses({ state: "running", pending: [pendingEntry(1, { summary: "" })] }, /summary/);
  refuses({ state: "running", pending: [pendingEntry(1, { summary: "é".repeat(257) })] }, /summary/);
  assert.ok(decodeActions({ state: "running", pending: [pendingEntry(1, { summary: "x".repeat(512), detail: "" })] }));
  refuses({ state: "running", pending: [pendingEntry(1, { detail: "x".repeat(16_385) })] }, /detail/);
  refuses({ state: "running", pending: [pendingEntry(1, { expires_in_ms: -1 })] }, /expires_in_ms/);
  refuses({ state: "running", pending: Array.from({ length: 9 }, (_, i) => pendingEntry(i + 1)) }, /8/);
  // Held to the grant the attempt was admitted under.
  refuses({ state: "running", pending: [pendingEntry(1, { kind: "decision" })] }, /not granted/, GRANT);
  refuses({ state: "running", pending: [pendingEntry(1), pendingEntry(2), pendingEntry(3)] }, /max_pending/, GRANT);
  refuses({ state: "running", pending: [pendingEntry(9)] }, /max_total/, GRANT);
  refuses({ state: "running", pending: [pendingEntry(1, { expires_in_ms: 300_001 })] }, /wait_secs/, GRANT);
  assert.ok(decodeActions(ok, GRANT));
});

// ---- answer ----------------------------------------------------------------------------

test("answer sends the adapter's command and returns the node's answer, checked against what was asked", async () => {
  const fake = scripted({ requests: [pendingEntry(1), pendingEntry(2)] });
  const adapter = fake.spawnAdapter();
  try {
    assert.deepEqual(await adapter.answer(BINDING, 1, "approved", 263, "go ahead"), { result: "answered", request: 1, decision: "approved", operation_id: 263 });
    // The same operation id and answer again: answered again, nothing applied twice.
    assert.deepEqual(await adapter.answer(BINDING, 1, "approved", 263, "go ahead"), { result: "answered", request: 1, decision: "approved", operation_id: 263 });
    assert.deepEqual(await adapter.answer(BINDING, 1, "denied", 263), { result: "rejected", reason: "stale_operation", operation_id: 263 });
    assert.deepEqual(await adapter.answer(BINDING, 1, "denied", 264), { result: "rejected", reason: "already_answered", operation_id: 264 });
    assert.deepEqual(await adapter.answer(BINDING, 7, "denied", 269), { result: "rejected", reason: "unknown_request", operation_id: 269 });
    assert.deepEqual(await adapter.answer(BINDING, 2, "denied", 264), { result: "answered", request: 2, decision: "denied", operation_id: 264 });
    assert.equal(await adapter.close(), 0);
    assert.deepEqual(fake.received()[0], { cmd: "answer", binding: BINDING, request: 1, decision: "approved", operation_id: 263, note: "go ahead" });
    assert.deepEqual(fake.received()[2], { cmd: "answer", binding: BINDING, request: 1, decision: "denied", operation_id: 263 }, "no note, no field");
  } finally {
    fake.cleanup();
  }
  const ended = scripted({ requests: [pendingEntry(1)], state: "sealed" });
  try {
    const adapter = ended.spawnAdapter();
    assert.deepEqual(await adapter.answer(BINDING, 1, "approved", 263), { result: "rejected", reason: "invalid_state", operation_id: 263 });
    assert.equal(await adapter.close(), 0);
  } finally {
    ended.cleanup();
  }
});

test("an answer outside the contract is refused before it is sent", async () => {
  const fake = scripted({ requests: [pendingEntry(1)] });
  const adapter = fake.spawnAdapter();
  try {
    await assert.rejects(adapter.answer(BINDING, 1, "expired", 263), /approved or denied/);
    await assert.rejects(adapter.answer(BINDING, 1, "cancelled", 263), /approved or denied/);
    await assert.rejects(adapter.answer(BINDING, 0, "approved", 263), /request/);
    await assert.rejects(adapter.answer(BINDING, 1, "approved", 0), /operation id/);
    await assert.rejects(adapter.answer(BINDING, 1, "approved", 263, "x".repeat(513)), /note/);
    await assert.rejects(adapter.answer(BINDING, 1, "approved", 263, 7), /note/);
    await assert.rejects(adapter.answer({ ...BINDING, task: "task_x" }, 1, "approved", 263), /task/);
    assert.ok(await adapter.answer(BINDING, 1, "approved", 263, "é".repeat(256)), "512 bytes of note");
    assert.equal(await adapter.close(), 0);
    assert.equal(fake.received().length, 1, "only the valid answer reached the adapter");
  } finally {
    fake.cleanup();
  }
});

test("an answer event that names another request, decision or operation, or an unknown reason, is refused", async () => {
  for (const [override, pattern] of [
    [{ request: 2 }, /request/],
    [{ decision: "denied" }, /decision/],
    [{ operation_id: 999 }, /operation/],
    [{ event: "rejected", verb: "answer", reason: "because" }, /reason/],
    [{ event: "rejected", verb: "actions", reason: "invalid_state" }, /verb/],
  ]) {
    const fake = scripted({ requests: [pendingEntry(1), pendingEntry(2)], answer_override: override });
    const adapter = fake.spawnAdapter();
    try {
      await assert.rejects(adapter.answer(BINDING, 1, "approved", 263), pattern);
      assert.equal(await adapter.close(), 0);
    } finally {
      fake.cleanup();
    }
  }
});

// ---- the answer loop -------------------------------------------------------------------

test("the answer loop answers each request once by the policy, persisting before sending, and stops at the attempt's end", async () => {
  const fake = scripted({ requests: [pendingEntry(1), pendingEntry(2, { after: 2 })], end_after: 5 });
  const signed = recordRun(fake.runs);
  const adapter = fake.spawnAdapter();
  const asked = [];
  const seen = [];
  try {
    const result = await adapter.answerLoop(
      BINDING,
      (request) => {
        asked.push(request.action);
        // The answer is in the record only once the policy has decided, and before it is sent.
        const record = loadRunRecord(fake.runs, BINDING.attempt);
        assert.ok(!(record.answers ?? []).some((answer) => answer.request === request.action));
        return request.action === 1 ? { decision: "approved", note: "go ahead" } : "denied";
      },
      { pollMs: 5, runDir: fake.runs, onRequest: (request) => seen.push(["request", request.action]), onAnswer: (answer) => seen.push(["answer", answer.request, answer.result]) },
    );
    assert.equal(result.state, "exited");
    assert.deepEqual(asked, [1, 2], "the policy is asked once per request");
    assert.deepEqual(seen, [["request", 1], ["answer", 1, "answered"], ["request", 2], ["answer", 2, "answered"]]);
    assert.deepEqual(
      result.answers.map(({ request, decision, operation_id, result: answered, replayed }) => [request, decision, operation_id, answered, replayed]),
      [[1, "approved", 263, "answered", false], [2, "denied", 264, "answered", false]],
    );
    assert.deepEqual(loadRunRecord(fake.runs, BINDING.attempt).answers, [
      { request: 1, id: "ask-1", kind: "approval", decision: "approved", note: "go ahead", operation_id: 263 },
      { request: 2, id: "ask-2", kind: "approval", decision: "denied", operation_id: 264 },
    ]);
    const answers = fake.received().filter((line) => line.cmd === "answer");
    assert.deepEqual(answers, [
      { cmd: "answer", binding: BINDING, request: 1, decision: "approved", operation_id: 263, note: "go ahead" },
      { cmd: "answer", binding: BINDING, request: 2, decision: "denied", operation_id: 264 },
    ]);
    assert.ok(fake.received().length >= 6, "it kept polling until the attempt ended");
    assert.equal(actionsGrantOf(signed.envelope_json).max_pending, 2);
    assert.equal(await adapter.close(), 0);
  } finally {
    fake.cleanup();
  }
});

test("a restarted control plane replays the recorded answer under the same operation id and never asks again", async () => {
  // The first control plane decides, persists, and dies before the answer is delivered.
  const fake = scripted({ requests: [pendingEntry(1)], die_on_answer: true, end_after: 1000 });
  recordRun(fake.runs, GRANT, 20);
  try {
    const first = fake.spawnAdapter();
    await assert.rejects(first.answerLoop(BINDING, () => "denied", { pollMs: 5, runDir: fake.runs }), /exited without answering/);
    assert.deepEqual(loadRunRecord(fake.runs, BINDING.attempt).answers, [{ request: 1, id: "ask-1", kind: "approval", decision: "denied", operation_id: 282 }]);
    assert.deepEqual(fake.channel().answered, {}, "the node never received it");
    // The restarted one finds the request still pending and replays exactly that answer.
    const controller = new AbortController();
    const second = fake.spawnAdapter();
    const result = await second.answerLoop(
      BINDING,
      () => {
        throw new Error("the policy must not be asked again for a recorded answer");
      },
      { pollMs: 5, runDir: fake.runs, signal: controller.signal, onAnswer: () => controller.abort() },
    );
    assert.equal(result.state, null, "stopped by the signal, not by the attempt");
    assert.deepEqual(result.answers.map(({ request, decision, operation_id, result: answered, replayed }) => [request, decision, operation_id, answered, replayed]), [[1, "denied", 282, "answered", true]]);
    assert.equal(await second.close(), 0);
    const sent = fake.received().filter((line) => line.cmd === "answer");
    assert.deepEqual(sent, [
      { cmd: "answer", binding: BINDING, request: 1, decision: "denied", operation_id: 282 },
      { cmd: "answer", binding: BINDING, request: 1, decision: "denied", operation_id: 282 },
    ]);
    assert.deepEqual(fake.channel().answered, { 1: 282 }, "answered exactly once");
  } finally {
    fake.cleanup();
  }
});

test("a recorded answer whose delivery was confirmed is idempotent: replayed to the node it is answered again", async () => {
  const fake = scripted({ requests: [pendingEntry(1)], end_after: 1000, keep_listing_answered: true });
  recordRun(fake.runs);
  try {
    const controller = new AbortController();
    let answered = 0;
    const onAnswer = () => {
      answered += 1;
      if (answered === 1) controller.abort();
    };
    const first = fake.spawnAdapter();
    await first.answerLoop(BINDING, () => "approved", { pollMs: 5, runDir: fake.runs, signal: controller.signal, onAnswer });
    assert.equal(await first.close(), 0);
    // A second control plane over the same record and a listing that still shows the request
    // (a race with the node's own bookkeeping): the replay is answered, nothing applied twice.
    const again = new AbortController();
    const second = fake.spawnAdapter();
    const result = await second.answerLoop(BINDING, () => "denied", { pollMs: 5, runDir: fake.runs, signal: again.signal, onAnswer: () => again.abort() });
    assert.deepEqual(result.answers.map(({ decision, operation_id, result: r, replayed }) => [decision, operation_id, r, replayed]), [["approved", 263, "answered", true]]);
    assert.equal(await second.close(), 0);
    assert.deepEqual(Object.keys(fake.channel().applied), ["263"]);
  } finally {
    fake.cleanup();
  }
});

test("the loop handles each refusal by what it means: already answered and stale are final, unavailable is retried with the same id", async () => {
  const fake = scripted({
    requests: [pendingEntry(1), pendingEntry(2), pendingEntry(3)],
    answer_reject: { 1: ["already_answered"], 2: ["resource_unavailable"], 3: ["stale_operation"] },
    end_after: 6,
  });
  recordRun(fake.runs, { ...GRANT, max_pending: 3 });
  const adapter = fake.spawnAdapter();
  try {
    const result = await adapter.answerLoop(BINDING, () => "approved", { pollMs: 5, runDir: fake.runs });
    assert.equal(result.state, "exited");
    assert.deepEqual(
      result.answers.map(({ request, operation_id, result: r, reason }) => [request, operation_id, r, reason ?? null]),
      [
        [1, 263, "rejected", "already_answered"],
        [2, 264, "rejected", "resource_unavailable"],
        [3, 265, "rejected", "stale_operation"],
        [2, 264, "answered", null],
      ],
    );
    const sent = fake.received().filter((line) => line.cmd === "answer").map((line) => [line.request, line.operation_id]);
    assert.deepEqual(sent, [[1, 263], [2, 264], [3, 265], [2, 264]], "only the unavailable one is sent again, under its recorded id");
    assert.equal(await adapter.close(), 0);
  } finally {
    fake.cleanup();
  }
});

test("the loop waits through task_not_found before the run creates the task, and an answer refused invalid_state is final", async () => {
  const fake = scripted({ requests: [pendingEntry(1)], missing_until: 3, end_after: 4, answer_reject: { 1: ["invalid_state"] } });
  recordRun(fake.runs);
  const adapter = fake.spawnAdapter();
  try {
    const result = await adapter.answerLoop(BINDING, () => "approved", { pollMs: 5, runDir: fake.runs });
    assert.equal(result.state, "exited", "the loop ends when the listing says the attempt ended");
    assert.deepEqual(result.answers.map(({ result: r, reason }) => [r, reason]), [["rejected", "invalid_state"]]);
    assert.equal(fake.received().filter((line) => line.cmd === "actions").length, 5);
    assert.equal(fake.received().filter((line) => line.cmd === "answer").length, 1, "never sent again");
    assert.equal(await adapter.close(), 0);
  } finally {
    fake.cleanup();
  }
});

test("the loop gives up on a node that cannot serve the channel, and on a listing the grant does not allow", async () => {
  const unsupported = scripted({ requests: [], reject_actions: "unsupported_operation" });
  recordRun(unsupported.runs);
  try {
    const adapter = unsupported.spawnAdapter();
    await assert.rejects(adapter.answerLoop(BINDING, () => "approved", { pollMs: 5, runDir: unsupported.runs }), /unsupported_operation/);
    assert.equal(await adapter.close(), 0);
  } finally {
    unsupported.cleanup();
  }
  const hostile = scripted({ requests: [pendingEntry(1, { kind: "decision" })] });
  recordRun(hostile.runs);
  try {
    const adapter = hostile.spawnAdapter();
    await assert.rejects(adapter.answerLoop(BINDING, () => "approved", { pollMs: 5, runDir: hostile.runs }), /not granted/);
    assert.equal(await adapter.close(), 0);
    assert.equal(hostile.received().filter((line) => line.cmd === "answer").length, 0, "nothing answered");
  } finally {
    hostile.cleanup();
  }
});

test("without a run record the loop needs a scheme, keeps its answers in memory, and stops on the signal", async () => {
  const fake = scripted({ requests: [pendingEntry(1)] });
  const adapter = fake.spawnAdapter();
  try {
    await assert.rejects(adapter.answerLoop(BINDING, () => "approved", { pollMs: 5 }), /runDir or operationIds/);
    const controller = new AbortController();
    const result = await adapter.answerLoop(BINDING, () => null, {
      pollMs: 5,
      operationIds: operationIds(1),
      signal: controller.signal,
      onRequest: () => setTimeout(() => controller.abort(), 30),
    });
    assert.equal(result.state, null);
    assert.deepEqual(result.answers, [], "a policy that returns null leaves the request to someone else");
    assert.equal(fake.received().filter((line) => line.cmd === "answer").length, 0);
    const aborted = new AbortController();
    aborted.abort();
    assert.deepEqual(await adapter.answerLoop(BINDING, () => "approved", { operationIds: operationIds(1), signal: aborted.signal }), { state: null, answers: [] });
    assert.equal(await adapter.close(), 0);
  } finally {
    fake.cleanup();
  }
});
