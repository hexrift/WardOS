// Backpressure on the control-plane side (node-integration.md §5, §8.2, §11.2; #260): a
// `start` refused `capacity_exhausted` leaves the task `ready` and its admission valid, so
// `run` with a capacity wait sends the same `run` again (the same signed bytes, proof and
// operation ids, so the same `start`) with backoff until the node accepts it or the wait
// is spent, reading the node's live `scheduling` before each wait; it never re-signs or
// allocates a version. Without a wait, and on `replay`, the refusal is the outcome. A
// cancel while waiting revokes the ready attempt and seals it. The adapter is
// `fixtures/fake-adapter.mjs`, scripted with FAKE_ADAPTER_CAPACITY.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  Adapter,
  CAPACITY_WAIT,
  buildEnvelope,
  capacityExhausted,
  createIssuerKey,
  deriveId,
  issuerFromSeed,
  loadRunRecord,
  operationIds,
  outcomeOf,
  rootLease,
  signEnvelope,
} from "../ward-node.mjs";

const FAKE = fileURLToPath(new URL("../fixtures/fake-adapter.mjs", import.meta.url));
const CLI = fileURLToPath(new URL("../control-plane.mjs", import.meta.url));
const SNAPSHOT = "c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b";
const BINDING = {
  task: "task_01M45YYRG00001249248SK6H24",
  attempt: "exec_01M45YYRG00005ANB6CSVQF248",
  lease: "lease_01M45YYRG00009K6DANAXVQK6C",
};
const FULL = { max_running: 1, running: 1, memory_floor_bytes: 0, memory_available_bytes: 2147483648, disk_floor_bytes: 0, disk_available_bytes: 8589934592 };

function signed() {
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
      grants: [{ capability: "workload.run", resource: `task:${BINDING.task}`, delegable: false }],
      issuedAtUnixMs: now - 60_000,
      expiresAtUnixMs: now + 600_000,
    }),
    workload: { argv: ["sh", "-c", "true"], snapshot: SNAPSHOT, wallClockBudgetMs: 60_000 },
    issuedAtUnixMs: now - 60_000,
    expiresAtUnixMs: now + 600_000,
    version: 1,
  });
  return signEnvelope(issuerFromSeed(Buffer.alloc(32, 7)), envelope);
}

/** A fake adapter whose node refuses the first `refuse` starts capacity_exhausted. */
function fakeAdapter(refuse, extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), "ward-capacity-"));
  const log = join(dir, "received.jsonl");
  const capacity = join(dir, "capacity.json");
  writeFileSync(capacity, JSON.stringify({ refuse, max_running: 1, running: 1 }));
  const adapter = new Adapter({
    command: [process.execPath, FAKE],
    socket: "/run/ward-node/node.sock",
    env: { ...process.env, FAKE_ADAPTER_LOG: log, FAKE_ADAPTER_CAPACITY: capacity, ...extraEnv },
  });
  return {
    adapter,
    log,
    received: () => readFileSync(log, "utf8").trim().split("\n").map((line) => JSON.parse(line)),
    refused: () => JSON.parse(readFileSync(capacity, "utf8")).refused ?? 0,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

const FAST = { capacityDelayMs: 5, capacityMaxDelayMs: 20 };

test("the default backoff starts at a quarter second and doubles to five seconds", () => {
  assert.deepEqual(CAPACITY_WAIT, { firstDelayMs: 250, maxDelayMs: 5000 });
  assert.ok(Object.isFrozen(CAPACITY_WAIT));
});

test("a start refused capacity_exhausted is sent again, the same run with the same operation ids, until it is accepted", async () => {
  const fake = fakeAdapter(2);
  try {
    const request = signed();
    const waits = [];
    const { report, capacityWaits } = await fake.adapter.run(request, {
      operationIds: operationIds(20),
      capacityWaitMs: 5000,
      ...FAST,
      onCapacityWait: (wait) => waits.push(wait),
    });
    assert.equal(report.outcome, "completed");
    assert.equal(report.final_state, "sealed");
    assert.deepEqual(capacityWaits, [
      { retry: 1, operation_id: 22, delay_ms: 5, scheduling: FULL },
      { retry: 2, operation_id: 22, delay_ms: 10, scheduling: { ...FULL, running: 0 } },
    ]);
    assert.deepEqual(waits, capacityWaits, "each wait is reported as it begins");
    assert.equal(capacityExhausted(report), false);
    assert.equal(await fake.adapter.close(), 0);
    const received = fake.received();
    assert.deepEqual(received.map((line) => line.cmd), ["run", "capabilities", "run", "capabilities", "run"]);
    const runs = received.filter((line) => line.cmd === "run");
    for (const again of runs.slice(1)) assert.deepEqual(again, runs[0], "the same bytes, proof and operation ids: never re-signed");
    assert.equal(runs[0].envelope_json, request.envelope_json);
    assert.deepEqual(runs[0].operation_ids, { start_at: 20 });
  } finally {
    fake.cleanup();
  }
});

test("without a capacity wait the refusal is the outcome, and nothing is sent again", async () => {
  const fake = fakeAdapter(1);
  try {
    const { report, capacityWaits } = await fake.adapter.run(signed(), {});
    assert.deepEqual(report.outcome, { refused: { verb: "start", reason: "capacity_exhausted" } });
    assert.equal(report.final_state, "ready", "the task is still admitted and ready");
    assert.equal(capacityExhausted(report), true);
    assert.deepEqual(capacityWaits, []);
    const outcome = outcomeOf(report);
    assert.equal(outcome.outcome, "refused");
    assert.equal(outcome.certain, true);
    assert.deepEqual(outcome.refused, { verb: "start", reason: "capacity_exhausted" });
    assert.equal(await fake.adapter.close(), 0);
    assert.deepEqual(fake.received().map((line) => line.cmd), ["run"]);
  } finally {
    fake.cleanup();
  }
});

test("the wait gives up once it is spent, with the last refusal and every wait", async () => {
  const fake = fakeAdapter(1000);
  try {
    const started = Date.now();
    const { report, capacityWaits } = await fake.adapter.run(signed(), { capacityWaitMs: 200, ...FAST });
    assert.ok(Date.now() - started < 2000, "bounded by the wait, not by the node");
    assert.equal(capacityExhausted(report), true);
    assert.equal(report.final_state, "ready");
    assert.ok(capacityWaits.length >= 3, `waited ${capacityWaits.length} times`);
    assert.ok(capacityWaits.every((wait, index) => wait.retry === index + 1 && wait.operation_id === 3));
    assert.ok(capacityWaits.every((wait) => wait.delay_ms <= 20), "never past the longest delay");
    assert.ok(capacityWaits.reduce((sum, wait) => sum + wait.delay_ms, 0) <= 200, "never past the wait");
    assert.equal(await fake.adapter.close(), 0);
    const runs = fake.received().filter((line) => line.cmd === "run");
    assert.equal(runs.length, capacityWaits.length + 1);
    assert.equal(fake.refused(), runs.length);
  } finally {
    fake.cleanup();
  }
});

test("cancelling while waiting revokes the ready attempt under the scheme's id, then seals it", async () => {
  const fake = fakeAdapter(1000);
  try {
    const { report, capacityWaits } = await fake.adapter.run(signed(), {
      operationIds: operationIds(20),
      capacityWaitMs: 60_000,
      capacityDelayMs: 30_000,
      onCapacityWait: () => fake.adapter.cancel(),
    });
    assert.equal(capacityWaits.length, 1);
    assert.equal(report.cancelled, true);
    assert.equal(report.final_state, "sealed");
    assert.deepEqual(
      report.operations.map((operation) => [operation.verb, operation.operation_id, operation.state ?? operation.reason]),
      [
        ["create", 20, "created"],
        ["admit", 21, "ready"],
        ["start", 22, "capacity_exhausted"],
        ["revoke", 24, "revoked"],
        ["create", 20, "revoked"],
        ["admit", 21, "revoked"],
        ["seal", 25, "sealed"],
      ],
    );
    const outcome = outcomeOf(report);
    assert.equal(outcome.cancelled, true);
    assert.notEqual(outcome.outcome, "completed");
    assert.equal(await fake.adapter.close(), 0, "the adapter was never signalled while idle");
    assert.deepEqual(fake.received().map((line) => line.cmd), ["run", "capabilities", "revoke", "run"]);
  } finally {
    fake.cleanup();
  }
});

test("a cancel while waiting whose revoke the node refuses is reported, and the run is not sent again", async () => {
  const fake = fakeAdapter(1000, { FAKE_ADAPTER_REVOKE_REJECT: "invalid_state" });
  try {
    const { report } = await fake.adapter.run(signed(), {
      capacityWaitMs: 60_000,
      capacityDelayMs: 30_000,
      onCapacityWait: () => fake.adapter.cancel(),
    });
    assert.equal(report.cancelled, true);
    assert.equal(capacityExhausted(report), true, "the refusal stands");
    assert.equal(report.final_state, "ready");
    assert.deepEqual(report.operations.at(-1), { verb: "revoke", operation_id: 5, state: null, reason: "invalid_state" });
    assert.equal(await fake.adapter.close(), 0);
    assert.deepEqual(fake.received().map((line) => line.cmd), ["run", "capabilities", "revoke"], "a run sent now could start the attempt");
  } finally {
    fake.cleanup();
  }
});

test("the capacity options are checked before anything is sent", async () => {
  const fake = fakeAdapter(0);
  try {
    for (const options of [{ capacityWaitMs: -1 }, { capacityWaitMs: 1.5 }, { capacityWaitMs: "5" }, { capacityDelayMs: 0 }, { capacityMaxDelayMs: 0 }]) {
      await assert.rejects(fake.adapter.run(signed(), options), /capacity/);
    }
    assert.equal(await fake.adapter.close(), 0);
    assert.ok(!existsSync(fake.log), "nothing reached the adapter");
  } finally {
    fake.cleanup();
  }
});

// ---- the command line ------------------------------------------------------------------

function setup(refuse) {
  const dir = mkdtempSync(join(tmpdir(), "ward-cli-capacity-"));
  const adapter = join(dir, "adapter.sh");
  writeFileSync(adapter, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(FAKE)} "$@"\n`);
  chmodSync(adapter, 0o755);
  createIssuerKey(join(dir, "cp", "issuer.pem"));
  const log = join(dir, "received.jsonl");
  const capacity = join(dir, "capacity.json");
  writeFileSync(capacity, JSON.stringify({ refuse, max_running: 1, running: 1 }));
  const env = { ...process.env, FAKE_ADAPTER_LOG: log, FAKE_ADAPTER_CAPACITY: capacity };
  const common = ["--socket", "/run/ward-node/node.sock", "--adapter", adapter];
  const runArgs = (attempt) => [
    "run",
    ...common,
    "--key", join(dir, "cp", "issuer.pem"),
    "--principal", "cli-issuer",
    "--node", deriveId("node", "cli-host"),
    "--state-dir", join(dir, "cp"),
    "--snapshot", SNAPSHOT,
    "--budget-ms", "60000",
    "--task", "cli-task",
    "--attempt", attempt,
  ];
  return {
    dir,
    env,
    common,
    runArgs,
    runs: join(dir, "cp", "runs"),
    free: () => {
      const state = JSON.parse(readFileSync(capacity, "utf8"));
      writeFileSync(capacity, JSON.stringify({ ...state, refuse: state.refused ?? 0 }));
    },
    received: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : []),
    versions: () => JSON.parse(readFileSync(join(dir, "cp", "admission-versions.json"), "utf8")).versions,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function cli(args, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("exit", (status) => resolve({ status, stdout, stderr }));
  });
}

test("run --capacity-wait-secs sends the same start again until the node has room, and lists each wait", async () => {
  const fake = setup(2);
  try {
    const { status, stdout, stderr } = await cli([...fake.runArgs("cli-busy"), "--capacity-wait-secs", "10", "--", "true"], fake.env);
    assert.equal(status, 0, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(outcome.outcome, "completed");
    assert.equal(outcome.version, 1);
    assert.deepEqual(outcome.capacity_waits, [
      { retry: 1, operation_id: 3, delay_ms: 250, scheduling: FULL },
      { retry: 2, operation_id: 3, delay_ms: 500, scheduling: { ...FULL, running: 0 } },
    ]);
    assert.match(stderr, /start \(operation 3\) refused capacity_exhausted: the node runs 1 of 1 attempts; sending the same start again in 250 ms \(retry 1\)/);
    assert.match(stderr, /in 500 ms \(retry 2\)/);
    const runs = fake.received().filter((line) => line.cmd === "run");
    assert.equal(runs.length, 3);
    for (const again of runs.slice(1)) assert.deepEqual(again, runs[0], "never re-signed");
    assert.deepEqual(fake.versions(), { [deriveId("task", "cli-task")]: 1 }, "one version, allocated once");
    assert.equal(loadRunRecord(fake.runs, deriveId("exec", "cli-busy")).envelope_json, runs[0].envelope_json);
  } finally {
    fake.cleanup();
  }
});

test("run gives up once --capacity-wait-secs is spent, says so, and leaves the attempt ready for a replay", async () => {
  const fake = setup(1000);
  try {
    const { status, stdout, stderr } = await cli([...fake.runArgs("cli-full"), "--capacity-wait-secs", "1", "--", "true"], fake.env);
    assert.equal(status, 1, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(outcome.outcome, "refused");
    assert.deepEqual(outcome.refused, { verb: "start", reason: "capacity_exhausted" });
    assert.equal(outcome.finalState, "ready");
    assert.ok(outcome.capacity_waits.length >= 2);
    const attempt = deriveId("exec", "cli-full");
    assert.match(
      stderr,
      new RegExp(`the node stayed at capacity for 1 s \\(${outcome.capacity_waits.length} retries of start operation 3\\); the attempt is admitted and ready: replay --attempt ${attempt} sends the same start again`),
    );
    assert.deepEqual(fake.versions(), { [deriveId("task", "cli-task")]: 1 });
  } finally {
    fake.cleanup();
  }
});

test("--capacity-wait-secs 0 sends one start; replay sends the recorded run once, never waits, and completes once there is room", async () => {
  const fake = setup(1000);
  try {
    const first = await cli([...fake.runArgs("cli-once"), "--capacity-wait-secs", "0", "--", "true"], fake.env);
    assert.equal(first.status, 1, first.stderr);
    assert.deepEqual(JSON.parse(first.stdout).capacity_waits, []);
    assert.deepEqual(fake.received().map((line) => line.cmd), ["run"]);
    const replayArgs = ["replay", ...fake.common, "--state-dir", join(fake.dir, "cp"), "--attempt", deriveId("exec", "cli-once")];
    const busy = await cli(replayArgs, fake.env);
    assert.equal(busy.status, 1, busy.stderr);
    const refused = JSON.parse(busy.stdout);
    assert.equal(refused.replayed, true);
    assert.deepEqual(refused.refused, { verb: "start", reason: "capacity_exhausted" });
    assert.deepEqual(refused.capacity_waits, [], "a replay sends the recorded run once");
    const waited = await cli([...replayArgs, "--capacity-wait-secs", "5"], fake.env);
    assert.equal(waited.status, 2);
    assert.match(waited.stderr, /replay sends the recorded run once; --capacity-wait-secs is run's/);
    fake.free();
    const done = await cli(replayArgs, fake.env);
    assert.equal(done.status, 0, done.stderr);
    assert.equal(JSON.parse(done.stdout).outcome, "completed");
    const runs = fake.received().filter((line) => line.cmd === "run");
    assert.equal(runs.length, 3);
    for (const again of runs.slice(1)) assert.deepEqual(again, runs[0], "a replay is exact");
    assert.deepEqual(fake.versions(), { [deriveId("task", "cli-task")]: 1 });
  } finally {
    fake.cleanup();
  }
});

test("run refuses a --capacity-wait-secs that is not a non-negative integer before anything is sent", async () => {
  const fake = setup(0);
  try {
    for (const value of ["ten", "1.5"]) {
      const { status, stderr } = await cli([...fake.runArgs("cli-bad"), "--capacity-wait-secs", value, "--", "true"], fake.env);
      assert.equal(status, 2, stderr);
      assert.match(stderr, /--capacity-wait-secs takes a non-negative integer/);
    }
    assert.deepEqual(fake.received(), []);
    assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-bad")}.json`)));
  } finally {
    fake.cleanup();
  }
});
