// The command line's action channel (node-integration-from-nodejs.md §7.2): `run
// --actions` puts the grant in the signed manifest and, with a policy, answers the
// workload's requests from a second adapter while the first runs the attempt; `actions`
// and `answer` serve a run driven elsewhere. The adapter is `fixtures/fake-adapter.mjs`,
// whose run waits until every scripted request is answered and exits 0 only if all were
// approved, as the acceptance's workload does against a real node.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { createIssuerKey, deriveId, loadRunRecord } from "../ward-node.mjs";

const FAKE = fileURLToPath(new URL("../fixtures/fake-adapter.mjs", import.meta.url));
const CLI = fileURLToPath(new URL("../control-plane.mjs", import.meta.url));
const SNAPSHOT = "c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b";

function request(action, extra = {}) {
  return { action, id: `ask-${action}`, kind: "approval", summary: `deploy step ${action}`, detail: `plan ${action}`, expires_in_ms: 290_000, ...extra };
}

/** A control-plane state directory, an issuer key and a fake adapter scripted with `channel`. */
function setup(channel) {
  const dir = mkdtempSync(join(tmpdir(), "ward-cli-actions-"));
  const state = join(dir, "channel.json");
  writeFileSync(state, JSON.stringify(channel));
  const adapter = join(dir, "adapter.sh");
  writeFileSync(adapter, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(FAKE)} "$@"\n`);
  chmodSync(adapter, 0o755);
  createIssuerKey(join(dir, "cp", "issuer.pem"));
  const log = join(dir, "received.jsonl");
  const env = { ...process.env, FAKE_ADAPTER_ACTIONS: state, FAKE_ADAPTER_LOG: log };
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
    "--actions-poll-ms", "10",
  ];
  return {
    dir,
    env,
    common,
    runArgs,
    runs: join(dir, "cp", "runs"),
    channel: () => JSON.parse(readFileSync(state, "utf8")),
    received: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : []),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** Run the command line to its exit: {status, stdout, stderr}. */
function cli(args, env, input = null) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("exit", (status) => resolve({ status, stdout, stderr }));
    if (input !== null) child.stdin.write(input);
    child.stdin.end();
  });
}

test("run --actions --approve-all grants the channel, answers every request approved, prints each, and completes", async () => {
  const fake = setup({ requests: [request(1, { expires_in_ms: 59_000 }), request(2, { after: 3, expires_in_ms: 59_000 })] });
  try {
    const { status, stdout, stderr } = await cli(
      [...fake.runArgs("cli-approve"), "--actions", "approval", "--actions-max-pending", "1", "--actions-wait-secs", "60", "--approve-all", "--note", "ok by policy", "--", "python3", "agent.py"],
      fake.env,
    );
    assert.equal(status, 0, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(stdout.trim().split("\n").length, 1, "stdout is the one outcome line");
    assert.equal(outcome.outcome, "completed");
    assert.deepEqual(
      outcome.actions.map(({ request: n, id, kind, summary, decision, note, operation_id, result }) => [n, id, kind, summary, decision, note, operation_id, result]),
      [
        [1, "ask-1", "approval", "deploy step 1", "approved", "ok by policy", 263, "answered"],
        [2, "ask-2", "approval", "deploy step 2", "approved", "ok by policy", 264, "answered"],
      ],
    );
    assert.match(stderr, /request 1 \(approval, id ask-1\): deploy step 1/);
    assert.match(stderr, /request 1 answered approved \(operation 263\)/);
    assert.match(stderr, /request 2 answered approved \(operation 264\)/);
    const run = fake.received().find((line) => line.cmd === "run");
    const envelope = JSON.parse(run.envelope_json);
    assert.equal(
      Buffer.from(envelope.workload.capability_manifest.bytes, "hex").toString("utf8"),
      '{"network":"offline","actions":{"kinds":["approval"],"max_pending":1,"max_total":8,"wait_secs":60}}',
    );
    const record = loadRunRecord(fake.runs, deriveId("exec", "cli-approve"));
    assert.deepEqual(record.answers.map((answer) => [answer.request, answer.decision, answer.operation_id]), [[1, "approved", 263], [2, "approved", 264]]);
  } finally {
    fake.cleanup();
  }
});

test("run --deny-all answers denied, and the workload's failure is the outcome", async () => {
  const fake = setup({ requests: [request(1)] });
  try {
    const { status, stdout, stderr } = await cli([...fake.runArgs("cli-deny"), "--actions", "approval", "--deny-all", "--", "python3", "agent.py"], fake.env);
    assert.equal(status, 1, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(outcome.outcome, "failed");
    assert.equal(outcome.exitStatus, 3);
    assert.deepEqual(outcome.actions.map(({ decision, result }) => [decision, result]), [["denied", "answered"]]);
    assert.equal(outcome.actions[0].note, undefined, "no --note, no note");
    assert.match(stderr, /request 1 answered denied \(operation 263\)/);
  } finally {
    fake.cleanup();
  }
});

test("run --ask shows each request and answers from stdin, a note after the verdict", async () => {
  const fake = setup({ requests: [request(1), request(2, { kind: "decision", summary: "use the cache?", detail: "it is warm" })] });
  try {
    const { status, stdout, stderr } = await cli(
      [...fake.runArgs("cli-ask"), "--actions", "approval,decision", "--ask", "--", "python3", "agent.py"],
      fake.env,
      "y looks fine\nno\n",
    );
    assert.equal(status, 1, stderr);
    const outcome = JSON.parse(stdout);
    assert.deepEqual(
      outcome.actions.map(({ request: n, decision, note }) => [n, decision, note ?? null]),
      [[1, "approved", "looks fine"], [2, "denied", null]],
    );
    assert.match(stderr, /request 2 \(decision, id ask-2\): use the cache\?/);
    assert.match(stderr, /it is warm/);
    assert.match(stderr, /approve request 1\? \[y\/N\]/);
  } finally {
    fake.cleanup();
  }
});

test("run --ask with stdin closed denies rather than guesses", async () => {
  const fake = setup({ requests: [request(1)] });
  try {
    const { status, stdout } = await cli([...fake.runArgs("cli-ask-eof"), "--actions", "approval", "--ask", "--", "python3", "agent.py"], fake.env, "");
    assert.equal(status, 1);
    assert.deepEqual(JSON.parse(stdout).actions.map(({ decision, note }) => [decision, note]), [["denied", "no answer on stdin"]]);
  } finally {
    fake.cleanup();
  }
});

test("run refuses a bad grant or policy before anything is signed or recorded", async () => {
  const fake = setup({ requests: [] });
  try {
    for (const [flags, pattern] of [
      [["--approve-all"], /--approve-all, --deny-all and --ask need --actions/],
      [["--actions", "approval", "--approve-all", "--deny-all"], /one of --approve-all, --deny-all or --ask/],
      [["--actions", "credential", "--approve-all"], /credential/],
      [["--actions", "approval", "--actions-max-pending", "9", "--actions-max-total", "9", "--approve-all"], /unsupported_grant/],
      [["--actions", "approval", "--actions-wait-secs", "0", "--approve-all"], /wait_secs/],
      [["--actions-max-total", "4"], /need --actions/],
      [["--actions", "approval", "--note", "x".repeat(513), "--approve-all"], /note/],
      [["--actions", "approval", "--ask", "--note", "fine"], /--note goes with --approve-all or --deny-all/],
      [["--actions", "approval", "--note", "fine"], /--note goes with/],
    ]) {
      const { status, stdout, stderr } = await cli([...fake.runArgs("cli-bad"), ...flags, "--", "true"], fake.env);
      assert.equal(status, 2, `${flags.join(" ")}: ${stderr}`);
      assert.match(stderr, pattern, flags.join(" "));
      assert.equal(stdout, "");
    }
    assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-bad")}.json`)), "nothing was recorded");
    assert.deepEqual(fake.received(), [], "nothing reached the adapter");
  } finally {
    fake.cleanup();
  }
});

test("actions and answer serve a run driven elsewhere, from the run record or an explicit binding", async () => {
  const fake = setup({ requests: [request(1)] });
  try {
    // A run without a policy: nobody in this process answers.
    const running = cli([...fake.runArgs("cli-elsewhere"), "--actions", "approval", "--", "python3", "agent.py"], fake.env);
    const attempt = deriveId("exec", "cli-elsewhere");
    let listed;
    for (let i = 0; i < 500; i += 1) {
      listed = await cli(["actions", ...fake.common, "--state-dir", join(fake.dir, "cp"), "--attempt", attempt], fake.env);
      if (listed.status === 0 && JSON.parse(listed.stdout).pending.length === 1) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(listed.status, 0, listed.stderr);
    assert.deepEqual(JSON.parse(listed.stdout), { state: "running", pending: [request(1)] });
    const answer = (flags) => cli(["answer", ...fake.common, "--state-dir", join(fake.dir, "cp"), "--attempt", attempt, ...flags], fake.env);
    const first = await answer(["--request", "1", "--decision", "approved", "--note", "from elsewhere"]);
    assert.equal(first.status, 0, first.stderr);
    assert.deepEqual(JSON.parse(first.stdout), { result: "answered", request: 1, decision: "approved", operation_id: 263 });
    // The same answer again is a replay under the recorded id; another one is refused here.
    const replayed = await answer(["--request", "1", "--decision", "approved", "--note", "from elsewhere"]);
    assert.equal(replayed.status, 0, replayed.stderr);
    assert.deepEqual(JSON.parse(replayed.stdout), { result: "answered", request: 1, decision: "approved", operation_id: 263 });
    const other = await answer(["--request", "1", "--decision", "denied"]);
    assert.equal(other.status, 2);
    assert.match(other.stderr, /already answered request 1 approved under operation 263/);
    const outcome = JSON.parse((await running).stdout);
    assert.equal(outcome.outcome, "completed");
    assert.deepEqual(outcome.actions, [], "the run itself answered nothing");
    // An explicit binding needs an explicit operation id, and the node's refusal exits 1:
    // the attempt has ended, so a new answer is invalid_state.
    const binding = loadRunRecord(fake.runs, attempt).binding;
    const explicit = ["answer", ...fake.common, "--task", binding.task, "--attempt", binding.attempt, "--lease", binding.lease, "--request", "1", "--decision", "denied"];
    const missing = await cli(explicit, fake.env);
    assert.equal(missing.status, 2);
    assert.match(missing.stderr, /--operation-id is required/);
    const refused = await cli([...explicit, "--operation-id", "300"], fake.env);
    assert.equal(refused.status, 1);
    assert.deepEqual(JSON.parse(refused.stdout), { result: "rejected", reason: "invalid_state", operation_id: 300 });
    const bad = await cli([...explicit, "--operation-id", "300", "--decision", "expired"], fake.env);
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /approved or denied/);
  } finally {
    fake.cleanup();
  }
});
