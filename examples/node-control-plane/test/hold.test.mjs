// Approval holds on the control-plane side (node-integration.md §6.9, §7.5; ADR-0035): the
// `hold` is held to the protocol's grammar and to the rest of its manifest before anything
// is signed and is signed last; a listing's node-opened requests are held to the hold the
// attempt was admitted under; a node whose capability document does not offer holds is
// refused the manifest here; and `run --hold` signs it, answers the node-opened requests
// by the policy and lists the hold in the outcome. The adapter is
// `fixtures/fake-adapter.mjs`, which advertises holds with FAKE_ADAPTER_APPROVAL_HOLD=1.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  HOLD_LIMITS,
  answerOperationId,
  buildEnvelope,
  createIssuerKey,
  decodeActions,
  deriveId,
  heldCapabilities,
  holdGrant,
  holdGrantOf,
  issuerFromSeed,
  loadRunRecord,
  manifest,
  offersApprovalHold,
  operationIds,
  requireApprovalHold,
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
const NETWORK = { custom: ["deploy.example.com", "*.wild.example", "artifacts.example.com"] };
const ACTIONS = { kinds: ["approval"], max_pending: 1, max_total: 1, wait_secs: 60 };
const CREDENTIALS = [{ service: "artifacts", host: "artifacts.example.com", ttl_secs: 60 }];
const HOLD = { hosts: ["deploy.example.com", "*.wild.example"], services: ["artifacts"] };
// The manifest of ward-node-protocol's hold tests, as the node's encoder writes it.
const SIGNED =
  '{"network":{"custom":["deploy.example.com","*.wild.example","artifacts.example.com"]},' +
  '"actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":60},' +
  '"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":60}],' +
  '"hold":{"hosts":["deploy.example.com","*.wild.example"],"services":["artifacts"]}}';

function text(built) {
  return Buffer.from(built.bytes, "hex").toString("utf8");
}

function held(manifestObject = {}) {
  return { network: NETWORK, actions: ACTIONS, credentials: CREDENTIALS, hold: HOLD, ...manifestObject };
}

function opened(action, index, capability, extra = {}) {
  const summary = capability.host !== undefined ? `network ${capability.host}` : `credential ${capability.service}`;
  return { action, id: `hold:${index}`, kind: "approval", summary, detail: "held until approved", expires_in_ms: 1_000, hold: capability, ...extra };
}

function asked(action, extra = {}) {
  return { action, id: `ask-${action}`, kind: "approval", summary: `step ${action}`, detail: "", expires_in_ms: 1_000, ...extra };
}

// ---- the hold --------------------------------------------------------------------------

test("the limit is the protocol's: 8 held capabilities", () => {
  assert.deepEqual(HOLD_LIMITS, { holds: 8 });
  assert.ok(Object.isFrozen(HOLD_LIMITS));
});

test("a hold is built in wire spelling and signed last, byte for byte as the node encodes it", () => {
  assert.deepEqual(holdGrant({ hosts: HOLD.hosts, services: HOLD.services }), HOLD);
  assert.deepEqual(holdGrant({ services: ["artifacts"] }), { services: ["artifacts"] });
  assert.deepEqual(holdGrant({ hosts: ["a.example"], services: [] }), { hosts: ["a.example"] });
  const built = manifest(held());
  assert.equal(text(built), SIGNED);
  // The caller's key order changes nothing.
  assert.deepEqual(manifest({ hold: { services: ["artifacts"], hosts: HOLD.hosts }, credentials: CREDENTIALS, actions: ACTIONS, network: NETWORK }), built);
  assert.deepEqual(heldCapabilities(HOLD), [
    { id: "hold:1", capability: { host: "deploy.example.com" }, summary: "network deploy.example.com" },
    { id: "hold:2", capability: { host: "*.wild.example" }, summary: "network *.wild.example" },
    { id: "hold:3", capability: { service: "artifacts" }, summary: "credential artifacts" },
  ]);
});

test("a hold outside ADR-0035's grammar, or naming what its manifest does not grant, is refused before signing", () => {
  const refuses = (manifestObject, pattern) => assert.throws(() => manifest(held(manifestObject)), pattern);
  refuses({ hold: null }, /hold/);
  refuses({ hold: [] }, /hold/);
  refuses({ hold: {} }, /hosts and services/);
  refuses({ hold: { hosts: HOLD.hosts, ports: [443] } }, /hosts and services/);
  refuses({ hold: { hosts: [] } }, /non-empty/);
  refuses({ hold: { services: "artifacts" } }, /non-empty/);
  refuses({ hold: { hosts: ["deploy.example.com", "deploy.example.com"] } }, /repeats/);
  refuses({ hold: { hosts: ["Deploy.example.com"] } }, /DNS name/);
  refuses({ hold: { services: ["Artifacts"] } }, /a-z/);
  refuses({ hold: { hosts: ["other.example.com"] } }, /network.custom/);
  refuses({ hold: { hosts: ["x.wild.example"] } }, /network.custom/);
  refuses({ hold: { services: ["registry"] } }, /credentials/);
  assert.throws(() => manifest({ network: NETWORK, credentials: CREDENTIALS, hold: HOLD }), /approval/);
  refuses({ actions: { ...ACTIONS, kinds: ["decision"] } }, /approval/);
  assert.throws(() => manifest({ network: "offline", actions: ACTIONS, hold: { hosts: ["deploy.example.com"] } }), /network.custom/);
  const many = Array.from({ length: HOLD_LIMITS.holds + 1 }, (_, i) => `h${i}.example.com`);
  assert.throws(() => manifest({ network: { custom: many }, actions: ACTIONS, hold: { hosts: many } }), /at most 8/);
  assert.ok(manifest({ network: { custom: many }, actions: ACTIONS, hold: { hosts: many.slice(0, 8) } }));
  for (const bad of [{ hosts: [] , services: [] }, { hosts: "a" }, { services: [7] }]) assert.throws(() => holdGrant(bad));
});

test("the hold a signed envelope carries is read back from its exact bytes", () => {
  const now = 1_791_201_600_000;
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
      issuedAtUnixMs: now,
      expiresAtUnixMs: now + 3_600_000,
    }),
    workload: { argv: ["true"], manifest: held(), snapshot: SNAPSHOT, wallClockBudgetMs: 60_000 },
    issuedAtUnixMs: now,
    expiresAtUnixMs: now + 900_000,
    version: 1,
  });
  const signed = signEnvelope(issuerFromSeed(Buffer.alloc(32, 7)), envelope);
  assert.deepEqual(holdGrantOf(signed.envelope_json), HOLD);
  const plain = signEnvelope(issuerFromSeed(Buffer.alloc(32, 7)), { ...envelope, workload: { ...envelope.workload, capability_manifest: manifest() } });
  assert.equal(holdGrantOf(plain.envelope_json), null);
});

test("a node offers holds only when its actions section says hold: true", () => {
  const document = (actions) => ({ protocol: { major: 1, minor: 3 }, ...(actions === undefined ? {} : { actions }) });
  const ceilings = { approval: true, decision: true, max_pending: 8, max_total: 64, max_wait_secs: 3600 };
  assert.equal(offersApprovalHold(document({ ...ceilings, hold: true })), true);
  assert.equal(requireApprovalHold(document({ ...ceilings, hold: true })).actions.hold, true);
  for (const capabilities of [document(ceilings), document({ ...ceilings, hold: "true" }), document(undefined), null, undefined, {}]) {
    assert.equal(offersApprovalHold(capabilities), false);
    assert.throws(() => requireApprovalHold(capabilities), /actions.hold.*unsupported_grant/);
  }
});

// ---- the listing -----------------------------------------------------------------------

test("a listing's node-opened requests are decoded with their hold and held to the attempt's", () => {
  const listing = {
    state: "running",
    pending: [asked(1), opened(2, 1, { host: "deploy.example.com" }), opened(3, 3, { service: "artifacts" })],
  };
  const decoded = decodeActions(listing, ACTIONS, HOLD);
  assert.deepEqual(decoded.pending[1].hold, { host: "deploy.example.com" });
  assert.equal(decoded.pending[0].hold, undefined);
  assert.deepEqual(decodeActions(listing), decoded, "without the grant only the contract's bounds apply");
  const refuses = (pending, pattern, grant = ACTIONS, hold = HOLD) =>
    assert.throws(() => decodeActions({ state: "running", pending }, grant, hold), pattern);
  refuses([opened(1, 2, { host: "deploy.example.com" })], /not the request the node opens/);
  refuses([opened(1, 1, { host: "deploy.example.com" }, { summary: "network elsewhere" })], /not the request the node opens/);
  refuses([opened(1, 9, { host: "deploy.example.com" })], /not the request the node opens/);
  refuses([opened(1, 1, { host: "deploy.example.com" }, { id: "mine" })], /hold:N/);
  refuses([opened(1, 1, { host: "deploy.example.com" }, { kind: "decision" })], /hold:N|not granted/, null, null);
  refuses([opened(1, 1, { port: 443 })], /\{host: pattern\} or \{service: name\}/);
  refuses([opened(1, 1, { host: "deploy.example.com", service: "artifacts" })], /\{host: pattern\} or \{service: name\}/);
  refuses([asked(1, { id: "hold:1" })], /names no held capability/);
  refuses([opened(1, 1, { host: "deploy.example.com" })], /at most 0/, ACTIONS, null);
  refuses([opened(1, 1, { host: "deploy.example.com" }), opened(2, 2, { host: "*.wild.example" }), opened(3, 3, { service: "artifacts" }), opened(4, 3, { service: "artifacts" }, { id: "hold:4" })], /at most 3/);
  // Up to the workload's ceiling and every hold at once; numbers past max_total for the holds.
  const full = [
    ...Array.from({ length: 8 }, (_, i) => asked(i + 1)),
    ...Array.from({ length: 8 }, (_, i) => opened(9 + i, i + 1, { host: `h${i}.example.com` })),
  ];
  assert.equal(decodeActions({ state: "running", pending: full }).pending.length, 16);
  assert.throws(() => decodeActions({ state: "running", pending: [...full, opened(17, 9, { host: "x.example" })] }), /at most 8/);
  assert.ok(decodeActions({ state: "running", pending: [opened(4, 3, { service: "artifacts" })] }, ACTIONS, HOLD));
  refuses([opened(5, 3, { service: "artifacts" })], /max_total/);
  // The answers to the node's requests take operation ids past the workload's 64.
  assert.equal(answerOperationId(operationIds(1), 72), operationIds(1).first_answer + 71);
});

// ---- the command line --------------------------------------------------------------------

/** A control-plane state directory, an issuer key and a fake adapter scripted with `channel`. */
function setup(channel, holding = true) {
  const dir = mkdtempSync(join(tmpdir(), "ward-cli-hold-"));
  const state = join(dir, "channel.json");
  writeFileSync(state, JSON.stringify(channel));
  const adapter = join(dir, "adapter.sh");
  writeFileSync(adapter, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(FAKE)} "$@"\n`);
  chmodSync(adapter, 0o755);
  createIssuerKey(join(dir, "cp", "issuer.pem"));
  const log = join(dir, "received.jsonl");
  const env = {
    ...process.env,
    FAKE_ADAPTER_ACTIONS: state,
    FAKE_ADAPTER_LOG: log,
    FAKE_ADAPTER_CREDENTIALS: "1",
    FAKE_ADAPTER_APPROVAL_HOLD: holding ? "1" : "",
  };
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
    "--actions", "approval",
    "--actions-wait-secs", "60",
    "--credential", "artifacts=localhost:60",
  ];
  return {
    dir,
    env,
    common,
    runArgs,
    runs: join(dir, "cp", "runs"),
    received: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : []),
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

const NODE_OPENED = [
  { ...opened(1, 1, { host: "localhost" }), expires_in_ms: 59_000 },
  { ...opened(2, 2, { service: "artifacts" }), expires_in_ms: 59_000, after: 2 },
];

test("run --hold asks the node first, signs the hold last, answers the node's requests by the policy and lists the hold", async () => {
  const fake = setup({ requests: NODE_OPENED });
  try {
    const { status, stdout, stderr } = await cli(
      [...fake.runArgs("cli-hold"), "--hold", "service=artifacts", "--hold", "host=localhost", "--approve-all", "--", "python3", "fetch.py"],
      fake.env,
    );
    assert.equal(status, 0, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(outcome.outcome, "completed");
    assert.deepEqual(outcome.hold, { hosts: ["localhost"], services: ["artifacts"] });
    assert.deepEqual(
      outcome.actions.map(({ request, id, hold, decision, operation_id, result }) => [request, id, hold, decision, operation_id, result]),
      [
        [1, "hold:1", { host: "localhost" }, "approved", 263, "answered"],
        [2, "hold:2", { service: "artifacts" }, "approved", 264, "answered"],
      ],
    );
    assert.match(stderr, /request 1 \(approval, id hold:1, opened by the node for its hold on localhost\): network localhost/);
    const received = fake.received();
    assert.equal(received[0].cmd, "capabilities", "the node's offer is read before anything is signed");
    const run = received.find((line) => line.cmd === "run");
    assert.equal(
      Buffer.from(JSON.parse(run.envelope_json).workload.capability_manifest.bytes, "hex").toString("utf8"),
      '{"network":{"custom":["localhost"]},"actions":{"kinds":["approval"],"max_pending":2,"max_total":8,"wait_secs":60},' +
        '"credentials":[{"service":"artifacts","host":"localhost","ttl_secs":60}],"hold":{"hosts":["localhost"],"services":["artifacts"]}}',
    );
    const record = loadRunRecord(fake.runs, deriveId("exec", "cli-hold"));
    assert.deepEqual(holdGrantOf(record.envelope_json), { hosts: ["localhost"], services: ["artifacts"] });
    // A replay lists the recorded hold.
    const replayed = await cli(["replay", ...fake.common, "--state-dir", join(fake.dir, "cp"), "--attempt", deriveId("exec", "cli-hold")], fake.env);
    assert.equal(replayed.status, 0, replayed.stderr);
    assert.deepEqual(JSON.parse(replayed.stdout).hold, { hosts: ["localhost"], services: ["artifacts"] });
  } finally {
    fake.cleanup();
  }
});

test("run --hold --deny-all denies the node's request and the held workload's failure is the outcome", async () => {
  const fake = setup({ requests: [{ ...opened(1, 1, { service: "artifacts" }), expires_in_ms: 59_000 }] });
  try {
    const { status, stdout, stderr } = await cli([...fake.runArgs("cli-hold-deny"), "--hold", "service=artifacts", "--deny-all", "--", "python3", "fetch.py"], fake.env);
    assert.equal(status, 1, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(outcome.outcome, "failed");
    assert.deepEqual(outcome.actions.map(({ id, decision }) => [id, decision]), [["hold:1", "denied"]]);
  } finally {
    fake.cleanup();
  }
});

test("run --hold on a node that does not offer holds is refused before a version is allocated or anything is signed", async () => {
  const fake = setup({ requests: [] }, false);
  try {
    const { status, stdout, stderr } = await cli([...fake.runArgs("cli-unheld"), "--hold", "service=artifacts", "--", "true"], fake.env);
    assert.equal(status, 2, stderr);
    assert.match(stderr, /actions.hold.*unsupported_grant/);
    assert.equal(stdout, "");
    assert.deepEqual(fake.received(), [{ cmd: "capabilities" }], "only the capability document was asked for");
    assert.ok(!existsSync(join(fake.dir, "cp", "admission-versions.json")), "no version was allocated");
  } finally {
    fake.cleanup();
  }
});

test("run refuses a --hold outside the grammar or its manifest before the node is asked", async () => {
  const fake = setup({ requests: [] });
  try {
    for (const [flags, pattern] of [
      [["--hold", "artifacts"], /--hold takes host=<pattern> or service=<name>/],
      [["--hold", "port=443"], /--hold takes/],
      [["--hold", "host="], /--hold takes/],
      [["--hold", "host=other.example"], /network.custom/],
      [["--hold", "service=registry"], /credentials/],
      [["--hold", "service=Artifacts"], /a-z/],
      [["--hold", "service=artifacts", "--hold", "service=artifacts"], /repeats/],
    ]) {
      const { status, stdout, stderr } = await cli([...fake.runArgs("cli-bad-hold"), ...flags, "--", "true"], fake.env);
      assert.equal(status, 2, `${flags}: ${stderr}`);
      assert.match(stderr, pattern, flags.join(" "));
      assert.equal(stdout, "");
    }
    const withoutActions = fake.runArgs("cli-bad-hold").filter((arg, index, all) => !(arg === "--actions" || all[index - 1] === "--actions"));
    const unasked = await cli([...withoutActions.filter((arg, index, all) => !(arg === "--actions-wait-secs" || all[index - 1] === "--actions-wait-secs")), "--hold", "service=artifacts", "--", "true"], fake.env);
    assert.equal(unasked.status, 2);
    assert.match(unasked.stderr, /--hold needs --actions naming approval/);
    const decisionOnly = await cli([...fake.runArgs("cli-bad-hold").map((arg) => (arg === "approval" ? "decision" : arg)), "--hold", "service=artifacts", "--", "true"], fake.env);
    assert.equal(decisionOnly.status, 2);
    assert.match(decisionOnly.stderr, /naming approval/);
    assert.deepEqual(fake.received(), [], "nothing reached the adapter");
  } finally {
    fake.cleanup();
  }
});
