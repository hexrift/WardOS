// Isolation floors on the control-plane side (node-integration.md §5, §7.5; ADR-0039,
// #263): the floor is held to ward-node-protocol's grammar (one object whose only field is
// `minimum`, one of container, microvm and vm; sandbox is spelled by leaving the field
// out) before anything is signed; it is signed last, after `hold`, as the node's encoder
// writes it; a node whose capability document does not offer a Capsule backend at that
// level (`isolation.backends.<level>`) is refused the floor here, before a version is
// allocated; and `run --isolation` puts the floor in the signed manifest and lists it in
// the outcome. The adapter is `fixtures/fake-adapter.mjs`, which offers backends with
// FAKE_ADAPTER_BACKENDS.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  ISOLATION_LEVELS,
  blake3Hex,
  buildEnvelope,
  createIssuerKey,
  deriveId,
  isolationFloor,
  isolationFloorOf,
  issuerFromSeed,
  loadRunRecord,
  manifest,
  offersIsolation,
  requireIsolation,
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
// The example of node-integration.md §7.5, as signed.
const EXAMPLE = '{"network":"offline","isolation":{"minimum":"microvm"}}';

function text(built) {
  return Buffer.from(built.bytes, "hex").toString("utf8");
}

/** A capability document as a node reports it, offering backends at `levels` beside its sandbox. */
function document(levels = [], sandbox = true) {
  return {
    protocol: { major: 1, minor: 3 },
    isolation: {
      namespaces: { sandbox, user_namespace: sandbox },
      backends: { container: levels.includes("container"), microvm: levels.includes("microvm"), vm: levels.includes("vm") },
    },
    lifecycle: { pause: true, stop: true, revoke: true, admit: true, start: true },
  };
}

// ---- the floor -------------------------------------------------------------------------

test("the levels are the protocol's, weakest first", () => {
  assert.deepEqual(ISOLATION_LEVELS, ["sandbox", "container", "microvm", "vm"]);
  assert.ok(Object.isFrozen(ISOLATION_LEVELS));
});

test("a floor is built in wire spelling, and the §7.5 example is signed byte for byte", () => {
  assert.deepEqual(isolationFloor("microvm"), { minimum: "microvm" });
  const built = manifest({ network: "offline", isolation: isolationFloor("microvm") });
  assert.equal(text(built), EXAMPLE);
  assert.equal(built.hash, blake3Hex(Buffer.from(EXAMPLE)));
  assert.deepEqual(manifest({ isolation: { minimum: "microvm" }, network: "offline" }), built, "the caller's key order changes nothing");
  for (const level of ["container", "vm"]) {
    assert.equal(text(manifest({ network: "offline", isolation: isolationFloor(level) })), `{"network":"offline","isolation":{"minimum":"${level}"}}`);
  }
  // A manifest without it is byte for byte what it was.
  assert.equal(text(manifest({ network: "offline" })), '{"network":"offline"}');
});

test("the floor is signed after every grant, as the node's encoder writes it", () => {
  const all = manifest({
    isolation: { minimum: "vm" },
    hold: { services: ["artifacts"] },
    credentials: [{ service: "artifacts", host: "artifacts.example.com", ttl_secs: 60 }],
    actions: { kinds: ["approval"], max_pending: 1, max_total: 1, wait_secs: 1 },
    resources: { pids: 8 },
    network: { custom: ["artifacts.example.com"] },
  });
  assert.equal(
    text(all),
    '{"network":{"custom":["artifacts.example.com"]},"resources":{"pids":8},' +
      '"actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":1},' +
      '"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":60}],' +
      '"hold":{"services":["artifacts"]},"isolation":{"minimum":"vm"}}',
  );
});

test("a floor outside ward-node-protocol's grammar is refused before signing", () => {
  const refuses = (isolation, pattern) => assert.throws(() => manifest({ network: "offline", isolation }), pattern);
  // The decoder's own refusals (isolation.rs): sandbox, an unknown or misspelt level, null,
  // an array, a string, an empty object, and any other field.
  refuses({ minimum: "sandbox" }, /sandbox is spelled by leaving isolation out/);
  refuses({ minimum: "kvm" }, /one of container, microvm, vm, got "kvm"/);
  refuses({ minimum: "MicroVM" }, /one of container, microvm, vm/);
  refuses({ minimum: null }, /one of container, microvm, vm, got null/);
  refuses({ minimum: 2 }, /one of container, microvm, vm/);
  refuses({}, /the field `minimum` and nothing else/);
  refuses({ minimum: "vm", maximum: "vm" }, /the field `minimum` and nothing else/);
  refuses({ backend: "bubblewrap" }, /the field `minimum` and nothing else/);
  refuses(["microvm"], /one object/);
  refuses("microvm", /one object/);
  refuses(null, /one object/);
  assert.throws(() => isolationFloor("sandbox"), /leaving isolation out/);
  assert.throws(() => isolationFloor(undefined), /one of container, microvm, vm/);
});

test("isolationFloorOf reads the floor back from the signed bytes", () => {
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
    workload: { argv: ["make", "test"], manifest: { network: "offline", isolation: { minimum: "container" } }, snapshot: SNAPSHOT, wallClockBudgetMs: 600_000 },
    issuedAtUnixMs: now,
    expiresAtUnixMs: now + 900_000,
    version: 1,
  });
  const signed = signEnvelope(issuerFromSeed(Buffer.alloc(32, 7)), envelope);
  assert.deepEqual(isolationFloorOf(signed.envelope_json), { minimum: "container" });
  const plain = signEnvelope(issuerFromSeed(Buffer.alloc(32, 7)), { ...envelope, workload: { ...envelope.workload, capability_manifest: manifest() } });
  assert.equal(isolationFloorOf(plain.envelope_json), null);
});

// ---- the node's offer ------------------------------------------------------------------

test("a node offers a level only through its isolation flag for exactly that level", () => {
  const sandboxOnly = document();
  assert.equal(offersIsolation(sandboxOnly, "sandbox"), true);
  for (const level of ["container", "microvm", "vm"]) {
    assert.equal(offersIsolation(sandboxOnly, level), false, level);
    const offering = document([level]);
    for (const other of ISOLATION_LEVELS) {
      assert.equal(offersIsolation(offering, other), other === level || other === "sandbox", `${level} offers ${other}`);
    }
  }
  assert.equal(offersIsolation(document([], false), "sandbox"), false, "a node that executes nothing offers nothing");
  assert.equal(offersIsolation(document(["vm"]), "microvm"), false, "never a stronger level in place of the one asked for");
  assert.equal(offersIsolation(null, "sandbox"), false);
  assert.equal(offersIsolation({ isolation: { backends: { microvm: "yes" } } }, "microvm"), false);
  assert.equal(offersIsolation(document(["microvm"]), "kvm"), false);
});

test("requireIsolation refuses, naming the flag and unsupported_grant, or returns the document", () => {
  const offering = document(["microvm"]);
  assert.equal(requireIsolation(offering, isolationFloor("microvm")), offering);
  assert.throws(() => requireIsolation(document(), isolationFloor("microvm")), /does not advertise isolation\.backends\.microvm true.*floor of microvm as unsupported_grant/);
  assert.throws(() => requireIsolation(document(["vm"]), { minimum: "container" }), /isolation\.backends\.container.*unsupported_grant/);
  assert.throws(() => requireIsolation(offering, { minimum: "sandbox" }), /leaving isolation out/);
});

// ---- the command line ------------------------------------------------------------------

/** A control-plane state directory, an issuer key and a fake adapter offering `levels` (comma separated, or ""). */
function setup(levels) {
  const dir = mkdtempSync(join(tmpdir(), "ward-cli-isolation-"));
  const adapter = join(dir, "adapter.sh");
  writeFileSync(adapter, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(FAKE)} "$@"\n`);
  chmodSync(adapter, 0o755);
  createIssuerKey(join(dir, "cp", "issuer.pem"));
  const log = join(dir, "received.jsonl");
  const env = { ...process.env, FAKE_ADAPTER_LOG: log, FAKE_ADAPTER_BACKENDS: levels };
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

test("run --isolation asks the node first, signs the floor and lists it in the outcome", async () => {
  const fake = setup("microvm");
  try {
    const { status, stdout, stderr } = await cli([...fake.runArgs("cli-floor"), "--isolation", "microvm", "--", "make", "test"], fake.env);
    assert.equal(status, 0, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(outcome.outcome, "completed");
    assert.deepEqual(outcome.isolation, { minimum: "microvm" });
    const received = fake.received();
    assert.deepEqual(received.map((line) => line.cmd), ["capabilities", "run"], "the node's offer is read before the run");
    const envelope = JSON.parse(received[1].envelope_json);
    assert.equal(Buffer.from(envelope.workload.capability_manifest.bytes, "hex").toString("utf8"), EXAMPLE);
    const record = loadRunRecord(fake.runs, deriveId("exec", "cli-floor"));
    assert.deepEqual(isolationFloorOf(record.envelope_json), outcome.isolation);
    // A replay resends the recorded bytes and lists the same floor.
    const replayed = await cli(["replay", ...fake.common, "--state-dir", join(fake.dir, "cp"), "--attempt", deriveId("exec", "cli-floor")], fake.env);
    assert.equal(replayed.status, 0, replayed.stderr);
    assert.deepEqual(JSON.parse(replayed.stdout).isolation, outcome.isolation);
    assert.equal(fake.received().at(-1).envelope_json, received[1].envelope_json, "the same signed bytes");
    // A run without a floor lists none and asks nothing first.
    const before = fake.received().length;
    const plain = await cli([...fake.runArgs("cli-plain"), "--", "true"], fake.env);
    assert.equal(plain.status, 0, plain.stderr);
    assert.equal(JSON.parse(plain.stdout).isolation, undefined);
    assert.deepEqual(fake.received().slice(before).map((line) => line.cmd), ["run"]);
  } finally {
    fake.cleanup();
  }
});

test("run with a floor the node does not offer is refused before a version is allocated or anything is signed", async () => {
  for (const [levels, floor, pattern] of [
    ["", "container", /isolation\.backends\.container true.*unsupported_grant/],
    ["", "microvm", /isolation\.backends\.microvm true.*unsupported_grant/],
    ["vm", "microvm", /isolation\.backends\.microvm true.*unsupported_grant/],
    ["container", "vm", /isolation\.backends\.vm true.*unsupported_grant/],
  ]) {
    const fake = setup(levels);
    try {
      const { status, stdout, stderr } = await cli([...fake.runArgs("cli-unoffered"), "--isolation", floor, "--", "true"], fake.env);
      assert.equal(status, 2, stderr);
      assert.match(stderr, pattern);
      assert.equal(stdout, "");
      assert.deepEqual(fake.received(), [{ cmd: "capabilities" }], "only the capability document was asked for");
      assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-unoffered")}.json`)), "nothing was recorded");
      assert.ok(!existsSync(join(fake.dir, "cp", "admission-versions.json")), "no version was allocated");
    } finally {
      fake.cleanup();
    }
  }
});

test("run refuses a floor outside the grammar before the node is asked", async () => {
  const fake = setup("container,microvm,vm");
  try {
    for (const [level, pattern] of [
      ["sandbox", /leaving isolation out/],
      ["kvm", /one of container, microvm, vm, got "kvm"/],
      ["", /one of container, microvm, vm, got ""/],
    ]) {
      const { status, stdout, stderr } = await cli([...fake.runArgs("cli-bad"), "--isolation", level, "--", "true"], fake.env);
      assert.equal(status, 2, `${level}: ${stderr}`);
      assert.match(stderr, pattern, level);
      assert.equal(stdout, "");
    }
    assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-bad")}.json`)), "nothing was recorded");
    assert.deepEqual(fake.received(), [], "nothing reached the adapter");
  } finally {
    fake.cleanup();
  }
});
