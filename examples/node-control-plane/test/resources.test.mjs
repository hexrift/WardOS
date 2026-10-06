// Resource limits on the control-plane side (node-integration.md §5, §7.5, §9; #260): the
// `resources` grant is held to ward-node-protocol's grammar (at least one of cpu_millis,
// memory_bytes and pids, each an integer >= 1, pids at most 65 536) before anything is
// signed; it is signed after `output` and before `actions`, its limits in the node's
// order; a node whose capability document does not enforce every limit it names, or whose
// `capacity` is below it, is refused the grant here, before a version is allocated; and
// `run --cpu-millis/--memory-bytes/--pids` puts the grant in the signed manifest and lists
// it in the outcome. The adapter is `fixtures/fake-adapter.mjs`, which advertises the
// enforced limits with FAKE_ADAPTER_RESOURCES.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  RESOURCE_CEILINGS,
  blake3Hex,
  buildEnvelope,
  createIssuerKey,
  deriveId,
  enforcesResources,
  issuerFromSeed,
  loadRunRecord,
  manifest,
  requireResourceEnforcement,
  resourcesGrant,
  resourcesGrantOf,
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
const EXAMPLE = '{"network":"offline","resources":{"cpu_millis":500,"memory_bytes":268435456,"pids":64}}';
const MIB = 1024 * 1024;

function text(built) {
  return Buffer.from(built.bytes, "hex").toString("utf8");
}

/** A capability document as a node reports it: `capacity`, and `resources` with these flags or none. */
function document(flags, capacity = { logical_cpus: 2, memory_bytes: 4096 * MIB }) {
  return {
    protocol: { major: 1, minor: 3 },
    capacity,
    lifecycle: { pause: true, stop: true, revoke: true, admit: true, start: true },
    ...(flags === null ? {} : { resources: flags }),
  };
}

const ALL = { cpu: true, memory: true, pids: true };

// ---- the grant -------------------------------------------------------------------------

test("the pid ceiling is the protocol's, and cpu is bounded per logical CPU", () => {
  assert.deepEqual(RESOURCE_CEILINGS, { pids: 65_536, cpuMillisPerCpu: 1000 });
  assert.ok(Object.isFrozen(RESOURCE_CEILINGS));
});

test("a resources grant is built in wire spelling, and the §7.5 example is signed byte for byte", () => {
  assert.deepEqual(resourcesGrant({ cpuMillis: 500, memoryBytes: 256 * MIB, pids: 64 }), { cpu_millis: 500, memory_bytes: 256 * MIB, pids: 64 });
  const built = manifest({ network: "offline", resources: { cpu_millis: 500, memory_bytes: 256 * MIB, pids: 64 } });
  assert.equal(text(built), EXAMPLE);
  assert.equal(built.hash, blake3Hex(Buffer.from(EXAMPLE)));
  // The caller's key order, in the manifest and in the grant, changes nothing.
  assert.deepEqual(manifest({ resources: { pids: 64, memory_bytes: 256 * MIB, cpu_millis: 500 }, network: "offline" }), built);
  // Absent limits are left out, as the node's encoder leaves them out.
  assert.deepEqual(resourcesGrant({ pids: 32, cpuMillis: 250 }), { cpu_millis: 250, pids: 32 });
  assert.equal(
    text(manifest({ network: "offline", resources: resourcesGrant({ cpuMillis: 250, pids: 32 }) })),
    '{"network":"offline","resources":{"cpu_millis":250,"pids":32}}',
  );
  assert.equal(text(manifest({ network: "offline", resources: resourcesGrant({ memoryBytes: 1 }) })), '{"network":"offline","resources":{"memory_bytes":1}}');
  // A manifest without it is byte for byte what it was.
  assert.equal(text(manifest({ network: "offline" })), '{"network":"offline"}');
});

test("the grant is signed after output and before actions, credentials and hold, as the node's encoder writes it", () => {
  const all = manifest({
    hold: { services: ["artifacts"] },
    credentials: [{ service: "artifacts", host: "artifacts.example.com", ttl_secs: 60 }],
    actions: { kinds: ["approval"], max_pending: 1, max_total: 1, wait_secs: 1 },
    resources: { pids: 8 },
    output: { stdio_bytes: 1, files: [], files_bytes: 0 },
    network: { custom: ["artifacts.example.com"] },
  });
  assert.equal(
    text(all),
    '{"network":{"custom":["artifacts.example.com"]},"output":{"stdio_bytes":1,"files":[],"files_bytes":0},' +
      '"resources":{"pids":8},' +
      '"actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":1},' +
      '"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":60}],' +
      '"hold":{"services":["artifacts"]}}',
  );
});

test("a grant outside ward-node-protocol's grammar is refused before signing, naming the field", () => {
  const refuses = (resources, pattern) => assert.throws(() => manifest({ network: "offline", resources }), pattern);
  // The decoder's own refusals (resources.rs): empty, zero, null, negative, fractional, a
  // string, an unknown field, an array, and `resources: null`.
  refuses({}, /names at least one of cpu_millis, memory_bytes, pids/);
  refuses({ pids: 0 }, /`pids` is an integer >= 1/);
  refuses({ cpu_millis: 0 }, /`cpu_millis` is an integer >= 1/);
  refuses({ memory_bytes: 0 }, /`memory_bytes` is an integer >= 1/);
  refuses({ pids: null }, /`pids` is an integer >= 1/);
  refuses({ pids: -1 }, /`pids` is an integer >= 1/);
  refuses({ pids: 1.5 }, /`pids` is an integer >= 1/);
  refuses({ pids: "16" }, /`pids` is an integer >= 1/);
  refuses({ disk_bytes: 1 }, /cpu_millis, memory_bytes, pids/);
  refuses({ pids: 1, disk_bytes: 1 }, /cpu_millis, memory_bytes, pids/);
  refuses([1], /one object/);
  refuses(null, /one object/);
  // Past what JSON carries exactly in JavaScript, and past the pid ceiling every node refuses.
  refuses({ memory_bytes: 2 ** 53 }, /`memory_bytes` is an integer >= 1/);
  refuses({ pids: RESOURCE_CEILINGS.pids + 1 }, /`pids` 65537 is above the 65536 every node refuses as unsupported_grant/);
  assert.ok(manifest({ network: "offline", resources: { pids: RESOURCE_CEILINGS.pids } }).hash);
  // The builder refuses the same, and treats only an omitted limit as absent.
  assert.throws(() => resourcesGrant({}), /names at least one/);
  assert.throws(() => resourcesGrant(), /names at least one/);
  assert.throws(() => resourcesGrant({ pids: 0 }), /`pids` is an integer >= 1/);
  assert.throws(() => resourcesGrant({ cpuMillis: null }), /`cpu_millis` is an integer >= 1/);
});

test("resourcesGrantOf reads the grant back from the signed bytes", () => {
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
    workload: { argv: ["make", "test"], manifest: { network: "offline", resources: { memory_bytes: 64 * MIB } }, snapshot: SNAPSHOT, wallClockBudgetMs: 600_000 },
    issuedAtUnixMs: now,
    expiresAtUnixMs: now + 900_000,
    version: 1,
  });
  const signed = signEnvelope(issuerFromSeed(Buffer.alloc(32, 7)), envelope);
  assert.deepEqual(resourcesGrantOf(signed.envelope_json), { memory_bytes: 64 * MIB });
  const plain = signEnvelope(issuerFromSeed(Buffer.alloc(32, 7)), { ...envelope, workload: { ...envelope.workload, capability_manifest: manifest() } });
  assert.equal(resourcesGrantOf(plain.envelope_json), null);
});

// ---- the node's offer ------------------------------------------------------------------

test("a node enforces a grant only with a resources section, every flag it names, and within its capacity", () => {
  const grant = resourcesGrant({ cpuMillis: 2000, memoryBytes: 4096 * MIB, pids: 64 });
  assert.equal(enforcesResources(document(ALL), grant), true);
  assert.equal(enforcesResources(document(null), grant), false, "no section: no --cgroup-root");
  assert.equal(enforcesResources(document({ cpu: false, memory: true, pids: true }), grant), false);
  assert.equal(enforcesResources(document({ cpu: false, memory: false, pids: true }), resourcesGrant({ pids: 64 })), true, "only the named limits need a flag");
  assert.equal(enforcesResources(document(ALL), resourcesGrant({ cpuMillis: 2001 })), false, "1000 per logical CPU");
  assert.equal(enforcesResources(document(ALL), resourcesGrant({ memoryBytes: 4096 * MIB + 1 })), false, "at most the host's memory");
  assert.equal(enforcesResources(document(ALL, null), grant), false, "no capacity, no ceiling to hold it to");
  assert.equal(enforcesResources(null, grant), false);
  assert.equal(enforcesResources({ resources: { cpu: "yes", memory: true, pids: true }, capacity: { logical_cpus: 2, memory_bytes: 4096 * MIB } }, grant), false);
  assert.equal(enforcesResources(document(ALL), { pids: 0 }), false, "a grant outside the grammar is never enforced");
});

test("requireResourceEnforcement refuses, naming unsupported_grant and why, or returns the document", () => {
  const grant = resourcesGrant({ memoryBytes: 256 * MIB, pids: 64 });
  const offering = document(ALL);
  assert.equal(requireResourceEnforcement(offering, grant), offering);
  assert.throws(() => requireResourceEnforcement(document(null), grant), /does not advertise resources \(a node started with --cgroup-root does\).*unsupported_grant/);
  assert.throws(() => requireResourceEnforcement(document({ cpu: true, memory: false, pids: true }), grant), /resources\.memory.*unsupported_grant/);
  assert.throws(() => requireResourceEnforcement(document(ALL), resourcesGrant({ cpuMillis: 2500 })), /cpu_millis 2500 is above the 2000.*2 logical CPUs.*unsupported_grant/);
  assert.throws(() => requireResourceEnforcement(document(ALL), resourcesGrant({ memoryBytes: 8192 * MIB })), /memory_bytes 8589934592 is above the 4294967296.*unsupported_grant/);
});

// ---- the command line ------------------------------------------------------------------

/** A control-plane state directory, an issuer key and a fake adapter enforcing `flags` (comma separated, or ""). */
function setup(flags) {
  const dir = mkdtempSync(join(tmpdir(), "ward-cli-resources-"));
  const adapter = join(dir, "adapter.sh");
  writeFileSync(adapter, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(FAKE)} "$@"\n`);
  chmodSync(adapter, 0o755);
  createIssuerKey(join(dir, "cp", "issuer.pem"));
  const log = join(dir, "received.jsonl");
  const env = { ...process.env, FAKE_ADAPTER_LOG: log, FAKE_ADAPTER_RESOURCES: flags };
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

test("run --cpu-millis/--memory-bytes/--pids asks the node first, signs the grant and lists it in the outcome", async () => {
  const fake = setup("cpu,memory,pids");
  try {
    const { status, stdout, stderr } = await cli(
      [...fake.runArgs("cli-limits"), "--pids", "64", "--memory-bytes", "268435456", "--cpu-millis", "500", "--", "make", "test"],
      fake.env,
    );
    assert.equal(status, 0, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(outcome.outcome, "completed");
    assert.deepEqual(outcome.resources, { cpu_millis: 500, memory_bytes: 268435456, pids: 64 });
    const received = fake.received();
    assert.deepEqual(received.map((line) => line.cmd), ["capabilities", "run"], "the node's offer is read before the run");
    const envelope = JSON.parse(received[1].envelope_json);
    assert.equal(Buffer.from(envelope.workload.capability_manifest.bytes, "hex").toString("utf8"), EXAMPLE);
    const record = loadRunRecord(fake.runs, deriveId("exec", "cli-limits"));
    assert.deepEqual(resourcesGrantOf(record.envelope_json), outcome.resources);
    // A replay resends the recorded bytes and lists the same grant.
    const replayed = await cli(["replay", ...fake.common, "--state-dir", join(fake.dir, "cp"), "--attempt", deriveId("exec", "cli-limits")], fake.env);
    assert.equal(replayed.status, 0, replayed.stderr);
    assert.deepEqual(JSON.parse(replayed.stdout).resources, outcome.resources);
    assert.equal(fake.received().at(-1).envelope_json, received[1].envelope_json, "the same signed bytes");
    // One limit alone needs only its own flag; a run without one lists no grant and asks nothing first.
    const pidsOnly = await cli([...fake.runArgs("cli-pids"), "--pids", "16", "--", "true"], fake.env);
    assert.equal(pidsOnly.status, 0, pidsOnly.stderr);
    assert.deepEqual(JSON.parse(pidsOnly.stdout).resources, { pids: 16 });
    const before = fake.received().length;
    const plain = await cli([...fake.runArgs("cli-plain"), "--", "true"], fake.env);
    assert.equal(JSON.parse(plain.stdout).resources, undefined);
    assert.deepEqual(fake.received().slice(before).map((line) => line.cmd), ["run"]);
  } finally {
    fake.cleanup();
  }
});

test("run with a limit on a node that does not enforce it is refused before a version is allocated or anything is signed", async () => {
  for (const [flags, args, pattern] of [
    ["", ["--memory-bytes", "268435456"], /does not advertise resources \(a node started with --cgroup-root does\).*unsupported_grant/],
    ["memory", ["--memory-bytes", "268435456", "--pids", "64"], /resources\.pids.*unsupported_grant/],
    ["cpu,memory,pids", ["--cpu-millis", "2001"], /cpu_millis 2001 is above the 2000.*unsupported_grant/],
  ]) {
    const fake = setup(flags);
    try {
      const { status, stdout, stderr } = await cli([...fake.runArgs("cli-unenforced"), ...args, "--", "true"], fake.env);
      assert.equal(status, 2, stderr);
      assert.match(stderr, pattern);
      assert.equal(stdout, "");
      assert.deepEqual(fake.received(), [{ cmd: "capabilities" }], "only the capability document was asked for");
      assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-unenforced")}.json`)), "nothing was recorded");
      assert.ok(!existsSync(join(fake.dir, "cp", "admission-versions.json")), "no version was allocated");
    } finally {
      fake.cleanup();
    }
  }
});

test("run refuses a limit outside the grammar before the node is asked", async () => {
  const fake = setup("cpu,memory,pids");
  try {
    for (const [args, pattern] of [
      [["--pids", "0"], /`pids` is an integer >= 1/],
      [["--cpu-millis", "0"], /`cpu_millis` is an integer >= 1/],
      [["--memory-bytes", "0"], /`memory_bytes` is an integer >= 1/],
      [["--pids", "65537"], /65536 every node refuses as unsupported_grant/],
      [["--pids", "ten"], /--pids takes a non-negative integer/],
      [["--memory-bytes", "1.5"], /--memory-bytes takes a non-negative integer/],
    ]) {
      const { status, stdout, stderr } = await cli([...fake.runArgs("cli-bad"), ...args, "--", "true"], fake.env);
      assert.equal(status, 2, `${args}: ${stderr}`);
      assert.match(stderr, pattern, args.join(" "));
      assert.equal(stdout, "");
    }
    assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-bad")}.json`)), "nothing was recorded");
    assert.deepEqual(fake.received(), [], "nothing reached the adapter");
  } finally {
    fake.cleanup();
  }
});
