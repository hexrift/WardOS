// Agent adapters hosted on a node (node-integration.md §5, §7.3; ADR-0036), on the
// control-plane side: the workload's `adapter` is held to the grammar before anything is
// signed, spelled last in the workload and not at all without one, and read back from a
// signed envelope; a node whose capability document does not host the adapter is refused
// here, before a version is allocated; and `run --agent-adapter` signs it, leaves the
// manifest exactly as without it, and names it in the outcome. The adapter process is
// `fixtures/fake-adapter.mjs`, which hosts the adapters FAKE_ADAPTER_AGENT_ADAPTERS lists.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  AGENT_ADAPTERS,
  agentAdapterOf,
  buildEnvelope,
  createIssuerKey,
  deriveId,
  hostsAgentAdapter,
  issuerFromSeed,
  loadRunRecord,
  requireAgentAdapter,
  rootLease,
  signEnvelope,
  workloadAdapter,
} from "../ward-node.mjs";

const FAKE = fileURLToPath(new URL("../fixtures/fake-adapter.mjs", import.meta.url));
const CLI = fileURLToPath(new URL("../control-plane.mjs", import.meta.url));
const SNAPSHOT = "c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b";
const BINDING = {
  task: "task_01M45YYRG00001249248SK6H24",
  attempt: "exec_01M45YYRG00005ANB6CSVQF248",
  lease: "lease_01M45YYRG00009K6DANAXVQK6C",
};

function envelopeInput(argv, adapter) {
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
    workload: { argv, snapshot: SNAPSHOT, wallClockBudgetMs: 600_000, adapter },
    issuedAtUnixMs: now,
    expiresAtUnixMs: now + 900_000,
    version: 1,
  };
}

// ---- the workload field -----------------------------------------------------------------

test("the adapters a node can host are the contract's first-party ones and the generic process adapter", () => {
  assert.deepEqual(AGENT_ADAPTERS, ["claude-code", "codex", "process"]);
  assert.ok(Object.isFrozen(AGENT_ADAPTERS));
});

test("a workload names its adapter last, as {id}, and the manifest is the same bytes with or without it", () => {
  const plain = buildEnvelope(envelopeInput(["claude", "-p", "fix it"], undefined));
  assert.equal(Object.hasOwn(plain.workload, "adapter"), false, "no adapter, no field");
  const named = buildEnvelope(envelopeInput(["claude", "-p", "fix it"], "claude-code"));
  assert.deepEqual(Object.keys(named.workload), ["argv", "capability_manifest", "snapshot", "wall_clock_budget_ms", "adapter"]);
  assert.deepEqual(named.workload.adapter, { id: "claude-code" });
  assert.deepEqual(named.workload.capability_manifest, plain.workload.capability_manifest);
  const issuer = issuerFromSeed(Buffer.alloc(32, 7));
  const signed = signEnvelope(issuer, named);
  assert.ok(signed.envelope_json.endsWith(',"wall_clock_budget_ms":600000,"adapter":{"id":"claude-code"}},"issued_at_unix_ms":1791201600000,"expires_at_unix_ms":1791202500000,"version":1}'));
  assert.equal(agentAdapterOf(signed.envelope_json), "claude-code");
  assert.equal(agentAdapterOf(signEnvelope(issuer, plain).envelope_json), null);
  assert.equal(buildEnvelope(envelopeInput(["/opt/codex/bin/codex"], "codex")).workload.adapter.id, "codex");
  assert.equal(buildEnvelope(envelopeInput(["sh"], null)).workload.adapter, undefined);
});

test("an adapter outside the grammar, or a program it cannot launch, is refused before signing", () => {
  for (const id of ["", "Claude-Code", "-codex", "claude code", "a".repeat(65), 7, {}, ["codex"]]) {
    assert.throws(() => buildEnvelope(envelopeInput(["codex"], id)), /agent adapter id/, String(id));
  }
  for (const argv of [["bin/claude"], ["./claude"], ["../codex"]]) {
    assert.throws(() => buildEnvelope(envelopeInput(argv, "claude-code")), /argv\[0\]/, argv[0]);
  }
  assert.ok(buildEnvelope(envelopeInput(["bin/tool"], undefined)), "without an adapter argv[0] is as before");
  // An id the protocol accepts but no node hosts is the node's to refuse.
  assert.deepEqual(workloadAdapter("gemini-cli", ["gemini"]), { id: "gemini-cli" });
  assert.throws(() => agentAdapterOf("{not json"), /JSON/);
});

// ---- the node's offer --------------------------------------------------------------------

test("only a node whose adapters.hosted lists the adapter hosts it; any other is refused as unsupported_grant", () => {
  const document = { adapters: { contract: "1.0", hosted: ["codex", "process"] } };
  assert.equal(hostsAgentAdapter(document, "codex"), true);
  assert.equal(requireAgentAdapter(document, "process"), document);
  for (const [capabilities, id] of [
    [document, "claude-code"],
    [{ adapters: { contract: "1.0", hosted: "codex" } }, "codex"],
    [{}, "codex"],
    [null, "codex"],
    [undefined, "codex"],
  ]) {
    assert.equal(hostsAgentAdapter(capabilities, id), false);
    assert.throws(() => requireAgentAdapter(capabilities, id), new RegExp(`${id} in adapters.hosted.*unsupported_grant`));
  }
});

// ---- the command line --------------------------------------------------------------------

/** A control-plane state directory, an issuer key and a fake adapter hosting `hosted`. */
function setup(hosted) {
  const dir = mkdtempSync(join(tmpdir(), "ward-cli-agent-adapter-"));
  const adapter = join(dir, "adapter.sh");
  writeFileSync(adapter, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(FAKE)} "$@"\n`);
  chmodSync(adapter, 0o755);
  createIssuerKey(join(dir, "cp", "issuer.pem"));
  const log = join(dir, "received.jsonl");
  const env = { ...process.env, FAKE_ADAPTER_LOG: log, FAKE_ADAPTER_AGENT_ADAPTERS: hosted.join(",") };
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

test("run --agent-adapter asks the node first, signs the adapter beside the argv, and names it in the outcome", async () => {
  const fake = setup(["claude-code", "codex"]);
  try {
    const { status, stdout, stderr } = await cli([...fake.runArgs("cli-claude"), "--agent-adapter", "claude-code", "--", "claude", "-p", "fix the build"], fake.env);
    assert.equal(status, 0, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(outcome.outcome, "completed");
    assert.equal(outcome.agent_adapter, "claude-code");
    const received = fake.received();
    assert.deepEqual(received.map((line) => line.cmd), ["capabilities", "run"], "the node's offer is read before the run");
    const envelope = JSON.parse(received[1].envelope_json);
    assert.deepEqual(envelope.workload.argv, ["claude", "-p", "fix the build"]);
    assert.deepEqual(envelope.workload.adapter, { id: "claude-code" });
    assert.equal(Buffer.from(envelope.workload.capability_manifest.bytes, "hex").toString("utf8"), '{"network":"offline"}', "the manifest is untouched");
    const record = loadRunRecord(fake.runs, deriveId("exec", "cli-claude"));
    assert.equal(agentAdapterOf(record.envelope_json), "claude-code");
    const replayed = await cli(["replay", ...fake.common, "--state-dir", join(fake.dir, "cp"), "--attempt", deriveId("exec", "cli-claude")], fake.env);
    assert.equal(replayed.status, 0, replayed.stderr);
    assert.equal(JSON.parse(replayed.stdout).agent_adapter, "claude-code");
    assert.equal(fake.received().at(-1).envelope_json, received[1].envelope_json, "the same signed bytes");
    const plain = await cli([...fake.runArgs("cli-plain"), "--", "true"], fake.env);
    assert.equal(JSON.parse(plain.stdout).agent_adapter, undefined);
    assert.equal(fake.received().at(-1).cmd, "run", "a run naming no adapter does not ask the node first");
  } finally {
    fake.cleanup();
  }
});

test("run --agent-adapter on a node that does not host it is refused before a version is allocated or anything is signed", async () => {
  const fake = setup(["codex"]);
  try {
    const { status, stdout, stderr } = await cli([...fake.runArgs("cli-unhosted"), "--agent-adapter", "claude-code", "--", "claude"], fake.env);
    assert.equal(status, 2, stderr);
    assert.match(stderr, /claude-code in adapters.hosted.*unsupported_grant/);
    assert.equal(stdout, "");
    assert.deepEqual(fake.received(), [{ cmd: "capabilities" }], "only the capability document was asked for");
    assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-unhosted")}.json`)), "nothing was recorded");
    assert.ok(!existsSync(join(fake.dir, "cp", "admission-versions.json")), "no version was allocated");
  } finally {
    fake.cleanup();
  }
});

test("run refuses an --agent-adapter outside the grammar, or a program it cannot launch, before the node is asked", async () => {
  const fake = setup(["claude-code", "codex", "process"]);
  try {
    for (const [id, argv, pattern] of [
      ["Claude-Code", ["claude"], /agent adapter id/],
      ["", ["claude"], /agent adapter id/],
      ["codex", ["bin/codex"], /argv\[0\]/],
    ]) {
      const { status, stdout, stderr } = await cli([...fake.runArgs("cli-bad"), "--agent-adapter", id, "--", ...argv], fake.env);
      assert.equal(status, 2, `${id}: ${stderr}`);
      assert.match(stderr, pattern, id);
      assert.equal(stdout, "");
    }
    assert.deepEqual(fake.received(), [], "nothing reached the adapter");
    assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-bad")}.json`)), "nothing was recorded");
  } finally {
    fake.cleanup();
  }
});
