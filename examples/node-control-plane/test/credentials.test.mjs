// Node-brokered credentials on the control-plane side (node-integration.md §6.8, §7.5;
// ADR-0034): the `credentials` grant is held to the protocol's grammar, its hosts to the
// manifest's own `network.custom`, before anything is signed; it is signed last in the
// manifest; a node whose capability document does not offer the broker is refused the
// grant here, before a version is allocated; and `run --credential` puts the grant in the
// signed manifest and lists it in the outcome. The adapter is `fixtures/fake-adapter.mjs`,
// which advertises the broker with FAKE_ADAPTER_CREDENTIALS=1.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  CREDENTIAL_LIMITS,
  blake3Hex,
  brokersCredentials,
  buildEnvelope,
  createIssuerKey,
  credentialsGrant,
  credentialsGrantOf,
  deriveId,
  issuerFromSeed,
  loadRunRecord,
  manifest,
  requireCredentialBroker,
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
const HOST = "artifacts.example.com";
const NETWORK = { custom: [HOST] };
const GRANT = [{ service: "artifacts", host: HOST, ttl_secs: 600 }];
// The example of ADR-0034 §1 and node-integration.md §7.5, as signed.
const EXAMPLE = '{"network":{"custom":["artifacts.example.com"]},"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]}';

function text(built) {
  return Buffer.from(built.bytes, "hex").toString("utf8");
}

function envelopeInput(manifestObject) {
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
    workload: { argv: ["python3", "fetch.py"], manifest: manifestObject, snapshot: SNAPSHOT, wallClockBudgetMs: 600_000 },
    issuedAtUnixMs: now,
    expiresAtUnixMs: now + 900_000,
    version: 1,
  };
}

/** A capability document as a node reports it, with the broker on or off. */
function document(brokering) {
  return {
    protocol: { major: 1, minor: 3 },
    network: { offline: true, proxy_allowlist: true },
    credentials: { proxy_injection: brokering, scoped_http_gateway: brokering },
    lifecycle: { pause: true, stop: true, revoke: true, admit: true, start: true },
  };
}

// ---- the grant -------------------------------------------------------------------------

test("the limits are the protocol's: 4 grants, 32-byte service names, a u32 TTL", () => {
  assert.deepEqual(CREDENTIAL_LIMITS, { grants: 4, serviceBytes: 32, ttlSecs: 4_294_967_295 });
  assert.ok(Object.isFrozen(CREDENTIAL_LIMITS));
});

test("a credentials grant is built in wire spelling, and the §7.5 example is signed byte for byte", () => {
  assert.deepEqual(credentialsGrant([{ service: "artifacts", host: HOST, ttlSecs: 600 }]), GRANT);
  const built = manifest({ network: NETWORK, credentials: GRANT });
  assert.equal(text(built), EXAMPLE);
  assert.equal(built.hash, blake3Hex(Buffer.from(EXAMPLE)));
  // The caller's key order, in the manifest and in each grant, changes nothing.
  assert.deepEqual(manifest({ credentials: [{ ttl_secs: 600, host: HOST, service: "artifacts" }], network: NETWORK }), built);
  // The grant is signed last: after `output` and `actions`, as the node's encoder writes it.
  const all = manifest({
    credentials: GRANT,
    actions: { kinds: ["approval"], max_pending: 1, max_total: 1, wait_secs: 1 },
    output: { stdio_bytes: 1, files: [], files_bytes: 0 },
    network: NETWORK,
  });
  assert.equal(
    text(all),
    '{"network":{"custom":["artifacts.example.com"]},"output":{"stdio_bytes":1,"files":[],"files_bytes":0},' +
      '"actions":{"kinds":["approval"],"max_pending":1,"max_total":1,"wait_secs":1},' +
      '"credentials":[{"service":"artifacts","host":"artifacts.example.com","ttl_secs":600}]}',
  );
  // The grants keep the order given; four services, one host each or shared.
  const four = ["a", "b-2", "c", "d"].map((service) => ({ service, host: HOST, ttl_secs: 1 }));
  assert.deepEqual(JSON.parse(text(manifest({ network: NETWORK, credentials: four }))).credentials, four);
});

test("a grant outside ADR-0034's grammar is refused before signing, naming the field", () => {
  const refuses = (credentials, pattern) => assert.throws(() => manifest({ network: NETWORK, credentials }), pattern);
  refuses(null, /credentials/);
  refuses({ service: "artifacts", host: HOST, ttl_secs: 1 }, /credentials/);
  refuses([], /1 to 4/);
  refuses(["a", "b", "c", "d", "e"].map((service) => ({ service, host: HOST, ttl_secs: 1 })), /1 to 4/);
  refuses([{ service: "a", host: HOST, ttl_secs: 1 }, { service: "a", host: "g.example.com", ttl_secs: 1 }], /names the service `a` twice/);
  refuses([null], /credential grant/);
  refuses([{ service: "a", host: HOST }], /service, host, ttl_secs/);
  refuses([{ service: "a", host: HOST, ttl_secs: 1, header: "authorization" }], /service, host, ttl_secs/);
  refuses([{ service: "a", host: HOST, ttl_secs: 1, secret: "x" }], /service, host, ttl_secs/);
  refuses([{ service: "a", host: HOST, ttl_secs: 1, provider: "bao" }], /service, host, ttl_secs/);
  for (const service of ["", "A", "1a", "-a", "a_b", "a.b", "a".repeat(33), 7, null]) {
    refuses([{ service, host: HOST, ttl_secs: 1 }], /service .*\[a-z\]\[a-z0-9-\]\{0,31\}/);
  }
  for (const host of ["", "*.example.com", "H.example.com", "h example.com", "-h.example.com", "10.0.0.1", "10.0.0.1:443", "::1", "[::1]", 7]) {
    refuses([{ service: "a", host, ttl_secs: 1 }], /host .*lowercase DNS name/);
  }
  for (const ttl of [0, -1, 1.5, "60", null, 2 ** 53, CREDENTIAL_LIMITS.ttlSecs + 1]) {
    refuses([{ service: "a", host: HOST, ttl_secs: ttl }], /ttl_secs/);
  }
  assert.ok(manifest({ network: NETWORK, credentials: [{ service: "a".repeat(32), host: HOST, ttl_secs: CREDENTIAL_LIMITS.ttlSecs }] }).hash);
  assert.ok(manifest({ network: NETWORK, credentials: [{ service: "ci-artifacts2", host: HOST, ttl_secs: 1 }] }).hash);
  assert.throws(() => credentialsGrant([{ service: "A", host: HOST, ttlSecs: 1 }]), /service/);
  assert.throws(() => credentialsGrant([{ service: "a", host: HOST, ttlSecs: 0 }]), /ttl_secs/);
  assert.throws(() => credentialsGrant([]), /1 to 4/);
});

test("every host must be one the manifest's own network.custom covers; an offline manifest grants none", () => {
  const refuses = (network, host) =>
    assert.throws(() => manifest({ network, credentials: [{ service: "a", host, ttl_secs: 1 }] }), /not covered by the manifest's network.custom/);
  refuses("offline", HOST);
  refuses({ custom: ["g.example.com"] }, HOST);
  // A wildcard covers a name with at least one more label, never the name itself.
  refuses({ custom: ["*.example.com"] }, "example.com");
  refuses({ custom: ["*.example.com"] }, "xexample.com");
  refuses({ custom: ["api.other.org"] }, "x.api.other.org");
  refuses({ custom: ["api.other.org"] }, "other.org");
  for (const [patterns, host] of [
    [["*.example.com"], "a.example.com"],
    [["*.example.com"], "b.a.example.com"],
    [["*.example.com", "api.other.org"], "api.other.org"],
  ]) {
    assert.ok(manifest({ network: { custom: patterns }, credentials: [{ service: "a", host, ttl_secs: 1 }] }).hash, host);
  }
});

test("buildEnvelope refuses a bad grant before signing, and credentialsGrantOf reads the signed one back", () => {
  assert.throws(() => buildEnvelope(envelopeInput({ network: "offline", credentials: GRANT })), /network.custom/);
  assert.throws(() => buildEnvelope(envelopeInput({ network: NETWORK, credentials: [{ ...GRANT[0], ttl_secs: 0 }] })), /ttl_secs/);
  const issuer = issuerFromSeed(Buffer.alloc(32, 7));
  const signed = signEnvelope(issuer, buildEnvelope(envelopeInput({ network: NETWORK, credentials: GRANT })));
  assert.equal(text(JSON.parse(signed.envelope_json).workload.capability_manifest), EXAMPLE);
  assert.deepEqual(credentialsGrantOf(signed.envelope_json), GRANT);
  const offline = signEnvelope(issuer, buildEnvelope(envelopeInput(undefined)));
  assert.equal(credentialsGrantOf(offline.envelope_json), null, "no grant, no credential");
  assert.throws(() => credentialsGrantOf("{not json"), /JSON/);
});

// ---- the node's offer --------------------------------------------------------------------

test("only a node that advertises both credential flags is granted one; any other is refused as unsupported_grant", () => {
  assert.equal(brokersCredentials(document(true)), true);
  assert.equal(requireCredentialBroker(document(true)).credentials.proxy_injection, true);
  const half = document(true);
  half.credentials.scoped_http_gateway = false;
  const strings = document(true);
  strings.credentials = { proxy_injection: "true", scoped_http_gateway: "true" };
  const without = document(true);
  delete without.credentials;
  for (const capabilities of [document(false), half, strings, without, null, undefined, {}]) {
    assert.equal(brokersCredentials(capabilities), false);
    assert.throws(() => requireCredentialBroker(capabilities), /credentials.proxy_injection.*unsupported_grant/);
  }
});

// ---- the command line --------------------------------------------------------------------

/** A control-plane state directory, an issuer key and a fake adapter, brokering or not. */
function setup(brokering) {
  const dir = mkdtempSync(join(tmpdir(), "ward-cli-credentials-"));
  const adapter = join(dir, "adapter.sh");
  writeFileSync(adapter, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(FAKE)} "$@"\n`);
  chmodSync(adapter, 0o755);
  createIssuerKey(join(dir, "cp", "issuer.pem"));
  const log = join(dir, "received.jsonl");
  const env = { ...process.env, FAKE_ADAPTER_LOG: log, FAKE_ADAPTER_CREDENTIALS: brokering ? "1" : "" };
  const common = ["--socket", "/run/ward-node/node.sock", "--adapter", adapter];
  const runArgs = (attempt) => [
    "run",
    ...common,
    "--key", join(dir, "cp", "issuer.pem"),
    "--principal", "cli-issuer",
    "--node", deriveId("node", "cli-host"),
    "--state-dir", join(dir, "cp"),
    "--snapshot", SNAPSHOT,
    "--budget-ms", "90500",
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

test("run --credential asks the node first, signs the grant with its hosts as the allowlist, and lists it in the outcome", async () => {
  const fake = setup(true);
  try {
    const { status, stdout, stderr } = await cli(
      [...fake.runArgs("cli-credential"), "--credential", "artifacts=localhost:60", "--credential", "ci-cache=localhost", "--credential", "registry=registry.example.com:5", "--", "python3", "fetch.py"],
      fake.env,
    );
    assert.equal(status, 0, stderr);
    const outcome = JSON.parse(stdout);
    assert.equal(outcome.outcome, "completed");
    // Without a TTL the lease may live as long as the budget, rounded up to whole seconds.
    const granted = [
      { service: "artifacts", host: "localhost", ttl_secs: 60 },
      { service: "ci-cache", host: "localhost", ttl_secs: 91 },
      { service: "registry", host: "registry.example.com", ttl_secs: 5 },
    ];
    assert.deepEqual(outcome.credentials, granted);
    const received = fake.received();
    assert.deepEqual(received.map((line) => line.cmd), ["capabilities", "run"], "the node's offer is read before the run");
    const envelope = JSON.parse(received[1].envelope_json);
    assert.equal(
      Buffer.from(envelope.workload.capability_manifest.bytes, "hex").toString("utf8"),
      `{"network":{"custom":["localhost","registry.example.com"]},"credentials":${JSON.stringify(granted)}}`,
    );
    const record = loadRunRecord(fake.runs, deriveId("exec", "cli-credential"));
    assert.deepEqual(credentialsGrantOf(record.envelope_json), granted);
    // A replay resends the recorded bytes and lists the same grants.
    const replayed = await cli(["replay", ...fake.common, "--state-dir", join(fake.dir, "cp"), "--attempt", deriveId("exec", "cli-credential")], fake.env);
    assert.equal(replayed.status, 0, replayed.stderr);
    const again = JSON.parse(replayed.stdout);
    assert.equal(again.replayed, true);
    assert.deepEqual(again.credentials, granted);
    assert.equal(fake.received().at(-1).envelope_json, received[1].envelope_json, "the same signed bytes");
    // A run without the flag lists no credentials.
    const plain = await cli([...fake.runArgs("cli-plain"), "--", "true"], fake.env);
    assert.equal(JSON.parse(plain.stdout).credentials, undefined);
  } finally {
    fake.cleanup();
  }
});

test("run --credential on a node that does not broker credentials is refused before a version is allocated or anything is signed", async () => {
  const fake = setup(false);
  try {
    const { status, stdout, stderr } = await cli([...fake.runArgs("cli-unbrokered"), "--credential", "artifacts=localhost:60", "--", "true"], fake.env);
    assert.equal(status, 2, stderr);
    assert.match(stderr, /credentials.proxy_injection.*unsupported_grant/);
    assert.equal(stdout, "");
    assert.deepEqual(fake.received(), [{ cmd: "capabilities" }], "only the capability document was asked for");
    assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-unbrokered")}.json`)), "nothing was recorded");
    assert.ok(!existsSync(join(fake.dir, "cp", "admission-versions.json")), "no version was allocated");
  } finally {
    fake.cleanup();
  }
});

test("run refuses a --credential outside the grammar before the node is asked", async () => {
  const fake = setup(true);
  try {
    for (const [flag, pattern] of [
      ["artifacts", /--credential takes <service>=<host>\[:<ttl-secs>\]/],
      ["=localhost", /--credential takes/],
      ["artifacts=localhost:", /--credential takes/],
      ["artifacts=localhost:ten", /--credential takes/],
      ["Artifacts=localhost", /service/],
      ["artifacts=Localhost", /host/],
      ["artifacts=10.0.0.1", /host/],
      ["artifacts=*.example.com", /host/],
      ["artifacts=localhost:0", /ttl_secs/],
      ["artifacts=localhost:4294967296", /ttl_secs/],
    ]) {
      const { status, stdout, stderr } = await cli([...fake.runArgs("cli-bad"), "--credential", flag, "--", "true"], fake.env);
      assert.equal(status, 2, `${flag}: ${stderr}`);
      assert.match(stderr, pattern, flag);
      assert.equal(stdout, "");
    }
    const twice = await cli([...fake.runArgs("cli-bad"), "--credential", "a=localhost", "--credential", "a=other.example", "--", "true"], fake.env);
    assert.equal(twice.status, 2);
    assert.match(twice.stderr, /twice/);
    const five = ["a", "b", "c", "d", "e"].flatMap((service) => ["--credential", `${service}=localhost`]);
    const many = await cli([...fake.runArgs("cli-bad"), ...five, "--", "true"], fake.env);
    assert.equal(many.status, 2);
    assert.match(many.stderr, /1 to 4/);
    assert.ok(!existsSync(join(fake.runs, `${deriveId("exec", "cli-bad")}.json`)), "nothing was recorded");
    assert.deepEqual(fake.received(), [], "nothing reached the adapter");
  } finally {
    fake.cleanup();
  }
});
