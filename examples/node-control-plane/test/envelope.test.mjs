// The admission envelope and its proof (node-integration.md §7): the client's output is
// held to the §7.4 test vector byte for byte, including the complete admit request line.
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { test } from "node:test";

import {
  OFFLINE_MANIFEST,
  admitRequest,
  buildEnvelope,
  issuerFromSeed,
  manifest,
  rootLease,
  serialiseEnvelope,
  signEnvelope,
} from "../ward-node.mjs";

const VECTOR = {
  publicKey: "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
  keyId: "0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433",
  signature:
    "c2336bf71cc42af7222a4f736ac991c830cb560d1aa1af8241a3356ab58a8f23cb236ef558b113832d81ca3114de958b55c24eb6e45b317db3c05fac5bc26002",
  envelopeJson:
    '{"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"agent":"agent_01M43CJ1G0000DVQFEXVZZY001","node":"node_01M3KY5QG0000028T5CY4TQKFF","session":"sess_01M45YYRG0000FXQ5TK1V58CGG","authority":{"lease":{"id":"lease_01M45YYRG00009K6DANAXVQK6C","delegation_id":"deleg_01M45YYRG000016NWVVWJ6HB70","issuer":"prn_01M1RQ16G00000Y3RF1W7GY3RF","subject":"agent_01M43CJ1G0000DVQFEXVZZY001","task":"task_01M45YYRG00001249248SK6H24","parent_lease_id":null,"delegated_by":null,"grants":[{"capability":"repo.read","resource":"repo:example/project","delegable":false},{"capability":"repo.write","resource":"repo:example/project","delegable":false}],"issued_at_unix_ms":1791201600000,"expires_at_unix_ms":1791205200000,"version":1},"lineage":[]},"workload":{"argv":["sh","-c","make test"],"capability_manifest":{"hash":"eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3","bytes":"7b226e6574776f726b223a226f66666c696e65227d"},"snapshot":"c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b","wall_clock_budget_ms":600000},"issued_at_unix_ms":1791201600000,"expires_at_unix_ms":1791202500000,"version":1}',
};

const BINDING = {
  task: "task_01M45YYRG00001249248SK6H24",
  attempt: "exec_01M45YYRG00005ANB6CSVQF248",
  lease: "lease_01M45YYRG00009K6DANAXVQK6C",
};

function vectorInput() {
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
      grants: [
        { capability: "repo.read", resource: "repo:example/project", delegable: false },
        { capability: "repo.write", resource: "repo:example/project", delegable: false },
      ],
      issuedAtUnixMs: 1791201600000,
      expiresAtUnixMs: 1791205200000,
      version: 1,
    }),
    workload: {
      argv: ["sh", "-c", "make test"],
      snapshot: "c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b",
      wallClockBudgetMs: 600000,
    },
    issuedAtUnixMs: 1791201600000,
    expiresAtUnixMs: 1791202500000,
    version: 1,
  };
}

const testIssuer = () => issuerFromSeed(Buffer.alloc(32, 7));

test("the offline manifest hashes as §7.5 says", () => {
  assert.deepEqual(manifest(OFFLINE_MANIFEST), {
    hash: "eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3",
    bytes: "7b226e6574776f726b223a226f66666c696e65227d",
  });
  assert.deepEqual(manifest(), manifest(OFFLINE_MANIFEST));
  assert.throws(() => manifest({ network: "development" }), /manifest/);
  assert.throws(() => manifest({}), /manifest/);
  assert.throws(() => manifest({ network: { custom: [] } }), /manifest/);
  assert.throws(() => manifest({ network: { custom: ["GitHub.com"] } }), /manifest/);
  assert.ok(manifest({ network: { custom: ["github.com", "*.crates.io"] } }).hash);
});

test("the issuer key reproduces the §7.4 key, key id and trust-store line", () => {
  const issuer = testIssuer();
  assert.equal(issuer.publicKeyHex, VECTOR.publicKey);
  assert.equal(issuer.keyId, VECTOR.keyId);
  assert.equal(
    issuer.trustStoreLine("prn_01M1RQ16G00000Y3RF1W7GY3RF"),
    `${VECTOR.publicKey} ${VECTOR.keyId} prn_01M1RQ16G00000Y3RF1W7GY3RF`,
  );
  assert.throws(() => issuer.trustStoreLine("agent_01M43CJ1G0000DVQFEXVZZY001"));
});

test("the envelope serialises to the §7.4 bytes and signs to the §7.4 signature", () => {
  const envelope = buildEnvelope(vectorInput());
  const json = serialiseEnvelope(envelope);
  assert.equal(json, VECTOR.envelopeJson);
  assert.equal(Buffer.byteLength(json, "utf8"), 1203);
  const signed = signEnvelope(testIssuer(), envelope);
  assert.equal(signed.envelope_json, VECTOR.envelopeJson);
  assert.deepEqual(signed.proof, { issuer_key_id: VECTOR.keyId, signature: VECTOR.signature });
  assert.deepEqual(signed.binding, BINDING);
  const spki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(VECTOR.publicKey, "hex"),
  ]);
  const publicKey = createPublicKey({ key: spki, format: "der", type: "spki" });
  assert.ok(
    verify(null, Buffer.from(signed.envelope_json, "utf8"), publicKey, Buffer.from(signed.proof.signature, "hex")),
  );
});

test("the complete admit request line is the §7.4 line", () => {
  const signed = signEnvelope(testIssuer(), buildEnvelope(vectorInput()));
  const line = admitRequest(signed, 2);
  const expected =
    '{"request":"admit","protocol":{"major":1,"minor":3},"operation_id":2,"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"envelope_json":' +
    JSON.stringify(VECTOR.envelopeJson) +
    `,"proof":{"issuer_key_id":"${VECTOR.keyId}","signature":"${VECTOR.signature}"}}`;
  assert.equal(line, expected);
  assert.ok(line.includes('"envelope_json":"{\\"binding\\":{\\"task\\":\\"task_01M45YYRG00001249248SK6H24\\"'));
});

test("buildEnvelope refuses what the node would refuse, before anything is signed", () => {
  const refuses = (mutate, pattern) => {
    const input = vectorInput();
    mutate(input);
    assert.throws(() => buildEnvelope(input), pattern);
  };
  refuses((i) => { i.binding = { ...BINDING, lease: "lease_01M45YYRG00000000000000001" }; }, /lease/);
  refuses((i) => { i.lease = { ...i.lease, task: "task_01M45YYRG00000000000000001" }; }, /task/);
  refuses((i) => { i.agent = "agent_01M45YYRG00000000000000003"; }, /subject/);
  refuses((i) => { i.workload.argv = []; }, /argv/);
  refuses((i) => { i.workload.argv = ["", "x"]; }, /argv/);
  refuses((i) => { i.workload.argv = ["sh", "a\0b"]; }, /argv/);
  refuses((i) => { i.workload.argv = ["sh", "x".repeat(4097)]; }, /argv/);
  refuses((i) => { i.workload.wallClockBudgetMs = 0; }, /budget/);
  refuses((i) => { i.workload.wallClockBudgetMs = 1.5; }, /budget/);
  refuses((i) => { i.workload.snapshot = "C19C769FDD8644DF9167A36D0133289C9FA44A8C768CD0AAFA1756A13FB3E33B"; }, /snapshot/);
  refuses((i) => { i.expiresAtUnixMs = i.issuedAtUnixMs; }, /expires/);
  refuses((i) => { i.version = 0; }, /version/);
  refuses((i) => { i.node = "node_01m3ky5qg0000028t5cy4tqkff"; }, /node/);
  refuses((i) => { i.session = "task_01M45YYRG0000FXQ5TK1V58CGG"; }, /session/);
  refuses((i) => { i.lease = { ...i.lease, grants: [] }; }, /grants/);
  refuses((i) => {
    i.lease = { ...i.lease, grants: [...i.lease.grants].reverse() };
  }, /sorted/);
  refuses((i) => {
    i.lease = { ...i.lease, grants: [{ capability: "Repo.Read", resource: "r", delegable: false }] };
  }, /capability/);
  refuses((i) => {
    i.lease = { ...i.lease, grants: [{ capability: "repo.read", resource: "has space", delegable: false }] };
  }, /resource/);
  refuses((i) => { i.workload.argv = ["sh", "-c", "x".repeat(4000), "y".repeat(4000), "z".repeat(4000), "w".repeat(4000), "v".repeat(1000)]; }, /argv/);
});

test("rootLease carries explicit nulls and a sorted grant set", () => {
  const lease = rootLease({
    id: BINDING.lease,
    delegationId: "deleg_01M45YYRG000016NWVVWJ6HB70",
    issuer: "prn_01M1RQ16G00000Y3RF1W7GY3RF",
    subject: "agent_01M43CJ1G0000DVQFEXVZZY001",
    task: BINDING.task,
    grants: [
      { capability: "repo.write", resource: "repo:example/project", delegable: false },
      { capability: "repo.read", resource: "repo:example/project", delegable: false },
    ],
    issuedAtUnixMs: 1,
    expiresAtUnixMs: 2,
  });
  assert.equal(lease.parent_lease_id, null);
  assert.equal(lease.delegated_by, null);
  assert.equal(lease.version, 1);
  assert.deepEqual(
    lease.grants.map((grant) => grant.capability),
    ["repo.read", "repo.write"],
    "rootLease sorts the grants the way §7.3 requires",
  );
});
