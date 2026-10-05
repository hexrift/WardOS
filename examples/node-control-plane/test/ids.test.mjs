// WardOS ids (node-integration.md §7.2): a prefix and a 128-bit value rendered as 26
// upper-case Crockford base32 characters, first character 0–7. The client derives them
// deterministically from the control plane's own ids.
import assert from "node:assert/strict";
import { test } from "node:test";

import { decodeId, deriveId, encodeId, isId, randomId } from "../ward-node.mjs";

test("encodeId renders a u128 as the node renders it", () => {
  assert.equal(encodeId("task", 0n), "task_00000000000000000000000000");
  assert.equal(encodeId("task", 7n), "task_00000000000000000000000007");
  assert.equal(encodeId("node", 4n), "node_00000000000000000000000004");
  assert.equal(encodeId("agent", 3), "agent_00000000000000000000000003");
  assert.equal(encodeId("exec", 32n), "exec_00000000000000000000000010");
  const max = (1n << 128n) - 1n;
  assert.equal(encodeId("lease", max), "lease_7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
});

test("decodeId inverts encodeId and refuses what the node refuses", () => {
  for (const id of [
    "task_01M45YYRG00001249248SK6H24",
    "exec_01M45YYRG00005ANB6CSVQF248",
    "lease_01M45YYRG00009K6DANAXVQK6C",
    "prn_01M1RQ16G00000Y3RF1W7GY3RF",
    "node_01M3KY5QG0000028T5CY4TQKFF",
  ]) {
    const { prefix, value } = decodeId(id);
    assert.equal(encodeId(prefix, value), id);
    assert.ok(isId(id));
    assert.ok(isId(id, prefix));
  }
  assert.equal(isId("task_01m45yyrg00001249248sk6h24"), false, "lower case");
  assert.equal(isId("task_81M45YYRG00001249248SK6H24"), false, "first char above 7");
  assert.equal(isId("task_01M45YYRG00001249248SK6H2"), false, "25 characters");
  assert.equal(isId("task_01M45YYRG00001249248SK6HI4"), false, "I is not Crockford");
  assert.equal(isId("job_01M45YYRG00001249248SK6H24"), false, "unknown prefix");
  assert.equal(isId("exec_01M45YYRG00005ANB6CSVQF248", "task"), false, "other prefix");
  assert.throws(() => decodeId("task_01m45yyrg00001249248sk6h24"));
  assert.throws(() => encodeId("task", -1n));
  assert.throws(() => encodeId("task", 1n << 128n));
  assert.throws(() => encodeId("job", 1n));
});

test("deriveId is deterministic, prefix-separated and pinned", () => {
  const a = deriveId("task", "work-item-42");
  assert.equal(a, deriveId("task", "work-item-42"));
  assert.ok(isId(a, "task"));
  assert.notEqual(decodeId(a).value, decodeId(deriveId("exec", "work-item-42")).value);
  assert.notEqual(a, deriveId("task", "work-item-43"));
  // Pinned so that two control-plane versions derive the same id for the same input.
  assert.equal(
    deriveId("task", "mission-7/task-3"),
    "task_4FENAMVWMKGE9NB9E6SYNQAWZZ",
  );
  assert.equal(
    deriveId("lease", "lease-9#2"),
    "lease_6Q3KYGTRVYXYV4ST2ZM8Y2EZPS",
  );
  assert.throws(() => deriveId("task", ""));
  assert.throws(() => deriveId("job", "x"));
});

test("randomId renders a fresh valid id", () => {
  const one = randomId("sess");
  assert.ok(isId(one, "sess"));
  assert.notEqual(one, randomId("sess"));
});
