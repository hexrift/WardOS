// The per-task admission version (node-integration.md §7.3, §10): strictly increasing
// per task, durable across a control-plane restart. A "restart" here is a new process
// reading the same file.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { VersionStore } from "../ward-node.mjs";

const LIB = fileURLToPath(new URL("../ward-node.mjs", import.meta.url));
const TASK_A = "task_01M45YYRG00001249248SK6H24";
const TASK_B = "task_01M45YYRG00000000000000001";

function scratch() {
  const dir = mkdtempSync(join(tmpdir(), "ward-versions-"));
  return { dir, path: join(dir, "admission-versions.json") };
}

test("a new store starts every task at 1 and counts each task on its own", () => {
  const { dir, path } = scratch();
  try {
    const store = new VersionStore(path);
    assert.equal(store.current(TASK_A), 0);
    assert.equal(store.next(TASK_A), 1);
    assert.equal(store.next(TASK_A), 2);
    assert.equal(store.next(TASK_B), 1);
    assert.equal(store.current(TASK_A), 2);
    const file = JSON.parse(readFileSync(path, "utf8"));
    assert.deepEqual(file, { format: 1, versions: { [TASK_A]: 2, [TASK_B]: 1 } });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the counter survives a restart: a new process continues above the last version", () => {
  const { dir, path } = scratch();
  try {
    const first = new VersionStore(path);
    assert.equal(first.next(TASK_A), 1);
    assert.equal(first.next(TASK_A), 2);
    const script = `
      import { VersionStore } from ${JSON.stringify(LIB)};
      const store = new VersionStore(process.argv[1]);
      console.log(store.next(process.argv[2]));
      console.log(store.next(process.argv[2]));
    `;
    const out = execFileSync(process.execPath, ["--input-type=module", "-e", script, path, TASK_A], {
      encoding: "utf8",
    });
    assert.deepEqual(out.trim().split("\n"), ["3", "4"], "the restarted process continues the count");
    // The surviving in-process store re-reads the file: it never hands out a stale version.
    assert.equal(first.next(TASK_A), 5);
    assert.equal(new VersionStore(path).current(TASK_A), 5);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a store that cannot be trusted is refused rather than reset", () => {
  const { dir, path } = scratch();
  try {
    writeFileSync(path, "{not json");
    assert.throws(() => new VersionStore(path).next(TASK_A), /admission-versions/);
    writeFileSync(path, JSON.stringify({ format: 2, versions: {} }));
    assert.throws(() => new VersionStore(path).next(TASK_A), /format/);
    writeFileSync(path, JSON.stringify({ format: 1, versions: { [TASK_A]: "7" } }));
    assert.throws(() => new VersionStore(path).next(TASK_A), /version/);
    writeFileSync(path, JSON.stringify({ format: 1, versions: { [TASK_A]: 7 } }));
    assert.equal(new VersionStore(path).next(TASK_A), 8);
    assert.throws(() => new VersionStore(path).next("task_lowercase"), /task/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
