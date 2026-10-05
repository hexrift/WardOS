// Result return on the control-plane side (node-integration.md §6.6, §7.5): the `output`
// grant is held to the manifest grammar and the node's ceilings before anything is
// signed, a returned result is decoded with every count checked and every file's
// BLAKE3-256 digest recomputed over its content, a disagreement is refused rather than
// reported, and returned files are written under a directory and nowhere else.
import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  OFFLINE_MANIFEST,
  OUTPUT_CEILINGS,
  blake3Hex,
  buildEnvelope,
  decodeOutput,
  issuerFromSeed,
  manifest,
  outcomeOf,
  outputGrant,
  outputGrantOf,
  rootLease,
  writeReturnedFiles,
} from "../ward-node.mjs";

const BINDING = {
  task: "task_01M45YYRG00001249248SK6H24",
  attempt: "exec_01M45YYRG00005ANB6CSVQF248",
  lease: "lease_01M45YYRG00009K6DANAXVQK6C",
};

function b64(text) {
  return Buffer.from(text).toString("base64");
}

function stream(text, dropped = 0) {
  const content = Buffer.from(text);
  return { bytes: content.length, truncated: dropped > 0, dropped, content_base64: content.toString("base64") };
}

function returned(path, text) {
  const content = Buffer.from(text);
  return { path, size: content.length, digest: blake3Hex(content), truncated: false, content_base64: content.toString("base64") };
}

/** The §6.6 example, with real digests. */
function wireOutput() {
  const big = Buffer.alloc(3000, "b");
  return {
    stdout: stream("hello stdout\n"),
    stderr: stream("eeee", 4996),
    files: [
      returned("out/report.json", '{"ok":true}'),
      { path: "big.bin", size: 3000, digest: blake3Hex(big), truncated: true },
      { path: "missing.txt", skipped: "missing" },
      { path: "planted", skipped: "not_a_regular_file" },
    ],
  };
}

function report(output) {
  return {
    binding: BINDING,
    final_state: "sealed",
    outcome: "completed",
    outcome_certain: true,
    receipt: "completed",
    cause: { Exited: { code: 0 } },
    sealed: true,
    cancelled: false,
    deadline_exceeded: false,
    evidence_log: null,
    evidence_head: null,
    operations: [],
    transport_error: null,
    output,
  };
}

// ---- the grant -------------------------------------------------------------------------

test("the ceilings are the node's: 1 MiB per stream, 8 MiB of files, 64 paths", () => {
  assert.deepEqual(OUTPUT_CEILINGS, { stdioBytes: 1_048_576, filesBytes: 8_388_608, files: 64, pathBytes: 255 });
  assert.ok(Object.isFrozen(OUTPUT_CEILINGS));
});

test("an output grant is built in wire spelling, with zero as a grant too", () => {
  assert.deepEqual(outputGrant({ stdioBytes: 4096, files: ["out/report.json", "big.bin"], filesBytes: 2048 }), {
    stdio_bytes: 4096,
    files: ["out/report.json", "big.bin"],
    files_bytes: 2048,
  });
  assert.deepEqual(outputGrant({ stdioBytes: 0, files: [], filesBytes: 0 }), { stdio_bytes: 0, files: [], files_bytes: 0 });
  assert.deepEqual(outputGrant({ stdioBytes: OUTPUT_CEILINGS.stdioBytes, files: [], filesBytes: OUTPUT_CEILINGS.filesBytes }), {
    stdio_bytes: 1_048_576,
    files: [],
    files_bytes: 8_388_608,
  });
});

test("the manifest carries the grant after network, hashes over exactly those bytes, and the §7.5 example decodes", () => {
  const grant = { stdio_bytes: 4096, files: ["out/report.json", "big.bin"], files_bytes: 2048 };
  const json = '{"network":"offline","output":{"stdio_bytes":4096,"files":["out/report.json","big.bin"],"files_bytes":2048}}';
  const built = manifest({ network: "offline", output: grant });
  assert.equal(Buffer.from(built.bytes, "hex").toString("utf8"), json);
  assert.equal(built.hash, blake3Hex(Buffer.from(json)));
  // The order the caller wrote the keys in does not change the signed bytes.
  assert.deepEqual(manifest({ output: grant, network: "offline" }), built);
  assert.deepEqual(manifest(OFFLINE_MANIFEST), manifest({ network: "offline" }), "no grant, no `output` field");
  assert.ok(manifest({ network: { custom: ["github.com"] }, output: grant }).hash, "a grant beside a host allowlist");
});

test("a grant outside the grammar is refused before signing, naming the field", () => {
  const ok = { stdio_bytes: 16, files: ["x"], files_bytes: 16 };
  const refuses = (output, pattern) => assert.throws(() => manifest({ network: "offline", output }), pattern);
  refuses(null, /output/);
  refuses([], /output/);
  refuses({ ...ok, extra: 1 }, /stdio_bytes, files, files_bytes/);
  refuses({ stdio_bytes: 16, files: ["x"] }, /stdio_bytes, files, files_bytes/);
  refuses({ ...ok, stdio_bytes: -1 }, /stdio_bytes/);
  refuses({ ...ok, stdio_bytes: 1.5 }, /stdio_bytes/);
  refuses({ ...ok, stdio_bytes: "16" }, /stdio_bytes/);
  refuses({ ...ok, files_bytes: -1 }, /files_bytes/);
  refuses({ ...ok, files: "x" }, /files/);
  refuses({ ...ok, files: ["x", "x"] }, /repeats/);
  refuses({ ...ok, files: Array.from({ length: 65 }, (_, i) => `f${i}`) }, /0 to 64/);
  assert.ok(manifest({ network: "offline", output: { ...ok, files: Array.from({ length: 64 }, (_, i) => `f${i}`) } }).hash);
  for (const path of ["", "../x", "/etc/passwd", "a/../b", "./a", "a/", "/a", "a//b", "a b", "a\0b", "ä", "a*", "a?b", "x".repeat(256), 7]) {
    refuses({ ...ok, files: [path] }, /path/);
  }
  for (const path of ["x", "out/report.json", "a.b_c-d/E.F", "x".repeat(255), "...", "a/.../b"]) {
    assert.ok(manifest({ network: "offline", output: { ...ok, files: [path] } }).hash, path);
  }
  assert.throws(() => outputGrant({ stdioBytes: 16, files: ["../x"], filesBytes: 16 }), /path/);
});

test("a grant above the node's ceilings is refused here, not by the node as unsupported_grant", () => {
  const refuses = (output, pattern) => assert.throws(() => manifest({ network: "offline", output }), pattern);
  refuses({ stdio_bytes: 1_048_577, files: [], files_bytes: 0 }, /stdio_bytes.*1048576/);
  refuses({ stdio_bytes: 0, files: [], files_bytes: 8_388_609 }, /files_bytes.*8388608/);
  assert.throws(() => outputGrant({ stdioBytes: 1_048_577, files: [], filesBytes: 0 }), /unsupported_grant/);
  assert.throws(() => outputGrant({ stdioBytes: 0, files: [], filesBytes: 2 ** 53 }), /files_bytes/);
});

test("buildEnvelope refuses an envelope whose manifest grant is outside the grammar, before signing", () => {
  const now = 1_791_201_600_000;
  const input = (output) => ({
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
    workload: {
      argv: ["sh", "-c", "make test"],
      manifest: { network: "offline", output },
      snapshot: "c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b",
      wallClockBudgetMs: 600_000,
    },
    issuedAtUnixMs: now,
    expiresAtUnixMs: now + 900_000,
    version: 1,
  });
  assert.throws(() => buildEnvelope(input({ stdio_bytes: 1, files: ["../x"], files_bytes: 1 })), /path/);
  assert.throws(() => buildEnvelope(input({ stdio_bytes: 1_048_577, files: [], files_bytes: 1 })), /stdio_bytes/);
  const envelope = buildEnvelope(input({ stdio_bytes: 4096, files: ["out/report.json"], files_bytes: 2048 }));
  assert.equal(
    Buffer.from(envelope.workload.capability_manifest.bytes, "hex").toString(),
    '{"network":"offline","output":{"stdio_bytes":4096,"files":["out/report.json"],"files_bytes":2048}}',
  );
  assert.ok(issuerFromSeed(Buffer.alloc(32, 7)).prove(JSON.stringify(envelope)).signature);
});

// ---- the result -----------------------------------------------------------------------

test("a returned result decodes to bytes, with every digest recomputed and agreeing", () => {
  const output = decodeOutput(wireOutput());
  assert.deepEqual(output.stdout, { bytes: 13, truncated: false, dropped: 0, content: Buffer.from("hello stdout\n") });
  assert.deepEqual(output.stderr, { bytes: 4, truncated: true, dropped: 4996, content: Buffer.from("eeee") });
  assert.ok(Buffer.isBuffer(output.stdout.content));
  assert.equal(output.files.length, 4);
  assert.deepEqual(output.files[0], {
    path: "out/report.json",
    size: 11,
    digest: blake3Hex(Buffer.from('{"ok":true}')),
    truncated: false,
    content: Buffer.from('{"ok":true}'),
  });
  assert.deepEqual(output.files[1], { path: "big.bin", size: 3000, digest: blake3Hex(Buffer.alloc(3000, "b")), truncated: true });
  assert.deepEqual(output.files[2], { path: "missing.txt", skipped: "missing" });
  assert.deepEqual(output.files[3], { path: "planted", skipped: "not_a_regular_file" });
  assert.equal(output.truncated, true, "a truncated stream or a digest-only file marks the result truncated");
  const quiet = decodeOutput({ stdout: stream(""), stderr: stream(""), files: [] });
  assert.equal(quiet.truncated, false);
  assert.deepEqual(quiet.stdout.content, Buffer.alloc(0));
  assert.equal(decodeOutput(null), null);
  assert.equal(decodeOutput(undefined), null);
});

test("a digest that disagrees with the content is refused, and the content is never reported", () => {
  const wire = wireOutput();
  wire.files[0].digest = blake3Hex(Buffer.from('{"ok":false}'));
  assert.throws(() => decodeOutput(wire), /digest.*out\/report\.json|out\/report\.json.*digest/);
  assert.throws(() => outcomeOf(report(wire)), /digest/);
  const sizeOff = wireOutput();
  sizeOff.files[0].size = 12;
  assert.throws(() => decodeOutput(sizeOff), /size/);
  const badHex = wireOutput();
  badHex.files[0].digest = badHex.files[0].digest.toUpperCase();
  assert.throws(() => decodeOutput(badHex), /digest/);
  const shortHex = wireOutput();
  shortHex.files[1].digest = "abc";
  assert.throws(() => decodeOutput(shortHex), /digest/);
});

test("a result whose counts, flags or shape disagree with §6.6 is refused", () => {
  const refuses = (mutate, pattern) => {
    const wire = wireOutput();
    mutate(wire);
    assert.throws(() => decodeOutput(wire), pattern);
  };
  refuses((w) => (w.stdout.bytes = 12), /stdout.*bytes/);
  refuses((w) => (w.stdout.truncated = true), /stdout.*truncated/);
  refuses((w) => (w.stderr.truncated = false), /stderr.*truncated/);
  refuses((w) => (w.stderr.dropped = -1), /stderr.*dropped/);
  refuses((w) => (w.stdout.content_base64 = "aGVsbG8gc3Rkb3V0Cg"), /base64/); // no padding
  refuses((w) => (w.stdout.content_base64 = "aGVsbG8gc3Rkb3V0Cg=!"), /base64/);
  refuses((w) => (w.stdout.content_base64 = 7), /base64/);
  refuses((w) => delete w.stderr, /stderr/);
  refuses((w) => (w.stdout.extra = 1), /stdout/);
  refuses((w) => (w.files = {}), /files/);
  refuses((w) => w.files.push({ path: "x", skipped: "eaten" }), /skipped/);
  refuses((w) => w.files.push({ path: "x", skipped: "missing", size: 1 }), /skipped/);
  refuses((w) => w.files.push({ path: "../x", skipped: "missing" }), /path/);
  refuses((w) => w.files.push({ path: "out/report.json", skipped: "missing" }), /repeats/);
  refuses((w) => (w.files[1].truncated = false), /big\.bin/); // digest-only must be truncated
  refuses((w) => (w.files[1].content_base64 = b64("bbb")), /big\.bin/);
  refuses((w) => (w.files[0].truncated = true), /out\/report\.json/); // returned content is never truncated
  refuses((w) => delete w.files[0].content_base64, /out\/report\.json/);
  refuses((w) => w.files.push(...Array.from({ length: 61 }, (_, i) => ({ path: `g${i}`, skipped: "missing" }))), /0 to 64/);
  assert.throws(() => decodeOutput("output"), /object/);
  assert.throws(() => decodeOutput([]), /object/);
});

test("outcomeOf carries the decoded output, null without one, and a large returned file round-trips", () => {
  const outcome = outcomeOf(report(wireOutput()));
  assert.equal(outcome.outcome, "completed");
  assert.deepEqual(outcome.output.stdout.content, Buffer.from("hello stdout\n"));
  assert.equal(outcome.output.files[0].content.toString(), '{"ok":true}');
  assert.equal(outcomeOf(report(null)).output, null);
  const { output: _omitted, ...withoutField } = report(null);
  assert.equal(outcomeOf(withoutField).output, null, "a report of an earlier adapter has no output field");
  const large = Buffer.alloc(2 * 1024 * 1024 + 17, 0x5a);
  const decoded = decodeOutput({ stdout: stream(""), stderr: stream(""), files: [returned("large.bin", large)] });
  assert.ok(decoded.files[0].content.equals(large));
  assert.equal(decoded.files[0].size, large.length);
});

// ---- writing returned files -------------------------------------------------------------

function temporary() {
  const dir = mkdtempSync(join(tmpdir(), "ward-out-"));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("returned files are written under the directory with their declared paths, mode 0600, never overwriting", () => {
  const { dir, cleanup } = temporary();
  try {
    const output = decodeOutput(wireOutput());
    const written = writeReturnedFiles(dir, output.files);
    assert.deepEqual(written, [{ path: "out/report.json", written: join(dir, "out/report.json") }]);
    assert.equal(readFileSync(join(dir, "out/report.json"), "utf8"), '{"ok":true}');
    assert.equal(lstatSync(join(dir, "out/report.json")).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(dir), ["out"], "digest-only and skipped files leave nothing behind");
    assert.throws(() => writeReturnedFiles(dir, output.files), /exists|EEXIST/);
    assert.equal(readFileSync(join(dir, "out/report.json"), "utf8"), '{"ok":true}');
  } finally {
    cleanup();
  }
});

test("a path that would escape the directory is refused and nothing is written, even when the node sent it", () => {
  const { dir, cleanup } = temporary();
  try {
    const content = Buffer.from("escaped");
    const file = (path) => ({ path, size: content.length, digest: blake3Hex(content), truncated: false, content });
    for (const path of ["../escaped.txt", "/tmp/escaped.txt", "a/../../escaped.txt", "", ".", "a//b", "a\\b", "C:\\x"]) {
      assert.throws(() => writeReturnedFiles(dir, [file("fine.txt"), file(path)]), /path/, path);
      assert.ok(!existsSync(join(dir, "fine.txt")), `nothing was written before refusing ${path}`);
    }
    assert.ok(!existsSync(join(dir, "..", "escaped.txt")));
    // A symlink planted at a declared path's parent inside the directory is not followed either.
    const outside = mkdtempSync(join(tmpdir(), "ward-outside-"));
    try {
      symlinkSync(outside, join(dir, "link"));
      assert.throws(() => writeReturnedFiles(dir, [file("link/escaped.txt")]), /symlink|path/);
      assert.deepEqual(readdirSync(outside), []);
      writeFileSync(join(dir, "plain"), "x");
      symlinkSync(join(dir, "plain"), join(dir, "alias"));
      assert.throws(() => writeReturnedFiles(dir, [file("alias")]), /exists|EEXIST|symlink/);
      assert.equal(readFileSync(join(dir, "plain"), "utf8"), "x");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
    assert.throws(() => writeReturnedFiles(dir, [{ path: "x", size: 1, digest: "0".repeat(64), truncated: false, content: "text" }]), /content/);
    assert.throws(() => writeReturnedFiles("", []), /directory/);
  } finally {
    cleanup();
  }
});

// ---- the result against its grant -----------------------------------------------------------

const GRANT = { stdio_bytes: 4096, files: ["out/report.json", "big.bin", "missing.txt", "planted"], files_bytes: 2048 };

test("a result is held to the grant it answers: the declared paths in order, within both budgets", () => {
  assert.equal(decodeOutput(wireOutput(), GRANT).files.length, 4);
  assert.throws(() => decodeOutput(wireOutput(), { ...GRANT, files: ["out/report.json", "big.bin", "missing.txt"] }), /declared/);
  assert.throws(() => decodeOutput(wireOutput(), { ...GRANT, files: [...GRANT.files].reverse() }), /declared/);
  assert.throws(() => decodeOutput(wireOutput(), { ...GRANT, files: [...GRANT.files, "extra"] }), /declared/);
  assert.throws(() => decodeOutput(wireOutput(), { ...GRANT, stdio_bytes: 12 }), /stdout.*12/);
  assert.throws(() => decodeOutput(wireOutput(), { ...GRANT, files_bytes: 10 }), /11 bytes.*10/);
  assert.ok(decodeOutput(wireOutput(), { ...GRANT, stdio_bytes: 13, files_bytes: 11 }), "exactly at both budgets");
  assert.throws(() => decodeOutput(wireOutput(), { ...GRANT, files: ["../x"] }), /path/, "the grant itself is checked");
});

test("a granted output that did not come back is missing, never a success", () => {
  const missing = outcomeOf(report(null), { grant: GRANT });
  assert.equal(missing.outcome, "completed", "the workload's outcome is unchanged");
  assert.equal(missing.output, null);
  assert.equal(missing.outputMissing, true);
  const { output: _omitted, ...withoutField } = report(null);
  assert.equal(outcomeOf(withoutField, { grant: GRANT }).outputMissing, true, "an absent field is missing too");
  const returnedOutcome = outcomeOf(report(wireOutput()), { grant: GRANT });
  assert.equal(returnedOutcome.outputMissing, false);
  assert.equal(returnedOutcome.output.files[0].content.toString(), '{"ok":true}');
  assert.throws(() => outcomeOf(report(wireOutput()), { grant: { ...GRANT, files: ["other"] } }), /declared/);
  assert.equal(outcomeOf(report(null)).outputMissing, false, "without a grant nothing is expected");
});

test("outputGrantOf reads the grant from a signed envelope's exact manifest bytes", () => {
  const envelopeJson = (manifestJson) =>
    JSON.stringify({ workload: { capability_manifest: { hash: blake3Hex(Buffer.from(manifestJson)), bytes: Buffer.from(manifestJson).toString("hex") } } });
  const grant = { stdio_bytes: 4096, files: ["out/report.json"], files_bytes: 2048 };
  assert.deepEqual(outputGrantOf(envelopeJson(JSON.stringify({ network: "offline", output: grant }))), grant);
  assert.equal(outputGrantOf(envelopeJson('{"network":"offline"}')), null);
  assert.throws(() => outputGrantOf(envelopeJson('{"network":"offline","output":{"stdio_bytes":1,"files":["../x"],"files_bytes":1}}')), /path/);
  assert.throws(() => outputGrantOf(envelopeJson("not json")), /manifest/);
  assert.throws(() => outputGrantOf("{"), /JSON/);
  assert.throws(() => outputGrantOf(JSON.stringify({ workload: {} })), /manifest/);
  assert.throws(() => outputGrantOf(7), /envelope_json/);
});

test("writing refuses an existing target or a non-directory parent before writing anything", () => {
  const { dir, cleanup } = temporary();
  try {
    const content = Buffer.from("x");
    const file = (path) => ({ path, size: 1, digest: blake3Hex(content), truncated: false, content });
    writeFileSync(join(dir, "taken.txt"), "keep");
    assert.throws(() => writeReturnedFiles(dir, [file("first.txt"), file("taken.txt")]), /already exists/);
    assert.ok(!existsSync(join(dir, "first.txt")), "the first file was not written before the refusal");
    assert.equal(readFileSync(join(dir, "taken.txt"), "utf8"), "keep");
    assert.throws(() => writeReturnedFiles(dir, [file("first.txt"), file("taken.txt/inner")]), /non-directory/);
    assert.ok(!existsSync(join(dir, "first.txt")));
    assert.deepEqual(writeReturnedFiles(dir, [file("a/b/c.txt")]), [{ path: "a/b/c.txt", written: join(dir, "a/b/c.txt") }]);
    assert.equal(lstatSync(join(dir, "a/b")).mode & 0o777, 0o700);
  } finally {
    cleanup();
  }
});
