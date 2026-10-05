// A reference control-plane client for `ward-node`, in plain Node.js (>= 22, ESM, no
// dependencies). It is the control-plane side of docs/node-integration.md as a Node.js or
// TypeScript control plane would write it: ids (§7.2), the issuer key and its proof
// (§2.3, §7.4), the admission envelope (§7), the per-task version (§7.3, §10), and the
// JSON-lines conversation with `ward-node-adapter` (§11.4). The walk through it for an
// adapter author is docs/node-integration-from-nodejs.md.
//
// Everything here fails closed: an id, hex value, grant or bound outside the contract is
// refused before anything is signed or sent, an `unknown` outcome is never certain, and
// the key never leaves this process.

import { spawn } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";

import { blake3Hex } from "./blake3.mjs";

export { blake3Hex };

/** The one protocol version this client speaks (§4). */
export const PROTOCOL = Object.freeze({ major: 1, minor: 3 });

/** The manifest every workload runs under on a node without `--network-allowlist` (§7.5). */
export const OFFLINE_MANIFEST = Object.freeze({ network: "offline" });

/** Every id prefix of §7.2. */
export const ID_PREFIXES = Object.freeze(["task", "exec", "lease", "agent", "node", "sess", "deleg", "prn"]);

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ID_BODY = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const CAPABILITY = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const RESOURCE = /^[\x21-\x7e]{1,256}$/;
const HOST_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_ENVELOPE_BYTES = 32768;
const MAX_ARGV_ENTRY_BYTES = 4096;
const MAX_ARGV_BYTES = 16384;
const MAX_ARGV_ENTRIES = 256;
const MAX_MANIFEST_BYTES = 8192;
const MAX_LINEAGE = 16;
const ID_DERIVATION_DOMAIN = "ward-node id v1";
// PKCS#8 wrapping of a raw Ed25519 seed (RFC 8410): the prefix that precedes the 32 bytes.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

class ContractError extends Error {
  constructor(message) {
    super(message);
    this.name = "ContractError";
  }
}

function refuse(message) {
  throw new ContractError(message);
}

// ---------------------------------------------------------------------------------------
// Ids (§7.2)
// ---------------------------------------------------------------------------------------

function checkPrefix(prefix) {
  if (!ID_PREFIXES.includes(prefix)) refuse(`unknown id prefix \`${prefix}\`; one of ${ID_PREFIXES.join(", ")}`);
}

/** Render a 128-bit value (bigint or safe integer) as `<prefix>_` + 26 Crockford base32 characters. */
export function encodeId(prefix, value) {
  checkPrefix(prefix);
  let v = typeof value === "bigint" ? value : BigInt(value);
  if (v < 0n || v >= 1n << 128n) refuse("an id value is 128 bits");
  let body = "";
  for (let i = 0; i < 26; i += 1) {
    body = CROCKFORD[Number(v & 31n)] + body;
    v >>= 5n;
  }
  return `${prefix}_${body}`;
}

/** The prefix and 128-bit value of an id, refusing anything the node refuses (lower case included). */
export function decodeId(id) {
  if (typeof id !== "string") refuse("an id is a string");
  const underscore = id.indexOf("_");
  if (underscore < 0) refuse(`\`${id}\` has no prefix`);
  const prefix = id.slice(0, underscore);
  const body = id.slice(underscore + 1);
  checkPrefix(prefix);
  if (!ID_BODY.test(body)) refuse(`\`${id}\` is not a 26-character upper-case Crockford base32 id`);
  let value = 0n;
  for (const char of body) value = (value << 5n) | BigInt(CROCKFORD.indexOf(char));
  return { prefix, value };
}

/** Whether `id` is a well-formed id, optionally of one prefix. */
export function isId(id, prefix) {
  try {
    const decoded = decodeId(id);
    return prefix === undefined || decoded.prefix === prefix;
  } catch {
    return false;
  }
}

function requireId(id, prefix, what) {
  if (!isId(id, prefix)) refuse(`${what} must be a \`${prefix}_\` id, got ${JSON.stringify(id)}`);
  return id;
}

/**
 * Derive a WardOS id deterministically from the control plane's own id for the thing:
 * the first 16 bytes of SHA-256("ward-node id v1" ‖ 0x00 ‖ prefix ‖ 0x00 ‖ callerId),
 * read big-endian, rendered with `prefix`. The same caller id always gives the same
 * WardOS id, two prefixes never share a value, and the mapping needs no table; the top
 * three bits are whatever the hash gives, which the 26-character form always holds.
 */
export function deriveId(prefix, callerId) {
  checkPrefix(prefix);
  if (typeof callerId !== "string" || callerId.length === 0) refuse("a caller id is a non-empty string");
  const digest = createHash("sha256")
    .update(ID_DERIVATION_DOMAIN)
    .update(Buffer.from([0]))
    .update(prefix)
    .update(Buffer.from([0]))
    .update(callerId, "utf8")
    .digest();
  return encodeId(prefix, digest.subarray(0, 16).readBigUInt64BE(0) << 64n | digest.subarray(8, 16).readBigUInt64BE(0));
}

/** A fresh random id with `prefix`. */
export function randomId(prefix) {
  const bytes = randomBytes(16);
  return encodeId(prefix, bytes.readBigUInt64BE(0) << 64n | bytes.readBigUInt64BE(8));
}

// ---------------------------------------------------------------------------------------
// Capability manifest (§7.5)
// ---------------------------------------------------------------------------------------

function checkManifest(object) {
  if (object === null || typeof object !== "object" || Array.isArray(object)) refuse("a manifest is one JSON object");
  const keys = Object.keys(object);
  if (keys.length !== 1 || keys[0] !== "network") refuse("a manifest has exactly the field `network`");
  const network = object.network;
  if (network === "offline") return;
  if (network === null || typeof network !== "object" || Object.keys(network).join() !== "custom") {
    refuse("manifest `network` is \"offline\" or {\"custom\":[hosts]}");
  }
  const hosts = network.custom;
  if (!Array.isArray(hosts) || hosts.length < 1 || hosts.length > 64) refuse("manifest `network.custom` lists 1 to 64 hosts");
  if (new Set(hosts).size !== hosts.length) refuse("manifest `network.custom` repeats a host");
  for (const host of hosts) {
    if (typeof host !== "string") refuse("a manifest host is a string");
    const name = host.startsWith("*.") ? host.slice(2) : host;
    const labels = name.split(".");
    if (name.length > 253 || labels.some((label) => !HOST_LABEL.test(label))) {
      refuse(`manifest host ${JSON.stringify(host)} is not a lowercase DNS name or *.name pattern`);
    }
  }
}

/** The manifest as the envelope carries it: hex bytes as sent and their BLAKE3-256 (§7.3). */
export function manifest(object = OFFLINE_MANIFEST) {
  checkManifest(object);
  const bytes = Buffer.from(JSON.stringify(object), "utf8");
  if (bytes.length > MAX_MANIFEST_BYTES) refuse(`a manifest is at most ${MAX_MANIFEST_BYTES} bytes`);
  return { hash: blake3Hex(bytes), bytes: bytes.toString("hex") };
}

// ---------------------------------------------------------------------------------------
// Issuer key (§2.2, §2.3, §7.4)
// ---------------------------------------------------------------------------------------

/** An Ed25519 issuer key held in this process. Construct with the `issuer*` functions. */
export class Issuer {
  #key;

  constructor(privateKey) {
    if (privateKey.asymmetricKeyType !== "ed25519") refuse("the issuer key is an Ed25519 key");
    this.#key = privateKey;
    const spki = createPublicKey(privateKey).export({ type: "spki", format: "der" });
    this.publicKey = Buffer.from(spki.subarray(spki.length - 32));
    this.publicKeyHex = this.publicKey.toString("hex");
    this.keyId = blake3Hex(this.publicKey);
    Object.freeze(this);
  }

  /** The trust-store line binding this key to `principal` (§2.2). */
  trustStoreLine(principal) {
    requireId(principal, "prn", "the issuer principal");
    return `${this.publicKeyHex} ${this.keyId} ${principal}`;
  }

  /** The detached proof over the exact UTF-8 bytes of `envelopeJson` (§7.4). */
  prove(envelopeJson) {
    const bytes = Buffer.from(envelopeJson, "utf8");
    if (bytes.length < 1 || bytes.length > MAX_ENVELOPE_BYTES) refuse(`an envelope is 1 to ${MAX_ENVELOPE_BYTES} bytes`);
    return { issuer_key_id: this.keyId, signature: sign(null, bytes, this.#key).toString("hex") };
  }

  /** The key as a PKCS#8 PEM string, for `createIssuerKey` and for custody elsewhere. */
  toPem() {
    return this.#key.export({ type: "pkcs8", format: "pem" });
  }
}

/** The issuer whose Ed25519 seed is `seed` (32 bytes); §7.4's test key is 32 bytes of 0x07. */
export function issuerFromSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) refuse("an Ed25519 seed is 32 bytes");
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]);
  return new Issuer(createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
}

/** The issuer held in a PKCS#8 PEM string. */
export function issuerFromPem(pem) {
  return new Issuer(createPrivateKey({ key: pem, format: "pem" }));
}

function checkPrivateFile(path) {
  const stat = statSync(path);
  if (!stat.isFile()) refuse(`${path} is not a regular file`);
  const mode = stat.mode & 0o777;
  if (mode !== 0o600 && mode !== 0o400) refuse(`${path} has mode ${mode.toString(8)}, not 0600 or 0400`);
}

/** Load the issuer key from a PKCS#8 PEM file that must be a regular file of mode 0600 or 0400. */
export function loadIssuerKey(path) {
  checkPrivateFile(path);
  return issuerFromPem(readFileSync(path, "utf8"));
}

/** Generate a new Ed25519 issuer key and write it to `path` (mode 0600, never overwriting). */
export function createIssuerKey(path) {
  const { privateKey } = generateKeyPairSync("ed25519");
  const issuer = new Issuer(privateKey);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, issuer.toPem(), { mode: 0o600, flag: "wx" });
  return issuer;
}

/** `loadIssuerKey` when `path` exists, `createIssuerKey` otherwise. */
export function loadOrCreateIssuerKey(path) {
  try {
    statSync(path);
  } catch (error) {
    if (error.code === "ENOENT") return createIssuerKey(path);
    throw error;
  }
  return loadIssuerKey(path);
}

// ---------------------------------------------------------------------------------------
// Envelope (§7)
// ---------------------------------------------------------------------------------------

function checkTime(value, what) {
  if (!Number.isSafeInteger(value) || value < 0) refuse(`${what} is a non-negative integer of Unix milliseconds`);
  return value;
}

function checkGrants(grants) {
  if (!Array.isArray(grants) || grants.length === 0) refuse("a lease's grants are a non-empty array");
  const seen = new Set();
  for (const grant of grants) {
    if (grant === null || typeof grant !== "object" || Object.keys(grant).length !== 3) {
      refuse("a grant is {capability, resource, delegable}");
    }
    if (typeof grant.capability !== "string" || !CAPABILITY.test(grant.capability)) {
      refuse(`grant capability ${JSON.stringify(grant.capability)} is 1-64 bytes of a-z 0-9 . _ - starting with a letter or digit`);
    }
    if (typeof grant.resource !== "string" || !RESOURCE.test(grant.resource)) {
      refuse(`grant resource ${JSON.stringify(grant.resource)} is 1-256 printable ASCII bytes without spaces`);
    }
    if (typeof grant.delegable !== "boolean") refuse("grant delegable is a boolean");
    const key = `${grant.capability}\0${grant.resource}`;
    if (seen.has(key)) refuse(`two grants for ${grant.capability} on ${grant.resource}`);
    seen.add(key);
  }
  for (let i = 1; i < grants.length; i += 1) {
    if (compareGrants(grants[i - 1], grants[i]) >= 0) refuse("grants are sorted by capability, resource, then delegable (false first)");
  }
}

function compareGrants(a, b) {
  const byCapability = Buffer.compare(Buffer.from(a.capability), Buffer.from(b.capability));
  if (byCapability !== 0) return byCapability;
  const byResource = Buffer.compare(Buffer.from(a.resource), Buffer.from(b.resource));
  if (byResource !== 0) return byResource;
  return Number(a.delegable) - Number(b.delegable);
}

function checkLease(lease, what) {
  if (lease === null || typeof lease !== "object") refuse(`${what} is an object`);
  requireId(lease.id, "lease", `${what}.id`);
  requireId(lease.delegation_id, "deleg", `${what}.delegation_id`);
  requireId(lease.issuer, "prn", `${what}.issuer`);
  requireId(lease.subject, "agent", `${what}.subject`);
  requireId(lease.task, "task", `${what}.task`);
  if (lease.parent_lease_id !== null) requireId(lease.parent_lease_id, "lease", `${what}.parent_lease_id`);
  if (lease.delegated_by !== null) requireId(lease.delegated_by, "agent", `${what}.delegated_by`);
  if ((lease.parent_lease_id === null) !== (lease.delegated_by === null)) {
    refuse(`${what}: parent_lease_id and delegated_by are both null (root) or both set (delegated)`);
  }
  checkGrants(lease.grants);
  checkTime(lease.issued_at_unix_ms, `${what}.issued_at_unix_ms`);
  checkTime(lease.expires_at_unix_ms, `${what}.expires_at_unix_ms`);
  if (lease.expires_at_unix_ms <= lease.issued_at_unix_ms) refuse(`${what} expires_at must be after issued_at`);
  if (!Number.isSafeInteger(lease.version) || lease.version < 1) refuse(`${what}.version is an integer >= 1`);
  return {
    id: lease.id,
    delegation_id: lease.delegation_id,
    issuer: lease.issuer,
    subject: lease.subject,
    task: lease.task,
    parent_lease_id: lease.parent_lease_id,
    delegated_by: lease.delegated_by,
    grants: lease.grants.map((grant) => ({ capability: grant.capability, resource: grant.resource, delegable: grant.delegable })),
    issued_at_unix_ms: lease.issued_at_unix_ms,
    expires_at_unix_ms: lease.expires_at_unix_ms,
    version: lease.version,
  };
}

/**
 * A root lease (§7.3) from the control plane's inputs, with the grants sorted as the
 * contract requires and the two optional fields explicitly null.
 */
export function rootLease({ id, delegationId, issuer, subject, task, grants, issuedAtUnixMs, expiresAtUnixMs, version = 1 }) {
  const sorted = Array.isArray(grants) ? [...grants].sort(compareGrants) : grants;
  return checkLease(
    {
      id,
      delegation_id: delegationId,
      issuer,
      subject,
      task,
      parent_lease_id: null,
      delegated_by: null,
      grants: sorted,
      issued_at_unix_ms: issuedAtUnixMs,
      expires_at_unix_ms: expiresAtUnixMs,
      version,
    },
    "the lease",
  );
}

function checkArgv(argv) {
  if (!Array.isArray(argv) || argv.length < 1 || argv.length > MAX_ARGV_ENTRIES) {
    refuse(`argv is 1 to ${MAX_ARGV_ENTRIES} strings`);
  }
  let total = 0;
  argv.forEach((entry, index) => {
    if (typeof entry !== "string") refuse("every argv entry is a string");
    if (index === 0 && entry.length === 0) refuse("argv[0], the program, is non-empty");
    if (entry.includes("\0")) refuse("argv contains a NUL");
    const bytes = Buffer.byteLength(entry, "utf8");
    if (bytes > MAX_ARGV_ENTRY_BYTES) refuse(`an argv entry is at most ${MAX_ARGV_ENTRY_BYTES} bytes`);
    total += bytes;
  });
  if (total > MAX_ARGV_BYTES) refuse(`argv is at most ${MAX_ARGV_BYTES} bytes in all`);
  return [...argv];
}

/**
 * Build the envelope of §7.1, with the keys in the order the §7.4 vector has them, from:
 * binding {task, attempt, lease}, agent, node, session, lease (a `rootLease` or a
 * delegated lease in wire form), lineage (nearest parent first, default none), workload
 * {argv, manifest (object, default offline), snapshot, wallClockBudgetMs}, issuedAtUnixMs,
 * expiresAtUnixMs and version. Every bound of §7.3 is checked here, before signing.
 */
export function buildEnvelope(input) {
  const { binding, agent, node, session, lease, lineage = [], workload, issuedAtUnixMs, expiresAtUnixMs, version } = input;
  if (binding === null || typeof binding !== "object") refuse("binding is {task, attempt, lease}");
  requireId(binding.task, "task", "binding.task");
  requireId(binding.attempt, "exec", "binding.attempt");
  requireId(binding.lease, "lease", "binding.lease");
  requireId(agent, "agent", "agent");
  requireId(node, "node", "node");
  requireId(session, "sess", "session");
  const checkedLease = checkLease(lease, "the lease");
  if (checkedLease.id !== binding.lease) refuse("the lease is not the binding's lease");
  if (checkedLease.task !== binding.task) refuse("the lease is bound to another task");
  if (checkedLease.subject !== agent) refuse("the lease's subject is not the envelope's agent");
  if (!Array.isArray(lineage) || lineage.length > MAX_LINEAGE) refuse(`lineage holds at most ${MAX_LINEAGE} leases`);
  const checkedLineage = lineage.map((ancestor, index) => checkLease(ancestor, `lineage[${index}]`));
  if (workload === null || typeof workload !== "object") refuse("workload is {argv, manifest, snapshot, wallClockBudgetMs}");
  const argv = checkArgv(workload.argv);
  const capabilityManifest = manifest(workload.manifest ?? OFFLINE_MANIFEST);
  if (typeof workload.snapshot !== "string" || !HEX_32.test(workload.snapshot)) {
    refuse("snapshot is 64 lowercase hex digits, the line `ward-node snapshot import` printed");
  }
  if (!Number.isSafeInteger(workload.wallClockBudgetMs) || workload.wallClockBudgetMs < 1) {
    refuse("wallClockBudgetMs, the budget, is an integer >= 1");
  }
  checkTime(issuedAtUnixMs, "issuedAtUnixMs");
  checkTime(expiresAtUnixMs, "expiresAtUnixMs");
  if (expiresAtUnixMs <= issuedAtUnixMs) refuse("expiresAtUnixMs must be after issuedAtUnixMs");
  if (!Number.isSafeInteger(version) || version < 1) refuse("version is an integer >= 1");
  const envelope = {
    binding: { task: binding.task, attempt: binding.attempt, lease: binding.lease },
    agent,
    node,
    session,
    authority: { lease: checkedLease, lineage: checkedLineage },
    workload: {
      argv,
      capability_manifest: capabilityManifest,
      snapshot: workload.snapshot,
      wall_clock_budget_ms: workload.wallClockBudgetMs,
    },
    issued_at_unix_ms: issuedAtUnixMs,
    expires_at_unix_ms: expiresAtUnixMs,
    version,
  };
  serialiseEnvelope(envelope);
  return envelope;
}

/** The envelope as the string that is signed and sent: compact JSON, 1 to 32 KiB. */
export function serialiseEnvelope(envelope) {
  const json = JSON.stringify(envelope);
  const bytes = Buffer.byteLength(json, "utf8");
  if (bytes > MAX_ENVELOPE_BYTES) refuse(`the envelope is ${bytes} bytes, over the ${MAX_ENVELOPE_BYTES} the node accepts`);
  return json;
}

/**
 * Serialise once and sign those bytes (§7.4). The result, {envelope_json, proof, binding},
 * is exactly what `ward-node-adapter`'s pre-signed `run` takes and what a replay resends.
 */
export function signEnvelope(issuer, envelope) {
  const envelopeJson = serialiseEnvelope(envelope);
  return {
    envelope_json: envelopeJson,
    proof: issuer.prove(envelopeJson),
    binding: { ...envelope.binding },
  };
}

/** The complete `admit` request line of §7.4 for a signed envelope, for a client speaking to the socket itself. */
export function admitRequest(signed, operationId) {
  return JSON.stringify({
    request: "admit",
    protocol: PROTOCOL,
    operation_id: operationId,
    binding: signed.binding,
    envelope_json: signed.envelope_json,
    proof: signed.proof,
  });
}

// ---------------------------------------------------------------------------------------
// Durable per-task admission version (§7.3, §10)
// ---------------------------------------------------------------------------------------

function writeDurably(path, text) {
  const temporary = `${path}.tmp-${process.pid}`;
  const fd = openSync(temporary, "w", 0o600);
  try {
    writeFileSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, path);
  const dir = openSync(dirname(path), "r");
  try {
    fsyncSync(dir);
  } catch {
    // A directory that cannot be fsynced (some filesystems) still has the rename.
  } finally {
    closeSync(dir);
  }
}

/**
 * The control plane's record of the last admission version it issued per task, in one
 * JSON file: {"format":1,"versions":{"task_…":N}}. Every `next` re-reads the file, bumps
 * the task's version and writes the file durably (temporary file, fsync, rename) before
 * returning, so a version is never handed out twice, in this process or after a restart.
 * Allocate before `admit`; a refused admit leaves a gap, which the node does not mind.
 */
export class VersionStore {
  #path;

  constructor(path) {
    this.#path = path;
  }

  #read() {
    let text;
    try {
      text = readFileSync(this.#path, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") return { format: 1, versions: {} };
      throw error;
    }
    let file;
    try {
      file = JSON.parse(text);
    } catch {
      refuse(`${this.#path} (admission-versions) is not JSON; refusing to guess at versions`);
    }
    if (file === null || typeof file !== "object" || file.format !== 1) refuse(`${this.#path} has an unknown format`);
    if (file.versions === null || typeof file.versions !== "object") refuse(`${this.#path} has no versions object`);
    for (const [task, version] of Object.entries(file.versions)) {
      if (!isId(task, "task")) refuse(`${this.#path} names a task that is not a task id: ${task}`);
      if (!Number.isSafeInteger(version) || version < 1) refuse(`${this.#path} holds a version that is not an integer >= 1 for ${task}`);
    }
    return file;
  }

  /** The last version issued for `task`, 0 when none was. */
  current(task) {
    requireId(task, "task", "the task");
    return this.#read().versions[task] ?? 0;
  }

  /** Issue the next version for `task` and record it durably before returning it. */
  next(task) {
    requireId(task, "task", "the task");
    const file = this.#read();
    const version = (file.versions[task] ?? 0) + 1;
    file.versions[task] = version;
    mkdirSync(dirname(this.#path), { recursive: true, mode: 0o700 });
    writeDurably(this.#path, `${JSON.stringify(file)}\n`);
    return version;
  }
}

// ---------------------------------------------------------------------------------------
// Run records, for replay after a control-plane restart (§6.3, §11.2)
// ---------------------------------------------------------------------------------------

/** The operation-id scheme of §11.2 shifted to start at `startAt`. */
export function operationIds(startAt = 1) {
  if (!Number.isSafeInteger(startAt) || startAt < 1) refuse("operation ids start at an integer >= 1");
  return { start_at: startAt, create: startAt, admit: startAt + 1, start: startAt + 2, stop: startAt + 3, revoke: startAt + 4, seal: startAt + 5 };
}

/**
 * Persist what a replay needs before the first send: the signed bytes and proof, the
 * operation-id scheme and the task root, keyed by attempt id under `dir`.
 */
export function saveRunRecord(dir, record) {
  requireId(record.binding?.attempt, "exec", "the record's attempt");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeDurably(join(dir, `${record.binding.attempt}.json`), `${JSON.stringify({ format: 1, ...record })}\n`);
}

/** The record `saveRunRecord` wrote for `attempt`. */
export function loadRunRecord(dir, attempt) {
  requireId(attempt, "exec", "the attempt");
  const record = JSON.parse(readFileSync(join(dir, `${attempt}.json`), "utf8"));
  if (record.format !== 1 || typeof record.envelope_json !== "string" || typeof record.proof?.signature !== "string") {
    refuse(`the run record of ${attempt} is not one this client wrote`);
  }
  return record;
}

// ---------------------------------------------------------------------------------------
// The adapter conversation (§11.4)
// ---------------------------------------------------------------------------------------

/**
 * One `ward-node-adapter` process: JSON commands in, JSON events out, one per line. The
 * adapter is spawned the way any external tool is, with `--socket` on its command line;
 * `command` is the executable and any leading arguments (default `["ward-node-adapter"]`).
 * Cancellation is a signal: `cancel()` sends SIGTERM, which the adapter answers by
 * revoking and sealing the running attempt and writing its `done` (§11.4).
 */
export class Adapter {
  #child;
  #lines = [];
  #waiters = [];
  #exit = null;
  #trace;

  constructor({ command = ["ward-node-adapter"], socket, timeoutMs, connectTimeoutMs, env = process.env, trace = null }) {
    if (typeof socket !== "string" || socket.length === 0) refuse("the adapter needs the node's socket path");
    const [executable, ...leading] = command;
    const args = [...leading, "--socket", socket];
    if (timeoutMs !== undefined) args.push("--timeout-ms", String(timeoutMs));
    if (connectTimeoutMs !== undefined) args.push("--connect-timeout-ms", String(connectTimeoutMs));
    this.#trace = trace;
    this.#child = spawn(executable, args, { stdio: ["pipe", "pipe", "inherit"], env });
    this.#child.on("error", (error) => this.#push({ error }));
    this.#child.on("exit", (code, signal) => {
      this.#exit = { code, signal };
      this.#push({ eof: true });
    });
    const reader = createInterface({ input: this.#child.stdout, crlfDelay: Infinity });
    reader.on("line", (line) => {
      if (this.#trace) this.#trace(`<< ${line}`);
      let event;
      try {
        event = JSON.parse(line);
      } catch {
        this.#push({ error: new ContractError(`the adapter wrote a line that is not JSON: ${line}`) });
        return;
      }
      if (event === null || typeof event !== "object" || event.schema !== 1 || typeof event.event !== "string") {
        this.#push({ error: new ContractError(`the adapter wrote an event without schema 1: ${line}`) });
        return;
      }
      this.#push({ event });
    });
  }

  /** The adapter's pid, for an operator who wants to signal it. */
  get pid() {
    return this.#child.pid;
  }

  #push(item) {
    const waiter = this.#waiters.shift();
    if (waiter) waiter(item);
    else this.#lines.push(item);
  }

  #take() {
    if (this.#lines.length > 0) return Promise.resolve(this.#lines.shift());
    return new Promise((resolve) => this.#waiters.push(resolve));
  }

  /** Write one command line. */
  send(command) {
    const line = JSON.stringify(command);
    if (line.includes("\n")) refuse("a command line holds no newline");
    if (this.#trace) this.#trace(`>> ${line}`);
    this.#child.stdin.write(`${line}\n`);
  }

  /** The next event, or a rejection when the adapter wrote an `error` event or ended. */
  async next() {
    const item = await this.#take();
    if (item.error) throw item.error;
    if (item.eof) throw new ContractError("the adapter exited without answering");
    if (item.event.event === "error") throw new ContractError(`ward-node-adapter: ${item.event.error}`);
    return item.event;
  }

  async #one(command, expected) {
    this.send(command);
    const event = await this.next();
    if (!expected.includes(event.event)) refuse(`expected ${expected.join(" or ")}, the adapter wrote ${event.event}`);
    return event;
  }

  /** The node's capability document (§5). */
  async capabilities() {
    const event = await this.#one({ cmd: "capabilities" }, ["capabilities"]);
    return event.capabilities;
  }

  /** `inspect` the binding: {state, outcome} or a rejection {rejected: reason}. */
  async inspect(binding) {
    const event = await this.#one({ cmd: "inspect", binding }, ["inspected", "rejected"]);
    if (event.event === "rejected") return { rejected: event.reason };
    return { state: event.state, outcome: event.outcome ?? null };
  }

  /** `revoke` the binding under `operationId`, from a process that is not driving its run. */
  async revoke(binding, operationId) {
    const event = await this.#one({ cmd: "revoke", operation_id: operationId, binding }, ["verb"]);
    return event.result === "accepted"
      ? { result: "accepted", state: event.state, operation_id: event.operation_id }
      : { result: "rejected", reason: event.reason, operation_id: event.operation_id };
  }

  /**
   * Drive one attempt with a pre-signed envelope: `create`, `admit`, `start`, poll, read the
   * receipt, `seal`. Resolves with every event and the `done` report once the adapter
   * writes it; `onEvent` sees each event as it arrives. Replaying with the same `signed`
   * and `operationIds` after a restart acts on nothing (§6.3).
   */
  async run(signed, { operationIds: ids, taskRoot, pollMs, maxPollMs, graceMs, onEvent } = {}) {
    const command = { cmd: "run", envelope_json: signed.envelope_json, proof: signed.proof };
    if (ids !== undefined) command.operation_ids = { start_at: ids.start_at ?? ids };
    if (pollMs !== undefined) command.poll_ms = pollMs;
    if (maxPollMs !== undefined) command.max_poll_ms = maxPollMs;
    if (graceMs !== undefined) command.grace_ms = graceMs;
    if (taskRoot !== undefined) command.task_root = taskRoot;
    this.send(command);
    const events = [];
    for (;;) {
      const event = await this.next();
      events.push(event);
      if (onEvent) onEvent(event);
      if (event.event === "done") return { events, report: event.report };
    }
  }

  /** Cancel the attempt this adapter is running: the adapter revokes, seals and writes `done`. */
  cancel() {
    if (this.#exit === null) this.#child.kill("SIGTERM");
  }

  /** Close stdin and wait for the adapter to exit; resolves with its exit status. */
  async close() {
    this.#child.stdin.end();
    while (this.#exit === null) {
      const item = await this.#take();
      if (item.error) throw item.error;
    }
    return this.#exit.code ?? 1;
  }
}

// ---------------------------------------------------------------------------------------
// Outcomes (§9, §11.3)
// ---------------------------------------------------------------------------------------

/**
 * Map an attempt report (§11.3) to the outcome a control plane acts on. `outcome` is
 * `completed`, `failed`, `unknown` or `refused`; `certain` is false exactly for `unknown`,
 * which a control plane treats as failed and never as success; `exitStatus` is the
 * workload's exit status when the evidence log recorded one.
 */
export function outcomeOf(report) {
  if (report === null || typeof report !== "object") refuse("a report is an object");
  let outcome;
  let refused;
  if (typeof report.outcome === "string") {
    if (!["completed", "failed", "unknown"].includes(report.outcome)) refuse(`unknown outcome ${report.outcome}`);
    outcome = report.outcome;
  } else if (report.outcome && typeof report.outcome === "object" && report.outcome.refused) {
    outcome = "refused";
    refused = { verb: report.outcome.refused.verb, reason: report.outcome.refused.reason };
  } else {
    refuse("a report's outcome is completed, failed, unknown or {refused}");
  }
  if (report.outcome_certain !== (outcome !== "unknown")) refuse("outcome_certain is false exactly when the outcome is unknown");
  const code = report.cause && typeof report.cause === "object" ? report.cause.Exited?.code : undefined;
  return {
    outcome,
    certain: report.outcome_certain,
    receipt: report.receipt ?? null,
    cause: report.cause ?? null,
    exitStatus: Number.isInteger(code) ? code : undefined,
    finalState: report.final_state ?? null,
    sealed: report.sealed === true,
    cancelled: report.cancelled === true,
    deadlineExceeded: report.deadline_exceeded === true,
    evidenceLog: report.evidence_log ?? null,
    evidenceHead: report.evidence_head ?? null,
    refused,
    transportError: report.transport_error ?? null,
    binding: report.binding,
  };
}
