// A reference control-plane client for `ward-node`, in plain Node.js (>= 22, ESM, no
// dependencies). It is the control-plane side of docs/node-integration.md as a Node.js or
// TypeScript control plane would write it: ids (§7.2), the issuer key and its proof
// (§2.3, §7.4), the admission envelope (§7), the per-task version (§7.3, §10), and the
// JSON-lines conversation with `ward-node-adapter` (§11.4), result return (§6.6), the
// action channel (§6.7), brokered credentials (§6.8), approval holds (§6.9), resource
// limits (§7.5, §9) and waiting out a node at capacity (§8.2). The walk
// through it for an adapter author is docs/node-integration-from-nodejs.md.
//
// Everything here fails closed: an id, hex value, grant or bound outside the contract is
// refused before anything is signed or sent, an `unknown` outcome is never certain, and
// the key never leaves this process.

import { spawn } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { isIP } from "node:net";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { createInterface } from "node:readline";

import { blake3Hex } from "./blake3.mjs";

export { blake3Hex };

/** The one protocol version this client speaks (§4). */
export const PROTOCOL = Object.freeze({ major: 1, minor: 3 });

/** The manifest every workload runs under on a node without `--network-allowlist` (§7.5). */
export const OFFLINE_MANIFEST = Object.freeze({ network: "offline" });

/** Every id prefix of §7.2. */
export const ID_PREFIXES = Object.freeze(["task", "exec", "lease", "agent", "node", "sess", "deleg", "prn"]);

/**
 * What a node honours of an `output` grant (§6.6, §7.5): at most 1 MiB of each stream, 8
 * MiB of file content in all, 64 declared paths of at most 255 bytes. A grant above these
 * is refused `unsupported_grant` by every node, so the client refuses it before signing.
 */
export const OUTPUT_CEILINGS = Object.freeze({ stdioBytes: 1_048_576, filesBytes: 8_388_608, files: 64, pathBytes: 255 });

/**
 * What a node started with `--cgroup-root` honours of a `resources` grant (§7.5): at most
 * 65 536 `pids` on every node, and at most `cpuMillisPerCpu` `cpu_millis` per logical CPU
 * and the host's memory, both as the capability document's `capacity` reports them. A
 * grant above the pid ceiling is refused `unsupported_grant` by every node, so the client
 * refuses it before signing; the other two are held to the node's document.
 */
export const RESOURCE_CEILINGS = Object.freeze({ pids: 65_536, cpuMillisPerCpu: 1000 });

/**
 * How `Adapter.run` paces a capacity wait (§8.2) unless told otherwise: the first wait
 * after a `start` refused `capacity_exhausted` is `firstDelayMs`, each next one twice the
 * last, at most `maxDelayMs`, all within the run's `capacityWaitMs`.
 */
export const CAPACITY_WAIT = Object.freeze({ firstDelayMs: 250, maxDelayMs: 5000 });

/** The kinds of request a workload may send on the action channel (§6.7, ADR-0031). */
export const ACTION_KINDS = Object.freeze(["approval", "decision"]);

/**
 * What a node started with `--action-channel` honours of an `actions` grant (§7.5): at
 * most 8 requests waiting at once, 64 in the attempt's lifetime, 3600 seconds each. A
 * grant above these is refused `unsupported_grant` by every node, so the client refuses it
 * before signing.
 */
export const ACTION_CEILINGS = Object.freeze({ maxPending: 8, maxTotal: 64, waitSecs: 3600 });

/**
 * What the `credentials` grammar bounds (§7.5, ADR-0034 §1): 1 to 4 grants, service names
 * of at most 32 bytes, a `ttl_secs` the node decodes (a u32). Outside these the node fails
 * to decode the envelope, so the client refuses the grant before signing.
 */
export const CREDENTIAL_LIMITS = Object.freeze({ grants: 4, serviceBytes: 32, ttlSecs: 4_294_967_295 });

/**
 * What the `hold` grammar bounds (§6.9, §7.5, ADR-0035): at most 8 held capabilities, each
 * a `network.custom` pattern or a `credentials` service of the same manifest. Outside these
 * the node fails to decode the envelope, so the client refuses the hold before signing.
 */
export const HOLD_LIMITS = Object.freeze({ holds: 8 });

/**
 * The agent adapters a node can host on a workload (node-integration.md §7.3, ADR-0036):
 * Claude Code, the Codex CLI and the generic process adapter. Which of them a node hosts
 * is its capability document's `adapters.hosted`.
 */
export const AGENT_ADAPTERS = Object.freeze(["claude-code", "codex", "process"]);

/** The decisions a control plane may answer; `expired` and `cancelled` are the node's. */
export const ANSWER_DECISIONS = Object.freeze(["approved", "denied"]);

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ID_BODY = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const CAPABILITY = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const RESOURCE = /^[\x21-\x7e]{1,256}$/;
const HOST_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const CREDENTIAL_SERVICE = /^[a-z][a-z0-9-]{0,31}$/;
const ADAPTER_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MANIFEST_FIELDS = Object.freeze(["network", "output", "resources", "actions", "credentials", "hold"]);
// The limits of a `resources` grant, in the order the node's encoder writes them.
const RESOURCE_LIMITS = Object.freeze(["cpu_millis", "memory_bytes", "pids"]);
const OUTPUT_PATH_COMPONENT = /^[A-Za-z0-9._-]+$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const OUTPUT_SKIPS = Object.freeze(["missing", "not_a_regular_file", "too_large"]);
const LIFECYCLE_STATES = Object.freeze(["created", "ready", "running", "paused", "exited", "stopped", "revoked", "sealed"]);
const LIVE_STATES = Object.freeze(["running", "paused"]);
const ENDED_STATES = Object.freeze(["exited", "stopped", "revoked", "sealed"]);
const ACTION_ID = /^[A-Za-z0-9._:-]{1,64}$/;
const MAX_ACTION_SUMMARY_BYTES = 512;
const MAX_ACTION_DETAIL_BYTES = 16384;
const MAX_ACTION_NOTE_BYTES = 512;
const MAX_ACTION_NUMBER = 4_294_967_295;
const HOLD_REQUEST_ID = /^hold:([1-9][0-9]*)$/;
// The reasons `actions` and `answer` are refused with (§6.7); anything else is not this contract.
const ACTIONS_REFUSALS = Object.freeze(["task_not_found", "attempt_mismatch", "lease_mismatch", "unsupported_operation", "resource_unavailable"]);
const ANSWER_REFUSALS = Object.freeze([
  ...ACTIONS_REFUSALS,
  "invalid_state",
  "unknown_request",
  "already_answered",
  "stale_operation",
]);
// Operation ids past the scheme's six verbs: `pause` and `resume` count up from start + 6,
// at most 128 of each per attempt (§6.3), so answers start at start + 6 + 256, one per
// request number (at most 72: the ceiling of `max_total` and the requests a hold opens).
const INTERVENTION_IDS = 256;
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

/** A lowercase DNS name: 1–253 bytes of labels of 1–63 `a-z 0-9 -`, no `-` at either end. */
function isDnsName(name) {
  return name.length <= 253 && name.split(".").every((label) => HOST_LABEL.test(label));
}

/** A `network.custom` pattern: a lowercase DNS name, or `*.` and one. */
function isHostPattern(pattern) {
  return typeof pattern === "string" && isDnsName(pattern.startsWith("*.") ? pattern.slice(2) : pattern);
}

function checkNetwork(network) {
  if (network === "offline") return network;
  if (network === null || typeof network !== "object" || Object.keys(network).join() !== "custom") {
    refuse("manifest `network` is \"offline\" or {\"custom\":[hosts]}");
  }
  const hosts = network.custom;
  if (!Array.isArray(hosts) || hosts.length < 1 || hosts.length > 64) refuse("manifest `network.custom` lists 1 to 64 hosts");
  if (new Set(hosts).size !== hosts.length) refuse("manifest `network.custom` repeats a host");
  for (const host of hosts) {
    if (typeof host !== "string") refuse("a manifest host is a string");
    if (!isHostPattern(host)) {
      refuse(`manifest host ${JSON.stringify(host)} is not a lowercase DNS name or *.name pattern`);
    }
  }
  return { custom: [...hosts] };
}

/**
 * A declared output path (§7.5): 1–255 bytes of `a-z A-Z 0-9 . _ - /`, relative to the
 * workspace, no empty, `.` or `..` component, no leading, trailing or doubled `/`.
 */
function checkOutputPath(path, what) {
  if (typeof path !== "string" || path.length === 0 || Buffer.byteLength(path, "utf8") > OUTPUT_CEILINGS.pathBytes) {
    refuse(`${what} path ${JSON.stringify(path)} is 1 to ${OUTPUT_CEILINGS.pathBytes} bytes`);
  }
  for (const component of path.split("/")) {
    if (component === "" || component === "." || component === ".." || !OUTPUT_PATH_COMPONENT.test(component)) {
      refuse(`${what} path ${JSON.stringify(path)} is not a relative workspace path of a-z A-Z 0-9 . _ - / components without . or ..`);
    }
  }
  return path;
}

function checkOutputPaths(files, what) {
  if (!Array.isArray(files) || files.length > OUTPUT_CEILINGS.files) refuse(`${what} files lists 0 to ${OUTPUT_CEILINGS.files} paths`);
  const paths = files.map((path) => checkOutputPath(path, what));
  if (new Set(paths).size !== paths.length) refuse(`${what} files repeats a path`);
  return paths;
}

function checkOutputBudget(value, name, ceiling) {
  if (!Number.isSafeInteger(value) || value < 0) refuse(`output grant \`${name}\` is an integer >= 0`);
  if (value > ceiling) refuse(`output grant \`${name}\` ${value} is above the ${ceiling} every node refuses as unsupported_grant`);
  return value;
}

function checkOutputGrant(output) {
  if (output === null || typeof output !== "object" || Array.isArray(output)) refuse("manifest `output` is one object");
  const keys = Object.keys(output).sort().join();
  if (keys !== "files,files_bytes,stdio_bytes") refuse("manifest `output` has exactly the fields stdio_bytes, files, files_bytes");
  return {
    stdio_bytes: checkOutputBudget(output.stdio_bytes, "stdio_bytes", OUTPUT_CEILINGS.stdioBytes),
    files: checkOutputPaths(output.files, "output grant"),
    files_bytes: checkOutputBudget(output.files_bytes, "files_bytes", OUTPUT_CEILINGS.filesBytes),
  };
}

/**
 * The §7.5 `output` grant in wire spelling from the control plane's words: the first
 * `stdioBytes` of each of stdout and stderr, the declared `files` with up to `filesBytes`
 * of content in all. Refused outside the grammar or above the node's ceilings.
 */
export function outputGrant({ stdioBytes, files, filesBytes }) {
  return checkOutputGrant({ stdio_bytes: stdioBytes, files, files_bytes: filesBytes });
}

/**
 * The `resources` grant of §7.5 in wire spelling (`cpu_millis`, `memory_bytes`, `pids`, in
 * that order, each only when given), refused outside ward-node-protocol's grammar: one
 * object naming at least one limit and nothing else, each an integer >= 1 (and one that
 * JSON carries exactly here), `pids` within the ceiling every node holds.
 */
function checkResourcesGrant(resources) {
  if (resources === null || typeof resources !== "object" || Array.isArray(resources)) refuse("manifest `resources` is one object");
  const keys = Object.keys(resources);
  if (keys.length === 0 || keys.some((key) => !RESOURCE_LIMITS.includes(key))) {
    refuse("manifest `resources` names at least one of cpu_millis, memory_bytes, pids and nothing else (no limits is no resources field)");
  }
  const grant = {};
  for (const name of RESOURCE_LIMITS) {
    if (!keys.includes(name)) continue;
    const value = resources[name];
    if (!Number.isSafeInteger(value) || value < 1) refuse(`resources grant \`${name}\` is an integer >= 1, got ${JSON.stringify(value)}`);
    grant[name] = value;
  }
  if (grant.pids > RESOURCE_CEILINGS.pids) {
    refuse(`resources grant \`pids\` ${grant.pids} is above the ${RESOURCE_CEILINGS.pids} every node refuses as unsupported_grant`);
  }
  return grant;
}

/**
 * The §7.5 `resources` grant in wire spelling from the control plane's words: the CPU time
 * per second of wall clock in thousandths of one CPU (`cpuMillis`), the memory the
 * attempt's process tree may use, with no swap (`memoryBytes`), and the processes and
 * threads that may exist in it at once (`pids`); each optional, at least one given. An
 * omitted limit is not bounded by the grant. Refused outside the grammar or above the pid
 * ceiling; the node's own ceilings are `requireResourceEnforcement`'s to check.
 */
export function resourcesGrant({ cpuMillis, memoryBytes, pids } = {}) {
  const wire = {};
  if (cpuMillis !== undefined) wire.cpu_millis = cpuMillis;
  if (memoryBytes !== undefined) wire.memory_bytes = memoryBytes;
  if (pids !== undefined) wire.pids = pids;
  return checkResourcesGrant(wire);
}

/**
 * Why the node's capability document (§5) does not enforce `grant`, or `null` when it
 * does: it reports a `resources` section (a node started with `--cgroup-root` does) with
 * `true` for every limit the grant names, and the grant is within the ceilings of its
 * `capacity`.
 */
function resourceRefusal(capabilities, grant) {
  const section = capabilities?.resources;
  if (section === null || typeof section !== "object") {
    return "the node does not advertise resources (a node started with --cgroup-root does)";
  }
  const flags = { cpu_millis: "cpu", memory_bytes: "memory", pids: "pids" };
  for (const name of Object.keys(grant)) {
    if (section[flags[name]] !== true) return `the node does not advertise resources.${flags[name]} true, so it cannot enforce \`${name}\``;
  }
  const cpus = capabilities?.capacity?.logical_cpus;
  const memory = capabilities?.capacity?.memory_bytes;
  if (!Number.isSafeInteger(cpus) || cpus < 1 || !Number.isSafeInteger(memory) || memory < 1) {
    return "the node's capacity does not say how many logical CPUs and how much memory it has, so no limit is within its ceilings";
  }
  const cpuCeiling = cpus * RESOURCE_CEILINGS.cpuMillisPerCpu;
  if (grant.cpu_millis > cpuCeiling) {
    return `cpu_millis ${grant.cpu_millis} is above the ${cpuCeiling} the node honours (${RESOURCE_CEILINGS.cpuMillisPerCpu} per CPU, ${cpus} logical CPUs)`;
  }
  if (grant.memory_bytes > memory) return `memory_bytes ${grant.memory_bytes} is above the ${memory} bytes the node reports in capacity`;
  return null;
}

/**
 * Whether the node's capability document (§5) enforces the `resources` grant `grant`:
 * every limit it names has its flag `true` in the document's `resources` section and is
 * within the ceilings of its `capacity`. A grant outside the grammar is never enforced.
 */
export function enforcesResources(capabilities, grant) {
  try {
    return resourceRefusal(capabilities, checkResourcesGrant(grant)) === null;
  } catch {
    return false;
  }
}

/**
 * The capability document, refused unless it enforces `grant`: any other node refuses the
 * manifest `unsupported_grant` at `admit`, so the client refuses it before signing.
 */
export function requireResourceEnforcement(capabilities, grant) {
  const why = resourceRefusal(capabilities, checkResourcesGrant(grant));
  if (why !== null) refuse(`${why}, and refuses this resources grant as unsupported_grant`);
  return capabilities;
}

function checkActionBound(value, name, ceiling) {
  if (!Number.isSafeInteger(value) || value < 1) refuse(`actions grant \`${name}\` is an integer >= 1`);
  if (value > ceiling) refuse(`actions grant \`${name}\` ${value} is above the ${ceiling} every node refuses as unsupported_grant`);
  return value;
}

/** The `actions` grant of ADR-0031 §2 in wire spelling, refused outside the grammar or above the ceilings. */
function checkActionsGrant(actions) {
  if (actions === null || typeof actions !== "object" || Array.isArray(actions)) refuse("manifest `actions` is one object");
  if (Object.keys(actions).sort().join() !== "kinds,max_pending,max_total,wait_secs") {
    refuse("manifest `actions` has exactly the fields kinds, max_pending, max_total, wait_secs");
  }
  const { kinds } = actions;
  if (!Array.isArray(kinds) || kinds.length < 1 || kinds.length > ACTION_KINDS.length) {
    refuse(`actions grant \`kinds\` lists 1 to ${ACTION_KINDS.length} of ${ACTION_KINDS.join(", ")}`);
  }
  for (const kind of kinds) {
    if (!ACTION_KINDS.includes(kind)) refuse(`actions grant kind ${JSON.stringify(kind)} is not one of ${ACTION_KINDS.join(", ")}`);
  }
  if (new Set(kinds).size !== kinds.length) refuse("actions grant `kinds` repeats a kind");
  const grant = {
    kinds: [...kinds],
    max_pending: checkActionBound(actions.max_pending, "max_pending", ACTION_CEILINGS.maxPending),
    max_total: checkActionBound(actions.max_total, "max_total", ACTION_CEILINGS.maxTotal),
    wait_secs: checkActionBound(actions.wait_secs, "wait_secs", ACTION_CEILINGS.waitSecs),
  };
  if (grant.max_pending > grant.max_total) refuse(`actions grant max_pending ${grant.max_pending} is above max_total ${grant.max_total}`);
  return grant;
}

/**
 * The §7.5 `actions` grant in wire spelling from the control plane's words: the `kinds`
 * the workload may send, at most `maxPending` waiting at once and `maxTotal` in the
 * attempt's lifetime, each answered `expired` after `waitSecs`. Refused outside ADR-0031's
 * grammar or above the node's ceilings (`ACTION_CEILINGS`).
 */
export function actionsGrant({ kinds, maxPending, maxTotal, waitSecs }) {
  return checkActionsGrant({ kinds, max_pending: maxPending, max_total: maxTotal, wait_secs: waitSecs });
}

function checkCredentialGrant(grant) {
  if (grant === null || typeof grant !== "object" || Array.isArray(grant)) refuse("a credential grant is one object {service, host, ttl_secs}");
  if (Object.keys(grant).sort().join() !== "host,service,ttl_secs") {
    refuse("a credential grant has exactly the fields service, host, ttl_secs: never a provider, header or secret");
  }
  const { service, host, ttl_secs: ttlSecs } = grant;
  if (typeof service !== "string" || !CREDENTIAL_SERVICE.test(service)) {
    refuse(`credential service ${JSON.stringify(service)} is not [a-z][a-z0-9-]{0,31}`);
  }
  if (typeof host !== "string" || !isDnsName(host) || isIP(host) !== 0) {
    refuse(`credential host ${JSON.stringify(host)} is not a lowercase DNS name (no wildcard, no address literal)`);
  }
  if (!Number.isSafeInteger(ttlSecs) || ttlSecs < 1 || ttlSecs > CREDENTIAL_LIMITS.ttlSecs) {
    refuse(`credential grant \`ttl_secs\` is an integer from 1 to ${CREDENTIAL_LIMITS.ttlSecs}, got ${JSON.stringify(ttlSecs)}`);
  }
  return { service, host, ttl_secs: ttlSecs };
}

/** Whether a `network.custom` pattern covers `host`: a name itself, `*.name` any deeper name, never the name. */
function covers(network, host) {
  if (network === "offline") return false;
  return network.custom.some((pattern) =>
    pattern.startsWith("*.") ? host.endsWith(pattern.slice(1)) && host.length > pattern.length - 1 : pattern === host,
  );
}

/**
 * The `credentials` grant of ADR-0034 §1 in wire spelling, refused outside the grammar and,
 * given the manifest's checked `network`, for a host its `network.custom` does not cover.
 */
function checkCredentialsGrant(credentials, network) {
  if (!Array.isArray(credentials) || credentials.length < 1 || credentials.length > CREDENTIAL_LIMITS.grants) {
    refuse(`manifest \`credentials\` lists 1 to ${CREDENTIAL_LIMITS.grants} grants`);
  }
  const grants = credentials.map(checkCredentialGrant);
  grants.forEach((grant, index) => {
    if (grants.slice(0, index).some((earlier) => earlier.service === grant.service)) {
      refuse(`manifest \`credentials\` names the service \`${grant.service}\` twice`);
    }
  });
  if (network !== undefined) {
    for (const { host } of grants) {
      if (!covers(network, host)) {
        refuse(`credential host ${JSON.stringify(host)} is not covered by the manifest's network.custom: a credential is granted only for a host the attempt may reach`);
      }
    }
  }
  return grants;
}

/**
 * The §7.5 `credentials` grant in wire spelling from the control plane's words: for each
 * entry, the operator's `service`, injected by the node's proxy into requests for `host`
 * only, under a lease of at most `ttlSecs`. Refused outside ADR-0034's grammar; the
 * manifest that carries it is refused unless its `network.custom` covers every host.
 */
export function credentialsGrant(grants) {
  const wire = Array.isArray(grants)
    ? grants.map((grant) => (grant === null || typeof grant !== "object" ? grant : { service: grant.service, host: grant.host, ttl_secs: grant.ttlSecs }))
    : grants;
  return checkCredentialsGrant(wire);
}

/**
 * Whether the node's capability document (§5) offers the credential broker: both
 * `credentials.proxy_injection` and `credentials.scoped_http_gateway` are `true`, which a
 * node started with `--network-allowlist` and `--credentials` reports.
 */
export function brokersCredentials(capabilities) {
  const credentials = capabilities?.credentials;
  return credentials?.proxy_injection === true && credentials?.scoped_http_gateway === true;
}

/**
 * The capability document, refused unless it offers the credential broker: any other node
 * refuses a `credentials` grant `unsupported_grant`, so the client refuses it before signing.
 */
export function requireCredentialBroker(capabilities) {
  if (!brokersCredentials(capabilities)) {
    refuse(
      "the node does not advertise credentials.proxy_injection and credentials.scoped_http_gateway " +
        "(a node started with --network-allowlist and --credentials does) and refuses a credentials grant as unsupported_grant",
    );
  }
  return capabilities;
}

/**
 * The `hold` of ADR-0035 in wire spelling (`hosts` first, then `services`, each only when
 * non-empty), refused outside the grammar and, given the rest of the checked manifest
 * (`canonical`), for a host that is not one of its `network.custom` patterns, a service
 * that is not one of its `credentials`, or a manifest whose `actions` grant does not name
 * `approval` (the node asks through it).
 */
function checkHold(hold, canonical) {
  if (hold === null || typeof hold !== "object" || Array.isArray(hold)) refuse("manifest `hold` is one object {hosts?, services?}");
  const keys = Object.keys(hold);
  if (keys.length === 0 || keys.some((key) => key !== "hosts" && key !== "services")) {
    refuse("manifest `hold` has the fields hosts and services, at least one, nothing else");
  }
  const list = (name, valid, what) => {
    if (!keys.includes(name)) return [];
    const entries = hold[name];
    if (!Array.isArray(entries) || entries.length === 0) refuse(`hold \`${name}\` is a non-empty list`);
    for (const entry of entries) if (!valid(entry)) refuse(`held ${what} ${JSON.stringify(entry)} is not ${what === "host" ? "a lowercase DNS name or *.name pattern" : "[a-z][a-z0-9-]{0,31}"}`);
    if (new Set(entries).size !== entries.length) refuse(`hold \`${name}\` repeats a ${what}`);
    return [...entries];
  };
  const hosts = list("hosts", isHostPattern, "host");
  const services = list("services", (service) => typeof service === "string" && CREDENTIAL_SERVICE.test(service), "service");
  if (hosts.length + services.length > HOLD_LIMITS.holds) refuse(`a hold names at most ${HOLD_LIMITS.holds} capabilities`);
  if (canonical !== undefined) {
    const custom = canonical.network === "offline" ? [] : canonical.network.custom;
    for (const host of hosts) {
      if (!custom.includes(host)) refuse(`held host ${JSON.stringify(host)} is not one of the manifest's network.custom patterns: a hold names a capability the manifest grants`);
    }
    for (const service of services) {
      if (!(canonical.credentials ?? []).some((grant) => grant.service === service)) {
        refuse(`held service ${JSON.stringify(service)} is not one of the manifest's credentials: a hold names a capability the manifest grants`);
      }
    }
    if (!canonical.actions?.kinds.includes("approval")) {
      refuse("a hold needs an actions grant naming approval: the node asks for each held capability through the action channel");
    }
  }
  return { ...(hosts.length > 0 ? { hosts } : {}), ...(services.length > 0 ? { services } : {}) };
}

/**
 * The §7.5 `hold` in wire spelling from the control plane's words: the `hosts` (patterns
 * of the manifest's `network.custom`) and `services` (of its `credentials`) the node holds
 * until the control plane approves the request it opens for each on first use (ADR-0035).
 * Refused outside the grammar; the manifest that carries it is refused unless it grants
 * every one and an `actions` grant naming `approval`.
 */
export function holdGrant({ hosts = [], services = [] } = {}) {
  const wire = {};
  if (!Array.isArray(hosts) || hosts.length > 0) wire.hosts = hosts;
  if (!Array.isArray(services) || services.length > 0) wire.services = services;
  return checkHold(wire);
}

/**
 * The capabilities a checked `hold` names, in the order the node numbers its requests:
 * hosts first, then services, each `{host}` or `{service}` as the listing's `hold` field
 * spells it, with the id the node opens its request under (`hold:1`, `hold:2`, …) and the
 * summary it asks with.
 */
export function heldCapabilities(hold) {
  const checked = checkHold(hold);
  return [
    ...(checked.hosts ?? []).map((host) => ({ capability: { host }, summary: `network ${host}` })),
    ...(checked.services ?? []).map((service) => ({ capability: { service }, summary: `credential ${service}` })),
  ].map((entry, index) => ({ id: `hold:${index + 1}`, ...entry }));
}

/**
 * Whether the node's capability document (§5) offers approval holds: its `actions` section
 * carries `hold: true`, which a node started with --network-allowlist, --action-channel and
 * --approval-hold reports.
 */
export function offersApprovalHold(capabilities) {
  return capabilities?.actions?.hold === true;
}

/**
 * The capability document, refused unless it offers approval holds: any other node refuses
 * a manifest with a `hold` `unsupported_grant`, so the client refuses it before signing.
 */
export function requireApprovalHold(capabilities) {
  if (!offersApprovalHold(capabilities)) {
    refuse(
      "the node does not advertise actions.hold (a node started with --network-allowlist, --action-channel and " +
        "--approval-hold does) and refuses a manifest with a hold as unsupported_grant",
    );
  }
  return capabilities;
}

/** The manifest in canonical key order, refusing anything outside the §7.5 grammar. */
function checkManifest(object) {
  if (object === null || typeof object !== "object" || Array.isArray(object)) refuse("a manifest is one JSON object");
  const keys = Object.keys(object);
  if (!keys.includes("network") || keys.some((key) => !MANIFEST_FIELDS.includes(key))) {
    refuse("a manifest has the field `network` and optionally `output`, `resources`, `actions`, `credentials` and `hold`, nothing else");
  }
  const canonical = { network: checkNetwork(object.network) };
  if (keys.includes("output")) canonical.output = checkOutputGrant(object.output);
  if (keys.includes("resources")) canonical.resources = checkResourcesGrant(object.resources);
  if (keys.includes("actions")) canonical.actions = checkActionsGrant(object.actions);
  if (keys.includes("credentials")) canonical.credentials = checkCredentialsGrant(object.credentials, canonical.network);
  if (keys.includes("hold")) canonical.hold = checkHold(object.hold, canonical);
  return canonical;
}

/**
 * The manifest as the envelope carries it: hex bytes as sent and their BLAKE3-256 (§7.3).
 * The bytes are compact JSON with `network` first, then `output`, `resources`, `actions`,
 * `credentials` and `hold` when granted, whatever order the caller wrote the fields in, so one grant has
 * one signed spelling.
 */
export function manifest(object = OFFLINE_MANIFEST) {
  const bytes = Buffer.from(JSON.stringify(checkManifest(object)), "utf8");
  if (bytes.length > MAX_MANIFEST_BYTES) refuse(`a manifest is at most ${MAX_MANIFEST_BYTES} bytes`);
  return { hash: blake3Hex(bytes), bytes: bytes.toString("hex") };
}

/**
 * The `output` grant a signed envelope's manifest carries (wire spelling), or `null`
 * without one: what a run of it must return. Takes the serialised envelope (`envelope_json`
 * of a signed run or a run record) and reads the manifest from its exact bytes.
 */
export function outputGrantOf(envelopeJson) {
  return manifestOf(envelopeJson).output ?? null;
}

/**
 * The `resources` grant a signed envelope's manifest carries (wire spelling), or `null`
 * without one: the limits a run of it was admitted under.
 */
export function resourcesGrantOf(envelopeJson) {
  return manifestOf(envelopeJson).resources ?? null;
}

/**
 * The `actions` grant a signed envelope's manifest carries (wire spelling), or `null`
 * without one: the channel a run of it has, and what its listings are held to.
 */
export function actionsGrantOf(envelopeJson) {
  return manifestOf(envelopeJson).actions ?? null;
}

/**
 * The `credentials` grant a signed envelope's manifest carries (wire spelling), or `null`
 * without one: the services a run of it is leased, in the order granted.
 */
export function credentialsGrantOf(envelopeJson) {
  return manifestOf(envelopeJson).credentials ?? null;
}

/**
 * The `hold` a signed envelope's manifest carries (wire spelling), or `null` without one:
 * the capabilities the node holds for a run of it, and what its listings are held to.
 */
export function holdGrantOf(envelopeJson) {
  return manifestOf(envelopeJson).hold ?? null;
}

/** The checked manifest of a serialised envelope, read from its exact bytes. */
function manifestOf(envelopeJson) {
  if (typeof envelopeJson !== "string") refuse("envelope_json is the serialised envelope");
  let envelope;
  try {
    envelope = JSON.parse(envelopeJson);
  } catch {
    refuse("envelope_json is not JSON");
  }
  const hex = envelope?.workload?.capability_manifest?.bytes;
  if (typeof hex !== "string" || !/^(?:[0-9a-f]{2})+$/.test(hex)) refuse("the envelope carries no manifest bytes");
  let object;
  try {
    object = JSON.parse(Buffer.from(hex, "hex").toString("utf8"));
  } catch {
    refuse("the envelope's manifest is not JSON");
  }
  return checkManifest(object);
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

/**
 * The adapter a workload names, in wire spelling (`{"id": …}`), refused outside the §7.3
 * grammar: an id of 1 to 64 bytes of lowercase letters, digits, `.`, `_` and `-`, starting
 * with a letter or digit, and an `argv[0]` the adapter can launch (a name on the sandbox
 * PATH or an absolute path, never a relative path with a `/`).
 */
export function workloadAdapter(id, argv) {
  if (typeof id !== "string" || !ADAPTER_ID.test(id)) {
    refuse("an agent adapter id is 1 to 64 bytes of a-z 0-9 . _ -, starting with a letter or digit (claude-code, codex, process)");
  }
  const program = Array.isArray(argv) ? argv[0] : undefined;
  if (typeof program !== "string" || (program.includes("/") && !program.startsWith("/"))) {
    refuse("a workload naming an agent adapter runs argv[0] as a name on the sandbox PATH or an absolute path");
  }
  return { id };
}

/**
 * Whether the node's capability document (§5) hosts the agent adapter `id`: its `adapters`
 * section lists it, which a node started with `--agent-adapter <id>` reports.
 */
export function hostsAgentAdapter(capabilities, id) {
  const hosted = capabilities?.adapters?.hosted;
  return Array.isArray(hosted) && hosted.includes(id);
}

/**
 * The capability document, refused unless it hosts the agent adapter `id`: any other node
 * refuses a workload naming it `unsupported_grant`, so the client refuses it before signing.
 */
export function requireAgentAdapter(capabilities, id) {
  if (!hostsAgentAdapter(capabilities, id)) {
    refuse(
      `the node does not list ${id} in adapters.hosted (a node started with --agent-adapter ${id} does) ` +
        "and refuses a workload naming it as unsupported_grant",
    );
  }
  return capabilities;
}

/**
 * The agent adapter a signed envelope's workload names, or `null` for a plain workload:
 * what a run of it was launched as.
 */
export function agentAdapterOf(envelopeJson) {
  if (typeof envelopeJson !== "string") refuse("envelope_json is the serialised envelope");
  let envelope;
  try {
    envelope = JSON.parse(envelopeJson);
  } catch {
    refuse("envelope_json is not JSON");
  }
  const adapter = envelope?.workload?.adapter;
  return adapter === undefined ? null : workloadAdapter(adapter?.id, envelope.workload.argv).id;
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
 * {argv, manifest (object, default offline), snapshot, wallClockBudgetMs, adapter (an agent
 * adapter id, default none)}, issuedAtUnixMs, expiresAtUnixMs and version. Every bound of
 * §7.3 is checked here, before signing; `adapter` is spelled last in the workload, and not
 * at all without one.
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
  const adapter = workload.adapter === undefined || workload.adapter === null ? null : workloadAdapter(workload.adapter, argv);
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
      ...(adapter === null ? {} : { adapter }),
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

/**
 * The operation-id scheme of §11.2 shifted to start at `startAt`: `create` to `seal` are
 * `startAt` to `startAt + 5`, `pause` and `resume` count up from `startAt + 6` (at most 128
 * of each, §6.3), and `first_answer` (`startAt + 262`) is the id of the answer to request 1
 * of the action channel, `answerOperationId` the one for request N.
 */
export function operationIds(startAt = 1) {
  if (!Number.isSafeInteger(startAt) || startAt < 1) refuse("operation ids start at an integer >= 1");
  return {
    start_at: startAt,
    create: startAt,
    admit: startAt + 1,
    start: startAt + 2,
    stop: startAt + 3,
    revoke: startAt + 4,
    seal: startAt + 5,
    first_answer: startAt + 6 + INTERVENTION_IDS,
  };
}

/**
 * The operation id of the answer to the node's request number `request` (1 to 72: the
 * workload's 64 at most and the 8 a hold may open) under a scheme (`operationIds(N)` or a
 * run record's `{start_at: N}`): one id per request, so a replay of an answer is the same
 * operation and the node applies it at most once (§6.7).
 */
export function answerOperationId(ids, request) {
  const startAt = ids?.start_at;
  if (!Number.isSafeInteger(startAt) || startAt < 1) refuse("an operation-id scheme has start_at, an integer >= 1");
  const last = ACTION_CEILINGS.maxTotal + HOLD_LIMITS.holds;
  if (!Number.isSafeInteger(request) || request < 1 || request > last) {
    refuse(`a request number is an integer from 1 to ${last}, got ${JSON.stringify(request)}`);
  }
  return operationIds(startAt).first_answer + request - 1;
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
  if (record.answers !== undefined && !Array.isArray(record.answers)) refuse(`the run record of ${attempt} holds answers that are not a list`);
  return record;
}

function checkNote(note) {
  if (note === undefined || note === null) return undefined;
  if (typeof note !== "string" || Buffer.byteLength(note, "utf8") > MAX_ACTION_NOTE_BYTES) {
    refuse(`an answer's note is a string of at most ${MAX_ACTION_NOTE_BYTES} bytes`);
  }
  return note;
}

function checkDecision(decision) {
  if (!ANSWER_DECISIONS.includes(decision)) refuse(`an answer's decision is approved or denied, got ${JSON.stringify(decision)}`);
  return decision;
}

/**
 * Record an answer to the node's request number `request` in the run record of `attempt`
 * under `dir`, durably, before it is sent: {request, id, kind, decision, note?,
 * operation_id}, where `operation_id` must be the scheme's id for the request
 * (`answerOperationId`). A request already answered in the record keeps its first answer:
 * that one is returned and nothing is written, so a restarted control plane sends the
 * answer it recorded, under the same id, and never a second one.
 */
export function recordAnswer(dir, attempt, { request, id, kind, decision, note, operation_id: operationId }) {
  const record = loadRunRecord(dir, attempt);
  const recorded = (record.answers ?? []).find((answer) => answer.request === request);
  if (recorded) return recorded;
  checkDecision(decision);
  const expected = answerOperationId(record.operation_ids, request);
  if (operationId !== expected) refuse(`the answer to request ${request} takes operation id ${expected} of the record's scheme, not ${operationId}`);
  const entry = { request };
  if (id !== undefined) entry.id = id;
  if (kind !== undefined) entry.kind = kind;
  entry.decision = decision;
  if (checkNote(note) !== undefined) entry.note = note;
  entry.operation_id = operationId;
  const { format, ...rest } = record;
  void format;
  saveRunRecord(dir, { ...rest, answers: [...(record.answers ?? []), entry] });
  return entry;
}

// ---------------------------------------------------------------------------------------
// The adapter conversation (§11.4)
// ---------------------------------------------------------------------------------------

const SPKI_PIN = /^sha256:[0-9a-f]{64}$/;
const TLS_FIELDS = [
  ["address", "--connect-tls"],
  ["cert", "--tls-cert"],
  ["key", "--tls-key"],
  ["serverCa", "--tls-server-ca"],
  ["serverName", "--tls-server-name"],
];

/**
 * The adapter's flags for the node it speaks to: `--socket <path>` for the node's Unix
 * socket, or, for a node serving `--listen-tls` (§3, ADR-0038), `--connect-tls` with this
 * client's certificate and key, the server CA, the name the node's certificate must carry
 * and optionally the node's pinned key (`sha256:` and 64 lowercase hex digits). Never both.
 */
export function adapterNodeArgs({ socket, tls }) {
  if (socket !== undefined && tls !== undefined) refuse("the adapter takes the node's socket or its TLS settings, not both");
  if (tls === undefined) {
    if (typeof socket !== "string" || socket.length === 0) refuse("the adapter needs the node's socket path or its TLS settings");
    return ["--socket", socket];
  }
  if (tls === null || typeof tls !== "object") refuse("the TLS settings are an object");
  const args = [];
  for (const [field, flag] of TLS_FIELDS) {
    const value = tls[field];
    if (typeof value !== "string" || value.length === 0) refuse(`the TLS settings need ${field} (${flag})`);
    args.push(flag, value);
  }
  if (tls.serverPin !== undefined) {
    if (typeof tls.serverPin !== "string" || !SPKI_PIN.test(tls.serverPin)) refuse("serverPin is sha256: and 64 lowercase hex digits");
    args.push("--tls-server-pin", tls.serverPin);
  }
  return args;
}

/**
 * Whether an attempt report (§11.3) is a `start` the node refused `capacity_exhausted`
 * (§8.2): the task is still `ready` and its admission valid, so the same `start` (the same
 * run, with the same operation ids) may be sent again once the node has room.
 */
export function capacityExhausted(report) {
  const refused = report?.outcome?.refused;
  return refused?.verb === "start" && refused?.reason === "capacity_exhausted";
}

/**
 * One `ward-node-adapter` process: JSON commands in, JSON events out, one per line. The
 * adapter is spawned the way any external tool is, with `--socket` (or `--connect-tls` and
 * its files, see `adapterNodeArgs`) on its command line; `command` is the executable and
 * any leading arguments (default `["ward-node-adapter"]`). Cancellation is a signal:
 * `cancel()` sends SIGTERM, which the adapter answers by revoking and sealing the running
 * attempt and writing its `done` (§11.4).
 */
export class Adapter {
  #child;
  #lines = [];
  #waiters = [];
  #exit = null;
  #trace;
  #waiting = false;
  #cancelRequested = false;
  #wake = null;

  constructor({ command = ["ward-node-adapter"], socket, tls, timeoutMs, connectTimeoutMs, env = process.env, trace = null }) {
    const [executable, ...leading] = command;
    const args = [...leading, ...adapterNodeArgs({ socket, tls })];
    if (timeoutMs !== undefined) args.push("--timeout-ms", String(timeoutMs));
    if (connectTimeoutMs !== undefined) args.push("--connect-timeout-ms", String(connectTimeoutMs));
    this.#trace = trace;
    this.#child = spawn(executable, args, { stdio: ["pipe", "pipe", "inherit"], env });
    this.#child.on("error", (error) => this.#push({ error }));
    // A write to an adapter that has exited fails with EPIPE; its exit is reported as `eof`.
    this.#child.stdin.on("error", () => {});
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
   * `result` for the binding (§6.6), for a run driven elsewhere or read again later:
   * {state, output} with the output decoded and every digest verified (`decodeOutput`),
   * or a rejection {rejected: reason}. A `run` under an `output` grant needs no `result`
   * of its own: the adapter reads it after `seal` and `done` carries it.
   */
  async result(binding) {
    const event = await this.#one({ cmd: "result", binding }, ["result", "rejected"]);
    if (event.event === "rejected") return { rejected: event.reason };
    return { state: event.state, output: decodeOutput(event.output) };
  }

  /**
   * Drive one attempt with a pre-signed envelope: `create`, `admit`, `start`, poll, read the
   * receipt, `seal`. Resolves with every event, the `done` report once the adapter writes
   * it, and `capacityWaits`; `onEvent` sees each event as it arrives. Replaying with the
   * same `signed` and `operationIds` after a restart acts on nothing (§6.3).
   *
   * With `capacityWaitMs` (default 0: none), a `start` the node refuses `capacity_exhausted`
   * (§8.2, `capacityExhausted`) is not the end: the task is still `ready`, so the same `run`
   * command (the same signed bytes, proof and operation ids, hence the same `start`) is sent
   * again after `capacityDelayMs` (default `CAPACITY_WAIT.firstDelayMs`), each wait twice
   * the last up to `capacityMaxDelayMs`, until the node starts it or `capacityWaitMs` is
   * spent; nothing is re-signed and no version is allocated. Before each wait the node's
   * `scheduling` (§5) is read, and the wait {retry, operation_id, delay_ms, scheduling} is
   * listed in `capacityWaits` and passed to `onCapacityWait`. Once the wait is spent the
   * last report, the refusal, is the result. A `cancel()` while waiting revokes the ready
   * attempt under the scheme's `revoke` id and sends the run once more, which replays
   * `create` and `admit`, sends no `start` and seals it; that report is the result, with
   * `cancelled` true and every operation of both runs and the revoke in `operations`.
   */
  async run(signed, options = {}) {
    const { operationIds: ids, taskRoot, pollMs, maxPollMs, graceMs, onEvent, onCapacityWait } = options;
    const {
      capacityWaitMs = 0,
      capacityDelayMs = CAPACITY_WAIT.firstDelayMs,
      capacityMaxDelayMs = CAPACITY_WAIT.maxDelayMs,
    } = options;
    if (!Number.isSafeInteger(capacityWaitMs) || capacityWaitMs < 0) refuse("capacityWaitMs is an integer >= 0");
    for (const [name, value] of [["capacityDelayMs", capacityDelayMs], ["capacityMaxDelayMs", capacityMaxDelayMs]]) {
      if (!Number.isSafeInteger(value) || value < 1) refuse(`${name}, a capacity wait's delay, is an integer >= 1`);
    }
    const command = { cmd: "run", envelope_json: signed.envelope_json, proof: signed.proof };
    if (ids !== undefined) command.operation_ids = { start_at: ids.start_at ?? ids };
    if (pollMs !== undefined) command.poll_ms = pollMs;
    if (maxPollMs !== undefined) command.max_poll_ms = maxPollMs;
    if (graceMs !== undefined) command.grace_ms = graceMs;
    if (taskRoot !== undefined) command.task_root = taskRoot;
    const deadline = Date.now() + capacityWaitMs;
    const events = [];
    const capacityWaits = [];
    let delay = capacityDelayMs;
    this.#cancelRequested = false;
    for (;;) {
      const report = await this.#runOnce(command, events, onEvent);
      const remaining = deadline - Date.now();
      if (!capacityExhausted(report) || this.#cancelRequested || remaining <= 0) return { events, report, capacityWaits };
      // Idle between runs: a cancel now revokes through this adapter instead of signalling it.
      this.#waiting = true;
      try {
        const capabilities = await this.capabilities();
        const start = report.operations?.find((operation) => operation.verb === "start");
        const wait = {
          retry: capacityWaits.length + 1,
          operation_id: start?.operation_id ?? null,
          delay_ms: Math.min(delay, remaining),
          scheduling: capabilities?.scheduling ?? null,
        };
        capacityWaits.push(wait);
        if (onCapacityWait) onCapacityWait(wait);
        await this.#idle(wait.delay_ms);
        if (this.#cancelRequested) {
          return { events, report: await this.#cancelReady(report, command, events, onEvent), capacityWaits };
        }
      } finally {
        this.#waiting = false;
      }
      delay = Math.min(delay * 2, capacityMaxDelayMs);
    }
  }

  /** Send one `run` command and collect its events to `done`. */
  async #runOnce(command, events, onEvent) {
    this.send(command);
    for (;;) {
      const event = await this.next();
      events.push(event);
      if (onEvent) onEvent(event);
      if (event.event === "done") return event.report;
    }
  }

  /** Wait `ms`, or less when `cancel()` is called meanwhile (or was already). */
  #idle(ms) {
    if (this.#cancelRequested) return Promise.resolve();
    return new Promise((resolve) => {
      const timer = setTimeout(done, ms);
      function done() {
        clearTimeout(timer);
        resolve();
      }
      this.#wake = done;
    }).finally(() => {
      this.#wake = null;
    });
  }

  /**
   * End an attempt left `ready` by a capacity refusal when its run is cancelled: `revoke`
   * under the scheme's id, so nothing starts it later, then the same run once more, which
   * finds it revoked, sends no `start`, reads the receipt and seals.
   */
  async #cancelReady(refused, command, events, onEvent) {
    const revokeId = operationIds(command.operation_ids?.start_at ?? 1).revoke;
    const revoked = await this.revoke(refused.binding, revokeId);
    const sealed = await this.#runOnce(command, events, onEvent);
    return {
      ...sealed,
      cancelled: true,
      operations: [
        ...(refused.operations ?? []),
        { verb: "revoke", operation_id: revokeId, state: revoked.state ?? null, reason: revoked.reason ?? null },
        ...(sealed.operations ?? []),
      ],
    };
  }

  /**
   * `actions` for the binding (§6.7): {state, pending} with every pending request held to
   * the contract (`decodeActions`), oldest first, or a rejection {rejected: reason}. Read-only
   * and without an operation id; ask it from an adapter that is not running the attempt.
   */
  async actions(binding) {
    checkBinding(binding);
    const event = await this.#one({ cmd: "actions", binding }, ["actions", "rejected"]);
    if (event.event === "rejected") return { rejected: checkRefusal(event, "actions", null, ACTIONS_REFUSALS) };
    return decodeActions({ state: event.state, pending: event.pending });
  }

  /**
   * `answer` the node's request number `request` of the binding (§6.7) with `decision`
   * (`approved` or `denied`) under `operationId`, with an optional `note` (at most 512
   * bytes) relayed to the workload. Resolves with {result: "answered", request, decision,
   * operation_id}, or {result: "rejected", reason, operation_id} with one of the §6.7
   * reasons (`already_answered`, `unknown_request`, `invalid_state`, `stale_operation`,
   * `resource_unavailable`, …). Replaying the same id with the same answer is answered
   * again and applies nothing (take the id from `answerOperationId`). An answer that names
   * another request, decision or operation id than the one sent is refused.
   */
  async answer(binding, request, decision, operationId, note) {
    checkBinding(binding);
    if (!Number.isSafeInteger(request) || request < 1 || request > MAX_ACTION_NUMBER) {
      refuse(`the request number is an integer from 1 to ${MAX_ACTION_NUMBER}, got ${JSON.stringify(request)}`);
    }
    checkDecision(decision);
    if (!Number.isSafeInteger(operationId) || operationId < 1) refuse(`an answer's operation id is an integer >= 1, got ${JSON.stringify(operationId)}`);
    const command = { cmd: "answer", binding, request, decision, operation_id: operationId };
    if (checkNote(note) !== undefined) command.note = note;
    const event = await this.#one(command, ["answered", "rejected"]);
    if (event.event === "rejected") {
      return { result: "rejected", reason: checkRefusal(event, "answer", operationId, ANSWER_REFUSALS), operation_id: operationId };
    }
    if (event.operation_id !== operationId) refuse(`the adapter answered operation ${event.operation_id}, not ${operationId}`);
    if (event.request !== request) refuse(`the adapter answered request ${event.request}, not request ${request}`);
    if (event.decision !== decision) refuse(`the adapter answered decision ${event.decision}, not ${decision}`);
    return { result: "answered", request, decision, operation_id: operationId };
  }

  /**
   * Answer the binding's action-channel requests by `policy` until the attempt ends: poll
   * `actions` every `pollMs` (default 250), and for each pending request not yet answered
   * ask `policy(request, {signal})` once, which returns `"approved"`, `"denied"`,
   * `{decision, note}`, or `null` to leave the request to someone else (it then expires).
   * A request the node opened for a held capability (§6.9) carries `hold` ({host} or
   * {service}); approving it is what lets the workload's proxy traffic for that capability
   * through. Run it on a second adapter while the first one's `run` blocks (§11.4).
   *
   * With `runDir` (the directory of `saveRunRecord`) the answers take their operation ids
   * from the record's scheme (`answerOperationId`) and each is written to the record
   * (`recordAnswer`) before it is sent; a request the record already answered is sent that
   * answer again, under the same id, and the policy is not asked. So a control plane that
   * restarts mid-answer replays rather than answers twice. Without `runDir`, `operationIds`
   * gives the scheme and answers live in memory only.
   *
   * Refusals: `resource_unavailable` is retried at the next poll with the same id and
   * answer; `already_answered` (expired, cancelled or answered elsewhere), `stale_operation`,
   * `unknown_request` and `invalid_state` are final for the request. Before the attempt
   * exists (`task_not_found`, `attempt_mismatch` until the run's `create`) the loop waits;
   * a listing outside the contract or the record's grant and hold (or `grant` and `hold`
   * when given), or a node that cannot serve the
   * channel, is refused. Resolves with {state, answers} once a listing reads an ended state
   * (`exited`, `stopped`, `revoked`, `sealed`), or with state `null` when `signal` aborts;
   * `answers` holds every answer sent and how the node took it, also reported to
   * `onAnswer`, and each request is reported to `onRequest` when first seen.
   */
  async answerLoop(binding, policy, { pollMs = 250, signal, runDir, operationIds: ids, grant, hold, onRequest, onAnswer } = {}) {
    checkBinding(binding);
    if (typeof policy !== "function") refuse("the answer policy is a function");
    if (!Number.isSafeInteger(pollMs) || pollMs < 1) refuse("pollMs is an integer >= 1");
    let scheme = ids;
    let held = grant ?? null;
    let holding = hold ?? null;
    if (runDir !== undefined) {
      const record = loadRunRecord(runDir, binding.attempt);
      if (["task", "attempt", "lease"].some((key) => record.binding?.[key] !== binding[key])) refuse("the run record is not this binding's");
      scheme = record.operation_ids;
      if (grant === undefined) held = actionsGrantOf(record.envelope_json);
      if (hold === undefined) holding = holdGrantOf(record.envelope_json);
    } else if (scheme === undefined) {
      refuse("the answer loop needs runDir or operationIds: its answers take their operation ids from a scheme");
    }
    if (held !== null) held = checkActionsGrant(held);
    answerOperationId(scheme, 1); // refuses a scheme without a valid start_at before anything is sent
    const inMemory = new Map();
    const recorded = (request) =>
      runDir !== undefined ? (loadRunRecord(runDir, binding.attempt).answers ?? []).find((answer) => answer.request === request) : inMemory.get(request);
    const settled = new Set();
    const seen = new Set();
    const answers = [];
    let exists = false;
    while (!signal?.aborted) {
      const listed = await this.actions(binding);
      if (listed.rejected !== undefined) {
        const absent = listed.rejected === "task_not_found" || listed.rejected === "attempt_mismatch";
        if (absent && exists) return { state: null, answers };
        if (!absent && listed.rejected !== "resource_unavailable") refuse(`the node refused actions: ${listed.rejected}`);
        await pause(pollMs, signal);
        continue;
      }
      exists = true;
      const listing = decodeActions(listed, held, holding);
      if (ENDED_STATES.includes(listing.state)) return { state: listing.state, answers };
      for (const request of listing.pending) {
        if (signal?.aborted) break;
        if (settled.has(request.action)) continue;
        if (!seen.has(request.action)) {
          seen.add(request.action);
          if (onRequest) onRequest(request);
        }
        let entry = recorded(request.action);
        const replayed = entry !== undefined;
        if (replayed && entry.id !== undefined && entry.id !== request.id) {
          refuse(`request ${request.action} is ${request.id} on the node but ${entry.id} in the record; refusing to answer it`);
        }
        if (!replayed) {
          const verdict = verdictOf(await policy(request, { signal }));
          if (signal?.aborted) break;
          if (verdict === null) {
            settled.add(request.action);
            continue;
          }
          const candidate = { request: request.action, id: request.id, kind: request.kind, ...verdict, operation_id: answerOperationId(scheme, request.action) };
          if (runDir !== undefined) {
            entry = recordAnswer(runDir, binding.attempt, candidate);
          } else {
            entry = candidate;
            inMemory.set(request.action, entry);
          }
        }
        const answered = await this.answer(binding, entry.request, entry.decision, entry.operation_id, entry.note);
        const outcome = {
          request: request.action,
          id: request.id,
          kind: request.kind,
          ...(request.hold === undefined ? {} : { hold: request.hold }),
          summary: request.summary,
          decision: entry.decision,
          ...(entry.note === undefined ? {} : { note: entry.note }),
          operation_id: entry.operation_id,
          result: answered.result,
          ...(answered.reason === undefined ? {} : { reason: answered.reason }),
          replayed,
        };
        answers.push(outcome);
        if (onAnswer) onAnswer(outcome);
        if (answered.reason !== "resource_unavailable") settled.add(request.action);
      }
      await pause(pollMs, signal);
    }
    return { state: null, answers };
  }

  /**
   * Cancel the attempt this adapter is running: the adapter revokes, seals and writes
   * `done`. While `run` waits out a capacity refusal the adapter is idle and is not
   * signalled (an idle adapter exits at once); `run` revokes and seals the ready attempt.
   */
  cancel() {
    this.#cancelRequested = true;
    if (this.#waiting) {
      if (this.#wake) this.#wake();
      return;
    }
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

function checkBinding(binding) {
  if (binding === null || typeof binding !== "object") refuse("binding is {task, attempt, lease}");
  requireId(binding.task, "task", "binding.task");
  requireId(binding.attempt, "exec", "binding.attempt");
  requireId(binding.lease, "lease", "binding.lease");
}

/** The reason of a `rejected` event for `verb`, refusing one that is not this verb's or not in `reasons`. */
function checkRefusal(event, verb, operationId, reasons) {
  if (event.verb !== verb) refuse(`a rejected ${verb} names verb ${event.verb}`);
  if (event.operation_id !== operationId) refuse(`a rejected ${verb} names operation ${event.operation_id}, not ${operationId}`);
  if (!reasons.includes(event.reason)) refuse(`a rejected ${verb} gives reason ${JSON.stringify(event.reason)}, which is not one of ${reasons.join(", ")}`);
  return event.reason;
}

/** A policy's verdict as {decision, note?}, or `null` for no answer. */
function verdictOf(verdict) {
  if (verdict === null || verdict === undefined) return null;
  if (typeof verdict === "string") return { decision: checkDecision(verdict) };
  if (typeof verdict !== "object" || Array.isArray(verdict)) refuse("a policy returns approved, denied, {decision, note} or null");
  const note = checkNote(verdict.note);
  return note === undefined ? { decision: checkDecision(verdict.decision) } : { decision: checkDecision(verdict.decision), note };
}

/** Wait `ms`, or less when `signal` aborts. Polling, never synchronisation: the loop re-reads the node. */
function pause(ms, signal) {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve();
      return;
    }
    const done = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
  });
}

// ---------------------------------------------------------------------------------------
// The action channel's listing (§6.7)
// ---------------------------------------------------------------------------------------

function textBytes(value, what, min, max) {
  if (typeof value !== "string") refuse(`${what} is a string`);
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes < min || bytes > max) refuse(`${what} is ${min} to ${max} bytes, got ${bytes}`);
  return value;
}

/**
 * Decode an `actions` answer (§6.7): {state, pending}, each pending request {action, id,
 * kind, summary, detail, expires_in_ms} within the channel's bounds, and a request the node
 * opened for a held capability (§6.9) also with `hold` ({host} or {service}), its id
 * `hold:N`, its kind `approval`; oldest first (strictly increasing `action`), ids unique, at
 * most 8 of the workload's and 8 of the node's, and none unless the attempt is `running` or
 * `paused`. With the `grant` the attempt was admitted under (`actionsGrantOf`), also held to
 * it: only granted kinds, at most `max_pending` of the workload's, numbers up to
 * `max_total` and the holds, and no wait longer than `wait_secs`; and to its `hold`
 * (`holdGrantOf`; with a `grant` and no `hold` the manifest had none): each node-opened
 * request names exactly the capability its id numbers and asks with its summary. A
 * listing outside these is refused, not acted on.
 */
export function decodeActions(listing, grant = null, hold = null) {
  if (listing === null || typeof listing !== "object" || Array.isArray(listing)) refuse("a listing is {state, pending}");
  if (!LIFECYCLE_STATES.includes(listing.state)) refuse(`a listing's state ${JSON.stringify(listing.state)} is not a lifecycle state`);
  if (!Array.isArray(listing.pending)) refuse("a listing's pending is a list");
  const held = grant === null || grant === undefined ? null : checkActionsGrant(grant);
  const holds = hold === null || hold === undefined ? null : heldCapabilities(hold);
  const opened = listing.pending.filter((entry) => entry !== null && typeof entry === "object" && "hold" in entry).length;
  const limit = held ? held.max_pending : ACTION_CEILINGS.maxPending;
  if (listing.pending.length - opened > limit) {
    refuse(`a listing holds at most ${limit} pending requests of the workload's (${held ? "the grant's max_pending" : "the node's ceiling"}), got ${listing.pending.length - opened}`);
  }
  const holdLimit = holds ? holds.length : held ? 0 : HOLD_LIMITS.holds;
  if (opened > holdLimit) refuse(`a listing holds at most ${holdLimit} requests the node opened for a hold, got ${opened}`);
  if (listing.pending.length > 0 && !LIVE_STATES.includes(listing.state)) {
    refuse(`only a running or paused attempt has pending requests; this one is ${listing.state}`);
  }
  const ids = new Set();
  let previous = 0;
  const pending = listing.pending.map((entry) => {
    const keys = entry === null || typeof entry !== "object" ? "" : Object.keys(entry).sort().join();
    if (keys !== "action,detail,expires_in_ms,id,kind,summary" && keys !== "action,detail,expires_in_ms,hold,id,kind,summary") {
      refuse("a pending request is {action, id, kind, summary, detail, expires_in_ms} and, when the node opened it for a hold, hold");
    }
    const { action } = entry;
    if (!Number.isSafeInteger(action) || action < 1 || action > MAX_ACTION_NUMBER) refuse(`a pending request's action is an integer from 1 to ${MAX_ACTION_NUMBER}`);
    if (action <= previous) refuse("pending requests are listed oldest first, by strictly increasing action");
    previous = action;
    if (held && action > held.max_total + holdLimit) {
      refuse(`request ${action} is above the grant's max_total ${held.max_total} and the requests a hold opens`);
    }
    if (typeof entry.id !== "string" || !ACTION_ID.test(entry.id)) refuse(`request ${action}'s id ${JSON.stringify(entry.id)} is not 1-64 bytes of A-Z a-z 0-9 . _ : -`);
    if (ids.has(entry.id)) refuse(`the listing repeats the id ${entry.id}`);
    ids.add(entry.id);
    if (!ACTION_KINDS.includes(entry.kind)) refuse(`request ${action}'s kind ${JSON.stringify(entry.kind)} is not one of ${ACTION_KINDS.join(", ")}`);
    if (held && !held.kinds.includes(entry.kind)) refuse(`request ${action}'s kind ${entry.kind} is not granted (${held.kinds.join(", ")})`);
    textBytes(entry.summary, `request ${action}'s summary`, 1, MAX_ACTION_SUMMARY_BYTES);
    textBytes(entry.detail, `request ${action}'s detail`, 0, MAX_ACTION_DETAIL_BYTES);
    if (!Number.isSafeInteger(entry.expires_in_ms) || entry.expires_in_ms < 0) refuse(`request ${action}'s expires_in_ms is an integer >= 0`);
    if (held && entry.expires_in_ms > held.wait_secs * 1000) refuse(`request ${action} expires in ${entry.expires_in_ms} ms, longer than the grant's wait_secs ${held.wait_secs}`);
    const decoded = { action, id: entry.id, kind: entry.kind, summary: entry.summary, detail: entry.detail, expires_in_ms: entry.expires_in_ms };
    const number = HOLD_REQUEST_ID.exec(entry.id);
    if (!("hold" in entry)) {
      if (holds && number !== null && Number(number[1]) <= holds.length) refuse(`request ${action} is under the node's id ${entry.id} but names no held capability`);
      return decoded;
    }
    decoded.hold = checkHeldCapability(entry.hold, action);
    if (number === null || entry.kind !== "approval") refuse(`request ${action} names a held capability, so the node opened it: its id is hold:N and its kind approval`);
    if (holds) {
      const expected = holds[Number(number[1]) - 1];
      if (expected === undefined || JSON.stringify(expected.capability) !== JSON.stringify(decoded.hold) || expected.summary !== entry.summary) {
        refuse(`request ${action} (${entry.id}) is not the request the node opens for the hold's capability ${number[1]}`);
      }
    }
    return decoded;
  });
  return { state: listing.state, pending };
}

/** A listing's `hold`: {host: pattern} or {service: name}, nothing else. */
function checkHeldCapability(capability, action) {
  const keys = capability === null || typeof capability !== "object" || Array.isArray(capability) ? [] : Object.keys(capability);
  if (keys.length === 1 && keys[0] === "host" && isHostPattern(capability.host)) return { host: capability.host };
  if (keys.length === 1 && keys[0] === "service" && typeof capability.service === "string" && CREDENTIAL_SERVICE.test(capability.service)) {
    return { service: capability.service };
  }
  return refuse(`request ${action}'s hold is {host: pattern} or {service: name}, got ${JSON.stringify(capability)}`);
}

// ---------------------------------------------------------------------------------------
// The bounded result (§6.6)
// ---------------------------------------------------------------------------------------

function decodeBase64(text, what) {
  if (typeof text !== "string" || !BASE64.test(text)) refuse(`${what} content_base64 is standard base64 with padding`);
  return Buffer.from(text, "base64");
}

function checkCount(value, what) {
  if (!Number.isSafeInteger(value) || value < 0) refuse(`${what} is an integer >= 0`);
  return value;
}

function decodeStream(stream, what) {
  if (stream === null || typeof stream !== "object" || Object.keys(stream).sort().join() !== "bytes,content_base64,dropped,truncated") {
    refuse(`${what} is {bytes, truncated, dropped, content_base64}`);
  }
  const content = decodeBase64(stream.content_base64, what);
  if (checkCount(stream.bytes, `${what} bytes`) !== content.length) refuse(`${what} bytes ${stream.bytes} is not the content's length ${content.length}`);
  const dropped = checkCount(stream.dropped, `${what} dropped`);
  if (stream.truncated !== (dropped > 0)) refuse(`${what} truncated is true exactly when dropped > 0`);
  return { bytes: content.length, truncated: dropped > 0, dropped, content };
}

function decodeFile(file, index) {
  if (file === null || typeof file !== "object") refuse(`output files[${index}] is an object`);
  const path = checkOutputPath(file.path, `output files[${index}]`);
  const keys = Object.keys(file).sort().join();
  if (keys === "path,skipped") {
    if (!OUTPUT_SKIPS.includes(file.skipped)) refuse(`${path} skipped is one of ${OUTPUT_SKIPS.join(", ")}`);
    return { path, skipped: file.skipped };
  }
  if (keys === "digest,path,size,truncated") {
    if (file.truncated !== true) refuse(`${path}: a file without content is digest-only, so truncated is true`);
    if (typeof file.digest !== "string" || !HEX_32.test(file.digest)) refuse(`${path} digest is 64 lowercase hex digits`);
    return { path, size: checkCount(file.size, `${path} size`), digest: file.digest, truncated: true };
  }
  if (keys !== "content_base64,digest,path,size,truncated") {
    refuse(`${path}: an output file is {path, skipped}, {path, size, digest, truncated: true} or {path, size, digest, truncated: false, content_base64}`);
  }
  if (file.truncated !== false) refuse(`${path}: returned content is never truncated`);
  if (typeof file.digest !== "string" || !HEX_32.test(file.digest)) refuse(`${path} digest is 64 lowercase hex digits`);
  const content = decodeBase64(file.content_base64, path);
  if (checkCount(file.size, `${path} size`) !== content.length) refuse(`${path} size ${file.size} is not the content's length ${content.length}`);
  // The digest is recomputed over the bytes received; content whose digest disagrees is
  // refused here, so nothing downstream ever sees it as the file the node collected.
  const digest = blake3Hex(content);
  if (digest !== file.digest) refuse(`${path}: the returned digest ${file.digest} is not the BLAKE3-256 of the returned content, ${digest}`);
  return { path, size: content.length, digest, truncated: false, content };
}

/**
 * Decode the `output` of a `result` answer or a `done` report (§6.6) into bytes, checking
 * every count and flag and recomputing every returned file's BLAKE3-256 over its content;
 * a result whose digests, sizes or shape disagree is refused. Streams are `{bytes,
 * truncated, dropped, content}` (a Buffer, the head of the stream); files are `{path,
 * size, digest, truncated: false, content}`, `{path, size, digest, truncated: true}` past
 * the content budget, or `{path, skipped}`; `truncated` on the whole says whether any
 * stream or file was cut. `null` and `undefined` (no output) decode to `null`. With the
 * `grant` the attempt was admitted under (`outputGrantOf`), the result must also answer it:
 * exactly the declared paths in order, and neither stream nor file content past its budget.
 */
export function decodeOutput(output, grant = null) {
  if (output === null || output === undefined) return null;
  if (typeof output !== "object" || Array.isArray(output) || Object.keys(output).sort().join() !== "files,stderr,stdout") {
    refuse("an output is one object {stdout, stderr, files}");
  }
  const stdout = decodeStream(output.stdout, "output stdout");
  const stderr = decodeStream(output.stderr, "output stderr");
  if (!Array.isArray(output.files) || output.files.length > OUTPUT_CEILINGS.files) {
    refuse(`output files lists 0 to ${OUTPUT_CEILINGS.files} entries`);
  }
  const files = output.files.map(decodeFile);
  if (new Set(files.map((file) => file.path)).size !== files.length) refuse("output files repeats a path");
  if (grant !== null && grant !== undefined) checkAgainstGrant({ stdout, stderr, files }, checkOutputGrant(grant));
  const truncated = stdout.truncated || stderr.truncated || files.some((file) => file.truncated === true);
  return { stdout, stderr, files, truncated };
}

/**
 * A result answers its grant (§6.6): one entry per declared path in declaration order, no
 * stream head longer than `stdio_bytes`, no more returned file content than `files_bytes`.
 * A result that answers some other grant is not this attempt's and is refused.
 */
function checkAgainstGrant({ stdout, stderr, files }, grant) {
  const paths = files.map((file) => file.path);
  if (paths.length !== grant.files.length || paths.some((path, index) => path !== grant.files[index])) {
    refuse(`output files ${JSON.stringify(paths)} are not the declared ${JSON.stringify(grant.files)} in order`);
  }
  for (const [name, stream] of [["stdout", stdout], ["stderr", stderr]]) {
    if (stream.bytes > grant.stdio_bytes) refuse(`output ${name} returned ${stream.bytes} bytes, more than the granted ${grant.stdio_bytes}`);
  }
  const returnedBytes = files.reduce((sum, file) => sum + (file.content ? file.content.length : 0), 0);
  if (returnedBytes > grant.files_bytes) refuse(`output files returned ${returnedBytes} bytes of content, more than the granted ${grant.files_bytes}`);
}

function lstatOrNull(path) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

/**
 * Visit the parent directories of `path` under `root`, outermost first: a symlink or a
 * non-directory is refused (a symlink could lead outside `root`), and `create` is called
 * for each one that does not exist yet.
 */
function walkParents(root, path, create) {
  let ancestor = root;
  for (const component of path.split("/").slice(0, -1)) {
    ancestor = join(ancestor, component);
    const stat = lstatOrNull(ancestor);
    if (stat === null) create(ancestor);
    else if (stat.isSymbolicLink()) refuse(`returned path ${JSON.stringify(path)} crosses a symlink at ${ancestor}`);
    else if (!stat.isDirectory()) refuse(`returned path ${JSON.stringify(path)} crosses a non-directory at ${ancestor}`);
  }
}

/**
 * Write the returned files of a decoded output (those with content) under `dir` at their
 * declared paths, creating directories as needed and never overwriting: each file is
 * created `wx` with mode 0600. Every path is checked again here — the node already held
 * it to the §7.5 grammar, but a path that would resolve outside `dir`, or that crosses a
 * symlink inside it, or that already exists, is refused before anything is written.
 * Returns `[{path, written}]`, the absolute path of each file written, in declaration
 * order; digest-only and skipped files write nothing.
 */
export function writeReturnedFiles(dir, files) {
  if (typeof dir !== "string" || dir.length === 0) refuse("the output directory is a non-empty path");
  if (!Array.isArray(files)) refuse("the files are the `files` of a decoded output");
  const root = resolve(dir);
  const plan = [];
  for (const file of files) {
    if (file === null || typeof file !== "object") refuse("an output file is an object");
    if (file.skipped !== undefined || file.truncated === true) continue;
    if (!Buffer.isBuffer(file.content)) refuse(`${JSON.stringify(file.path)}: a returned file's content is a Buffer`);
    const path = checkOutputPath(file.path, "returned");
    if (isAbsolute(path) || path.includes("\\")) refuse(`returned path ${JSON.stringify(path)} is not relative`);
    const target = resolve(root, path);
    if (target !== join(root, path) || !target.startsWith(root + sep)) refuse(`returned path ${JSON.stringify(path)} escapes ${root}`);
    plan.push({ path, target, content: file.content });
  }
  // Every target is checked before the first is written, so a refusal leaves nothing half done.
  for (const { path, target } of plan) {
    walkParents(root, path, () => {});
    if (lstatOrNull(target) !== null) refuse(`returned path ${JSON.stringify(path)} already exists at ${target}`);
  }
  const written = [];
  mkdirSync(root, { recursive: true, mode: 0o700 });
  for (const { path, target, content } of plan) {
    walkParents(root, path, (ancestor) => mkdirSync(ancestor, { mode: 0o700 }));
    // `wx` is O_CREAT|O_EXCL: it neither overwrites nor follows a symlink planted at the target.
    const fd = openSync(target, "wx", 0o600);
    try {
      writeFileSync(fd, content);
    } finally {
      closeSync(fd);
    }
    written.push({ path, written: target });
  }
  return written;
}

// ---------------------------------------------------------------------------------------
// Outcomes (§9, §11.3)
// ---------------------------------------------------------------------------------------

/**
 * Map an attempt report (§11.3) to the outcome a control plane acts on. `outcome` is
 * `completed`, `failed`, `unknown` or `refused`; `certain` is false exactly for `unknown`,
 * which a control plane treats as failed and never as success; `exitStatus` is the
 * workload's exit status when the evidence log recorded one; `output` is the bounded
 * result decoded and verified by `decodeOutput`, `null` when none was granted or returned.
 *
 * Pass `grant`, the `output` grant the attempt was admitted under (`outputGrantOf` of its
 * envelope_json), and the output is also held to it, and `outputMissing` is true when the
 * grant asked for a result and none came back (the node refused `result`, the answer was
 * lost, or the attempt never reached it). A completed attempt whose granted output is
 * missing is not a success: what it was run for cannot be read.
 */
export function outcomeOf(report, { grant = null } = {}) {
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
  const output = decodeOutput(report.output, grant);
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
    output,
    outputMissing: grant !== null && output === null,
    binding: report.binding,
  };
}
