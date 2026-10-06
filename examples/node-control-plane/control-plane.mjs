#!/usr/bin/env node
// A reference control plane for `ward-node` in plain Node.js: one task end to end through
// `ward-node-adapter`, the way docs/node-integration-from-nodejs.md describes it for the
// ai-institution adapter. The library is ward-node.mjs; this file is the command line
// over it. Run `control-plane.mjs --help`.
//
// Exit status: 0 when the attempt completed and, when the manifest granted output, its
// output came back; 1 when it failed, ended unknown, was refused or was cancelled, or its
// granted output did not come back (`outputMissing`; the outcome object on stdout says
// which); 2 for a usage error or a failure of the client itself (the message is on
// stderr), a returned result whose digests disagree with its content or its grant, a
// returned file that could not be written, or an answer loop that failed, included.

import { join } from "node:path";
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";

import {
  Adapter,
  CREDENTIAL_LIMITS,
  VersionStore,
  actionsGrant,
  actionsGrantOf,
  answerOperationId,
  buildEnvelope,
  credentialsGrant,
  credentialsGrantOf,
  decodeActions,
  deriveId,
  isId,
  loadIssuerKey,
  loadOrCreateIssuerKey,
  loadRunRecord,
  operationIds,
  outcomeOf,
  outputGrant,
  outputGrantOf,
  recordAnswer,
  requireCredentialBroker,
  rootLease,
  saveRunRecord,
  signEnvelope,
  writeReturnedFiles,
} from "./ward-node.mjs";

const USAGE = `usage: control-plane.mjs <command> [options]

  keygen       --key <pem> --principal <id>
               Create the issuer key at <pem> (PKCS#8 PEM, mode 0600) unless it exists,
               and print the trust-store line for the node's --trusted-issuers file.
  derive-id    <prefix> <caller-id>
               Print the WardOS id this client derives for a caller id (task, exec,
               lease, agent, node, sess, deleg, prn).
  capabilities --socket <path> [--adapter <bin>] [--trace]
               Print the node's capability document.
  run          --socket <path> --key <pem> --principal <id> --node <id> --state-dir <dir>
               --snapshot <hex> --budget-ms <n> --task <caller-id> --attempt <caller-id>
               [--lease <caller-id>] [--agent <caller-id>] [--session <caller-id>]
               [--grant <capability>=<resource>]... [--task-root <dir>] [--valid-for-ms <n>]
               [--stdio-bytes <n>] [--files <path>[,<path>...]]... [--files-bytes <n>] [--out-dir <dir>]
               [--actions <kind>[,<kind>]] [--actions-max-pending <n>] [--actions-max-total <n>]
               [--actions-wait-secs <n>] [--approve-all | --deny-all | --ask] [--note <text>]
               [--actions-poll-ms <n>] [--credential <service>=<host>[:<ttl-secs>]]...
               [--cancel-after <ms>] [--adapter <bin>] [--timeout-ms <n>] [--trace] -- <argv>...
               Admit, start, watch and seal one attempt; print its outcome as one JSON line.
               SIGINT or SIGTERM cancels it (revoke, then seal). Any of --stdio-bytes, --files
               and --files-bytes puts an output grant in the manifest (the others default to 0
               and none): the node, started with --output-return, returns the first n bytes of
               stdout and of stderr and the declared files; the outcome's output carries them
               with every digest verified, and --out-dir writes the returned files there.
               A completed attempt whose granted output did not come back exits 1.
               --actions grants the action channel for the kinds (approval, decision) with
               at most --actions-max-pending (default 2) waiting, --actions-max-total
               (default 8) in all and --actions-wait-secs (default 300) each; the node must
               be started with --action-channel. With a policy, a second adapter answers
               every request while the run goes on: --approve-all, --deny-all, or --ask
               (shows each request on stderr and reads "y [note]" or "n [note]" from stdin;
               end of input denies), each with --note when given. Every request and its
               answer is printed on stderr and listed in the outcome's actions; answers are
               recorded in the run record before they are sent, so a replay never answers
               twice. Without a policy nobody here answers (see actions and answer).
               --credential grants a credential the node leases from the operator's
               configured service (1 to 4, no service twice): its proxy injects it into the
               workload's requests for /<service>/... on WARD_PROXY_SOCKET, sent to the
               service's upstream at <host>, and revokes the lease when the attempt ends;
               the workload never sees it. The lease lives at most <ttl-secs> (default: the
               budget, rounded up to whole seconds). The manifest's network.custom is then
               exactly the granted hosts. The node's capability document is read first: a
               node not started with --network-allowlist and --credentials is refused here
               (unsupported_grant) before anything is signed. The outcome lists the grants
               in credentials.
  replay       --socket <path> --state-dir <dir> --attempt <exec_…> [--out-dir <dir>] [--adapter <bin>] [--trace]
               [--approve-all | --deny-all | --ask] [--note <text>]
               Resend a recorded run with the same bytes and operation ids; nothing acts twice.
               A policy answers its action channel as run's does, replaying recorded answers;
               a recorded credentials grant is listed in the outcome as run's is.
  inspect      --socket <path> --task <task_…> --attempt <exec_…> --lease <lease_…>
  result       --socket <path> --task <task_…> --attempt <exec_…> --lease <lease_…> [--out-dir <dir>]
               Read an ended attempt's stored result again (its run must have carried the grant).
  revoke       --socket <path> --task <task_…> --attempt <exec_…> --lease <lease_…> --operation-id <n>
  actions      --socket <path> (--state-dir <dir> --attempt <exec_…> | --task <task_…> --attempt <exec_…> --lease <lease_…>)
               List the attempt's pending action-channel requests, for a run driven elsewhere.
  answer       --socket <path> (--state-dir <dir> --attempt <exec_…> | --task <task_…> --attempt <exec_…>
               --lease <lease_…> --operation-id <n>) --request <n> --decision approved|denied [--note <text>]
               Answer one request. With --state-dir the operation id is the run record's for the
               request and the answer is recorded before it is sent; the same answer again is a
               replay, and a different one for a recorded request is refused here. An answer the
               node refuses (already_answered, invalid_state, …) prints it and exits 1.

An id option takes a WardOS id of the right prefix as is, and derives one from anything
else with deriveId (docs/node-integration-from-nodejs.md §3). Output streams and, without
--out-dir, returned file contents are printed as content_base64, the exact bytes.
`;

const OPTIONS = {
  socket: { type: "string" },
  key: { type: "string" },
  principal: { type: "string" },
  node: { type: "string" },
  "state-dir": { type: "string" },
  snapshot: { type: "string" },
  "budget-ms": { type: "string" },
  task: { type: "string" },
  attempt: { type: "string" },
  lease: { type: "string" },
  agent: { type: "string" },
  session: { type: "string" },
  grant: { type: "string", multiple: true },
  "task-root": { type: "string" },
  "valid-for-ms": { type: "string" },
  "stdio-bytes": { type: "string" },
  files: { type: "string", multiple: true },
  "files-bytes": { type: "string" },
  "out-dir": { type: "string" },
  "cancel-after": { type: "string" },
  adapter: { type: "string" },
  "timeout-ms": { type: "string" },
  "operation-id": { type: "string" },
  actions: { type: "string" },
  "actions-max-pending": { type: "string" },
  "actions-max-total": { type: "string" },
  "actions-wait-secs": { type: "string" },
  "actions-poll-ms": { type: "string" },
  credential: { type: "string", multiple: true },
  "approve-all": { type: "boolean" },
  "deny-all": { type: "boolean" },
  ask: { type: "boolean" },
  note: { type: "string" },
  request: { type: "string" },
  decision: { type: "string" },
  trace: { type: "boolean" },
  help: { type: "boolean", short: "h" },
};

class UsageError extends Error {}

function need(values, name) {
  const value = values[name];
  if (value === undefined || value === "") throw new UsageError(`--${name} is required`);
  return value;
}

function integer(values, name, fallback) {
  const raw = values[name];
  if (raw === undefined) {
    if (fallback === undefined) throw new UsageError(`--${name} is required`);
    return fallback;
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) throw new UsageError(`--${name} takes a non-negative integer`);
  return value;
}

/** A WardOS id of `prefix` as given, or the id derived from the caller's own id. */
function idOf(prefix, value) {
  return isId(value, prefix) ? value : deriveId(prefix, value);
}

function wardId(values, name, prefix) {
  const value = need(values, name);
  if (!isId(value, prefix)) throw new UsageError(`--${name} takes a ${prefix}_ id`);
  return value;
}

function trace(values) {
  return values.trace ? (line) => process.stderr.write(`${line}\n`) : null;
}

function adapterOf(values) {
  const options = { command: [values.adapter ?? "ward-node-adapter"], socket: need(values, "socket"), trace: trace(values) };
  if (values["timeout-ms"] !== undefined) options.timeoutMs = integer(values, "timeout-ms");
  return new Adapter(options);
}

function grantsOf(values, task) {
  const raw = values.grant ?? [`workload.run=task:${task}`];
  return raw.map((entry) => {
    const equals = entry.indexOf("=");
    if (equals <= 0) throw new UsageError("--grant takes <capability>=<resource>");
    return { capability: entry.slice(0, equals), resource: entry.slice(equals + 1), delegable: false };
  });
}

const CREDENTIAL_FLAG = /^([^=]+)=([^:]+)(?::([0-9]+))?$/;

/**
 * The credentials grant the --credential flags ask for, or `null` without one: each
 * `<service>=<host>[:<ttl-secs>]`, the TTL defaulting to the budget in whole seconds.
 */
function credentialsOf(values, budgetMs) {
  if (values.credential === undefined) return null;
  const fallback = Math.min(Math.max(1, Math.ceil(budgetMs / 1000)), CREDENTIAL_LIMITS.ttlSecs);
  return credentialsGrant(
    values.credential.map((entry) => {
      const parsed = CREDENTIAL_FLAG.exec(entry);
      if (parsed === null) throw new UsageError("--credential takes <service>=<host>[:<ttl-secs>]");
      return { service: parsed[1], host: parsed[2], ttlSecs: parsed[3] === undefined ? fallback : Number(parsed[3]) };
    }),
  );
}

/**
 * The manifest the flags ask for: offline, with an output grant when any output flag is
 * given and an actions grant when --actions is; with --credential, the credentials grant
 * and a network.custom of exactly its hosts.
 */
function manifestOf(values, budgetMs) {
  const object = { network: "offline" };
  const credentials = credentialsOf(values, budgetMs);
  if (credentials !== null) object.network = { custom: [...new Set(credentials.map((grant) => grant.host))] };
  if (values["stdio-bytes"] !== undefined || values.files !== undefined || values["files-bytes"] !== undefined) {
    object.output = outputGrant({
      stdioBytes: integer(values, "stdio-bytes", 0),
      files: (values.files ?? []).flatMap((entry) => entry.split(",")),
      filesBytes: integer(values, "files-bytes", 0),
    });
  }
  const tuning = ["actions-max-pending", "actions-max-total", "actions-wait-secs"].some((name) => values[name] !== undefined);
  if (values.actions === undefined) {
    if (tuning) throw new UsageError("--actions-max-pending, --actions-max-total and --actions-wait-secs need --actions");
  } else {
    const maxTotal = integer(values, "actions-max-total", 8);
    object.actions = actionsGrant({
      kinds: values.actions.split(","),
      maxPending: integer(values, "actions-max-pending", Math.min(2, maxTotal)),
      maxTotal,
      waitSecs: integer(values, "actions-wait-secs", 300),
    });
  }
  if (credentials !== null) object.credentials = credentials;
  return Object.keys(object).length === 1 ? undefined : object;
}

const POLICIES = ["approve-all", "deny-all", "ask"];

/** One line of stdin at a time, for --ask; `null` once stdin has ended. */
function stdinLines() {
  const reader = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const lines = [];
  const waiters = [];
  let closed = false;
  reader.on("line", (line) => {
    const waiter = waiters.shift();
    if (waiter) waiter(line);
    else lines.push(line);
  });
  reader.on("close", () => {
    closed = true;
    while (waiters.length > 0) waiters.shift()(null);
  });
  return {
    next: () => {
      if (lines.length > 0) return Promise.resolve(lines.shift());
      if (closed) return Promise.resolve(null);
      return new Promise((resolve) => waiters.push(resolve));
    },
    close: () => reader.close(),
  };
}

function abortable(promise, signal) {
  if (!signal) return promise;
  return new Promise((resolve) => {
    if (signal.aborted) resolve(null);
    signal.addEventListener("abort", () => resolve(null), { once: true });
    promise.then(resolve);
  });
}

/**
 * The answer policy the flags ask for, or `null` without one: --approve-all and --deny-all
 * answer every request so, --ask shows it and reads a verdict from stdin. `--note` goes
 * with every answer of the first two. Refused unless the manifest grants `actions`.
 */
function policyOf(values, granted) {
  const chosen = POLICIES.filter((name) => values[name]);
  if (values.note !== undefined && Buffer.byteLength(values.note, "utf8") > 512) throw new UsageError("--note is at most 512 bytes");
  if (values.note !== undefined && !values["approve-all"] && !values["deny-all"]) {
    throw new UsageError("--note goes with --approve-all or --deny-all (--ask reads a note after the verdict)");
  }
  if (chosen.length === 0) return null;
  if (!granted) throw new UsageError("--approve-all, --deny-all and --ask need --actions (an actions grant in the manifest)");
  if (chosen.length > 1) throw new UsageError("give one of --approve-all, --deny-all or --ask");
  const note = values.note;
  const fixed = (decision) => () => (note === undefined ? decision : { decision, note });
  if (chosen[0] === "approve-all") return { policy: fixed("approved"), close: () => {} };
  if (chosen[0] === "deny-all") return { policy: fixed("denied"), close: () => {} };
  const lines = stdinLines();
  const ask = async (request, { signal }) => {
    for (;;) {
      process.stderr.write(`control-plane: approve request ${request.action}? [y/N] `);
      const line = await abortable(lines.next(), signal);
      if (line === null) return signal?.aborted ? null : { decision: "denied", note: "no answer on stdin" };
      const text = line.trim();
      const word = text.split(/\s+/)[0];
      const rest = text.slice(word.length).trim();
      if (Buffer.byteLength(rest, "utf8") > 512) {
        process.stderr.write("control-plane: a note is at most 512 bytes; answer again\n");
        continue;
      }
      const decision = /^(y|yes)$/i.test(word) ? "approved" : "denied";
      return rest === "" ? decision : { decision, note: rest };
    }
  };
  return { policy: ask, close: () => lines.close() };
}

function printRequest(request) {
  const lines = [`control-plane: request ${request.action} (${request.kind}, id ${request.id}): ${request.summary}`];
  if (request.detail !== "") lines.push(...request.detail.split("\n").map((line) => `control-plane:   ${line}`));
  lines.push(`control-plane:   expires in ${Math.ceil(request.expires_in_ms / 1000)} s unless answered`);
  process.stderr.write(`${lines.join("\n")}\n`);
}

function printAnswer(answer) {
  const replayed = answer.replayed ? ", replayed from the run record" : "";
  const note = answer.note === undefined ? "" : ` with note ${JSON.stringify(answer.note)}`;
  const line =
    answer.result === "answered"
      ? `request ${answer.request} answered ${answer.decision} (operation ${answer.operation_id}${replayed})${note}`
      : `request ${answer.request} answer ${answer.decision} refused ${answer.reason} (operation ${answer.operation_id}${replayed})`;
  process.stderr.write(`control-plane: ${line}\n`);
}

/**
 * Drive a run and, with a policy, answer its action channel from a second adapter beside
 * it until the run's `done`. Resolves with the report, the answers and the loop's failure.
 */
async function driveWithAnswers(values, signed, options, cancelAfterMs, answering) {
  const adapter = adapterOf(values);
  const controller = new AbortController();
  let answerer = null;
  let loop = Promise.resolve({ answers: [] });
  if (answering !== null) {
    answerer = adapterOf(values);
    loop = answerer
      .answerLoop(signed.binding, answering.policy, {
        pollMs: integer(values, "actions-poll-ms", 250),
        signal: controller.signal,
        runDir: answering.runDir,
        onRequest: printRequest,
        onAnswer: printAnswer,
      })
      .catch((error) => ({ answers: [], error }));
  }
  let report;
  try {
    report = await drive(adapter, signed, options, cancelAfterMs);
  } finally {
    controller.abort();
    await adapter.close();
  }
  const loopResult = await loop;
  if (answerer !== null) {
    answering.close();
    await answerer.close().catch(() => 1);
  }
  return { report, answers: loopResult.answers, loopError: loopResult.error ?? null };
}

/**
 * Exit status 2 when the answer loop failed while the attempt could have asked: not when
 * the run was refused before it started (a node without the channel refuses `actions` as
 * it refuses the grant) or was cancelled anyway.
 */
function withLoop(status, outcome, loopError) {
  if (loopError === null) return status;
  process.stderr.write(`control-plane: the answer loop failed: ${loopError.message}\n`);
  return outcome.cancelled || outcome.outcome === "refused" ? status : 2;
}

/**
 * The decoded output as the JSON line prints it: stream heads and, without `outDir`, file
 * contents as content_base64 (the exact bytes); with `outDir` the returned files are
 * written there first and the line names where (`written`) instead of carrying them.
 */
function renderOutput(output, outDir) {
  if (output === null) return null;
  const written = outDir === undefined ? new Map() : new Map(writeReturnedFiles(outDir, output.files).map((entry) => [entry.path, entry.written]));
  const stream = ({ bytes, truncated, dropped, content }) => ({ bytes, truncated, dropped, content_base64: content.toString("base64") });
  return {
    stdout: stream(output.stdout),
    stderr: stream(output.stderr),
    truncated: output.truncated,
    files: output.files.map((file) => {
      if (file.skipped !== undefined || file.truncated) return file;
      const { content, ...rest } = file;
      return written.has(file.path) ? { ...rest, written: written.get(file.path) } : { ...rest, content_base64: content.toString("base64") };
    }),
  };
}

function emit(object) {
  process.stdout.write(`${JSON.stringify(object)}\n`);
}

/** 0 only for a completed, uncancelled attempt whose granted output, if any, came back. */
function exitStatusOf(outcome) {
  return outcome.outcome === "completed" && !outcome.cancelled && !outcome.outputMissing ? 0 : 1;
}

/** Drive a run to its outcome, cancelling on SIGINT/SIGTERM and after `cancelAfterMs` if set. */
async function drive(adapter, signed, options, cancelAfterMs) {
  let timer = null;
  const cancel = () => adapter.cancel();
  process.once("SIGINT", cancel);
  process.once("SIGTERM", cancel);
  try {
    const { report } = await adapter.run(signed, {
      ...options,
      onEvent: (event) => {
        if (cancelAfterMs !== undefined && timer === null && event.event === "state" && event.state === "running") {
          timer = setTimeout(cancel, cancelAfterMs);
        }
      },
    });
    return report;
  } finally {
    if (timer !== null) clearTimeout(timer);
    process.off("SIGINT", cancel);
    process.off("SIGTERM", cancel);
  }
}

async function keygen(values) {
  const issuer = loadOrCreateIssuerKey(need(values, "key"));
  process.stdout.write(`${issuer.trustStoreLine(idOf("prn", need(values, "principal")))}\n`);
  return 0;
}

function deriveCommand(positionals) {
  const [prefix, callerId] = positionals;
  if (prefix === undefined || callerId === undefined) throw new UsageError("derive-id takes <prefix> <caller-id>");
  process.stdout.write(`${deriveId(prefix, callerId)}\n`);
  return 0;
}

/** Refuse a credentials grant unless the node's capability document offers the broker. */
async function requireBroker(values) {
  const adapter = adapterOf(values);
  try {
    requireCredentialBroker(await adapter.capabilities());
  } finally {
    await adapter.close();
  }
}

async function capabilities(values) {
  const adapter = adapterOf(values);
  try {
    emit(await adapter.capabilities());
  } finally {
    await adapter.close();
  }
  return 0;
}

async function run(values, argv) {
  if (argv.length === 0) throw new UsageError("run needs the workload's argv after --");
  const stateDir = need(values, "state-dir");
  const issuer = loadIssuerKey(need(values, "key"));
  const principal = idOf("prn", need(values, "principal"));
  const node = wardId(values, "node", "node");
  const callerTask = need(values, "task");
  const callerAttempt = need(values, "attempt");
  const callerLease = values.lease ?? callerAttempt;
  const task = idOf("task", callerTask);
  const attempt = idOf("exec", callerAttempt);
  const lease = idOf("lease", callerLease);
  const agent = idOf("agent", values.agent ?? "control-plane");
  const session = idOf("sess", values.session ?? callerAttempt);
  const budgetMs = integer(values, "budget-ms");
  const validForMs = integer(values, "valid-for-ms", 15 * 60_000);
  // The grants, the policy and the node's offer of a credential broker are checked before
  // a version is allocated or anything is signed.
  const workloadManifest = manifestOf(values, budgetMs);
  const answering = policyOf(values, workloadManifest?.actions !== undefined);
  if (workloadManifest?.credentials !== undefined) await requireBroker(values);
  const now = Date.now();
  const binding = { task, attempt, lease };
  const versions = new VersionStore(join(stateDir, "admission-versions.json"));
  const version = versions.next(task);
  const envelope = buildEnvelope({
    binding,
    agent,
    node,
    session,
    lease: rootLease({
      id: lease,
      delegationId: idOf("deleg", callerLease),
      issuer: principal,
      subject: agent,
      task,
      grants: grantsOf(values, task),
      issuedAtUnixMs: now - 60_000,
      expiresAtUnixMs: now + validForMs + budgetMs,
    }),
    workload: { argv, manifest: workloadManifest, snapshot: need(values, "snapshot"), wallClockBudgetMs: budgetMs },
    issuedAtUnixMs: now - 60_000,
    expiresAtUnixMs: now + validForMs,
    version,
  });
  const signed = signEnvelope(issuer, envelope);
  const ids = operationIds(1);
  const record = {
    binding,
    caller: { task: callerTask, attempt: callerAttempt, lease: callerLease },
    version,
    envelope_json: signed.envelope_json,
    proof: signed.proof,
    operation_ids: { start_at: ids.start_at },
    task_root: values["task-root"] ?? null,
  };
  // The record goes to disk before the first byte is sent, so a restart can replay it.
  saveRunRecord(join(stateDir, "runs"), record);
  const { report, answers, loopError } = await driveWithAnswers(
    values,
    signed,
    { operationIds: ids, taskRoot: record.task_root ?? undefined },
    values["cancel-after"] === undefined ? undefined : integer(values, "cancel-after"),
    answering === null ? null : { ...answering, runDir: join(stateDir, "runs") },
  );
  const outcome = { ...outcomeOf(report, { grant: outputGrantOf(signed.envelope_json) }), version, operations: report.operations };
  if (workloadManifest?.actions !== undefined) outcome.actions = answers;
  if (workloadManifest?.credentials !== undefined) outcome.credentials = workloadManifest.credentials;
  emit({ ...outcome, output: renderOutput(outcome.output, values["out-dir"]) });
  return withLoop(exitStatusOf(outcome), outcome, loopError);
}

async function replay(values) {
  const runs = join(need(values, "state-dir"), "runs");
  const record = loadRunRecord(runs, wardId(values, "attempt", "exec"));
  const granted = actionsGrantOf(record.envelope_json) !== null;
  const answering = policyOf(values, granted);
  const { report, answers, loopError } = await driveWithAnswers(
    values,
    { envelope_json: record.envelope_json, proof: record.proof, binding: record.binding },
    { operationIds: operationIds(record.operation_ids.start_at), taskRoot: record.task_root ?? undefined },
    undefined,
    answering === null ? null : { ...answering, runDir: runs },
  );
  const outcome = {
    ...outcomeOf(report, { grant: outputGrantOf(record.envelope_json) }),
    version: record.version,
    operations: report.operations,
    replayed: true,
  };
  if (granted) outcome.actions = answers;
  const credentials = credentialsGrantOf(record.envelope_json);
  if (credentials !== null) outcome.credentials = credentials;
  emit({ ...outcome, output: renderOutput(outcome.output, values["out-dir"]) });
  return withLoop(exitStatusOf(outcome), outcome, loopError);
}

function bindingOf(values) {
  return { task: wardId(values, "task", "task"), attempt: wardId(values, "attempt", "exec"), lease: wardId(values, "lease", "lease") };
}

async function inspect(values) {
  const adapter = adapterOf(values);
  try {
    emit(await adapter.inspect(bindingOf(values)));
  } finally {
    await adapter.close();
  }
  return 0;
}

async function result(values) {
  const adapter = adapterOf(values);
  let resulted;
  try {
    resulted = await adapter.result(bindingOf(values));
  } finally {
    await adapter.close();
  }
  if (resulted.rejected !== undefined) {
    emit(resulted);
    return 1;
  }
  emit({ state: resulted.state, output: renderOutput(resulted.output, values["out-dir"]) });
  return 0;
}

/** The binding and run record the flags name: a record under --state-dir, or the explicit ids. */
function targetOf(values) {
  if (values["state-dir"] === undefined) return { binding: bindingOf(values), record: null, runs: null };
  const runs = join(values["state-dir"], "runs");
  const record = loadRunRecord(runs, idOf("exec", need(values, "attempt")));
  return { binding: record.binding, record, runs };
}

async function actionsCommand(values) {
  const { binding, record } = targetOf(values);
  const adapter = adapterOf(values);
  let listed;
  try {
    listed = await adapter.actions(binding);
  } finally {
    await adapter.close();
  }
  if (listed.rejected !== undefined) {
    emit(listed);
    return 1;
  }
  // A recorded run's listing is also held to the grant it was admitted under.
  emit(record === null ? listed : decodeActions(listed, actionsGrantOf(record.envelope_json)));
  return 0;
}

async function answerCommand(values) {
  const request = integer(values, "request");
  const decision = need(values, "decision");
  const { binding, record, runs } = targetOf(values);
  let operationId;
  let note = values.note;
  if (record !== null) {
    if (values["operation-id"] !== undefined) throw new UsageError("with --state-dir the operation id is the run record's; leave out --operation-id");
    // Recorded before it is sent; a request the record already answered is answered the same way again.
    const entry = recordAnswer(runs, binding.attempt, { request, decision, note, operation_id: answerOperationId(record.operation_ids, request) });
    if (entry.decision !== decision || (entry.note ?? null) !== (note ?? null)) {
      throw new Error(
        `the run record already answered request ${request} ${entry.decision} under operation ${entry.operation_id}; ` +
          "only that answer is sent again (a different one would be stale_operation or already_answered)",
      );
    }
    operationId = entry.operation_id;
    note = entry.note;
  } else {
    operationId = integer(values, "operation-id");
  }
  const adapter = adapterOf(values);
  let answered;
  try {
    answered = await adapter.answer(binding, request, decision, operationId, note);
  } finally {
    await adapter.close();
  }
  emit(answered);
  return answered.result === "answered" ? 0 : 1;
}

async function revoke(values) {
  const adapter = adapterOf(values);
  try {
    emit(await adapter.revoke(bindingOf(values), integer(values, "operation-id")));
  } finally {
    await adapter.close();
  }
  return 0;
}

async function main(args) {
  const separator = args.indexOf("--");
  const argv = separator >= 0 ? args.slice(separator + 1) : [];
  const own = separator >= 0 ? args.slice(0, separator) : args;
  const { values, positionals } = parseArgs({ args: own, options: OPTIONS, allowPositionals: true, strict: true });
  const [command, ...rest] = positionals;
  if (values.help || command === undefined) {
    process.stdout.write(USAGE);
    return command === undefined && !values.help ? 2 : 0;
  }
  switch (command) {
    case "keygen":
      return keygen(values);
    case "derive-id":
      return deriveCommand(rest);
    case "capabilities":
      return capabilities(values);
    case "run":
      return run(values, argv);
    case "replay":
      return replay(values);
    case "inspect":
      return inspect(values);
    case "result":
      return result(values);
    case "revoke":
      return revoke(values);
    case "actions":
      return actionsCommand(values);
    case "answer":
      return answerCommand(values);
    default:
      throw new UsageError(`unknown command \`${command}\``);
  }
}

main(process.argv.slice(2)).then(
  (status) => process.exit(status),
  (error) => {
    const usage = error instanceof UsageError || error?.code === "ERR_PARSE_ARGS_UNKNOWN_OPTION" || error?.code === "ERR_PARSE_ARGS_INVALID_OPTION_VALUE";
    process.stderr.write(`control-plane: ${error.message}\n`);
    if (usage) process.stderr.write(USAGE);
    process.exit(2);
  },
);
