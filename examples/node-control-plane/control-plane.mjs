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
// stderr), a returned result whose digests disagree with its content or its grant, or a
// returned file that could not be written, included.

import { join } from "node:path";
import { parseArgs } from "node:util";

import {
  Adapter,
  VersionStore,
  buildEnvelope,
  deriveId,
  isId,
  loadIssuerKey,
  loadOrCreateIssuerKey,
  loadRunRecord,
  operationIds,
  outcomeOf,
  outputGrant,
  outputGrantOf,
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
               [--cancel-after <ms>] [--adapter <bin>] [--timeout-ms <n>] [--trace] -- <argv>...
               Admit, start, watch and seal one attempt; print its outcome as one JSON line.
               SIGINT or SIGTERM cancels it (revoke, then seal). Any of --stdio-bytes, --files
               and --files-bytes puts an output grant in the manifest (the others default to 0
               and none): the node, started with --output-return, returns the first n bytes of
               stdout and of stderr and the declared files; the outcome's output carries them
               with every digest verified, and --out-dir writes the returned files there.
               A completed attempt whose granted output did not come back exits 1.
  replay       --socket <path> --state-dir <dir> --attempt <exec_…> [--out-dir <dir>] [--adapter <bin>] [--trace]
               Resend a recorded run with the same bytes and operation ids; nothing acts twice.
  inspect      --socket <path> --task <task_…> --attempt <exec_…> --lease <lease_…>
  result       --socket <path> --task <task_…> --attempt <exec_…> --lease <lease_…> [--out-dir <dir>]
               Read an ended attempt's stored result again (its run must have carried the grant).
  revoke       --socket <path> --task <task_…> --attempt <exec_…> --lease <lease_…> --operation-id <n>

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

/** The manifest the flags ask for: offline, with an output grant when any output flag is given. */
function manifestOf(values) {
  if (values["stdio-bytes"] === undefined && values.files === undefined && values["files-bytes"] === undefined) return undefined;
  return {
    network: "offline",
    output: outputGrant({
      stdioBytes: integer(values, "stdio-bytes", 0),
      files: (values.files ?? []).flatMap((entry) => entry.split(",")),
      filesBytes: integer(values, "files-bytes", 0),
    }),
  };
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
    workload: { argv, manifest: manifestOf(values), snapshot: need(values, "snapshot"), wallClockBudgetMs: budgetMs },
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
  const adapter = adapterOf(values);
  let report;
  try {
    report = await drive(
      adapter,
      signed,
      { operationIds: ids, taskRoot: record.task_root ?? undefined },
      values["cancel-after"] === undefined ? undefined : integer(values, "cancel-after"),
    );
  } finally {
    await adapter.close();
  }
  const outcome = { ...outcomeOf(report, { grant: outputGrantOf(signed.envelope_json) }), version, operations: report.operations };
  emit({ ...outcome, output: renderOutput(outcome.output, values["out-dir"]) });
  return exitStatusOf(outcome);
}

async function replay(values) {
  const record = loadRunRecord(join(need(values, "state-dir"), "runs"), wardId(values, "attempt", "exec"));
  const adapter = adapterOf(values);
  let report;
  try {
    report = await drive(
      adapter,
      { envelope_json: record.envelope_json, proof: record.proof, binding: record.binding },
      { operationIds: operationIds(record.operation_ids.start_at), taskRoot: record.task_root ?? undefined },
    );
  } finally {
    await adapter.close();
  }
  const outcome = {
    ...outcomeOf(report, { grant: outputGrantOf(record.envelope_json) }),
    version: record.version,
    operations: report.operations,
    replayed: true,
  };
  emit({ ...outcome, output: renderOutput(outcome.output, values["out-dir"]) });
  return exitStatusOf(outcome);
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
