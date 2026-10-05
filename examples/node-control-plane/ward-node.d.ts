// Hand-written declarations for ward-node.mjs, so a TypeScript control plane can import
// the reference client as is. The contract each type follows is docs/node-integration.md;
// the section numbers below are its.

/** The one protocol version this client speaks (§4). */
export const PROTOCOL: Readonly<{ major: 1; minor: 3 }>;

/** `{"network":"offline"}`, the manifest a node without `--network-allowlist` admits (§7.5). */
export const OFFLINE_MANIFEST: Readonly<{ network: "offline" }>;

/** Every id prefix of §7.2. */
export const ID_PREFIXES: ReadonlyArray<IdPrefix>;

/**
 * What every node honours of an `output` grant (§6.6, §7.5): 1 MiB per stream, 8 MiB of
 * file content, 64 paths of at most 255 bytes. A grant above these is refused before signing.
 */
export const OUTPUT_CEILINGS: Readonly<{ stdioBytes: 1048576; filesBytes: 8388608; files: 64; pathBytes: 255 }>;

export type IdPrefix = "task" | "exec" | "lease" | "agent" | "node" | "sess" | "deleg" | "prn";

/** `<prefix>_` and 26 upper-case Crockford base32 characters, first character 0–7 (§7.2). */
export type WardId<P extends IdPrefix = IdPrefix> = `${P}_${string}`;

export type LifecycleState =
  | "created" | "ready" | "running" | "paused" | "exited" | "stopped" | "revoked" | "sealed";

export type ReceiptOutcome = "completed" | "failed" | "unknown";

export type RejectionReason =
  | "task_not_found" | "attempt_mismatch" | "lease_mismatch" | "lease_expired" | "lease_revoked"
  | "stale_operation" | "invalid_state" | "authority_denied" | "unsupported_grant"
  | "resource_unavailable" | "unsupported_operation";

export type Verb = "create" | "admit" | "start" | "pause" | "resume" | "stop" | "revoke" | "seal";

/** The verbs a `rejected` event may name: the mutating verbs and the two read-only requests. */
export type RejectedVerb = Verb | "inspect" | "result";

export interface Binding {
  task: WardId<"task">;
  attempt: WardId<"exec">;
  lease: WardId<"lease">;
}

export interface Grant {
  capability: string;
  resource: string;
  delegable: boolean;
}

/** A lease in wire form (§7.3). */
export interface Lease {
  id: WardId<"lease">;
  delegation_id: WardId<"deleg">;
  issuer: WardId<"prn">;
  subject: WardId<"agent">;
  task: WardId<"task">;
  parent_lease_id: WardId<"lease"> | null;
  delegated_by: WardId<"agent"> | null;
  grants: Grant[];
  issued_at_unix_ms: number;
  expires_at_unix_ms: number;
  version: number;
}

/**
 * The `output` grant of §7.5 in wire spelling: the first `stdio_bytes` of each of stdout
 * and stderr, and the declared `files` (relative workspace paths, exact, 0–64, no repeats)
 * with up to `files_bytes` of content in all. Honoured only by a node started with
 * `--output-return` and within `OUTPUT_CEILINGS`; refused `unsupported_grant` otherwise.
 */
export interface OutputGrant {
  stdio_bytes: number;
  files: string[];
  files_bytes: number;
}

export type Manifest = ({ network: "offline" } | { network: { custom: string[] } }) & { output?: OutputGrant };

export interface ManifestBytes {
  /** BLAKE3-256 of `bytes`, 64 lowercase hex digits. */
  hash: string;
  /** The manifest bytes as sent, lowercase hex. */
  bytes: string;
}

export interface Envelope {
  binding: Binding;
  agent: WardId<"agent">;
  node: WardId<"node">;
  session: WardId<"sess">;
  authority: { lease: Lease; lineage: Lease[] };
  workload: {
    argv: string[];
    capability_manifest: ManifestBytes;
    snapshot: string;
    wall_clock_budget_ms: number;
  };
  issued_at_unix_ms: number;
  expires_at_unix_ms: number;
  version: number;
}

export interface Proof {
  issuer_key_id: string;
  signature: string;
}

/** The exact signed bytes and their proof: what `run` sends and what a replay resends (§7.4). */
export interface SignedEnvelope {
  envelope_json: string;
  proof: Proof;
  binding: Binding;
}

export interface RootLeaseInput {
  id: WardId<"lease">;
  delegationId: WardId<"deleg">;
  issuer: WardId<"prn">;
  subject: WardId<"agent">;
  task: WardId<"task">;
  grants: Grant[];
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  /** Default 1. */
  version?: number;
}

export interface EnvelopeInput {
  binding: Binding;
  agent: WardId<"agent">;
  node: WardId<"node">;
  session: WardId<"sess">;
  lease: Lease;
  /** Nearest parent first; default none (a root lease). */
  lineage?: Lease[];
  workload: {
    argv: string[];
    /** Default `OFFLINE_MANIFEST`. */
    manifest?: Manifest;
    /** The line `ward-node snapshot import` printed (§2.4). */
    snapshot: string;
    wallClockBudgetMs: number;
  };
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  /** Strictly above every version the node accepted for the task (§7.3, §10). */
  version: number;
}

export function encodeId<P extends IdPrefix>(prefix: P, value: bigint | number): WardId<P>;
export function decodeId(id: string): { prefix: IdPrefix; value: bigint };
export function isId(id: unknown, prefix?: IdPrefix): id is WardId;
/**
 * The WardOS id for the control plane's own id of the thing: the first 16 bytes of
 * SHA-256("ward-node id v1" ‖ 0x00 ‖ prefix ‖ 0x00 ‖ callerId), big-endian, rendered.
 */
export function deriveId<P extends IdPrefix>(prefix: P, callerId: string): WardId<P>;
export function randomId<P extends IdPrefix>(prefix: P): WardId<P>;

export function blake3Hex(input: Uint8Array): string;
export function manifest(object?: Manifest): ManifestBytes;
/** The `output` grant a signed envelope's manifest carries, read from its exact bytes, or `null`. */
export function outputGrantOf(envelopeJson: string): OutputGrant | null;
/** The §7.5 grant from the control plane's words, refused outside the grammar or above the ceilings. */
export function outputGrant(input: { stdioBytes: number; files: string[]; filesBytes: number }): OutputGrant;

export class Issuer {
  private constructor(privateKey: unknown);
  readonly publicKey: Buffer;
  readonly publicKeyHex: string;
  /** BLAKE3-256 of the 32 public-key bytes, 64 lowercase hex digits (§2.3). */
  readonly keyId: string;
  /** `<public-key> <key-id> <prn_…>` for the node's trust store (§2.2). */
  trustStoreLine(principal: WardId<"prn">): string;
  /** The detached Ed25519 signature over the exact UTF-8 bytes of `envelopeJson` (§7.4). */
  prove(envelopeJson: string): Proof;
  toPem(): string;
}

export function issuerFromSeed(seed: Uint8Array): Issuer;
export function issuerFromPem(pem: string): Issuer;
/** The PEM file must be a regular file of mode 0600 or 0400. */
export function loadIssuerKey(path: string): Issuer;
/** Generates an Ed25519 key and writes it PKCS#8 PEM, mode 0600, never overwriting. */
export function createIssuerKey(path: string): Issuer;
export function loadOrCreateIssuerKey(path: string): Issuer;

export function rootLease(input: RootLeaseInput): Lease;
export function buildEnvelope(input: EnvelopeInput): Envelope;
export function serialiseEnvelope(envelope: Envelope): string;
export function signEnvelope(issuer: Issuer, envelope: Envelope): SignedEnvelope;
/** The complete `admit` request line of §7.4, for a client speaking to the socket itself. */
export function admitRequest(signed: SignedEnvelope, operationId: number): string;

/** `{"format":1,"versions":{"task_…":N}}` on disk; every `next` is durable before it returns. */
export class VersionStore {
  constructor(path: string);
  current(task: WardId<"task">): number;
  next(task: WardId<"task">): number;
}

export interface OperationIds {
  start_at: number;
  create: number;
  admit: number;
  start: number;
  stop: number;
  revoke: number;
  seal: number;
}

/** The scheme of §11.2 shifted to start at `startAt` (default 1). */
export function operationIds(startAt?: number): OperationIds;

export interface RunRecord {
  binding: Binding;
  envelope_json: string;
  proof: Proof;
  operation_ids: { start_at: number };
  task_root?: string | null;
  [extra: string]: unknown;
}

export function saveRunRecord(dir: string, record: RunRecord): void;
export function loadRunRecord(dir: string, attempt: WardId<"exec">): RunRecord & { format: 1 };

/** One event line of `ward-node-adapter` (§11.4). */
export interface AdapterEvent {
  schema: 1;
  event: "state" | "rejected" | "admitted" | "recovering" | "receipt" | "evidence" | "output" | "done"
    | "capabilities" | "inspected" | "result" | "verb" | "error";
  [field: string]: unknown;
}

/** One stream of a `result` as the wire carries it (§6.6): the head, base64 with padding. */
export interface WireOutputStream {
  bytes: number;
  truncated: boolean;
  dropped: number;
  content_base64: string;
}

export type OutputFileSkip = "missing" | "not_a_regular_file" | "too_large";

/** One declared file as the wire carries it (§6.6). */
export type WireOutputFile =
  | { path: string; size: number; digest: string; truncated: false; content_base64: string }
  | { path: string; size: number; digest: string; truncated: true }
  | { path: string; skipped: OutputFileSkip };

/** The `output` of a `result` answer or a `done` report, undecoded (§6.6). */
export interface WireOutput {
  stdout: WireOutputStream;
  stderr: WireOutputStream;
  files: WireOutputFile[];
}

/** One stream decoded: `content` is the head of the stream, `dropped` the bytes past it. */
export interface OutputStream {
  bytes: number;
  truncated: boolean;
  dropped: number;
  content: Buffer;
}

/**
 * One declared file decoded. Returned content carries the digest the client recomputed
 * over it; a file past `files_bytes` is digest-only with `truncated: true`; anything else
 * is `skipped` with why. A digest that disagreed with its content never gets this far.
 */
export type OutputFile =
  | { path: string; size: number; digest: string; truncated: false; content: Buffer }
  | { path: string; size: number; digest: string; truncated: true }
  | { path: string; skipped: OutputFileSkip };

/** The bounded result of an ended attempt, decoded and verified (§6.6). */
export interface AttemptOutput {
  stdout: OutputStream;
  stderr: OutputStream;
  files: OutputFile[];
  /** Whether a stream was cut or a file came back digest-only. */
  truncated: boolean;
}

/**
 * Decode a wire output, checking every count and flag and recomputing every returned
 * file's BLAKE3-256; refuses a result whose digests, sizes or shape disagree, or, given the
 * grant, that does not answer it (the declared paths in order, within both budgets).
 * `null` in, `null` out.
 */
export function decodeOutput(output: WireOutput, grant?: OutputGrant | null): AttemptOutput;
export function decodeOutput(output: null | undefined, grant?: OutputGrant | null): null;

/**
 * Write the returned files (those with content) under `dir` at their declared paths,
 * `wx` and mode 0600, refusing a path that would leave `dir`, cross a symlink in it or
 * overwrite anything before anything is written. Digest-only and skipped files write nothing.
 */
export function writeReturnedFiles(dir: string, files: OutputFile[]): Array<{ path: string; written: string }>;

export interface Operation {
  verb: Verb;
  operation_id: number;
  state: LifecycleState | null;
  reason: RejectionReason | null;
}

/** The attempt report of §11.3. */
export interface AttemptReport {
  binding: Binding;
  final_state: LifecycleState | null;
  outcome: ReceiptOutcome | { refused: { verb: RejectedVerb; reason: RejectionReason } };
  outcome_certain: boolean;
  receipt: ReceiptOutcome | null;
  cause: unknown;
  sealed: boolean;
  cancelled: boolean;
  deadline_exceeded: boolean;
  evidence_log: string | null;
  evidence_head: string | null;
  operations: Operation[];
  transport_error: string | null;
  /** The §6.6 output when the manifest granted it and the node returned it; else `null` (absent from an earlier adapter). */
  output?: WireOutput | null;
}

export interface AdapterOptions {
  /** The executable and any leading arguments; default `["ward-node-adapter"]`. */
  command?: string[];
  /** The node's Unix socket, passed as `--socket`. */
  socket: string;
  timeoutMs?: number;
  connectTimeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  /** Receives every line exchanged, prefixed `>> ` (sent) or `<< ` (received). */
  trace?: ((line: string) => void) | null;
}

export interface RunOptions {
  operationIds?: OperationIds | number;
  taskRoot?: string;
  pollMs?: number;
  maxPollMs?: number;
  graceMs?: number;
  onEvent?: (event: AdapterEvent) => void;
}

export class Adapter {
  constructor(options: AdapterOptions);
  readonly pid: number | undefined;
  send(command: object): void;
  next(): Promise<AdapterEvent>;
  capabilities(): Promise<Record<string, unknown>>;
  inspect(binding: Binding): Promise<{ state: LifecycleState; outcome: ReceiptOutcome | null } | { rejected: RejectionReason }>;
  /** `result` for the binding (§6.6): the decoded, verified output, or the node's refusal. */
  result(binding: Binding): Promise<{ state: LifecycleState; output: AttemptOutput } | { rejected: RejectionReason }>;
  revoke(binding: Binding, operationId: number): Promise<
    | { result: "accepted"; state: LifecycleState; operation_id: number }
    | { result: "rejected"; reason: RejectionReason; operation_id: number }
  >;
  run(signed: Pick<SignedEnvelope, "envelope_json" | "proof">, options?: RunOptions): Promise<{ events: AdapterEvent[]; report: AttemptReport }>;
  /** SIGTERM to the adapter: it revokes and seals the running attempt and writes `done`. */
  cancel(): void;
  close(): Promise<number>;
}

/** What a control plane acts on. `certain` is false exactly for `unknown`, which is never success. */
export interface Outcome {
  outcome: ReceiptOutcome | "refused";
  certain: boolean;
  receipt: ReceiptOutcome | null;
  cause: unknown;
  /** The workload's exit status when the evidence log recorded one. */
  exitStatus: number | undefined;
  finalState: LifecycleState | null;
  sealed: boolean;
  cancelled: boolean;
  deadlineExceeded: boolean;
  evidenceLog: string | null;
  evidenceHead: string | null;
  refused: { verb: string; reason: RejectionReason } | undefined;
  transportError: string | null;
  /** The bounded result, decoded and verified, when granted and returned; `null` otherwise. */
  output: AttemptOutput | null;
  /** True when `outcomeOf` was given a grant and no output came back: never a success. */
  outputMissing: boolean;
  binding: Binding;
}

/**
 * Map a report to the outcome a control plane acts on. With `grant` (`outputGrantOf` of the
 * envelope) the output is held to it and `outputMissing` says a granted output did not come back.
 */
export function outcomeOf(report: AttemptReport, options?: { grant?: OutputGrant | null }): Outcome;
