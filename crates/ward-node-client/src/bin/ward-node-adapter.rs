//! `ward-node-adapter`: the node client as a process, for control planes in other
//! languages (node-integration.md §11).
//!
//! `ward-node-adapter (--socket <path> | --connect-tls <host:port> --tls-cert <file>
//! --tls-key <file> --tls-server-ca <file> --tls-server-name <name> [--tls-server-pin <pin>])
//! [--timeout-ms <ms>] [--connect-timeout-ms <ms>]` reads one JSON command per line on stdin
//! and writes one JSON event per line on stdout, each carrying `"schema":1`; stderr is
//! diagnostics only. With `--connect-tls` every command reaches a node serving
//! `--listen-tls` over mutual TLS (ADR-0038) instead of its socket; TLS files that cannot
//! be used are an `error` before any command is read. Commands:
//!
//! * `{"cmd":"capabilities"}` → `capabilities`;
//! * `{"cmd":"run", ...}` with a pre-signed envelope (`envelope_json` and `proof`, sent
//!   byte for byte) or, as a convenience, `issuer_seed_file` and `envelope` to sign here,
//!   plus optional `operation_ids`, `poll_ms`, `max_poll_ms`, `grace_ms` and `task_root`
//!   → a stream of `state`, `rejected`, `admitted`, `recovering`, `receipt`, `evidence`
//!   and, for a manifest with an `output` grant, `output` events and one final `done`
//!   with the attempt report, which then carries the bounded output;
//! * `{"cmd":"revoke","operation_id":N,"binding":{...}}` → `verb`;
//! * `{"cmd":"inspect","binding":{...}}` → `inspected` or `rejected`;
//! * `{"cmd":"result","binding":{...}}` → `result` (the state and the bounded output) or
//!   `rejected`;
//! * `{"cmd":"actions","binding":{...}}` → `actions` (the state and the pending
//!   action-channel requests) or `rejected`;
//! * `{"cmd":"answer","binding":{...},"request":N,"decision":"approved"|"denied",
//!   "operation_id":N[,"note":"..."]}` → `answered` or `rejected`.
//!
//! A `run` blocks this adapter until the attempt is sealed, so a control plane that runs an
//! attempt whose workload asks through its action channel answers from a second adapter
//! process (or its own client) while the first one runs.
//!
//! A `SIGTERM` or `SIGINT` during a `run` cancels it: the attempt is revoked and sealed,
//! `done` is written, and the adapter exits without reading further commands; while idle,
//! the adapter exits at once. The exit status is 0 when every command was well formed and
//! answered (an attempt that failed is still a clean answer: its outcome is in `done`),
//! 1 when an `error` event was written, 2 for bad flags.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use nix::sys::signal::{SigSet, Signal};
use serde::Deserialize;
use serde_json::{Value, json};
use ward_node_client::{
    ActionsListed, AnswerApplied, Applied, AttemptRequest, CancelToken, Client, Driver,
    EnvelopeInput, Inspection, IssuerKey, OperationIds, Resulted, RunConfig, SignedEnvelope,
    Timeouts, TlsSettings, TlsTransport, Transport, UnixTransport,
};
use ward_node_protocol::{
    ActionDecision, ActionNote, AdmissionEnvelopeJson, IssuerProof, OperationId, TaskBinding,
};

const SCHEMA: u64 = 1;
const MAX_COMMAND_BYTES: usize = 256 * 1024;

#[derive(Parser)]
#[command(name = "ward-node-adapter", version)]
#[command(group(clap::ArgGroup::new("node").required(true).args(["socket", "connect_tls"])))]
struct Cli {
    /// The node's Unix socket.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Reach the node over mutual TLS at this `<host>:<port>` (its `--listen-tls`) instead
    /// of a socket. Needs `--tls-cert`, `--tls-key`, `--tls-server-ca` and
    /// `--tls-server-name`.
    #[arg(
        long,
        value_name = "HOST:PORT",
        requires_all = ["tls_cert", "tls_key", "tls_server_ca", "tls_server_name"]
    )]
    connect_tls: Option<String>,
    /// This client's certificate chain, leaf first, in PEM.
    #[arg(long, value_name = "FILE", requires = "connect_tls")]
    tls_cert: Option<PathBuf>,
    /// This client's private key in PEM, mode 0600 or 0400.
    #[arg(long, value_name = "FILE", requires = "connect_tls")]
    tls_key: Option<PathBuf>,
    /// The CA certificates, in PEM, the node's certificate must chain to.
    #[arg(long, value_name = "FILE", requires = "connect_tls")]
    tls_server_ca: Option<PathBuf>,
    /// The DNS name or IP address the node's certificate must be valid for.
    #[arg(long, value_name = "NAME", requires = "connect_tls")]
    tls_server_name: Option<String>,
    /// The node's key: `sha256:` and the 64 lowercase hex digits of the SHA-256 of its
    /// certificate's DER `SubjectPublicKeyInfo`.
    #[arg(long, value_name = "PIN", requires = "connect_tls")]
    tls_server_pin: Option<String>,
    /// Bound on a verb's answer; `start`, `stop` and `revoke` need more than 60 000.
    #[arg(long, default_value_t = 90_000)]
    timeout_ms: u64,
    /// Bound on connecting and receiving the handshake answer.
    #[arg(long, default_value_t = 10_000)]
    connect_timeout_ms: u64,
}

#[derive(Deserialize)]
struct Tag {
    cmd: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilitiesCommand {
    #[serde(rename = "cmd")]
    _cmd: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunCommand {
    #[serde(rename = "cmd")]
    _cmd: String,
    envelope_json: Option<String>,
    proof: Option<IssuerProof>,
    issuer_seed_file: Option<PathBuf>,
    envelope: Option<EnvelopeInput>,
    operation_ids: Option<OperationIds>,
    poll_ms: Option<u64>,
    max_poll_ms: Option<u64>,
    grace_ms: Option<u64>,
    task_root: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeCommand {
    #[serde(rename = "cmd")]
    _cmd: String,
    operation_id: OperationId,
    binding: TaskBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectCommand {
    #[serde(rename = "cmd")]
    _cmd: String,
    binding: TaskBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultCommand {
    #[serde(rename = "cmd")]
    _cmd: String,
    binding: TaskBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionsCommand {
    #[serde(rename = "cmd")]
    _cmd: String,
    binding: TaskBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerCommand {
    #[serde(rename = "cmd")]
    _cmd: String,
    binding: TaskBinding,
    request: u32,
    decision: ActionDecision,
    operation_id: OperationId,
    note: Option<ActionNote>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cancel = CancelToken::default();
    let running = Arc::new(AtomicBool::new(false));
    if let Err(error) = watch_termination(cancel.clone(), Arc::clone(&running)) {
        eprintln!("ward-node-adapter: cannot watch for termination: {error}");
        return ExitCode::from(1);
    }
    let timeouts = Timeouts {
        connect: Duration::from_millis(cli.connect_timeout_ms),
        request: Duration::from_millis(cli.timeout_ms),
    };
    match (cli.socket, cli.connect_tls) {
        (Some(socket), None) => serve(UnixTransport::new(socket, timeouts), cancel, running),
        (None, Some(address)) => {
            let settings = TlsSettings {
                address,
                server_name: cli.tls_server_name.unwrap_or_default(),
                server_ca: cli.tls_server_ca.unwrap_or_default(),
                client_cert: cli.tls_cert.unwrap_or_default(),
                client_key: cli.tls_key.unwrap_or_default(),
                server_pin: cli.tls_server_pin,
            };
            match TlsTransport::new(&settings, timeouts) {
                Ok(transport) => serve(transport, cancel, running),
                Err(error) => {
                    let message = format!("TLS: {error}");
                    eprintln!("ward-node-adapter: {message}");
                    emit(json!({"event": "error", "error": message}));
                    ExitCode::from(1)
                }
            }
        }
        _ => ExitCode::from(2),
    }
}

fn serve<T: Transport + Clone>(
    transport: T,
    cancel: CancelToken,
    running: Arc<AtomicBool>,
) -> ExitCode {
    let mut adapter = Adapter {
        transport,
        cancel,
        running,
        failed: false,
    };
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    loop {
        if adapter.cancel.is_cancelled() {
            break;
        }
        match read_command(&mut reader) {
            Ok(None) => break,
            Ok(Some(line)) if line.trim().is_empty() => {}
            Ok(Some(line)) => adapter.handle(&line),
            Err(message) => {
                adapter.error(&message);
                break;
            }
        }
    }
    if adapter.failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn watch_termination(cancel: CancelToken, running: Arc<AtomicBool>) -> Result<(), nix::Error> {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGINT);
    mask.thread_block()?;
    std::thread::spawn(move || {
        while mask.wait().is_ok() {
            cancel.cancel();
            if !running.load(Ordering::SeqCst) {
                std::process::exit(0);
            }
        }
    });
    Ok(())
}

fn read_command(reader: &mut impl BufRead) -> Result<Option<String>, String> {
    let mut buffer = Vec::new();
    let limit = u64::try_from(MAX_COMMAND_BYTES + 1).map_err(|error| error.to_string())?;
    let read = reader
        .by_ref()
        .take(limit)
        .read_until(b'\n', &mut buffer)
        .map_err(|error| format!("reading stdin failed: {error}"))?;
    if read == 0 {
        return Ok(None);
    }
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
    } else if buffer.len() > MAX_COMMAND_BYTES {
        return Err(format!("command line exceeds {MAX_COMMAND_BYTES} bytes"));
    }
    String::from_utf8(buffer)
        .map(Some)
        .map_err(|_| "command line is not UTF-8".to_owned())
}

fn emit(mut event: Value) -> bool {
    if let Value::Object(fields) = &mut event {
        fields.insert("schema".to_owned(), json!(SCHEMA));
    }
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{event}").is_ok() && stdout.flush().is_ok()
}

struct Adapter<T> {
    transport: T,
    cancel: CancelToken,
    running: Arc<AtomicBool>,
    failed: bool,
}

impl<T: Transport + Clone> Adapter<T> {
    fn error(&mut self, message: &str) {
        self.failed = true;
        eprintln!("ward-node-adapter: {message}");
        emit(json!({"event": "error", "error": message}));
    }

    fn handle(&mut self, line: &str) {
        let Ok(tag) = serde_json::from_str::<Tag>(line) else {
            self.error("command line is not a JSON object with a `cmd` string");
            return;
        };
        let result = match tag.cmd.as_str() {
            "capabilities" => self.capabilities(line),
            "run" => self.run(line),
            "revoke" => self.revoke(line),
            "inspect" => self.inspect(line),
            "result" => self.result(line),
            "actions" => self.actions(line),
            "answer" => self.answer(line),
            other => Err(format!(
                "unknown command `{other}`; the commands are capabilities, run, revoke, inspect, result, actions and answer"
            )),
        };
        if let Err(message) = result {
            self.error(&message);
        }
    }

    fn client(&self) -> Result<Client<T>, String> {
        Client::connect(self.transport.clone()).map_err(|error| error.to_string())
    }

    fn capabilities(&self, line: &str) -> Result<(), String> {
        parse::<CapabilitiesCommand>(line)?;
        let client = self.client()?;
        let capabilities = client.capabilities().map_err(|error| error.to_string())?;
        emit(json!({
            "event": "capabilities",
            "protocol": client.protocol(),
            "capabilities": capabilities,
        }));
        Ok(())
    }

    fn run(&self, line: &str) -> Result<(), String> {
        let command = parse::<RunCommand>(line)?;
        let request = match (
            command.envelope_json,
            command.proof,
            command.issuer_seed_file,
            command.envelope,
        ) {
            (Some(envelope_json), Some(proof), None, None) => AttemptRequest::pre_signed(
                SignedEnvelope {
                    envelope_json: AdmissionEnvelopeJson::new(envelope_json)
                        .map_err(|error| error.to_string())?,
                    proof,
                },
                command.task_root,
            )
            .map_err(|error| format!("envelope_json is not a valid envelope: {error}"))?,
            (None, None, Some(seed_file), Some(envelope)) => {
                let issuer =
                    IssuerKey::from_seed_file(&seed_file).map_err(|error| error.to_string())?;
                let envelope = envelope.build().map_err(|error| error.to_string())?;
                AttemptRequest::sign(&envelope, &issuer, command.task_root)
                    .map_err(|error| error.to_string())?
            }
            _ => {
                return Err("run takes either envelope_json and proof (pre-signed) or \
                            issuer_seed_file and envelope (signed here), not a mixture"
                    .to_owned());
            }
        };
        let defaults = RunConfig::default();
        let config = RunConfig {
            poll_interval: command
                .poll_ms
                .map_or(defaults.poll_interval, Duration::from_millis),
            max_poll_interval: command
                .max_poll_ms
                .map_or(defaults.max_poll_interval, Duration::from_millis),
            grace: command
                .grace_ms
                .map_or(defaults.grace, Duration::from_millis),
        };
        let ids = command.operation_ids.unwrap_or_default();
        let client = self.client()?;
        self.running.store(true, Ordering::SeqCst);
        let report =
            Driver::new(&client, config).run_attempt(&request, &ids, &self.cancel, &mut |event| {
                if let Ok(value) = serde_json::to_value(event) {
                    emit(value);
                }
            });
        self.running.store(false, Ordering::SeqCst);
        emit(json!({"event": "done", "report": report}));
        Ok(())
    }

    fn revoke(&self, line: &str) -> Result<(), String> {
        let command = parse::<RevokeCommand>(line)?;
        let client = self.client()?;
        let applied = client
            .revoke(command.binding, command.operation_id)
            .map_err(|error| error.to_string())?;
        emit(match applied {
            Applied::Accepted { state } => json!({
                "event": "verb",
                "verb": "revoke",
                "operation_id": command.operation_id,
                "result": "accepted",
                "state": state,
            }),
            Applied::Rejected { reason } => json!({
                "event": "verb",
                "verb": "revoke",
                "operation_id": command.operation_id,
                "result": "rejected",
                "reason": reason,
            }),
        });
        Ok(())
    }

    fn inspect(&self, line: &str) -> Result<(), String> {
        let command = parse::<InspectCommand>(line)?;
        let client = self.client()?;
        let inspection = client
            .inspect(command.binding)
            .map_err(|error| error.to_string())?;
        emit(match inspection {
            Inspection::Inspected { state, outcome } => {
                json!({"event": "inspected", "state": state, "outcome": outcome})
            }
            Inspection::Rejected { reason } => json!({
                "event": "rejected",
                "verb": "inspect",
                "operation_id": Value::Null,
                "reason": reason,
            }),
        });
        Ok(())
    }
}

impl<T: Transport + Clone> Adapter<T> {
    fn result(&self, line: &str) -> Result<(), String> {
        let command = parse::<ResultCommand>(line)?;
        let client = self.client()?;
        let resulted = client
            .result(command.binding)
            .map_err(|error| error.to_string())?;
        emit(match resulted {
            Resulted::Result { state, output } => {
                json!({"event": "result", "state": state, "output": output})
            }
            Resulted::Rejected { reason } => json!({
                "event": "rejected",
                "verb": "result",
                "operation_id": Value::Null,
                "reason": reason,
            }),
        });
        Ok(())
    }
}

impl<T: Transport + Clone> Adapter<T> {
    fn actions(&self, line: &str) -> Result<(), String> {
        let command = parse::<ActionsCommand>(line)?;
        let client = self.client()?;
        let listed = client
            .actions(command.binding)
            .map_err(|error| error.to_string())?;
        emit(match listed {
            ActionsListed::Actions { state, pending } => {
                json!({"event": "actions", "state": state, "pending": pending})
            }
            ActionsListed::Rejected { reason } => json!({
                "event": "rejected",
                "verb": "actions",
                "operation_id": Value::Null,
                "reason": reason,
            }),
        });
        Ok(())
    }

    fn answer(&self, line: &str) -> Result<(), String> {
        let command = parse::<AnswerCommand>(line)?;
        if !command.decision.answerable() {
            return Err("an answer's decision is approved or denied".to_owned());
        }
        let client = self.client()?;
        let applied = client
            .answer(
                command.binding,
                command.operation_id,
                command.request,
                command.decision,
                command.note,
            )
            .map_err(|error| error.to_string())?;
        emit(match applied {
            AnswerApplied::Answered { action, decision } => json!({
                "event": "answered",
                "operation_id": command.operation_id,
                "request": action,
                "decision": decision,
            }),
            AnswerApplied::Rejected { reason } => json!({
                "event": "rejected",
                "verb": "answer",
                "operation_id": command.operation_id,
                "reason": reason,
            }),
        });
        Ok(())
    }
}

fn parse<'de, C: Deserialize<'de>>(line: &'de str) -> Result<C, String> {
    serde_json::from_str(line).map_err(|error| format!("malformed command: {error}"))
}
