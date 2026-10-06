//! Local Ward node service executable.
//!
//! `ward-node --socket <path> --state-dir <dir> --node-id <node_…> [--trusted-issuers <file>]
//! [--task-root <dir>] [--network-allowlist [--credentials <file>]] [--output-return]
//! [--action-channel [--approval-hold]] [--cgroup-root <dir>] [--max-running <n> [--memory-floor <bytes>] [--disk-floor <bytes>]]
//! [--agent-adapter <id>…] [--agent-shim <file>] [--client-uid <uid>]… [--client-group <group>]
//! [--listen-tls <addr> --tls-cert <file> --tls-key <file> --tls-client-ca <file> [--tls-client-pin <pin>]… [--tls-client-revoked <file>]]`
//! serves the local node protocol. `--node-id` is this node's
//! audience identity; the state directory pins it at first start and holds the durable
//! admission version, revocation and retired-attempt stores, one record per registered task
//! (`tasks`, from which a restarted node recovers its registry) and the node's snapshot
//! store (`cas`). Without
//! `--trusted-issuers` no issuer is trusted and every `admit` is refused; with it, each
//! trusted key is bound to the one issuing principal (`prn_…`) whose leases it may sign. With
//! `--task-root` (created mode 0700, refused if group- or world-accessible) the node starts
//! and stops admitted tasks in a bubblewrap sandbox over workspaces it allocates there; it
//! refuses to run when the sandbox is unavailable. With `--network-allowlist` as well, a
//! manifest naming `network.custom` is honoured through a per-attempt egress proxy and the
//! node advertises `network.proxy_allowlist`; without it such a manifest is refused
//! `unsupported_grant`. With `--output-return` as well, a manifest's `output` grant is
//! honoured: the node keeps the head of the workload's stdout and stderr, collects the
//! declared workspace files once the attempt has ended, stores the bounded result beside
//! the workspace and returns it through `result`, advertising `output`; without it such a
//! manifest is refused `unsupported_grant`. With `--action-channel` as well, a manifest's
//! `actions` grant is honoured: the attempt gets its own action channel, a socket bound
//! into the sandbox at `/run/ward/actions.sock` and named by `WARD_ACTION_SOCKET`, on which
//! the workload asks and the node records, relays and answers; the control plane reads the
//! pending requests with `actions` and answers them with `answer`, and the node advertises
//! `actions`; without it such a manifest is refused `unsupported_grant`. With
//! `--approval-hold` as well (it needs `--action-channel` and `--network-allowlist`), a
//! manifest's `hold` is honoured: the first request the attempt's egress proxy sees for a
//! held host or credential service opens an approval request on the action channel, and
//! the proxy refuses that capability with a named `403` until the control plane's approval
//! of that request is recorded; the node advertises `actions.hold`, and without the flag
//! such a manifest is refused `unsupported_grant`. With `--credentials`
//! as well (it needs `--network-allowlist`), the operator's credentials file names the
//! providers and services the node brokers: a manifest's `credentials` grant for a
//! configured service gets a short-lived lease, bounded by the attempt, that the attempt's
//! egress proxy injects into requests for that service's host only, never into the
//! sandbox, and that is revoked at its provider when the attempt ends; the node advertises
//! `credentials`, and without the flag such a manifest is refused `unsupported_grant`. With `--cgroup-root`
//! as well, every attempt runs in a cgroup of its own under that delegated cgroup v2
//! directory, a manifest's `resources` limits are enforced there and what each attempt used
//! is recorded in its task record and evidence log; without it such a manifest is refused
//! `unsupported_grant`. With `--max-running` as well, at most that many attempts execute at
//! once and a `start` past it, or below `--memory-floor` or `--disk-floor`, is refused
//! `capacity_exhausted` with the task still `ready`. With `--agent-adapter` (`claude-code`,
//! `codex` or `process`, repeatable) as well, a workload naming that adapter runs through
//! the shared adapter contract: its command line, environment and settings files on top of
//! exactly the sandbox, proxy and credentials its manifest grants, its hook lines recorded
//! as agent-origin claims; the node advertises `adapters`, and without the flag such a
//! workload is refused `unsupported_grant`. With `--agent-shim` (it needs `--agent-adapter`
//! or `--network-allowlist`), the operator's `ward-agent` shim, verified at start, runs every
//! hosted adapter's attempt and every attempt behind an egress proxy: a hosted adapter's
//! command hooks reach the hook socket and, behind an egress proxy, its loopback relay
//! forwards to the attempt's proxy with the proxy variables naming it, so a stock HTTP client
//! such as `git` reaches the allowlist and the credential routes; a hosted adapter's
//! provider base URL points at the relay only for a provider the manifest grants a
//! credential for. The socket is served to the node's own
//! uid and to each `--client-uid` (a uid or user name); every other peer is closed without
//! a response. With `--client-group` the socket is created mode 0660 owned by that group,
//! in a directory owned by it with mode 0750 or stricter, so a client of another uid can
//! connect at all; without it the socket is mode 0600 in a 0700 directory as before.
//! With `--listen-tls` the node also serves the same protocol on that TCP address over TLS
//! 1.3 with a mandatory client certificate (ADR-0038): its own certificate and key
//! (`--tls-cert`, `--tls-key`), the CA its clients' certificates must chain to
//! (`--tls-client-ca`) and, optionally, the client keys it serves (`--tls-client-pin`) and
//! those it refuses all the same (`--tls-client-revoked`); the certificate takes the place
//! of the peer-credential check, not of an issuer signature.
//!
//! `ward-node snapshot import --state-dir <dir> <project-dir>` captures a local directory
//! into the node's snapshot store and prints its id as 64 lowercase hex characters with no
//! prefix: exactly the value an admission envelope's `workload.snapshot` carries.
//! `ward-node issuer-key-id <hex-public-key>` prints the key id an issuer proof must name
//! for that Ed25519 public key. `ward-node audit --state-dir <dir> <task_…> [--attempt
//! <exec_…>] [--task-root <dir>] [--json]` answers, from the task's durable record, who
//! delegated what authority to the task and when, and with `--task-root` cross-checks the
//! attempt's evidence log; it exits non-zero when the record cannot be read or the
//! evidence disagrees with it. `ward-node --version` prints the version, followed by
//! `(test-loopback)` in a build with that feature, which no shipped `ward-node` has.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{ArgGroup, Parser, Subcommand};
use nix::sys::signal::SigSet;
use ward_events::{ExecutionAttemptId, NodeId, TaskId};
use ward_node::admit::{NodeAdmission, SystemClock};
use ward_node::capsule::CapsuleBackend;
use ward_node::cgroup::{CgroupLauncher, CgroupRoot, ResourceEnforcement};
use ward_node::credentials::NodeCredentials;
use ward_node::execution::{NodeExecution, SandboxLauncher};
use ward_node::issuer::{IssuerKeyParseError, IssuerPublicKey, TrustedIssuers};
use ward_node::peer::{ClientGroup, ClientUids};
use ward_node::scheduling::SchedulingLimits;
use ward_node::shim::AgentShim;
use ward_node::state::{NodeState, open_private_dir};
use ward_node::tls::{
    ClientPins, NodeTls, TlsListener, TlsSources, block_hangup, reload_on_hangup,
};
use ward_node::workspace::{TaskRoot, import_snapshot, open_snapshot_store};
use ward_node::{NodeService, SocketAccess, serve_node};
use ward_node_protocol::{
    AdapterCapabilities, CredentialCapabilities, ExecutionBackendCapabilities, HostedAdapter,
    IsolationCapabilities, LifecycleCapabilities, NamespaceCapabilities, NetworkCapabilities,
    NodeArchitecture, NodeCapabilities, NodeCapacity, ProtocolVersion, SnapshotCapabilities,
    VerifierCapabilities,
};

/// What `--version` prints after the name: a `test-loopback` build says it is one.
#[cfg(not(feature = "test-loopback"))]
const VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(feature = "test-loopback")]
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (test-loopback)");

#[derive(Parser)]
#[command(name = "ward-node", version = VERSION, subcommand_negates_reqs = true)]
#[command(group(ArgGroup::new("shim_runs").multiple(true).args(["agent_adapter", "network_allowlist"])))]
#[allow(clippy::struct_excessive_bools)] // one flag per operator-enabled capability
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Local administrative Unix socket. This path is never mounted into a task sandbox.
    #[arg(long, required = true)]
    socket: Option<PathBuf>,
    /// Private node state directory (created mode 0700): pinned node id, last accepted
    /// admission version per task, known revocations, retired execution attempts and one
    /// record per registered task.
    #[arg(long, required = true)]
    state_dir: Option<PathBuf>,
    /// This node's identity (`node_…`), the only audience it admits envelopes for.
    #[arg(long, required = true)]
    node_id: Option<NodeId>,
    /// Trusted issuers: one `<public-key> [<key-id>] <prn_…>` per line, binding a lowercase
    /// hex Ed25519 key to the one principal it may issue leases as; `#` comments allowed.
    /// Without it no issuer is trusted and every `admit` is refused.
    #[arg(long)]
    trusted_issuers: Option<PathBuf>,
    /// Private task root (created mode 0700) under which the node allocates each attempt's
    /// workspace. With it the node starts and stops admitted tasks; without it, it does not.
    #[arg(long)]
    task_root: Option<PathBuf>,
    /// Honour a manifest's `network.custom` host allowlist by running the workload behind a
    /// node-owned egress proxy allowing exactly those hosts (private ranges and the metadata
    /// endpoint always refused), and advertise `network.proxy_allowlist`. Needs
    /// `--task-root`. Without it every `network.custom` manifest is refused
    /// `unsupported_grant`.
    #[arg(long, requires = "task_root")]
    network_allowlist: bool,
    /// Honour a manifest's `output` grant: keep the first `stdio_bytes` of the workload's
    /// stdout and stderr, collect the declared workspace files once the attempt has ended
    /// (relative paths only, nothing followed outside the workspace, bounded), store the
    /// result beside the workspace and return it through `result`; advertise `output`.
    /// Needs `--task-root`. Without it every manifest with `output` is refused
    /// `unsupported_grant`.
    #[arg(long, requires = "task_root")]
    output_return: bool,
    /// Honour a manifest's `actions` grant: give the attempt its own action channel (a
    /// socket bound into the sandbox, beside the workspace on the host), relay each bounded
    /// request to the control plane (`actions`), record it and every answer (`answer`), the
    /// node's `expired` and `cancelled` included, in the attempt's evidence log, and
    /// advertise `actions`. An approval is a recorded statement, not a capability the node
    /// enforces. Needs `--task-root`. Without it every manifest with `actions` is refused
    /// `unsupported_grant`.
    #[arg(long, requires = "task_root")]
    action_channel: bool,
    /// Honour a manifest's `hold`: the first request the attempt's egress proxy sees for a
    /// held host or credential service opens an approval request on the attempt's action
    /// channel, and the proxy refuses that capability with a named `403` until the control
    /// plane's approval of that request is recorded; a denial, an expiry or the attempt's
    /// end keep it refused. Advertise `actions.hold`. Needs `--action-channel` and
    /// `--network-allowlist`. Without it every manifest with `hold` is refused
    /// `unsupported_grant`.
    #[arg(long, requires_all = ["action_channel", "network_allowlist"])]
    approval_hold: bool,
    /// Broker credentials to admitted workloads: a TOML file of the operator's (the node
    /// user's own, writable by no one else) naming credential providers and the services
    /// they back. A manifest's `credentials` grant for a configured service gets a
    /// short-lived lease, bounded by the attempt, that the attempt's egress proxy injects
    /// into requests for the service's host only; the secret never enters the sandbox, and
    /// every lease is revoked at its provider when the attempt ends. Advertise
    /// `credentials`. Needs `--network-allowlist`. Without it every manifest with
    /// `credentials` is refused `unsupported_grant`.
    #[arg(long, value_name = "FILE", requires = "network_allowlist")]
    credentials: Option<PathBuf>,
    /// A cgroup v2 directory delegated to the node (writable by its uid, with no process of
    /// its own): every attempt runs in a cgroup of its own under it, its manifest's
    /// `resources` limits are enforced there (`cpu.max`, `memory.max` with no swap,
    /// `pids.max`, for the controllers the directory offers) and what it used is recorded;
    /// advertise `resources`. Needs `--task-root`. Without it every manifest with
    /// `resources` is refused `unsupported_grant`.
    #[arg(long, value_name = "DIR", requires = "task_root")]
    cgroup_root: Option<PathBuf>,
    /// Execute at most this many attempts at once (1 to 1024); a `start` past it is refused
    /// `capacity_exhausted` with the task still `ready`; advertise `scheduling`. Needs
    /// `--task-root`. Without it the node bounds nothing.
    #[arg(
        long,
        value_name = "N",
        requires = "task_root",
        value_parser = clap::value_parser!(u32).range(1..=1024)
    )]
    max_running: Option<u32>,
    /// Refuse a `start` `capacity_exhausted` while the host's available memory
    /// (`MemAvailable`) is below this many bytes. Needs `--max-running`.
    #[arg(long, value_name = "BYTES", requires = "max_running")]
    memory_floor: Option<u64>,
    /// Refuse a `start` `capacity_exhausted` while the task root's filesystem has fewer
    /// than this many bytes available. Needs `--max-running`.
    #[arg(long, value_name = "BYTES", requires = "max_running")]
    disk_floor: Option<u64>,
    /// Host this agent adapter (`claude-code`, `codex` or `process`; repeatable) on
    /// workloads that name it: the node launches the workload's argv through the adapter
    /// contract, adding the adapter's environment and settings files and, for an adapter
    /// with hooks, a hook socket whose lines are recorded as agent-origin claims, never
    /// anything its manifest does not grant; advertise `adapters`. Needs `--task-root`.
    /// Without it every workload naming an adapter is refused `unsupported_grant`.
    #[arg(
        long = "agent-adapter",
        value_name = "ID",
        requires = "task_root",
        value_parser = parse_adapter
    )]
    agent_adapter: Vec<HostedAdapter>,
    /// The operator's `ward-agent` shim (an absolute path to a regular file, executable,
    /// owned by root or the node's user and writable by no one else), verified at start.
    /// Every hosted adapter's attempt and every attempt behind an egress proxy runs under
    /// it, bound read-only at `/run/ward/ward-agent`: a hosted adapter's command hooks run
    /// it against the hook socket, and behind an egress proxy its relay on 127.0.0.1:3128
    /// forwards to the attempt's proxy and the proxy variables name it, with a hosted
    /// adapter's provider base URL pointing at it for a provider the manifest grants a
    /// credential for. Needs `--agent-adapter` or `--network-allowlist`. Without it no
    /// shim is bound and no relay runs.
    #[arg(long = "agent-shim", value_name = "FILE", requires = "shim_runs")]
    agent_shim: Option<PathBuf>,
    /// A uid, or user name, served on the socket besides the node's own; repeatable. Any
    /// other peer is closed without a response. Being served grants no authority: `admit`
    /// still needs a trusted signature.
    #[arg(long = "client-uid", value_name = "UID")]
    client_uid: Vec<String>,
    /// Share the socket with this group (a gid or group name): the socket is created mode
    /// 0660 owned by it, and its parent directory must be owned by it with mode 0750 or
    /// stricter. Needs at least one `--client-uid`. Without it the socket is mode 0600.
    #[arg(long, value_name = "GROUP", requires = "client_uid")]
    client_group: Option<String>,
    /// Also serve the protocol on this TCP address (`<ip>:<port>`) over TLS 1.3 with a
    /// mandatory client certificate chained to `--tls-client-ca`. The certificate takes
    /// the place of the socket's peer-credential check; `admit` still needs a trusted
    /// signature. Needs `--tls-cert`, `--tls-key` and `--tls-client-ca`.
    #[arg(
        long,
        value_name = "ADDR",
        requires_all = ["tls_cert", "tls_key", "tls_client_ca"]
    )]
    listen_tls: Option<SocketAddr>,
    /// The node's certificate chain, leaf first, in PEM: the node user's own regular file,
    /// writable by no one else. Needs `--listen-tls`.
    #[arg(long, value_name = "FILE", requires = "listen_tls")]
    tls_cert: Option<PathBuf>,
    /// The node's private key in PEM, matching `--tls-cert`: the node user's own regular
    /// file with no group or other permission bits. Needs `--listen-tls`.
    #[arg(long, value_name = "FILE", requires = "listen_tls")]
    tls_key: Option<PathBuf>,
    /// The CA certificates, in PEM, a client's certificate must chain to (for client
    /// authentication): the node user's own regular file, writable by no one else. Needs
    /// `--listen-tls`.
    #[arg(long, value_name = "FILE", requires = "listen_tls")]
    tls_client_ca: Option<PathBuf>,
    /// Serve only the client keys pinned here (`sha256:` and the 64 lowercase hex digits
    /// of the SHA-256 of the certificate's DER `SubjectPublicKeyInfo`); repeatable. Without
    /// it every key the client CA certified is served. Needs `--listen-tls`.
    #[arg(long, value_name = "PIN", requires = "listen_tls")]
    tls_client_pin: Vec<String>,
    /// Refuse the client keys listed in this file, even when pinned: one pin per line as
    /// `--tls-client-pin` spells it, `#` starting a comment; the node user's own regular
    /// file, writable by no one else. Needs `--listen-tls`.
    #[arg(long, value_name = "FILE", requires = "listen_tls")]
    tls_client_revoked: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Print the issuer key id (BLAKE3 of the public key) for a hex Ed25519 public key.
    IssuerKeyId {
        /// The 32-byte Ed25519 public key as 64 lowercase hex characters.
        public_key: String,
    },
    /// Manage the node's content-addressed snapshot store.
    Snapshot {
        /// The snapshot operation.
        #[command(subcommand)]
        command: SnapshotCommand,
    },
    /// Answer who delegated what authority to a task and when, from its durable record.
    Audit {
        /// The node state directory holding the task records.
        #[arg(long)]
        state_dir: PathBuf,
        /// The node's task root; with it the attempt's evidence log is verified and
        /// cross-checked against the record, and a disagreement exits non-zero.
        #[arg(long)]
        task_root: Option<PathBuf>,
        /// The execution attempt (`exec_…`) the record must hold; any other is an error.
        #[arg(long)]
        attempt: Option<ExecutionAttemptId>,
        /// Print the audit as one JSON object (`"schema":1`) instead of text.
        #[arg(long)]
        json: bool,
        /// The task (`task_…`) to audit.
        task: TaskId,
    },
}

#[derive(Subcommand)]
enum SnapshotCommand {
    /// Capture a local directory into the node's snapshot store and print its id: 64
    /// lowercase hex characters, exactly the envelope's `workload.snapshot` value.
    Import {
        /// Private node state directory (created mode 0700) holding the store.
        #[arg(long)]
        state_dir: PathBuf,
        /// The project directory to capture.
        project_dir: PathBuf,
    },
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut cli = Cli::parse();
    if let Some(command) = cli.command.take() {
        return run(command);
    }
    let hangup = cli.listen_tls.map(|_| block_hangup()).transpose()?;
    let remote = cli
        .listen_tls
        .map(|addr| load_tls(&cli, addr))
        .transpose()?;
    let (Some(socket), Some(state_dir), Some(node_id)) = (cli.socket, cli.state_dir, cli.node_id)
    else {
        return Err(io::Error::other("--socket, --state-dir and --node-id are required").into());
    };

    let clients = ClientUids::parse(&cli.client_uid)?;
    let client_group = cli
        .client_group
        .as_deref()
        .map(ClientGroup::parse)
        .transpose()?;
    let issuers = match cli.trusted_issuers {
        Some(path) => TrustedIssuers::load(&path)?,
        None => TrustedIssuers::empty(),
    };
    let task_root = cli
        .task_root
        .map(|dir| {
            TaskRoot::open(&dir)
                .map_err(|error| io::Error::other(format!("task root {}: {error}", dir.display())))
        })
        .transpose()?;
    if task_root.is_some() && !SandboxLauncher::available() {
        return Err(io::Error::other(
            "task root configured but the bubblewrap sandbox is unavailable on this host",
        )
        .into());
    }
    let agent_shim = cli
        .agent_shim
        .as_deref()
        .zip(task_root.as_ref())
        .map(|(path, root)| {
            AgentShim::verify(path, root.dir()).map_err(|error| io::Error::other(error.to_string()))
        })
        .transpose()?;
    let cgroups = cli
        .cgroup_root
        .as_deref()
        .map(|dir| CgroupRoot::open(dir).map(Arc::new))
        .transpose()?;
    let scheduling = cli
        .max_running
        .map(|max_running| {
            SchedulingLimits::new(
                max_running,
                cli.memory_floor.unwrap_or(0),
                cli.disk_floor.unwrap_or(0),
            )
            .ok_or_else(|| io::Error::other("--max-running must be between 1 and 1024"))
        })
        .transpose()?;
    let credentials = cli
        .credentials
        .as_deref()
        .map(|path| NodeCredentials::load(path).map(Arc::new))
        .transpose()?;
    let state = NodeState::open(&state_dir, node_id)?;
    let admission = NodeAdmission::new(issuers, state, Box::new(SystemClock));
    let capabilities = conservative_host_capabilities()?;
    let service = match task_root {
        Some(task_root) => {
            let backend: Arc<dyn CapsuleBackend> = match &cgroups {
                Some(root) => Arc::new(CgroupLauncher::new(Arc::clone(root))),
                None => Arc::new(SandboxLauncher),
            };
            let enforcement = cgroups
                .as_ref()
                .map(|root| ResourceEnforcement::new(root.enforces(), capabilities.capacity()));
            NodeService::with_execution(
                capabilities,
                admission,
                NodeExecution::new(task_root, open_snapshot_store(&state_dir)?, backend)
                    .with_network_allowlist(cli.network_allowlist)
                    .with_output_return(cli.output_return)
                    .with_action_channel(cli.action_channel)
                    .with_approval_hold(cli.approval_hold)
                    .with_credentials(credentials)
                    .with_resource_enforcement(enforcement)
                    .with_scheduling(scheduling)
                    .with_agent_adapters(AdapterCapabilities::hosting(cli.agent_adapter))
                    .with_agent_shim(agent_shim),
            )?
        }
        None => NodeService::with_admission(capabilities, admission)?,
    };
    let access = SocketAccess::new(client_group, clients);
    serve_node(&socket, &service, access, bind_tls(remote, hangup)?)?;
    Ok(ExitCode::SUCCESS)
}

/// Bind the TLS listener, if any, and reload its configuration on every `SIGHUP`.
fn bind_tls(
    remote: Option<(NodeTls, SocketAddr)>,
    hangup: Option<SigSet>,
) -> io::Result<Option<TlsListener>> {
    let Some((tls, addr)) = remote else {
        return Ok(None);
    };
    let listener = tls
        .bind(addr)
        .map_err(|error| io::Error::other(format!("TLS listener {addr}: {error}")))?;
    if let Some(hangup) = hangup {
        reload_on_hangup(listener.reloader(), hangup)?;
    }
    Ok(Some(listener))
}

fn load_tls(cli: &Cli, addr: SocketAddr) -> io::Result<(NodeTls, SocketAddr)> {
    let (Some(cert), Some(key), Some(client_ca)) =
        (&cli.tls_cert, &cli.tls_key, &cli.tls_client_ca)
    else {
        return Err(io::Error::other(
            "--listen-tls needs --tls-cert, --tls-key and --tls-client-ca",
        ));
    };
    let tls = ClientPins::parse(&cli.tls_client_pin)
        .and_then(|client_pins| {
            NodeTls::load(TlsSources {
                cert: cert.clone(),
                key: key.clone(),
                client_ca: client_ca.clone(),
                client_pins,
                client_revoked: cli.tls_client_revoked.clone(),
            })
        })
        .map_err(|error| io::Error::other(format!("TLS: {error}")))?;
    Ok((tls, addr))
}

fn parse_adapter(id: &str) -> Result<HostedAdapter, String> {
    HostedAdapter::from_id(id).ok_or_else(|| {
        let known: Vec<&str> = HostedAdapter::ALL.iter().map(|a| a.id()).collect();
        format!("no such adapter `{id}` (known: {})", known.join(", "))
    })
}

fn run(command: Command) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match command {
        Command::IssuerKeyId { public_key } => {
            println!("{}", issuer_key_id(&public_key)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Snapshot {
            command:
                SnapshotCommand::Import {
                    state_dir,
                    project_dir,
                },
        } => {
            println!("{}", import(&state_dir, &project_dir)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Audit {
            state_dir,
            task_root,
            attempt,
            json,
            task,
        } => audit(&state_dir, task, attempt, task_root.as_deref(), json),
    }
}

fn audit(
    state_dir: &Path,
    task: TaskId,
    attempt: Option<ExecutionAttemptId>,
    task_root: Option<&Path>,
    json: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let audit = match ward_node::audit::audit(state_dir, task, attempt, task_root) {
        Ok(audit) => audit,
        Err(error) => {
            eprintln!("ward-node audit: {error}");
            return Ok(ExitCode::FAILURE);
        }
    };
    if json {
        println!("{}", serde_json::to_string(&audit)?);
    } else {
        print!("{audit}");
    }
    Ok(if audit.evidence_agrees() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn import(state_dir: &Path, project_dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    open_private_dir(state_dir)?;
    let snapshots = open_snapshot_store(state_dir)?;
    Ok(import_snapshot(&snapshots, project_dir)?.hash().to_hex())
}

fn issuer_key_id(public_key: &str) -> Result<String, IssuerKeyParseError> {
    IssuerPublicKey::from_hex(public_key).map(|key| key.key_id().to_hex())
}

fn conservative_host_capabilities() -> Result<NodeCapabilities, Box<dyn std::error::Error>> {
    let architecture = match std::env::consts::ARCH {
        "x86_64" => NodeArchitecture::X86_64,
        "aarch64" => NodeArchitecture::Aarch64,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported ward-node architecture: {other}"),
            )
            .into());
        }
    };

    let logical_cpus = u16::try_from(std::thread::available_parallelism()?.get())
        .map_err(|_| io::Error::other("logical CPU count exceeds protocol capacity"))?;
    let capacity = NodeCapacity::new(logical_cpus, total_memory_bytes()?)
        .map_err(|error| io::Error::other(error.to_string()))?;

    NodeCapabilities::new(
        ProtocolVersion::new(1, 1),
        architecture,
        capacity,
        IsolationCapabilities {
            namespaces: NamespaceCapabilities::default(),
            backends: ExecutionBackendCapabilities::default(),
        },
        NetworkCapabilities::default(),
        CredentialCapabilities::default(),
        SnapshotCapabilities::default(),
        VerifierCapabilities::default(),
        LifecycleCapabilities::default(),
    )
    .map_err(|error| io::Error::other(error.to_string()).into())
}

fn total_memory_bytes() -> io::Result<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo")?;
    let line = meminfo
        .lines()
        .find(|line| line.starts_with("MemTotal:"))
        .ok_or_else(|| io::Error::other("MemTotal is absent from /proc/meminfo"))?;
    let kibibytes = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::other("MemTotal has no numeric value"))?
        .parse::<u64>()
        .map_err(|_| io::Error::other("MemTotal is not a u64"))?;

    kibibytes
        .checked_mul(1024)
        .ok_or_else(|| io::Error::other("MemTotal overflows bytes"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn meminfo_parser_source_reports_nonzero_host_memory() {
        assert!(total_memory_bytes().expect("Linux MemTotal") > 0);
    }

    #[test]
    fn version_names_a_test_loopback_build() {
        let version = <Cli as clap::CommandFactory>::command().render_version();
        let expected = if cfg!(feature = "test-loopback") {
            format!("ward-node {} (test-loopback)\n", env!("CARGO_PKG_VERSION"))
        } else {
            format!("ward-node {}\n", env!("CARGO_PKG_VERSION"))
        };
        assert_eq!(version, expected);
    }

    #[test]
    fn issuer_key_id_is_the_blake3_hash_of_the_public_key() {
        let key = [0x5a_u8; 32];
        let hex = "5a".repeat(32);
        assert_eq!(
            issuer_key_id(&hex).expect("valid key"),
            ward_events::Blake3Hash::hash(&key).to_hex()
        );
        assert!(issuer_key_id("not-a-key").is_err());
    }

    #[test]
    fn serving_requires_socket_state_dir_and_node_id_but_the_helper_does_not() {
        let node = NodeId::from_u128(4).to_string();
        assert!(Cli::try_parse_from(["ward-node", "--socket", "s"]).is_err());
        assert!(Cli::try_parse_from(["ward-node", "--socket", "s", "--state-dir", "d"]).is_err());
        assert!(
            Cli::try_parse_from([
                "ward-node",
                "--socket",
                "s",
                "--state-dir",
                "d",
                "--node-id",
                "node-4",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "ward-node",
            "--socket",
            "s",
            "--state-dir",
            "d",
            "--node-id",
            &node,
            "--trusted-issuers",
            "t",
        ])
        .expect("serve arguments");
        assert_eq!(cli.node_id, Some(NodeId::from_u128(4)));
        assert!(cli.command.is_none());

        let cli = Cli::try_parse_from(["ward-node", "issuer-key-id", "00"]).expect("helper");
        assert!(matches!(cli.command, Some(Command::IssuerKeyId { .. })));
    }

    #[test]
    fn an_approval_hold_needs_the_action_channel_and_the_allowlist() {
        let node = NodeId::from_u128(4).to_string();
        let serve = [
            "ward-node",
            "--socket",
            "s",
            "--state-dir",
            "d",
            "--node-id",
            &node,
            "--task-root",
            "t",
        ];
        let cli = Cli::try_parse_from(serve.iter().copied().chain([
            "--network-allowlist",
            "--action-channel",
            "--approval-hold",
        ]))
        .expect("serve holding approval-gated capabilities");
        assert!(cli.approval_hold && cli.action_channel && cli.network_allowlist);
        for without in [
            ["--action-channel", "--approval-hold"],
            ["--network-allowlist", "--approval-hold"],
        ] {
            assert!(
                Cli::try_parse_from(serve.iter().copied().chain(without)).is_err(),
                "a hold needs the action channel and the allowlist: {without:?}"
            );
        }
    }

    #[test]
    fn an_agent_shim_is_the_operators_file_and_needs_a_hosted_adapter_or_an_allowlist() {
        let node = NodeId::from_u128(4).to_string();
        let serve = [
            "ward-node",
            "--socket",
            "s",
            "--state-dir",
            "d",
            "--node-id",
            &node,
            "--task-root",
            "t",
        ];
        let parse = |extra: &[&str]| Cli::try_parse_from(serve.iter().chain(extra));
        let cli = parse(&[
            "--agent-adapter",
            "claude-code",
            "--agent-shim",
            "/usr/libexec/ward-agent",
        ])
        .expect("a shim for a hosted adapter");
        assert_eq!(
            cli.agent_shim,
            Some(PathBuf::from("/usr/libexec/ward-agent"))
        );
        assert_eq!(
            parse(&["--agent-adapter", "codex"])
                .expect("no shim")
                .agent_shim,
            None
        );
        assert_eq!(
            parse(&[
                "--network-allowlist",
                "--agent-shim",
                "/usr/libexec/ward-agent"
            ])
            .expect("a shim for the relay of a plain workload")
            .agent_shim,
            Some(PathBuf::from("/usr/libexec/ward-agent"))
        );
        let refused = parse(&["--agent-shim", "/usr/libexec/ward-agent"])
            .err()
            .expect("a shim with nothing to run")
            .to_string();
        assert!(
            refused.contains("--agent-adapter") && refused.contains("--network-allowlist"),
            "{refused}"
        );
    }

    #[test]
    fn agent_adapters_are_named_by_id_and_need_a_task_root() {
        let node = NodeId::from_u128(4).to_string();
        let serve = [
            "ward-node",
            "--socket",
            "s",
            "--state-dir",
            "d",
            "--node-id",
            &node,
        ];
        let parse = |extra: &[&str]| Cli::try_parse_from(serve.iter().chain(extra));
        let cli = parse(&[
            "--task-root",
            "t",
            "--agent-adapter",
            "codex",
            "--agent-adapter",
            "claude-code",
        ])
        .expect("adapters with a task root");
        assert_eq!(
            cli.agent_adapter,
            [HostedAdapter::Codex, HostedAdapter::ClaudeCode]
        );
        assert_eq!(
            AdapterCapabilities::hosting(cli.agent_adapter)
                .expect("two hosted")
                .hosted(),
            [HostedAdapter::ClaudeCode, HostedAdapter::Codex]
        );
        assert!(
            parse(&["--agent-adapter", "codex"]).is_err(),
            "needs --task-root"
        );
        let unknown = parse(&["--task-root", "t", "--agent-adapter", "gemini-cli"])
            .err()
            .expect("an unknown adapter is refused");
        assert!(
            unknown.to_string().contains("claude-code, codex, process"),
            "{unknown}"
        );
        assert!(
            parse(&["--task-root", "t"])
                .expect("no adapter")
                .agent_adapter
                .is_empty()
        );
    }

    #[test]
    fn task_root_is_optional_and_snapshot_import_needs_a_state_dir() {
        let node = NodeId::from_u128(4).to_string();
        let serve = [
            "ward-node",
            "--socket",
            "s",
            "--state-dir",
            "d",
            "--node-id",
            &node,
        ];
        let cli = Cli::try_parse_from(serve).expect("serve");
        assert_eq!(cli.task_root, None);
        assert!(!cli.network_allowlist);
        let cli = Cli::try_parse_from(serve.iter().copied().chain(["--task-root", "t"]))
            .expect("serve with a task root");
        assert_eq!(cli.task_root, Some(PathBuf::from("t")));
        assert!(!cli.network_allowlist);
        let cli = Cli::try_parse_from(serve.iter().copied().chain([
            "--task-root",
            "t",
            "--network-allowlist",
        ]))
        .expect("serve with a network allowlist");
        assert!(cli.network_allowlist);
        assert!(
            Cli::try_parse_from(serve.iter().copied().chain(["--network-allowlist"])).is_err(),
            "a network allowlist needs a task root"
        );
        let cli = Cli::try_parse_from(serve.iter().copied().chain([
            "--task-root",
            "t",
            "--output-return",
        ]))
        .expect("serve returning output");
        assert!(cli.output_return);
        assert!(!cli.network_allowlist);
        assert!(
            Cli::try_parse_from(serve.iter().copied().chain(["--output-return"])).is_err(),
            "result return needs a task root"
        );
        let cli = Cli::try_parse_from(serve).expect("serve");
        assert!(!cli.output_return);
        assert!(!cli.action_channel);
        let cli = Cli::try_parse_from(serve.iter().copied().chain([
            "--task-root",
            "t",
            "--action-channel",
        ]))
        .expect("serve offering the action channel");
        assert!(cli.action_channel);
        assert!(!cli.output_return && !cli.network_allowlist);
        assert!(
            Cli::try_parse_from(serve.iter().copied().chain(["--action-channel"])).is_err(),
            "the action channel needs a task root"
        );
        assert!(!cli.approval_hold);
        let cli = Cli::try_parse_from(serve.iter().copied().chain([
            "--task-root",
            "t",
            "--network-allowlist",
            "--credentials",
            "c.toml",
        ]))
        .expect("serve brokering credentials");
        assert_eq!(cli.credentials, Some(PathBuf::from("c.toml")));
        assert!(
            Cli::try_parse_from(serve.iter().copied().chain([
                "--task-root",
                "t",
                "--credentials",
                "c.toml",
            ]))
            .is_err(),
            "brokering credentials needs the network allowlist"
        );

        let cli = Cli::try_parse_from(["ward-node", "snapshot", "import", "--state-dir", "d", "p"])
            .expect("import");
        assert!(matches!(
            cli.command,
            Some(Command::Snapshot {
                command: SnapshotCommand::Import { ref state_dir, ref project_dir },
            }) if state_dir == Path::new("d") && project_dir == Path::new("p")
        ));
        assert!(Cli::try_parse_from(["ward-node", "snapshot", "import", "p"]).is_err());
    }

    #[test]
    fn audit_needs_a_state_dir_and_a_task_and_takes_the_rest_optionally() {
        let task = TaskId::from_u128(7).to_string();
        let attempt = ExecutionAttemptId::from_u128(8).to_string();
        let cli =
            Cli::try_parse_from(["ward-node", "audit", "--state-dir", "d", &task]).expect("audit");
        assert!(matches!(
            cli.command,
            Some(Command::Audit {
                ref state_dir,
                task_root: None,
                attempt: None,
                json: false,
                task: parsed,
            }) if state_dir == Path::new("d") && parsed == TaskId::from_u128(7)
        ));
        let cli = Cli::try_parse_from([
            "ward-node",
            "audit",
            "--state-dir",
            "d",
            "--task-root",
            "t",
            "--attempt",
            &attempt,
            "--json",
            &task,
        ])
        .expect("audit with every option");
        assert!(matches!(
            cli.command,
            Some(Command::Audit {
                ref task_root,
                attempt: Some(parsed),
                json: true,
                ..
            }) if task_root.as_deref() == Some(Path::new("t"))
                && parsed == ExecutionAttemptId::from_u128(8)
        ));
        assert!(Cli::try_parse_from(["ward-node", "audit", &task]).is_err());
        assert!(Cli::try_parse_from(["ward-node", "audit", "--state-dir", "d"]).is_err());
        assert!(Cli::try_parse_from(["ward-node", "audit", "--state-dir", "d", "task-7"]).is_err());
        assert!(
            Cli::try_parse_from([
                "ward-node",
                "audit",
                "--state-dir",
                "d",
                "--attempt",
                &task,
                &task
            ])
            .is_err()
        );
    }

    #[test]
    fn client_uids_repeat_and_a_client_group_needs_at_least_one_of_them() {
        let node = NodeId::from_u128(4).to_string();
        let serve = [
            "ward-node",
            "--socket",
            "s",
            "--state-dir",
            "d",
            "--node-id",
            &node,
        ];
        let cli = Cli::try_parse_from(serve).expect("serve");
        assert!(cli.client_uid.is_empty());
        assert_eq!(cli.client_group, None);

        let cli = Cli::try_parse_from(serve.iter().copied().chain([
            "--client-uid",
            "1000",
            "--client-uid",
            "control-plane",
            "--client-group",
            "ward-clients",
        ]))
        .expect("serve with clients");
        assert_eq!(cli.client_uid, ["1000", "control-plane"]);
        assert_eq!(cli.client_group.as_deref(), Some("ward-clients"));

        assert!(Cli::try_parse_from(serve.iter().copied().chain(["--client-group", "g"])).is_err());
        let cli = Cli::try_parse_from(serve.iter().copied().chain(["--client-uid", "0"]))
            .expect("a client uid alone");
        assert_eq!(cli.client_group, None);
    }

    #[test]
    fn a_tls_listener_needs_its_three_files_and_the_files_and_pins_need_the_listener() {
        let node = NodeId::from_u128(4).to_string();
        let serve = [
            "ward-node",
            "--socket",
            "s",
            "--state-dir",
            "d",
            "--node-id",
            &node,
        ];
        let parse = |extra: &[&str]| Cli::try_parse_from(serve.iter().chain(extra));
        let cli = parse(&[]).expect("serve");
        assert_eq!(cli.listen_tls, None);
        assert!(cli.tls_client_pin.is_empty());
        let full = [
            "--listen-tls",
            "0.0.0.0:7443",
            "--tls-cert",
            "c.pem",
            "--tls-key",
            "k.pem",
            "--tls-client-ca",
            "ca.pem",
        ];
        let cli = parse(&full).expect("serve over TLS");
        assert_eq!(cli.listen_tls, "0.0.0.0:7443".parse().ok());
        assert_eq!(cli.tls_cert, Some(PathBuf::from("c.pem")));
        assert_eq!(cli.tls_key, Some(PathBuf::from("k.pem")));
        assert_eq!(cli.tls_client_ca, Some(PathBuf::from("ca.pem")));
        let pinned: Vec<&str> = full
            .iter()
            .copied()
            .chain(["--tls-client-pin", "a", "--tls-client-pin", "b"])
            .collect();
        assert_eq!(
            parse(&pinned).expect("serve with pins").tls_client_pin,
            ["a", "b"]
        );
        for without in [0, 2, 4, 6] {
            let mut partial = full.to_vec();
            partial.drain(without..without + 2);
            assert!(parse(&partial).is_err(), "{partial:?}");
        }
        assert!(parse(&["--tls-client-pin", "a"]).is_err());
        assert_eq!(cli.tls_client_revoked, None);
        let revoked: Vec<&str> = full
            .iter()
            .copied()
            .chain(["--tls-client-revoked", "revoked"])
            .collect();
        assert_eq!(
            parse(&revoked)
                .expect("serve with a revocation list")
                .tls_client_revoked,
            Some(PathBuf::from("revoked"))
        );
        assert!(parse(&["--tls-client-revoked", "revoked"]).is_err());
        let mut named = full;
        named[1] = "localhost:7443";
        assert!(parse(&named).is_err(), "the address is an IP and a port");
    }

    #[test]
    fn cgroups_and_scheduling_need_a_task_root_and_floors_need_a_running_bound() {
        let node = NodeId::from_u128(4).to_string();
        let serve = [
            "ward-node",
            "--socket",
            "s",
            "--state-dir",
            "d",
            "--node-id",
            &node,
        ];
        let cli = Cli::try_parse_from(serve).expect("serve");
        assert_eq!(
            (
                cli.cgroup_root,
                cli.max_running,
                cli.memory_floor,
                cli.disk_floor
            ),
            (None, None, None, None)
        );
        let cli = Cli::try_parse_from(serve.iter().copied().chain([
            "--task-root",
            "t",
            "--cgroup-root",
            "/sys/fs/cgroup/ward",
            "--max-running",
            "25",
            "--memory-floor",
            "1073741824",
            "--disk-floor",
            "0",
        ]))
        .expect("serve with cgroups and scheduling");
        assert_eq!(cli.cgroup_root, Some(PathBuf::from("/sys/fs/cgroup/ward")));
        assert_eq!(cli.max_running, Some(25));
        assert_eq!(cli.memory_floor, Some(1_073_741_824));
        assert_eq!(cli.disk_floor, Some(0));
        for alone in [
            &["--cgroup-root", "c"][..],
            &["--max-running", "2"][..],
            &["--task-root", "t", "--memory-floor", "1"][..],
            &["--task-root", "t", "--disk-floor", "1"][..],
            &["--task-root", "t", "--max-running", "0"][..],
            &["--task-root", "t", "--max-running", "1025"][..],
            &["--task-root", "t", "--max-running", "-1"][..],
        ] {
            assert!(
                Cli::try_parse_from(serve.iter().copied().chain(alone.iter().copied())).is_err(),
                "{alone:?}"
            );
        }
    }
}
