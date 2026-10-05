//! Local Ward node service executable.
//!
//! `ward-node --socket <path> --state-dir <dir> --node-id <node_…> [--trusted-issuers <file>]
//! [--task-root <dir>]` serves the local node protocol. `--node-id` is this node's
//! audience identity; the state directory pins it at first start and holds the durable
//! admission version, revocation and retired-attempt stores, one record per registered task
//! (`tasks`, from which a restarted node recovers its registry) and the node's snapshot
//! store (`cas`). Without
//! `--trusted-issuers` no issuer is trusted and every `admit` is refused; with it, each
//! trusted key is bound to the one issuing principal (`prn_…`) whose leases it may sign. With
//! `--task-root` (created mode 0700, refused if group- or world-accessible) the node starts
//! and stops admitted tasks in a bubblewrap sandbox over workspaces it allocates there; it
//! refuses to run when the sandbox is unavailable.
//!
//! `ward-node snapshot import --state-dir <dir> <project-dir>` captures a local directory
//! into the node's snapshot store and prints its id as 64 lowercase hex characters with no
//! prefix: exactly the value an admission envelope's `workload.snapshot` carries.
//! `ward-node issuer-key-id <hex-public-key>` prints the key id an issuer proof must name
//! for that Ed25519 public key.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ward_events::NodeId;
use ward_node::admit::{NodeAdmission, SystemClock};
use ward_node::execution::{NodeExecution, SandboxLauncher};
use ward_node::issuer::{IssuerKeyParseError, IssuerPublicKey, TrustedIssuers};
use ward_node::state::{NodeState, open_private_dir};
use ward_node::workspace::{TaskRoot, import_snapshot, open_snapshot_store};
use ward_node::{NodeService, serve_local};
use ward_node_protocol::{
    CredentialCapabilities, ExecutionBackendCapabilities, IsolationCapabilities,
    LifecycleCapabilities, NamespaceCapabilities, NetworkCapabilities, NodeArchitecture,
    NodeCapabilities, NodeCapacity, ProtocolVersion, SnapshotCapabilities, VerifierCapabilities,
};

#[derive(Parser)]
#[command(name = "ward-node", subcommand_negates_reqs = true)]
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::IssuerKeyId { public_key }) => {
            println!("{}", issuer_key_id(&public_key)?);
            return Ok(());
        }
        Some(Command::Snapshot {
            command:
                SnapshotCommand::Import {
                    state_dir,
                    project_dir,
                },
        }) => {
            println!("{}", import(&state_dir, &project_dir)?);
            return Ok(());
        }
        None => {}
    }
    let (Some(socket), Some(state_dir), Some(node_id)) = (cli.socket, cli.state_dir, cli.node_id)
    else {
        return Err(io::Error::other("--socket, --state-dir and --node-id are required").into());
    };

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
    let state = NodeState::open(&state_dir, node_id)?;
    let admission = NodeAdmission::new(issuers, state, Box::new(SystemClock));
    let capabilities = conservative_host_capabilities()?;
    let service = match task_root {
        Some(task_root) => NodeService::with_execution(
            capabilities,
            admission,
            NodeExecution::new(
                task_root,
                open_snapshot_store(&state_dir)?,
                Arc::new(SandboxLauncher),
            ),
        )?,
        None => NodeService::with_admission(capabilities, admission)?,
    };
    serve_local(&socket, &service)?;
    Ok(())
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
        assert_eq!(Cli::try_parse_from(serve).expect("serve").task_root, None);
        let cli = Cli::try_parse_from(serve.iter().copied().chain(["--task-root", "t"]))
            .expect("serve with a task root");
        assert_eq!(cli.task_root, Some(PathBuf::from("t")));

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
}
