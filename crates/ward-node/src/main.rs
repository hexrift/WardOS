//! Local Ward node service executable.
//!
//! `ward-node --socket <path> --state-dir <dir> --node-id <node_…> [--trusted-issuers <file>]`
//! serves the local node protocol. `--node-id` is this node's audience identity; the
//! state directory pins it at first start and holds the durable admission version and
//! revocation stores. Without `--trusted-issuers` no issuer is trusted and every `admit`
//! is refused. `ward-node issuer-key-id <hex-public-key>` prints the key id an issuer
//! proof must name for that Ed25519 public key.

use std::io;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ward_events::NodeId;
use ward_node::admit::{NodeAdmission, SystemClock};
use ward_node::issuer::{IssuerKeyParseError, IssuerPublicKey, TrustedIssuers};
use ward_node::state::NodeState;
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
    /// admission version per task, and known revocations.
    #[arg(long, required = true)]
    state_dir: Option<PathBuf>,
    /// This node's identity (`node_…`), the only audience it admits envelopes for.
    #[arg(long, required = true)]
    node_id: Option<NodeId>,
    /// Trusted issuer public keys: one hex Ed25519 key per line, `#` comments allowed.
    /// Without it no issuer is trusted and every `admit` is refused.
    #[arg(long)]
    trusted_issuers: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Print the issuer key id (BLAKE3 of the public key) for a hex Ed25519 public key.
    IssuerKeyId {
        /// The 32-byte Ed25519 public key as 64 hex characters.
        public_key: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if let Some(Command::IssuerKeyId { public_key }) = cli.command {
        println!("{}", issuer_key_id(&public_key)?);
        return Ok(());
    }
    let (Some(socket), Some(state_dir), Some(node_id)) = (cli.socket, cli.state_dir, cli.node_id)
    else {
        return Err(io::Error::other("--socket, --state-dir and --node-id are required").into());
    };

    let issuers = match cli.trusted_issuers {
        Some(path) => TrustedIssuers::load(&path)?,
        None => TrustedIssuers::empty(),
    };
    let state = NodeState::open(&state_dir, node_id)?;
    let admission = NodeAdmission::new(issuers, state, Box::new(SystemClock));
    let service = NodeService::with_admission(conservative_host_capabilities()?, admission)?;
    serve_local(&socket, &service)?;
    Ok(())
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
}
