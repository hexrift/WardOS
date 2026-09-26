use std::io;
use std::path::PathBuf;

use clap::Parser;
use ward_node::serve_local;
use ward_node_protocol::{
    CredentialCapabilities, ExecutionBackendCapabilities, IsolationCapabilities,
    LifecycleCapabilities, NamespaceCapabilities, NetworkCapabilities, NodeArchitecture,
    NodeCapabilities, NodeCapacity, ProtocolVersion, SnapshotCapabilities, VerifierCapabilities,
};

#[derive(Parser)]
#[command(name = "ward-node")]
struct Cli {
    /// Local administrative Unix socket. This path is never mounted into a task sandbox.
    #[arg(long)]
    socket: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    serve_local(&cli.socket, conservative_host_capabilities()?)?;
    Ok(())
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
    use super::*;

    #[test]
    fn meminfo_parser_source_reports_nonzero_host_memory() {
        assert!(total_memory_bytes().expect("Linux MemTotal") > 0);
    }
}
