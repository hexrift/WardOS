//! Errors surfaced by [`crate::Proxy::spawn`] and [`crate::GatewayRoute::new`].

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Why the proxy could not start, or a gateway route could not be built.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A [`crate::GatewayRoute`] was misconfigured. The reason names the
    /// field, never its value.
    #[error("gateway route {prefix}: {reason}")]
    InvalidGateway {
        /// The route's path prefix as given.
        prefix: String,
        /// What was wrong with it.
        reason: &'static str,
    },
    /// The TCP listening socket could not be bound.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The requested address.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The Unix-domain listening socket could not be created at `path`:
    /// the parent directory is missing, a non-socket file is in the way, or
    /// the bind or `chmod 0600` failed.
    #[error("bind unix socket {}: {source}", path.display())]
    BindUnix {
        /// The requested socket path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The acceptor thread could not be spawned.
    #[error("spawn acceptor thread: {0}")]
    Spawn(#[source] io::Error),
}
