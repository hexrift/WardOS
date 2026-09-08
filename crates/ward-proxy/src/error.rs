//! Errors surfaced by [`crate::Proxy::spawn`].

use std::io;
use std::net::SocketAddr;

/// Why the proxy could not start.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The listening socket could not be bound.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The requested address.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The acceptor thread could not be spawned.
    #[error("spawn acceptor thread: {0}")]
    Spawn(#[source] io::Error),
}
