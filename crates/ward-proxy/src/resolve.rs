//! Hostname resolution behind a trait so policy checks can be tested with
//! injected answers, and so the daemon can later route lookups to `ward-dns`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};

/// Resolves a hostname to every address it currently maps to.
///
/// The proxy checks **every** returned address against the structural deny
/// ranges and connects only to one it checked. A resolver must therefore
/// return the complete answer set, never a single "best" address.
pub trait Resolver: Send + Sync {
    /// All addresses for `host`. An empty vector means "no such host".
    fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// Resolution through the platform resolver (`getaddrinfo`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let addrs = (host, 0u16).to_socket_addrs()?.map(|sa| sa.ip()).collect();
        Ok(addrs)
    }
}

/// A fixed table of answers. Unknown names resolve to "not found".
#[derive(Debug, Default, Clone)]
pub struct StaticResolver {
    table: HashMap<String, Vec<IpAddr>>,
}

impl StaticResolver {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Map `host` (matched ASCII case-insensitively) to `addrs`.
    #[must_use]
    pub fn with(mut self, host: &str, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        self.table
            .insert(host.to_ascii_lowercase(), addrs.into_iter().collect());
        self
    }
}

impl Resolver for StaticResolver {
    fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.table
            .get(&host.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn static_resolver_is_case_insensitive_and_complete() {
        let r = StaticResolver::new().with(
            "Example.com",
            [
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ],
        );
        assert_eq!(r.resolve("EXAMPLE.COM").unwrap().len(), 2);
        assert_eq!(
            r.resolve("missing").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn system_resolver_handles_localhost() {
        let addrs = SystemResolver.resolve("localhost").unwrap();
        assert!(addrs.iter().all(IpAddr::is_loopback));
    }
}
