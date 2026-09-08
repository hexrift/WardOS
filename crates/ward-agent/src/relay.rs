//! Loopback-to-Unix-socket relay for sandbox egress (ADR-0014).
//!
//! The sandbox's network namespace is isolated, so the only way out is the
//! session proxy's Unix socket bind-mounted into it. Each [`Relay`] listens on
//! a loopback address inside the sandbox and forwards every accepted
//! connection to that socket; the agent is simply pointed at the loopback port
//! through `HTTP_PROXY`. The relay is Zone 3 code: it runs under the same
//! Landlock domain and seccomp filter as the agent, so it can only *reach*
//! the socket and cannot widen what the proxy allows.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::error::{AgentError, Result};

/// Connections a relay serves at once; further accepts are refused until one closes.
pub const MAX_CONNECTIONS: usize = 256;

/// Pause after a failed `accept` so a persistent error (e.g. `EMFILE`) cannot spin.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// One `--relay LISTEN=SOCKET` mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    /// Loopback address to listen on inside the sandbox.
    pub listen: SocketAddr,
    /// Unix socket every accepted connection is forwarded to.
    pub socket: PathBuf,
}

impl FromStr for Relay {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        let (listen, socket) = s
            .split_once('=')
            .ok_or_else(|| format!("expected LISTEN=SOCKET, got `{s}`"))?;
        let listen: SocketAddr = listen
            .parse()
            .map_err(|e| format!("listen address `{listen}`: {e}"))?;
        if !listen.ip().is_loopback() {
            return Err(format!(
                "listen address {listen} is not loopback; the relay must only be reachable from inside the sandbox"
            ));
        }
        if listen.port() == 0 {
            return Err(format!(
                "listen address {listen} needs a fixed port; the agent is told where the proxy is up front"
            ));
        }
        if socket.is_empty() {
            return Err(format!("`{s}` names no socket path"));
        }
        Ok(Self {
            listen,
            socket: PathBuf::from(socket),
        })
    }
}

impl fmt::Display for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.listen, self.socket.display())
    }
}

impl Relay {
    fn error(&self, context: &'static str) -> impl FnOnce(io::Error) -> AgentError {
        let listen = self.listen;
        move |source| AgentError::Relay {
            listen,
            context,
            source,
        }
    }

    fn log(&self, context: &str, error: &io::Error) {
        eprintln!("ward-agent: relay {}: {context}: {error}", self.listen);
    }
}

/// Bind `relay.listen` and serve it on a detached thread for the rest of the
/// process's life. Binding fails closed (an agent with no egress is a broken
/// session); everything after that is logged and ignored so a misbehaving
/// peer cannot take the shim down. Threads are detached on purpose: they end
/// with the process when the supervised agent exits.
pub fn start(relay: &Relay) -> Result<()> {
    let listener = TcpListener::bind(relay.listen).map_err(relay.error("bind"))?;
    let served = relay.clone();
    thread::Builder::new()
        .name(format!("relay {}", relay.listen))
        .spawn(move || accept_loop(&listener, &served))
        .map(drop)
        .map_err(relay.error("spawn"))
}

fn accept_loop(listener: &TcpListener, relay: &Relay) {
    let live = Arc::new(AtomicUsize::new(0));
    loop {
        let client = match listener.accept() {
            Ok((client, _)) => client,
            Err(e) => {
                relay.log("accept", &e);
                thread::sleep(ACCEPT_RETRY);
                continue;
            }
        };
        let Some(slot) = Slot::take(&live) else {
            eprintln!(
                "ward-agent: relay {}: refusing connection, {MAX_CONNECTIONS} already open",
                relay.listen
            );
            continue;
        };
        let served = relay.clone();
        let spawned = thread::Builder::new()
            .name("relay connection".into())
            .spawn(move || {
                if let Err(e) = serve(client, &served.socket) {
                    served.log("connection", &e);
                }
                drop(slot);
            });
        if let Err(e) = spawned {
            relay.log("spawn", &e);
        }
    }
}

/// Forward one connection: the client's bytes to `socket`, the socket's back.
/// Each direction is pumped to EOF on its own thread; EOF (or failure) on one
/// side is propagated as a half-close so the other can drain, and both
/// streams close when both directions are done.
fn serve(client: TcpStream, socket: &Path) -> io::Result<()> {
    let upstream = UnixStream::connect(socket)?;
    let (mut client_rd, mut upstream_wr) = (client.try_clone()?, upstream.try_clone()?);
    let inbound = thread::Builder::new()
        .name("relay inbound".into())
        .spawn(move || pump(&mut client_rd, &mut upstream_wr))?;
    let (mut upstream_rd, mut client_wr) = (upstream, client);
    let outbound = pump(&mut upstream_rd, &mut client_wr);
    let inbound = inbound
        .join()
        .map_err(|_| io::Error::other("inbound pump panicked"))?;
    outbound.and(inbound)
}

/// A stream whose write side can be closed independently of its read side.
trait Half: Read + Write {
    fn shutdown_write(&self) -> io::Result<()>;
}

impl Half for TcpStream {
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

impl Half for UnixStream {
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

fn pump(from: &mut impl Read, to: &mut impl Half) -> io::Result<()> {
    let copied = io::copy(from, to).map(drop);
    // The peer may already be gone (ENOTCONN); nothing to do about it either way.
    let _ = to.shutdown_write();
    copied
}

/// One of the [`MAX_CONNECTIONS`] slots; released on drop.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(live: &Arc<AtomicUsize>) -> Option<Self> {
        let taken = live.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_CONNECTIONS).then_some(n + 1)
        });
        taken.ok().map(|_| Self(Arc::clone(live)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    use super::*;

    fn parse(s: &str) -> std::result::Result<Relay, String> {
        s.parse()
    }

    #[test]
    fn parses_loopback_v4_and_v6() {
        let v4 = parse("127.0.0.1:3128=/run/ward/proxy.sock").unwrap();
        assert_eq!(v4.listen, "127.0.0.1:3128".parse::<SocketAddr>().unwrap());
        assert_eq!(v4.socket, PathBuf::from("/run/ward/proxy.sock"));
        assert_eq!(v4.to_string(), "127.0.0.1:3128=/run/ward/proxy.sock");
        assert!(parse("[::1]:3128=/s").unwrap().listen.ip().is_loopback());
        // Only the first `=` separates; the path keeps any of its own.
        assert_eq!(
            parse("127.0.0.1:1=/a=b").unwrap().socket,
            PathBuf::from("/a=b")
        );
    }

    #[test]
    fn rejects_non_loopback_addresses() {
        for bad in ["0.0.0.0:3128=/s", "10.0.0.1:3128=/s", "[::]:3128=/s"] {
            let err = parse(bad).unwrap_err();
            assert!(err.contains("not loopback"), "{bad}: {err}");
        }
    }

    #[test]
    fn rejects_malformed_mappings() {
        assert!(parse("nope").unwrap_err().contains("LISTEN=SOCKET"));
        assert!(
            parse("127.0.0.1=/s")
                .unwrap_err()
                .contains("listen address")
        );
        assert!(
            parse("localhost:3128=/s")
                .unwrap_err()
                .contains("listen address")
        );
        assert!(
            parse("127.0.0.1:3128=")
                .unwrap_err()
                .contains("no socket path")
        );
        assert!(parse("127.0.0.1:0=/s").unwrap_err().contains("fixed port"));
    }

    /// A port that was free a moment ago.
    fn free_port() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// A Unix-socket server at `path` that echoes each connection's bytes back.
    fn unix_echo_server(path: &Path) {
        let listener = UnixListener::bind(path).unwrap();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut wr = stream.try_clone().unwrap();
                    let _ = io::copy(&mut &stream, &mut wr);
                });
            }
        });
    }

    #[test]
    fn relays_bytes_both_ways_and_propagates_eof() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("echo.sock");
        unix_echo_server(&socket);
        let relay = Relay {
            listen: free_port(),
            socket,
        };
        start(&relay).unwrap();

        let mut client = TcpStream::connect(relay.listen).unwrap();
        client.write_all(b"ping\n").unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "ping\n");

        // Half-closing the client reaches the echo server, whose EOF comes back.
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(reader.read_line(&mut line).unwrap(), 0);
    }

    #[test]
    fn unreachable_socket_closes_the_connection_and_keeps_serving() {
        let relay = Relay {
            listen: free_port(),
            socket: PathBuf::from("/definitely/not/here.sock"),
        };
        start(&relay).unwrap();
        for _ in 0..2 {
            let mut client = TcpStream::connect(relay.listen).unwrap();
            let mut sink = Vec::new();
            // EOF or a reset: either way the relay dropped us without hanging.
            let _ = client.read_to_end(&mut sink);
            assert!(sink.is_empty());
        }
    }

    #[test]
    fn slots_are_bounded_and_released() {
        let live = Arc::new(AtomicUsize::new(MAX_CONNECTIONS - 1));
        let last = Slot::take(&live).unwrap();
        assert!(Slot::take(&live).is_none());
        drop(last);
        assert!(Slot::take(&live).is_some());
    }
}
