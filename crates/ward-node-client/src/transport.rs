//! The Unix-socket, newline-delimited JSON transport of node-integration.md §3.
//!
//! One connection carries exactly one handshake line and at most one request line, each
//! answered by one line; both request lines are written at once and the node closes the
//! connection afterwards. Lines are bounded at [`MAX_LINE_BYTES`] in both directions. The
//! node answers nothing to a malformed request and simply closes, so EOF is a first-class
//! result here: before the handshake answer it is [`TransportError::ClosedWithoutResponse`],
//! after it an [`Exchange`] whose `response` is `None`, which the client reports as
//! "unknown whether the request took effect" (§10).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

/// Maximum bytes of one request or response line, excluding the newline (§3).
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// How long the transport waits for the node.
///
/// `connect` bounds the time until the node has accepted the connection and answered the
/// handshake: the node serves one connection at a time, so a connection queued behind a
/// slow `start` waits here. `request` bounds the verb's own answer; §3 asks for more than
/// 60 seconds on `start`, `stop` and `revoke`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// Bound on connecting and receiving the handshake answer.
    pub connect: Duration,
    /// Bound on receiving the request's answer once the handshake was accepted.
    pub request: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            request: Duration::from_secs(90),
        }
    }
}

/// The two answer lines of one connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    /// The handshake answer line, without its newline.
    pub handshake: String,
    /// The request's answer line, or `None` when the node closed the connection without
    /// one: the request was malformed or timed out, and may or may not have taken effect.
    pub response: Option<String>,
}

/// Why a connection to the node did not complete.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The socket could not be connected.
    #[error("connecting to the node socket failed: {0}")]
    Connect(std::io::Error),
    /// Reading from or writing to the socket failed.
    #[error("node socket I/O failed: {0}")]
    Io(std::io::Error),
    /// The node did not answer within the configured timeout.
    #[error("the node did not answer within the timeout")]
    TimedOut,
    /// A request line exceeds [`MAX_LINE_BYTES`]; nothing was sent.
    #[error("the request line exceeds {MAX_LINE_BYTES} bytes")]
    RequestTooLarge,
    /// The node closed the connection before answering the handshake.
    #[error("the node closed the connection without answering the handshake")]
    ClosedWithoutResponse,
    /// The node closed the connection in the middle of an answer line.
    #[error("the node closed the connection in the middle of a response line")]
    TruncatedResponse,
    /// An answer line exceeds [`MAX_LINE_BYTES`].
    #[error("a response line exceeds {MAX_LINE_BYTES} bytes")]
    ResponseTooLong,
    /// An answer line is not UTF-8.
    #[error("a response line is not UTF-8")]
    ResponseNotUtf8,
}

/// One connection per request to a node: handshake, then at most one request.
pub trait Transport {
    /// Send only the handshake line and return its answer.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] when the node could not be reached or did not answer.
    fn handshake(&self, hello: &str) -> Result<String, TransportError>;

    /// Send the handshake line and the request line at once and return both answers.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] when the node could not be reached, did not answer the
    /// handshake, or answered outside the line bounds.
    fn exchange(&self, hello: &str, request: &str) -> Result<Exchange, TransportError>;
}

/// The local Unix-socket transport.
#[derive(Clone, Debug)]
pub struct UnixTransport {
    socket: PathBuf,
    timeouts: Timeouts,
}

impl UnixTransport {
    /// A transport to the node socket at `socket`.
    pub fn new(socket: impl Into<PathBuf>, timeouts: Timeouts) -> Self {
        Self {
            socket: socket.into(),
            timeouts,
        }
    }

    /// The socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The configured timeouts.
    #[must_use]
    pub const fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    fn connect(&self, lines: &[&str]) -> Result<BufReader<UnixStream>, TransportError> {
        if lines.iter().any(|line| line.len() > MAX_LINE_BYTES) {
            return Err(TransportError::RequestTooLarge);
        }
        let mut stream = UnixStream::connect(&self.socket).map_err(TransportError::Connect)?;
        stream
            .set_write_timeout(Some(self.timeouts.connect))
            .map_err(TransportError::Io)?;
        let mut payload = Vec::with_capacity(lines.iter().map(|line| line.len() + 1).sum());
        for line in lines {
            payload.extend_from_slice(line.as_bytes());
            payload.push(b'\n');
        }
        stream
            .write_all(&payload)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => {
                    TransportError::ClosedWithoutResponse
                }
                _ => io_error(error),
            })?;
        Ok(BufReader::new(stream))
    }
}

fn io_error(error: std::io::Error) -> TransportError {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => TransportError::TimedOut,
        _ => TransportError::Io(error),
    }
}

fn read_line(
    reader: &mut BufReader<UnixStream>,
    timeout: Duration,
) -> Result<Option<String>, TransportError> {
    reader
        .get_ref()
        .set_read_timeout(Some(timeout))
        .map_err(TransportError::Io)?;
    let mut buffer = Vec::new();
    let limit = u64::try_from(MAX_LINE_BYTES + 1).map_err(|_| TransportError::ResponseTooLong)?;
    let read = match reader.by_ref().take(limit).read_until(b'\n', &mut buffer) {
        Ok(read) => read,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => 0,
        Err(error) => return Err(io_error(error)),
    };
    if read == 0 {
        return Ok(None);
    }
    if buffer.last() != Some(&b'\n') {
        return Err(if buffer.len() > MAX_LINE_BYTES {
            TransportError::ResponseTooLong
        } else {
            TransportError::TruncatedResponse
        });
    }
    buffer.pop();
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
    if buffer.len() > MAX_LINE_BYTES {
        return Err(TransportError::ResponseTooLong);
    }
    String::from_utf8(buffer)
        .map(Some)
        .map_err(|_| TransportError::ResponseNotUtf8)
}

impl Transport for UnixTransport {
    fn handshake(&self, hello: &str) -> Result<String, TransportError> {
        let mut reader = self.connect(&[hello])?;
        read_line(&mut reader, self.timeouts.connect)?.ok_or(TransportError::ClosedWithoutResponse)
    }

    fn exchange(&self, hello: &str, request: &str) -> Result<Exchange, TransportError> {
        let mut reader = self.connect(&[hello, request])?;
        let handshake = read_line(&mut reader, self.timeouts.connect)?
            .ok_or(TransportError::ClosedWithoutResponse)?;
        let response = read_line(&mut reader, self.timeouts.request)?;
        Ok(Exchange {
            handshake,
            response,
        })
    }
}
