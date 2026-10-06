//! The smallest HTTP/1.1 client a credential provider needs (#267): one
//! request per connection (`Connection: close`), TLS through the `rustls`
//! (`ring`) stack the proxy already uses, and every call bounded by one
//! deadline — name resolution, connect, handshake, write and read all count
//! against it, so a provider that hangs costs at most the configured timeout
//! and is reported as [`DegradedState::TimedOut`], never waited on.
//!
//! TLS is required. Plain HTTP is accepted only when the configuration asks
//! for the explicit loopback test mode *and* the address is a loopback IP
//! literal, so no real provider can be reached without TLS by accident.
//! Nothing here logs: a request carrying the provider token is built in a
//! zeroed-on-drop buffer, and errors name the step that failed, never a
//! header, a body or a token.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use zeroize::Zeroizing;

use super::{DegradedState, LeasedSecret, ProviderError};

/// The largest response body read from a provider.
pub const MAX_RESPONSE: usize = 1 << 20;

/// The longest any one provider call may take, whatever the configuration says.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a provider listens and how to reach it.
#[derive(Clone)]
pub struct Endpoint {
    host: String,
    port: u16,
    base: String,
    tls: Option<Arc<ClientConfig>>,
    timeout: Duration,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("base", &self.base)
            .field("tls", &self.tls.is_some())
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// A provider's answer: the status and the body, zeroed on drop since it may
/// carry a secret.
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The body, de-chunked.
    pub body: Zeroizing<Vec<u8>>,
}

fn misconfigured(detail: impl Into<String>) -> ProviderError {
    ProviderError::degraded(DegradedState::Misconfigured, detail)
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .finish()
    }
}

impl Endpoint {
    /// Parse `address` (`https://host[:port][/base]`, or `http://` with
    /// `insecure_loopback` and a loopback IP literal), trusting `ca_bundle`
    /// (PEM) when given and the host's trust store otherwise, with each call
    /// bounded by `timeout` (at most [`MAX_TIMEOUT`]).
    pub fn parse(
        address: &str,
        ca_bundle: Option<&Path>,
        insecure_loopback: bool,
        timeout: Duration,
    ) -> Result<Self, ProviderError> {
        let checked = check_address(address, insecure_loopback, timeout)?;
        let tls = if checked.tls {
            Some(tls_config(ca_bundle)?)
        } else {
            None
        };
        Ok(Self {
            host: checked.host,
            port: checked.port,
            base: checked.base,
            tls,
            timeout,
        })
    }

    /// Whether calls go over TLS.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// The per-call bound.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// `method path` with the `X-Vault-Token` header from `token` and a JSON
    /// `body`, bounded by the endpoint's timeout.
    pub fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&LeasedSecret>,
        body: Option<&[u8]>,
    ) -> Result<Response, ProviderError> {
        let deadline = Instant::now() + self.timeout;
        let request = self.request(method, path, token, body)?;
        let tcp = connect(&resolve(&self.host, self.port, deadline)?, deadline)?;
        let raw = match &self.tls {
            None => exchange(tcp, &request, deadline)?,
            Some(config) => {
                let name = ServerName::try_from(self.host.clone())
                    .map_err(|_| misconfigured("the address host is not a valid TLS name"))?;
                let conn = ClientConnection::new(Arc::clone(config), name)
                    .map_err(|_| ProviderError::degraded(DegradedState::TlsFailed, "tls setup"))?;
                exchange_tls(StreamOwned::new(conn, tcp), &request, deadline)?
            }
        };
        parse_response(&raw)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&LeasedSecret>,
        body: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let mut out = Zeroizing::new(Vec::with_capacity(512 + body.map_or(0, <[u8]>::len)));
        out.extend_from_slice(
            format!(
                "{method} {}{path} HTTP/1.1\r\nHost: {host}:{}\r\nAccept: application/json\r\n\
                 Connection: close\r\n",
                self.base, self.port
            )
            .as_bytes(),
        );
        if let Some(token) = token {
            let value = token.expose();
            if value.is_empty() || value.iter().any(|b| *b < b' ' || *b >= 0x7f) {
                return Err(misconfigured("the provider token has a control byte"));
            }
            out.extend_from_slice(b"X-Vault-Token: ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        match body {
            Some(body) => {
                out.extend_from_slice(
                    format!(
                        "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                out.extend_from_slice(body);
            }
            None => out.extend_from_slice(b"Content-Length: 0\r\n\r\n"),
        }
        Ok(out)
    }
}

/// An address that passed [`check_address`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedAddress {
    /// Whether it is `https://`.
    pub tls: bool,
    /// The host, without brackets.
    pub host: String,
    /// The port, defaulted by scheme.
    pub port: u16,
    /// The path prefix, without a trailing slash.
    pub base: String,
}

/// Check `address` and `timeout` without touching the trust store: the
/// scheme (`https://`, or `http://` only with `insecure_loopback` and a
/// loopback IP literal), the authority, the path prefix, and a timeout of
/// 1 ms to [`MAX_TIMEOUT`].
pub fn check_address(
    address: &str,
    insecure_loopback: bool,
    timeout: Duration,
) -> Result<CheckedAddress, ProviderError> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(misconfigured(format!(
            "timeout must be between 1 ms and {} s",
            MAX_TIMEOUT.as_secs()
        )));
    }
    let (tls, rest) = if let Some(rest) = address.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = address.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(misconfigured("address must start with https://"));
    };
    let (authority, base) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    let base = base.trim_end_matches('/').to_owned();
    if base
        .bytes()
        .any(|b| b <= b' ' || b >= 0x7f || b == b'?' || b == b'#')
    {
        return Err(misconfigured(
            "address path has a space, `?`, `#` or a control byte",
        ));
    }
    let (host, port) = split_authority(authority, if tls { 443 } else { 80 })?;
    if !tls {
        let loopback = host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !(insecure_loopback && loopback) {
            return Err(misconfigured(
                "plain http is refused: TLS is required (the loopback test mode needs \
                 insecure_loopback = true and a 127.0.0.1 or ::1 address)",
            ));
        }
    }
    Ok(CheckedAddress {
        tls,
        host,
        port,
        base,
    })
}

/// `host[:port]` or `[v6][:port]`.
fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16), ProviderError> {
    if authority.is_empty() || authority.contains('@') {
        return Err(misconfigured("address has no host, or carries userinfo"));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, rest) = v6
            .split_once(']')
            .ok_or_else(|| misconfigured("unterminated IPv6 address"))?;
        (host, rest.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => default_port,
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| misconfigured("address port is not 1-65535"))?,
    };
    if host.is_empty() || host.bytes().any(|b| b <= b' ' || b >= 0x7f || b == b'/') {
        return Err(misconfigured("address host is empty or has a control byte"));
    }
    Ok((host.to_owned(), port))
}

fn tls_config(ca_bundle: Option<&Path>) -> Result<Arc<ClientConfig>, ProviderError> {
    let mut roots = RootCertStore::empty();
    let added = match ca_bundle {
        Some(path) => {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
                .map_err(|_| misconfigured(format!("{}: unreadable CA bundle", path.display())))?
                .collect::<Result<_, _>>()
                .map_err(|_| misconfigured(format!("{}: not a PEM CA bundle", path.display())))?;
            roots.add_parsable_certificates(certs).0
        }
        None => {
            roots
                .add_parsable_certificates(rustls_native_certs::load_native_certs().certs)
                .0
        }
    };
    if added == 0 {
        return Err(misconfigured(
            "no usable CA certificate to verify the provider",
        ));
    }
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| misconfigured("tls protocol versions"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Time left before `deadline`, or the timed-out error.
fn remaining(deadline: Instant) -> Result<Duration, ProviderError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| ProviderError::degraded(DegradedState::TimedOut, "deadline passed"))
}

/// Resolve `host`, bounded by `deadline`: an IP literal directly, a name on
/// a helper thread so a stuck resolver costs the deadline and no more.
fn resolve(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>, ProviderError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let (tx, rx) = mpsc::channel();
    let name = format!("{host}:{port}");
    std::thread::spawn(move || {
        let _ = tx.send(name.to_socket_addrs().map(Iterator::collect::<Vec<_>>));
    });
    match rx.recv_timeout(remaining(deadline)?) {
        Ok(Ok(addrs)) if !addrs.is_empty() => Ok(addrs),
        Ok(_) => Err(ProviderError::degraded(
            DegradedState::Unreachable,
            "the address does not resolve",
        )),
        Err(_) => Err(ProviderError::degraded(
            DegradedState::TimedOut,
            "name resolution timed out",
        )),
    }
}

/// Connect to the first of `addrs` that answers, within `deadline`.
fn connect(addrs: &[SocketAddr], deadline: Instant) -> Result<TcpStream, ProviderError> {
    let mut last = ProviderError::degraded(DegradedState::Unreachable, "connect: no address");
    for addr in addrs {
        match TcpStream::connect_timeout(addr, remaining(deadline)?) {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = io_error("connect", &e),
        }
    }
    Err(last)
}

/// The degraded state an I/O failure at `step` means.
fn io_error(step: &str, e: &io::Error) -> ProviderError {
    let state = match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => DegradedState::TimedOut,
        io::ErrorKind::InvalidData => DegradedState::TlsFailed,
        _ => DegradedState::Unreachable,
    };
    ProviderError::degraded(state, format!("{step}: {}", e.kind()))
}

fn set_timeouts(tcp: &TcpStream, deadline: Instant) -> Result<(), ProviderError> {
    let left = remaining(deadline)?;
    tcp.set_read_timeout(Some(left))
        .and_then(|()| tcp.set_write_timeout(Some(left)))
        .map_err(|e| io_error("socket", &e))
}

/// Write `request` and read the whole response until the peer closes.
fn exchange(
    mut tcp: TcpStream,
    request: &[u8],
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    set_timeouts(&tcp, deadline)?;
    tcp.write_all(request)
        .and_then(|()| tcp.flush())
        .map_err(|e| io_error("write", &e))?;
    read_to_end(&mut tcp, deadline, set_timeouts)
}

fn exchange_tls(
    mut tls: StreamOwned<ClientConnection, TcpStream>,
    request: &[u8],
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    set_timeouts(&tls.sock, deadline)?;
    while tls.conn.is_handshaking() {
        set_timeouts(&tls.sock, deadline)?;
        tls.conn.complete_io(&mut tls.sock).map_err(|e| {
            if matches!(
                e.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) {
                io_error("tls handshake", &e)
            } else {
                ProviderError::degraded(DegradedState::TlsFailed, "tls handshake")
            }
        })?;
    }
    tls.write_all(request)
        .and_then(|()| tls.flush())
        .map_err(|e| io_error("write", &e))?;
    read_to_end(&mut tls, deadline, |s, d| set_timeouts(&s.sock, d))
}

/// Read until EOF, re-arming the socket timeout to what is left of the
/// deadline before every read, and refusing more than [`MAX_RESPONSE`].
fn read_to_end<S: Read>(
    stream: &mut S,
    deadline: Instant,
    arm: impl Fn(&S, Instant) -> Result<(), ProviderError>,
) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    let mut out = Zeroizing::new(Vec::with_capacity(4096));
    let mut buf = Zeroizing::new([0u8; 4096]);
    loop {
        arm(stream, deadline)?;
        match stream.read(&mut buf[..]) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len() + n > MAX_RESPONSE + 16 * 1024 {
                    return Err(ProviderError::degraded(
                        DegradedState::BadResponse,
                        "response too large",
                    ));
                }
                // Grow by copying into a fresh zeroed buffer so no stale copy
                // of a partial secret is left behind by a reallocation.
                if out.len() + n > out.capacity() {
                    let mut bigger = Zeroizing::new(Vec::with_capacity((out.len() + n) * 2));
                    bigger.extend_from_slice(&out);
                    out = bigger;
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // A TLS peer that closes without close_notify still delivered a
            // complete `Connection: close` response; the parse decides.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && !out.is_empty() => {
                return Ok(out);
            }
            Err(e) => return Err(io_error("read", &e)),
        }
    }
}

/// Status and body of a complete response, de-chunked.
fn parse_response(raw: &[u8]) -> Result<Response, ProviderError> {
    let bad = |what: &str| ProviderError::degraded(DegradedState::BadResponse, what.to_owned());
    if raw.is_empty() {
        return Err(ProviderError::degraded(
            DegradedState::Unreachable,
            "the connection closed before a response",
        ));
    }
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad("no complete response head"))?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| bad("response head is not text"))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.strip_prefix("HTTP/1."))
        .and_then(|l| l.get(2..5))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| bad("no HTTP status line"))?;
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        } else if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| bad("bad content-length"))?,
            );
        }
    }
    let rest = &raw[end + 4..];
    let body = if chunked {
        dechunk(rest).ok_or_else(|| bad("bad chunked body"))?
    } else if let Some(n) = length {
        let body = rest
            .get(..n)
            .ok_or_else(|| bad("body shorter than its length"))?;
        Zeroizing::new(body.to_vec())
    } else {
        Zeroizing::new(rest.to_vec())
    };
    if body.len() > MAX_RESPONSE {
        return Err(bad("response too large"));
    }
    Ok(Response { status, body })
}

fn dechunk(mut rest: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(rest.len()));
    loop {
        let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::net::TcpListener;

    fn state(e: &ProviderError) -> DegradedState {
        match e {
            ProviderError::Degraded { state, .. } => *state,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn plain_http_is_refused_unless_explicitly_loopback() {
        let t = Duration::from_secs(1);
        for (addr, loopback) in [
            ("http://127.0.0.1:8200", false),
            ("http://bao.example:8200", true),
            ("http://10.0.0.1:8200", true),
            ("ftp://127.0.0.1", true),
            ("bao.example:8200", true),
        ] {
            let e = Endpoint::parse(addr, None, loopback, t).unwrap_err();
            assert_eq!(state(&e), DegradedState::Misconfigured, "{addr}");
        }
        let e = Endpoint::parse("http://127.0.0.1:8200", None, true, t).unwrap();
        assert!(!e.is_tls());
        assert_eq!(e.timeout(), t);
        let e = Endpoint::parse("http://[::1]:8200/bao", None, true, t).unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.base.as_str()),
            ("::1", 8200, "/bao")
        );
    }

    #[test]
    fn https_needs_a_usable_ca_and_a_sane_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        let e = Endpoint::parse(
            "https://bao.example",
            Some(&empty),
            false,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(state(&e), DegradedState::Misconfigured);
        let e = Endpoint::parse(
            "https://bao.example",
            Some(&dir.path().join("missing.pem")),
            false,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(state(&e), DegradedState::Misconfigured);
        for t in [Duration::ZERO, Duration::from_secs(11)] {
            assert!(Endpoint::parse("http://127.0.0.1:1", None, true, t).is_err());
        }
        for bad in [
            "https://",
            "https://u:p@bao.example",
            "https://bao.example:0",
            "https://bao.example:99999",
            "https://[::1",
            "https://bao.example/a b",
        ] {
            assert!(
                Endpoint::parse(bad, None, false, Duration::from_secs(1)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn responses_are_parsed_by_length_by_chunks_or_to_eof() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokXX").unwrap();
        assert_eq!((r.status, &r.body[..]), (200, &b"ok"[..]));
        let r = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x\r\nde\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(&r.body[..], b"abcde");
        let r = parse_response(b"HTTP/1.0 204 No Content\r\n\r\n").unwrap();
        assert_eq!((r.status, r.body.len()), (204, 0));
        for bad in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nok"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
            b"garbage\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        ] {
            assert_eq!(
                state(&parse_response(bad).unwrap_err()),
                DegradedState::BadResponse
            );
        }
        assert_eq!(
            state(&parse_response(b"").unwrap_err()),
            DegradedState::Unreachable
        );
    }

    #[test]
    fn a_call_is_bounded_by_the_timeout_and_names_the_state() {
        // A listener that accepts and never answers: the call times out.
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = silent.local_addr().unwrap().port();
        let e = Endpoint::parse(
            &format!("http://127.0.0.1:{port}"),
            None,
            true,
            Duration::from_millis(200),
        )
        .unwrap();
        let started = Instant::now();
        let err = e.call("GET", "/v1/sys/health", None, None).err().unwrap();
        assert_eq!(state(&err), DegradedState::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(silent);

        // Nothing listening: unreachable.
        let gone = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = gone.local_addr().unwrap().port();
        drop(gone);
        let e = Endpoint::parse(
            &format!("http://127.0.0.1:{port}"),
            None,
            true,
            Duration::from_millis(500),
        )
        .unwrap();
        let err = e.call("GET", "/v1/sys/health", None, None).err().unwrap();
        assert_eq!(state(&err), DegradedState::Unreachable);
    }

    #[test]
    fn tls_is_verified_against_the_configured_ca_bundle() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};

        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let signing =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![key.cert.der().clone()], signing)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Exactly two connections: the trusted call, then the untrusted one.
        let server = std::thread::spawn(move || {
            for stream in listener.incoming().take(2).flatten() {
                let mut tls =
                    StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), stream);
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while tls.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                if head.is_empty() {
                    continue;
                }
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let trusted = dir.path().join("ca.pem");
        std::fs::write(&trusted, key.cert.pem()).unwrap();
        let address = format!("https://localhost:{port}");
        let e = Endpoint::parse(&address, Some(&trusted), false, Duration::from_secs(5)).unwrap();
        assert!(e.is_tls());
        let r = e.call("GET", "/v1/sys/health", None, None).ok().unwrap();
        assert_eq!((r.status, &r.body[..]), (200, &b"ok"[..]));

        let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let untrusted = dir.path().join("other.pem");
        std::fs::write(&untrusted, other.cert.pem()).unwrap();
        let e = Endpoint::parse(&address, Some(&untrusted), false, Duration::from_secs(5)).unwrap();
        let err = e.call("GET", "/v1/sys/health", None, None).err().unwrap();
        assert_eq!(state(&err), DegradedState::TlsFailed);
        server.join().unwrap();
    }

    #[test]
    fn a_token_with_a_control_byte_is_never_sent() {
        let e = Endpoint::parse("http://127.0.0.1:1", None, true, Duration::from_secs(1)).unwrap();
        let err = e
            .call("GET", "/x", Some(&LeasedSecret::new("a\r\nb")), None)
            .err()
            .unwrap();
        assert_eq!(state(&err), DegradedState::Misconfigured);
        assert!(!err.to_string().contains("a\r\nb"));
    }
}
