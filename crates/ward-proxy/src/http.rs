//! Defensive HTTP/1.x request parsing for the three request forms the sandbox
//! may use: `CONNECT host:port`, absolute-URI forwarding (`GET http://h/p`)
//! and origin-form (`GET /p` with a `Host` header), the last of which only a
//! gateway route ([`crate::GatewayRoute`]) can serve.
//!
//! The parser is deliberately strict: a bounded head, CRLF only, no
//! obs-fold, token-validated names, and exactly one request per connection.
//! Anything else is `400`. Only the first request line ever selects a
//! destination; after a `CONNECT` succeeds the bytes are opaque.

use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum size of the request line plus headers, in bytes.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Maximum number of header fields.
pub const MAX_HEADERS: usize = 100;
/// Maximum hostname length (RFC 1035).
const MAX_HOST_LEN: usize = 253;

/// A destination host as written by the client, normalised.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// A DNS name, ASCII-lowercased, without a trailing dot.
    Name(String),
    /// An IP literal (`1.2.3.4` or `[::1]`).
    Ip(IpAddr),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(n) => f.write_str(n),
            Self::Ip(IpAddr::V4(ip)) => write!(f, "{ip}"),
            Self::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
        }
    }
}

/// Where the client wants to go.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// Destination host.
    pub host: Host,
    /// Destination port.
    pub port: u16,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// What the client asked the proxy to do with the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// `CONNECT host:port` — an opaque TLS (or other) tunnel.
    Connect,
    /// Plain-HTTP forwarding of `verb http://host/path`.
    Forward {
        /// The HTTP verb (`GET`, `POST`, …).
        verb: String,
        /// Origin-form path plus query, always starting with `/`.
        path: String,
    },
}

/// The policy-relevant part of a request, handed to the [`crate::Observer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Tunnel or forward.
    pub method: Method,
    /// Destination host and port.
    pub target: Target,
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.method {
            Method::Connect => write!(f, "CONNECT {}", self.target),
            Method::Forward { verb, path } => {
                write!(f, "{verb} http://{}{path}", self.target)
            }
        }
    }
}

/// One header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Field name as sent (case preserved).
    pub name: String,
    /// Field value, surrounding whitespace trimmed.
    pub value: String,
}

/// A fully parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The policy-relevant request.
    pub request: Request,
    /// The `HTTP/1.x` version token.
    pub version: String,
    /// All header fields, in order.
    pub headers: Vec<Header>,
    /// `true` when the request line was origin-form (`GET /path`): the client
    /// addressed the proxy itself, so `request.target` is the `Host` header
    /// and only a gateway route can serve the request.
    pub origin_form: bool,
}

/// Why a request head was rejected. Every variant maps to `400`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The head exceeded [`MAX_HEAD_BYTES`] without a terminating blank line.
    #[error("request head exceeds {MAX_HEAD_BYTES} bytes")]
    TooLarge,
    /// The connection closed before the head was complete.
    #[error("connection closed before request head")]
    Truncated,
    /// The head was syntactically invalid.
    #[error("malformed request: {0}")]
    Malformed(&'static str),
}

/// A request head plus any bytes the client sent after it.
#[derive(Debug)]
pub struct Head {
    /// The raw head, excluding the terminating blank line.
    pub bytes: Vec<u8>,
    /// Bytes read past the head; they belong to the tunnel or body.
    pub remainder: Vec<u8>,
}

/// Read a request head from `r`, bounded by [`MAX_HEAD_BYTES`].
pub fn read_head<R: Read>(r: &mut R) -> io::Result<Result<Head, ParseError>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = r.read(&mut chunk)?;
        if n == 0 {
            return Ok(Err(ParseError::Truncated));
        }
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_terminator(&buf[scan_from..]).map(|i| i + scan_from) {
            if end > MAX_HEAD_BYTES {
                return Ok(Err(ParseError::TooLarge));
            }
            let remainder = buf.split_off(end + 4);
            buf.truncate(end);
            return Ok(Ok(Head {
                bytes: buf,
                remainder,
            }));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Ok(Err(ParseError::TooLarge));
        }
    }
}

fn find_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse a request head (without its terminating blank line).
pub fn parse(head: &[u8]) -> Result<Parsed, ParseError> {
    if !head.is_ascii() {
        return Err(ParseError::Malformed("non-ASCII bytes in head"));
    }
    let text = std::str::from_utf8(head).map_err(|_| ParseError::Malformed("not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(ParseError::Malformed("empty request line"))?;
    if request_line.contains('\n') {
        return Err(ParseError::Malformed("bare LF in request line"));
    }
    let mut parts = request_line.split(' ');
    let (Some(verb), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ParseError::Malformed(
            "request line is not `METHOD TARGET VERSION`",
        ));
    };
    if verb.is_empty() || verb.len() > 16 || !verb.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(ParseError::Malformed("invalid method"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(ParseError::Malformed("unsupported HTTP version"));
    }
    let headers = parse_headers(lines)?;
    let origin_form = verb != "CONNECT" && target.starts_with('/');
    let request = if verb == "CONNECT" {
        Request {
            method: Method::Connect,
            target: parse_authority(target, None)?,
        }
    } else if origin_form {
        parse_origin_form(verb, target, &headers)?
    } else {
        parse_absolute_uri(verb, target)?
    };
    Ok(Parsed {
        request,
        version: version.to_owned(),
        headers,
        origin_form,
    })
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Vec<Header>, ParseError> {
    let mut headers = Vec::new();
    for line in lines {
        if line.contains('\n') {
            return Err(ParseError::Malformed("bare LF in headers"));
        }
        if line.starts_with([' ', '\t']) {
            return Err(ParseError::Malformed("obsolete line folding"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(ParseError::Malformed("header without colon"))?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(ParseError::Malformed("invalid header name"));
        }
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f) {
            return Err(ParseError::Malformed("control byte in header value"));
        }
        headers.push(Header {
            name: name.to_owned(),
            value: value.to_owned(),
        });
        if headers.len() > MAX_HEADERS {
            return Err(ParseError::Malformed("too many headers"));
        }
    }
    Ok(headers)
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Is `s` a non-empty RFC 9110 token (a valid header or method name)?
pub(crate) fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_token_byte)
}

/// Parse `verb http://authority/path` into a forward request.
fn parse_absolute_uri(verb: &str, uri: &str) -> Result<Request, ParseError> {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return Err(ParseError::Malformed(
            "proxy requires an absolute http:// URI",
        ));
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(ParseError::Malformed("only http:// URIs can be forwarded"));
    }
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.contains('@') {
        return Err(ParseError::Malformed("userinfo in URI"));
    }
    let path = match path.as_bytes().first() {
        Some(b'/') => path.to_owned(),
        Some(_) => format!("/{path}"),
        None => "/".to_owned(),
    };
    Ok(Request {
        method: Method::Forward {
            verb: verb.to_owned(),
            path,
        },
        target: parse_authority(authority, Some(80))?,
    })
}

/// Parse `verb /path` plus the mandatory `Host` header into a forward request
/// whose target is the proxy address the client used.
fn parse_origin_form(verb: &str, path: &str, headers: &[Header]) -> Result<Request, ParseError> {
    let host = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .ok_or(ParseError::Malformed("origin-form request without Host"))?;
    Ok(Request {
        method: Method::Forward {
            verb: verb.to_owned(),
            path: path.to_owned(),
        },
        target: parse_authority(&host.value, Some(80))?,
    })
}

/// Parse `host[:port]`. `default_port` of `None` makes the port mandatory.
fn parse_authority(authority: &str, default_port: Option<u16>) -> Result<Target, ParseError> {
    let (host_part, port_part) = if let Some(rest) = authority.strip_prefix('[') {
        let (inner, after) = rest
            .split_once(']')
            .ok_or(ParseError::Malformed("unterminated IPv6 literal"))?;
        (inner, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match (port_part, default_port) {
        (Some(p), _) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or(ParseError::Malformed("invalid port"))?,
        (None, Some(d)) => d,
        (None, None) => return Err(ParseError::Malformed("CONNECT requires host:port")),
    };
    let host = if authority.starts_with('[') {
        Host::Ip(IpAddr::V6(
            host_part
                .parse::<Ipv6Addr>()
                .map_err(|_| ParseError::Malformed("invalid IPv6 literal"))?,
        ))
    } else {
        parse_host(host_part)?
    };
    Ok(Target { host, port })
}

/// Parse a bare host: an IPv4 literal (strict dotted-quad) or a DNS name.
///
/// A name whose last label is all digits is treated as an IPv4 literal and
/// must parse strictly, so shorthand forms like `127.1` or `0x7f.1` that libc
/// would happily turn into loopback are rejected instead of resolved.
pub(crate) fn parse_host(host: &str) -> Result<Host, ParseError> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(ParseError::Malformed("invalid host"));
    }
    let last_label_numeric = host
        .rsplit('.')
        .next()
        .is_some_and(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()));
    if last_label_numeric || host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host
            .parse::<Ipv4Addr>()
            .map(|ip| Host::Ip(IpAddr::V4(ip)))
            .map_err(|_| ParseError::Malformed("invalid IPv4 literal"));
    }
    let valid_label = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if !host.split('.').all(valid_label) {
        return Err(ParseError::Malformed("invalid hostname"));
    }
    Ok(Host::Name(host.to_ascii_lowercase()))
}

/// Rebuild the head of a forwarded request for the origin server.
///
/// The request line becomes origin-form, hop-by-hop and proxy headers are
/// dropped, `Host` is forced to the URI authority, and the upstream
/// connection is marked `close` so exactly one exchange happens per tunnel.
pub fn origin_head(parsed: &Parsed) -> Vec<u8> {
    let Method::Forward { verb, path } = &parsed.request.method else {
        return Vec::new();
    };
    let host = parsed.request.target.to_string();
    let mut out = build_head(parsed, verb, path, &host, &[]);
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

/// Request line, `Host: {host}` and every surviving client header, without
/// the terminating blank line so the caller can append more fields.
///
/// Dropped: the hop-by-hop set, anything named in `Connection`, every
/// `Proxy-*` field, `Host`, and the lowercase names in `extra_drop`.
pub(crate) fn build_head(
    parsed: &Parsed,
    verb: &str,
    path: &str,
    host: &str,
    extra_drop: &[String],
) -> Vec<u8> {
    const HOP_BY_HOP: [&str; 6] = [
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "host",
    ];
    let mut dropped: Vec<String> = extra_drop.to_vec();
    for h in &parsed.headers {
        if h.name.eq_ignore_ascii_case("connection") {
            dropped.extend(h.value.split(',').map(|t| t.trim().to_ascii_lowercase()));
        }
    }
    let mut out = format!("{verb} {path} {}\r\nHost: {host}\r\n", parsed.version).into_bytes();
    for h in &parsed.headers {
        let lower = h.name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str())
            || lower.starts_with("proxy-")
            || dropped.contains(&lower)
        {
            continue;
        }
        out.extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
    }
    out
}

/// How a request body is delimited (RFC 9112 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body follows the head.
    None,
    /// Exactly this many bytes follow the head.
    Length(usize),
    /// `Transfer-Encoding: chunked`; see [`ChunkTracker`].
    Chunked,
}

/// Determine the body framing of a parsed request. `Transfer-Encoding` takes
/// precedence over `Content-Length`; any coding other than a single `chunked`,
/// or conflicting lengths, is rejected.
pub fn body_framing(parsed: &Parsed) -> Result<Framing, ParseError> {
    let mut framing = Framing::None;
    for h in &parsed.headers {
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            if !h.value.eq_ignore_ascii_case("chunked") {
                return Err(ParseError::Malformed("unsupported Transfer-Encoding"));
            }
            framing = Framing::Chunked;
        }
    }
    if framing == Framing::Chunked {
        return Ok(framing);
    }
    for h in &parsed.headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            let n = h
                .value
                .parse::<usize>()
                .map_err(|_| ParseError::Malformed("invalid Content-Length"))?;
            match framing {
                Framing::Length(seen) if seen != n => {
                    return Err(ParseError::Malformed("conflicting Content-Length"));
                }
                _ => framing = Framing::Length(n),
            }
        }
    }
    Ok(framing)
}

/// Longest accepted chunk-size or trailer line.
const MAX_CHUNK_LINE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    /// Reading a `size[;ext]CRLF` line.
    Size,
    /// This many bytes of chunk data (plus its CRLF) remain.
    Data(usize),
    /// After the last chunk: trailer lines up to a blank line.
    Trailer,
    /// The body is complete.
    Done,
}

/// Follows `Transfer-Encoding: chunked` framing over a pass-through byte
/// stream, so the proxy knows where a request body ends without buffering or
/// re-encoding it. Chunk data is never inspected.
#[derive(Debug)]
pub struct ChunkTracker {
    state: ChunkState,
    line: Vec<u8>,
}

impl Default for ChunkTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkTracker {
    /// A tracker positioned at the first chunk-size line.
    pub fn new() -> Self {
        Self {
            state: ChunkState::Size,
            line: Vec::new(),
        }
    }

    /// Have the terminating chunk and its trailers been seen?
    pub fn done(&self) -> bool {
        self.state == ChunkState::Done
    }

    /// Account for `bytes` and return how many of them belong to the body;
    /// anything beyond that count lies past the end of the message.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<usize, ParseError> {
        let mut i = 0;
        while i < bytes.len() {
            match self.state {
                ChunkState::Done => break,
                ChunkState::Data(ref mut remaining) => {
                    let take = (*remaining).min(bytes.len() - i);
                    *remaining -= take;
                    i += take;
                    if *remaining == 0 {
                        self.state = ChunkState::Size;
                    }
                }
                ChunkState::Size | ChunkState::Trailer => {
                    if self.line.len() >= MAX_CHUNK_LINE {
                        return Err(ParseError::Malformed("chunk line too long"));
                    }
                    let b = bytes[i];
                    i += 1;
                    self.line.push(b);
                    if b == b'\n' {
                        let line = std::mem::take(&mut self.line);
                        self.end_of_line(&line)?;
                    }
                }
            }
        }
        Ok(i)
    }

    fn end_of_line(&mut self, line: &[u8]) -> Result<(), ParseError> {
        let text = std::str::from_utf8(line)
            .map_err(|_| ParseError::Malformed("chunk line is not UTF-8"))?
            .trim_end_matches(['\r', '\n']);
        self.state = match self.state {
            ChunkState::Size => {
                let size = text.split(';').next().unwrap_or("").trim();
                let n = usize::from_str_radix(size, 16)
                    .map_err(|_| ParseError::Malformed("invalid chunk size"))?;
                match n.checked_add(2) {
                    _ if n == 0 => ChunkState::Trailer,
                    Some(with_crlf) => ChunkState::Data(with_crlf),
                    None => return Err(ParseError::Malformed("chunk size overflow")),
                }
            }
            ChunkState::Trailer if text.is_empty() => ChunkState::Done,
            other => other,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::fmt::Write as _;

    fn parse_str(s: &str) -> Result<Parsed, ParseError> {
        parse(s.as_bytes())
    }

    fn name(s: &str) -> Host {
        Host::Name(s.to_owned())
    }

    #[test]
    fn connect_authority_form() {
        let p = parse_str("CONNECT GitHub.com:443 HTTP/1.1\r\nHost: github.com:443").unwrap();
        assert_eq!(p.request.method, Method::Connect);
        assert_eq!(p.request.target.host, name("github.com"));
        assert_eq!(p.request.target.port, 443);
        assert_eq!(p.headers.len(), 1);
        assert_eq!(p.request.to_string(), "CONNECT github.com:443");
    }

    #[test]
    fn connect_ip_literals() {
        let v4 = parse_str("CONNECT 127.0.0.1:8080 HTTP/1.1").unwrap();
        assert_eq!(
            v4.request.target.host,
            Host::Ip("127.0.0.1".parse().unwrap())
        );
        let v6 = parse_str("CONNECT [::1]:8080 HTTP/1.1").unwrap();
        assert_eq!(v6.request.target.host, Host::Ip("::1".parse().unwrap()));
        assert_eq!(v6.request.target.to_string(), "[::1]:8080");
    }

    #[test]
    fn connect_requires_port() {
        assert!(matches!(
            parse_str("CONNECT github.com HTTP/1.1"),
            Err(ParseError::Malformed(_))
        ));
        assert!(parse_str("CONNECT github.com:0 HTTP/1.1").is_err());
        assert!(parse_str("CONNECT github.com:99999 HTTP/1.1").is_err());
        assert!(parse_str("CONNECT github.com:x HTTP/1.1").is_err());
    }

    #[test]
    fn shorthand_ipv4_forms_are_rejected_not_resolved() {
        for h in ["127.1", "0x7f.1", "2130706433", "1.2.3", "01.02.03.04.05"] {
            assert!(
                parse_str(&format!("CONNECT {h}:80 HTTP/1.1")).is_err(),
                "{h}"
            );
        }
    }

    #[test]
    fn hostname_validation() {
        assert!(parse_str("CONNECT a_b.com:80 HTTP/1.1").is_err());
        assert!(parse_str("CONNECT -a.com:80 HTTP/1.1").is_err());
        assert!(parse_str("CONNECT a..com:80 HTTP/1.1").is_err());
        assert!(parse_str("CONNECT :80 HTTP/1.1").is_err());
        let long = format!("{}.com", "a".repeat(64));
        assert!(parse_str(&format!("CONNECT {long}:80 HTTP/1.1")).is_err());
        let ok = parse_str("CONNECT a-b.example.com.:80 HTTP/1.1").unwrap();
        assert_eq!(ok.request.target.host, name("a-b.example.com"));
    }

    #[test]
    fn forward_absolute_uri() {
        let p = parse_str("GET HTTP://Example.COM/a/b?q=1 HTTP/1.1\r\nHost: x").unwrap();
        assert_eq!(
            p.request.method,
            Method::Forward {
                verb: "GET".into(),
                path: "/a/b?q=1".into()
            }
        );
        assert_eq!(p.request.target.host, name("example.com"));
        assert_eq!(p.request.target.port, 80);
        let bare = parse_str("GET http://example.com:8080 HTTP/1.0").unwrap();
        assert_eq!(bare.request.target.port, 8080);
        assert!(matches!(bare.request.method, Method::Forward { ref path, .. } if path == "/"));
        let q = parse_str("GET http://example.com?x=1 HTTP/1.1").unwrap();
        assert!(matches!(q.request.method, Method::Forward { ref path, .. } if path == "/?x=1"));
    }

    #[test]
    fn forward_rejects_origin_form_https_and_userinfo() {
        assert!(parse_str("GET / HTTP/1.1").is_err());
        assert!(parse_str("GET https://example.com/ HTTP/1.1").is_err());
        assert!(parse_str("GET ftp://example.com/ HTTP/1.1").is_err());
        assert!(parse_str("GET http://user@example.com/ HTTP/1.1").is_err());
    }

    #[test]
    fn request_line_shape_is_strict() {
        assert!(parse_str("").is_err());
        assert!(parse_str("CONNECT github.com:443").is_err());
        assert!(parse_str("CONNECT github.com:443 HTTP/2.0").is_err());
        assert!(parse_str("CONNECT  github.com:443 HTTP/1.1").is_err());
        assert!(parse_str("connect github.com:443 HTTP/1.1").is_err());
        assert!(parse_str("CONNECT github.com:443 HTTP/1.1 extra").is_err());
        assert!(parse_str("CONNECT github.com:443 HTTP/1.1\nHost: x").is_err());
    }

    #[test]
    fn header_validation() {
        assert!(parse_str("CONNECT a.com:1 HTTP/1.1\r\nno-colon").is_err());
        assert!(parse_str("CONNECT a.com:1 HTTP/1.1\r\n: v").is_err());
        assert!(parse_str("CONNECT a.com:1 HTTP/1.1\r\nBad Name: v").is_err());
        assert!(parse_str("CONNECT a.com:1 HTTP/1.1\r\nX: a\r\n b").is_err());
        assert!(parse_str("CONNECT a.com:1 HTTP/1.1\r\nX: a\x01b").is_err());
        assert!(parse(b"CONNECT a.com:1 HTTP/1.1\r\nX: \xff").is_err());
        let many = (0..=MAX_HEADERS).fold(String::from("CONNECT a.com:1 HTTP/1.1"), |mut s, i| {
            let _ = write!(s, "\r\nX-{i}: v");
            s
        });
        assert!(parse_str(&many).is_err());
        let p = parse_str("CONNECT a.com:1 HTTP/1.1\r\nX-Y:  spaced \t").unwrap();
        assert_eq!(p.headers[0].value, "spaced");
    }

    #[test]
    fn read_head_bounds_and_splits_remainder() {
        let mut input: &[u8] = b"CONNECT a.com:443 HTTP/1.1\r\nHost: a.com\r\n\r\n\x16\x03\x01tls";
        let head = read_head(&mut input).unwrap().unwrap();
        assert_eq!(head.bytes, b"CONNECT a.com:443 HTTP/1.1\r\nHost: a.com");
        assert_eq!(head.remainder, b"\x16\x03\x01tls");

        let mut truncated: &[u8] = b"CONNECT a.com:443 HTTP/1.1\r\n";
        assert_eq!(
            read_head(&mut truncated).unwrap().unwrap_err(),
            ParseError::Truncated
        );

        let mut huge = b"CONNECT a.com:443 HTTP/1.1\r\n".to_vec();
        huge.extend(std::iter::repeat_n(b'x', MAX_HEAD_BYTES + 1));
        huge.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            read_head(&mut huge.as_slice()).unwrap().unwrap_err(),
            ParseError::TooLarge
        );

        let mut exact = b"CONNECT a.com:443 HTTP/1.1\r\nX: ".to_vec();
        exact.extend(std::iter::repeat_n(b'x', MAX_HEAD_BYTES - exact.len()));
        exact.extend_from_slice(b"\r\n\r\n");
        assert!(read_head(&mut exact.as_slice()).unwrap().is_ok());
    }

    #[test]
    fn origin_head_rewrites_and_strips_hop_by_hop() {
        let p = parse_str(
            "POST http://example.com:8080/x?y=1 HTTP/1.1\r\n\
             Host: attacker.invalid\r\n\
             Proxy-Authorization: Basic xx\r\n\
             Proxy-Connection: keep-alive\r\n\
             Connection: X-Drop, keep-alive\r\n\
             X-Drop: gone\r\n\
             Content-Length: 3\r\n\
             Accept: */*",
        )
        .unwrap();
        let head = String::from_utf8(origin_head(&p)).unwrap();
        assert_eq!(
            head,
            "POST /x?y=1 HTTP/1.1\r\n\
             Host: example.com:8080\r\n\
             Content-Length: 3\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\r\n"
        );
    }

    #[test]
    fn origin_form_targets_the_host_header() {
        let p =
            parse_str("POST /anthropic/v1/messages?x=1 HTTP/1.1\r\nHost: 127.0.0.1:3128").unwrap();
        assert!(p.origin_form);
        assert_eq!(
            p.request.method,
            Method::Forward {
                verb: "POST".into(),
                path: "/anthropic/v1/messages?x=1".into()
            }
        );
        assert_eq!(p.request.target.to_string(), "127.0.0.1:3128");
        assert!(!parse_str("GET http://a.com/ HTTP/1.1").unwrap().origin_form);
        assert!(matches!(
            parse_str("GET / HTTP/1.1"),
            Err(ParseError::Malformed("origin-form request without Host"))
        ));
        assert!(parse_str("GET / HTTP/1.1\r\nHost: bad host").is_err());
    }

    #[test]
    fn body_framing_from_headers() {
        let f = |h: &str| {
            body_framing(&parse_str(&format!("POST /p HTTP/1.1\r\nHost: h\r\n{h}")).unwrap())
        };
        assert_eq!(f("Accept: */*").unwrap(), Framing::None);
        assert_eq!(f("Content-Length: 12").unwrap(), Framing::Length(12));
        assert_eq!(
            f("Content-Length: 5\r\nContent-Length: 5").unwrap(),
            Framing::Length(5)
        );
        assert_eq!(
            f("Transfer-Encoding: Chunked\r\nContent-Length: 5").unwrap(),
            Framing::Chunked
        );
        assert!(f("Content-Length: -1").is_err());
        assert!(f("Content-Length: 5\r\nContent-Length: 6").is_err());
        assert!(f("Transfer-Encoding: gzip, chunked").is_err());
    }

    #[test]
    fn chunk_tracker_finds_the_end_of_a_chunked_body() {
        let body = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: v\r\n\r\nGET /next";
        let mut t = ChunkTracker::new();
        // Byte at a time, so every state boundary is crossed mid-buffer.
        let mut consumed = 0;
        for b in body.iter().take(body.len() - 9) {
            consumed += t.feed(std::slice::from_ref(b)).unwrap();
        }
        assert!(t.done());
        assert_eq!(consumed, body.len() - 9);
        assert_eq!(t.feed(b"GET /next").unwrap(), 0);

        let mut whole = ChunkTracker::new();
        assert_eq!(whole.feed(body).unwrap(), body.len() - 9);
        assert!(whole.done());

        let mut split = ChunkTracker::new();
        assert_eq!(split.feed(b"3\r\nab").unwrap(), 5);
        assert!(!split.done());
        assert_eq!(split.feed(b"c\r\n0\r\n\r\n").unwrap(), 8);
        assert!(split.done());

        assert!(ChunkTracker::new().feed(b"zz\r\n").is_err());
        assert!(ChunkTracker::new().feed(b"ffffffffffffffff\r\n").is_err());
        let long = vec![b'1'; MAX_CHUNK_LINE + 1];
        assert!(ChunkTracker::new().feed(&long).is_err());
    }
}
