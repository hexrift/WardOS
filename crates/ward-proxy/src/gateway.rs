//! Gateway routes: credential injection for an agent's own model API
//! (credential-broker §4 "gateway mode", ADR-0008 delivery A).
//!
//! The sandbox is given `ANTHROPIC_BASE_URL=http://127.0.0.1:3128/anthropic`
//! and a placeholder token. A plain-HTTP request whose path starts with a
//! route's prefix is rewritten to the real HTTPS upstream — the prefix is
//! stripped, `Host` replaced, the placeholder header removed and the real
//! credential added host-side — so the long-lived key never enters Zone 3.
//! `CONNECT` is never a gateway: a tunnel is opaque and cannot be injected
//! into. The upstream host goes through the same policy check and DNS
//! pinning as any other destination.
//!
//! A route may carry a **scope** ([`GatewayRoute::scope`]): the path prefixes
//! the credential may act on and whether writes are granted. This is where a
//! `CredentialScope` (repository + permission set, credential-broker §3) is
//! enforced: a request outside it is refused with `403` before the upstream
//! is contacted, so the secret is never sent on the agent's behalf for
//! anything the grant did not cover.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::http::{self, Host, Method, Parsed, Request, Target};
use crate::secret::Secret;

/// One path prefix mapped to one authenticated upstream.
///
/// Build with [`GatewayRoute::new`]; the fields are validated there so a bad
/// route fails at configuration time, not on the agent's first request.
#[derive(Clone)]
pub struct GatewayRoute {
    prefix: String,
    target: Target,
    header: String,
    value: Secret,
    strip: Vec<String>,
    /// Path prefixes (after the route prefix is stripped) the credential may
    /// act on; empty means every path.
    paths: Vec<String>,
    /// Whether requests that are not read-only are permitted.
    write: bool,
    #[cfg(feature = "test-loopback")]
    plain_upstream: bool,
}

/// Why a request was refused by a route's [`scope`](GatewayRoute::scope).
///
/// The `Display` text is the tail of the observer reason; it names neither
/// the path nor the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeDenial {
    /// The stripped path is under none of the scope's path prefixes.
    OutsideScope,
    /// The route is read-only and the request would write.
    WriteNotGranted,
}

impl fmt::Display for ScopeDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OutsideScope => "outside credential scope",
            Self::WriteNotGranted => "write not granted",
        })
    }
}

impl GatewayRoute {
    /// A route for requests under `prefix` (for example `/anthropic`) to
    /// `upstream_host:upstream_port` over TLS, adding `header: value`
    /// (for example `x-api-key`).
    ///
    /// `prefix` must start with `/` and be more than the bare slash; the
    /// host must be a valid DNS name or IP literal; `header` must be a token.
    /// Any client-sent header with the same name as `header` is always
    /// replaced; see [`Self::strip_headers`] for removing others.
    pub fn new(
        prefix: impl Into<String>,
        upstream_host: &str,
        upstream_port: u16,
        header: impl Into<String>,
        value: Secret,
    ) -> Result<Self, Error> {
        let prefix = prefix.into();
        let header = header.into();
        let invalid = |reason| Error::InvalidGateway {
            prefix: prefix.clone(),
            reason,
        };
        if !prefix.starts_with('/') || prefix.len() < 2 || prefix.ends_with('/') {
            return Err(invalid("prefix must be `/name`, without a trailing slash"));
        }
        if prefix
            .bytes()
            .any(|b| b <= b' ' || b == b'?' || b == b'#' || b >= 0x7f)
        {
            return Err(invalid(
                "prefix contains whitespace, `?`, `#` or a control byte",
            ));
        }
        if upstream_port == 0 {
            return Err(invalid("upstream port must be non-zero"));
        }
        if !http::is_token(&header) {
            return Err(invalid("header name is not a valid HTTP token"));
        }
        let host = http::parse_host(upstream_host).map_err(|_| invalid("invalid upstream host"))?;
        Ok(Self {
            prefix,
            target: Target {
                host,
                port: upstream_port,
            },
            header,
            value,
            strip: Vec::new(),
            paths: Vec::new(),
            write: true,
            #[cfg(feature = "test-loopback")]
            plain_upstream: false,
        })
    }

    /// Restrict what the injected credential may be used for.
    ///
    /// `paths` are path prefixes **after the route prefix is stripped** — for
    /// a `/github` route granting one repository, `/hexrift/WardOS.git` (git
    /// over HTTPS) and `/repos/hexrift/WardOS` (the REST API). A request whose
    /// stripped path is not under one of them is refused; the boundary rule is
    /// that of [`Self::matches_path`] (exact, or followed by `/` or `?`), so
    /// `/hexrift/WardOS.gitx` is not under `/hexrift/WardOS.git`. An empty
    /// list means every path. A trailing `/` on a prefix is ignored, a
    /// missing leading `/` is supplied, and a bare `/` covers everything.
    ///
    /// With `write == false` only read-only requests pass: `GET`, `HEAD`,
    /// `OPTIONS`, and a `POST` whose stripped path ends with
    /// `/git-upload-pack` (a git fetch). Everything else — `POST
    /// …/git-receive-pack` (a push), `PUT`, `PATCH`, `DELETE` — is refused.
    ///
    /// A refused request never reaches the upstream: see [`Self::permits`].
    /// Calling `scope` again replaces the previous scope.
    #[must_use]
    pub fn scope(
        mut self,
        paths: impl IntoIterator<Item = impl Into<String>>,
        write: bool,
    ) -> Self {
        self.paths = paths
            .into_iter()
            .map(|p| {
                let p = p.into();
                let trimmed = p.trim_end_matches('/');
                if trimmed.is_empty() || trimmed.starts_with('/') {
                    trimmed.to_owned()
                } else {
                    format!("/{trimmed}")
                }
            })
            .collect();
        self.write = write;
        self
    }

    /// Is a `verb` request for `stripped_path` (the path after
    /// [`Self::strip_prefix`], query included) within this route's scope?
    ///
    /// Pure: the verdict depends only on the route and the two arguments.
    /// The path is checked before the method, so a push to a repository
    /// outside the scope is reported as outside the scope.
    pub fn permits(&self, verb: &str, stripped_path: &str) -> Result<(), ScopeDenial> {
        if !self.paths.is_empty() && !self.paths.iter().any(|p| under_prefix(stripped_path, p)) {
            return Err(ScopeDenial::OutsideScope);
        }
        if self.write {
            return Ok(());
        }
        let path_only = stripped_path.split('?').next().unwrap_or_default();
        let read_only = match verb {
            "GET" | "HEAD" | "OPTIONS" => true,
            "POST" => path_only.ends_with("/git-upload-pack"),
            _ => false,
        };
        if read_only {
            Ok(())
        } else {
            Err(ScopeDenial::WriteNotGranted)
        }
    }

    /// Header names (matched case-insensitively) to remove from the client's
    /// request before injection — typically `authorization` and `x-api-key`,
    /// so the sandbox's placeholder token never reaches the upstream.
    #[must_use]
    pub fn strip_headers<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.strip
            .extend(names.into_iter().map(|n| n.as_ref().to_ascii_lowercase()));
        self
    }

    /// Speak plain HTTP to the upstream instead of TLS. Test builds only:
    /// lets an integration test run the upstream on loopback without a
    /// certificate.
    #[cfg(feature = "test-loopback")]
    #[must_use]
    pub fn plain_upstream(mut self, plain: bool) -> Self {
        self.plain_upstream = plain;
        self
    }

    /// The path prefix this route claims.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The upstream the route forwards to.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Does `path` fall under this route's prefix? `/anthropic` matches
    /// `/anthropic`, `/anthropic/v1` and `/anthropic?x`, never `/anthropicx`.
    pub fn matches_path(&self, path: &str) -> bool {
        under_prefix(path, &self.prefix)
    }

    /// Does this route serve `parsed`? Only forward requests can match.
    pub fn matches(&self, parsed: &Parsed) -> bool {
        match &parsed.request.method {
            Method::Forward { path, .. } => self.matches_path(path),
            Method::Connect => false,
        }
    }

    /// The path with the prefix removed, query kept: `/anthropic/v1?x` becomes
    /// `/v1?x`, `/anthropic` becomes `/`.
    pub fn strip_prefix<'a>(&self, path: &'a str) -> std::borrow::Cow<'a, str> {
        let rest = path.strip_prefix(self.prefix.as_str()).unwrap_or(path);
        match rest.as_bytes().first() {
            Some(b'/') => rest.into(),
            _ => format!("/{rest}").into(),
        }
    }

    /// The policy-relevant request as the upstream will see it: rewritten
    /// path, upstream target. This is what the [`crate::Observer`] receives.
    pub fn request(&self, parsed: &Parsed) -> Request {
        let method = match &parsed.request.method {
            Method::Forward { verb, path } => Method::Forward {
                verb: verb.clone(),
                path: self.strip_prefix(path).into_owned(),
            },
            Method::Connect => Method::Connect,
        };
        Request {
            method,
            target: self.target.clone(),
        }
    }

    /// The `Host` header for the upstream: the port is omitted when it is the
    /// HTTPS default.
    fn host_header(&self) -> String {
        if self.target.port == 443 {
            self.target.host.to_string()
        } else {
            self.target.to_string()
        }
    }

    /// Rebuild the request head for the upstream, injecting the credential.
    ///
    /// This is the single place the secret is read. The returned buffer is
    /// zeroed on drop; the error text never contains header values.
    pub(crate) fn rewrite_head(&self, parsed: &Parsed) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        const TRAILER: &[u8] = b"\r\nConnection: close\r\n\r\n";
        let Method::Forward { verb, path } = &parsed.request.method else {
            return Err("gateway routes serve forward requests only");
        };
        let value = self.value.expose();
        if value.is_empty()
            || value
                .iter()
                .any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f)
        {
            return Err("gateway credential is not a valid header value");
        }
        let mut drop = self.strip.clone();
        drop.push(self.header.to_ascii_lowercase());
        // `Expect: 100-continue` is answered by the proxy (see `proxy::serve`),
        // never forwarded.
        drop.push("expect".to_owned());
        let stripped = self.strip_prefix(path);
        let plain = http::build_head(parsed, verb, &stripped, &self.host_header(), &drop);
        // Sized up front so the buffer holding the secret never reallocates
        // (a reallocation would leave an unzeroed copy behind).
        let mut out = Zeroizing::new(Vec::with_capacity(
            plain.len() + self.header.len() + 2 + value.len() + TRAILER.len(),
        ));
        out.extend_from_slice(&plain);
        out.extend_from_slice(self.header.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(TRAILER);
        Ok(out)
    }

    /// Wrap a connected socket to a pinned address in TLS (SNI = the upstream
    /// host) and complete the handshake within `timeout`.
    pub(crate) fn connect(&self, tcp: TcpStream, timeout: Duration) -> io::Result<Upstream> {
        #[cfg(feature = "test-loopback")]
        if self.plain_upstream {
            return Ok(Upstream::Plain(tcp));
        }
        let name = match &self.target.host {
            Host::Name(n) => ServerName::try_from(n.clone()).map_err(io::Error::other)?,
            Host::Ip(ip) => ServerName::IpAddress((*ip).into()),
        };
        let conn = ClientConnection::new(tls_config()?, name).map_err(io::Error::other)?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.sock.set_read_timeout(Some(timeout))?;
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock)?;
        }
        Ok(Upstream::Tls(Box::new(tls)))
    }
}

/// Is `path` exactly `prefix`, or `prefix` followed by `/` or `?`? The one
/// boundary rule for route prefixes and scope paths alike.
fn under_prefix(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| matches!(rest.as_bytes().first(), None | Some(b'/' | b'?')))
}

impl fmt::Debug for GatewayRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayRoute")
            .field("prefix", &self.prefix)
            .field("target", &self.target)
            .field("header", &self.header)
            .field("value", &self.value)
            .field("strip", &self.strip)
            .field("paths", &self.paths)
            .field("write", &self.write)
            .finish_non_exhaustive()
    }
}

/// The upstream side of a gateway exchange.
pub(crate) enum Upstream {
    /// TLS to the pinned address (the shipped path).
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    /// Plain TCP; only constructible with the `test-loopback` feature.
    #[cfg_attr(not(feature = "test-loopback"), allow(dead_code))]
    Plain(TcpStream),
}

impl Upstream {
    /// The underlying socket, for timeouts.
    pub(crate) fn socket(&self) -> &TcpStream {
        match self {
            Self::Tls(tls) => &tls.sock,
            Self::Plain(tcp) => tcp,
        }
    }
}

impl Read for Upstream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tls(tls) => tls.read(buf),
            Self::Plain(tcp) => tcp.read(buf),
        }
    }
}

impl Write for Upstream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tls(tls) => tls.write(buf),
            Self::Plain(tcp) => tcp.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tls(tls) => tls.flush(),
            Self::Plain(tcp) => tcp.flush(),
        }
    }
}

/// The process-wide TLS client configuration: `ring` crypto, the platform's
/// safe default protocol versions (TLS 1.2 and 1.3), trust roots from the
/// host's certificate store, no client certificates. Built once.
fn tls_config() -> io::Result<Arc<ClientConfig>> {
    static CONFIG: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(build_tls_config)
        .clone()
        .map_err(io::Error::other)
}

fn build_tls_config() -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    let (added, _ignored) =
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if added == 0 {
        return Err("no usable CA certificates in the host trust store".to_owned());
    }
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const SECRET: &str = "sk-ant-api03-REAL-KEY";

    fn route() -> GatewayRoute {
        GatewayRoute::new(
            "/anthropic",
            "api.anthropic.com",
            443,
            "x-api-key",
            Secret::from(SECRET),
        )
        .unwrap()
        .strip_headers(["Authorization", "x-api-key"])
    }

    fn parsed(head: &str) -> Parsed {
        http::parse(head.as_bytes()).unwrap()
    }

    #[test]
    fn prefix_matching_respects_path_boundaries() {
        let r = route();
        for p in [
            "/anthropic",
            "/anthropic/",
            "/anthropic/v1/messages",
            "/anthropic?x=1",
        ] {
            assert!(r.matches_path(p), "{p}");
        }
        for p in [
            "/anthropicx",
            "/anthropi",
            "/",
            "/v1/anthropic",
            "anthropic/v1",
        ] {
            assert!(!r.matches_path(p), "{p}");
        }
        assert_eq!(
            r.strip_prefix("/anthropic/v1/messages?beta=1"),
            "/v1/messages?beta=1"
        );
        assert_eq!(r.strip_prefix("/anthropic"), "/");
        assert_eq!(r.strip_prefix("/anthropic?x=1"), "/?x=1");

        assert!(r.matches(&parsed(
            "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:3128"
        )));
        assert!(r.matches(&parsed(
            "GET http://127.0.0.1:3128/anthropic/v1/models HTTP/1.1"
        )));
        assert!(!r.matches(&parsed("CONNECT api.anthropic.com:443 HTTP/1.1")));
        assert!(!r.matches(&parsed("GET /other HTTP/1.1\r\nHost: h")));
    }

    #[test]
    fn rewrite_strips_prefix_replaces_host_and_injects_credential() {
        let p = parsed(
            "POST /anthropic/v1/messages?beta=true HTTP/1.1\r\n\
             Host: 127.0.0.1:3128\r\n\
             Authorization: Bearer placeholder-token\r\n\
             X-Api-Key: placeholder-key\r\n\
             Proxy-Connection: keep-alive\r\n\
             Proxy-Authorization: Basic zz\r\n\
             Expect: 100-continue\r\n\
             Connection: keep-alive\r\n\
             anthropic-version: 2023-06-01\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 2",
        );
        let head = route().rewrite_head(&p).unwrap();
        assert_eq!(
            std::str::from_utf8(&head).unwrap(),
            format!(
                "POST /v1/messages?beta=true HTTP/1.1\r\n\
                 Host: api.anthropic.com\r\n\
                 anthropic-version: 2023-06-01\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: 2\r\n\
                 x-api-key: {SECRET}\r\n\
                 Connection: close\r\n\r\n"
            )
        );
        let req = route().request(&p);
        assert_eq!(
            req.to_string(),
            "POST http://api.anthropic.com:443/v1/messages?beta=true"
        );
    }

    #[test]
    fn injected_header_always_replaces_the_client_copy() {
        let r = GatewayRoute::new(
            "/g",
            "example.com",
            8443,
            "Authorization",
            Secret::from("Bearer real"),
        )
        .unwrap();
        let p = parsed("GET /g HTTP/1.1\r\nHost: h\r\nauthorization: Bearer fake");
        let head = r.rewrite_head(&p).unwrap();
        let text = std::str::from_utf8(&head).unwrap();
        assert!(!text.contains("fake"), "{text}");
        assert!(text.starts_with("GET / HTTP/1.1\r\nHost: example.com:8443\r\n"));
        assert!(text.contains("Authorization: Bearer real\r\n"));
        assert_eq!(text.matches("uthorization").count(), 1);
    }

    #[test]
    fn debug_and_errors_never_contain_the_secret() {
        let r = route();
        let debug = format!("{r:?}");
        assert!(debug.contains("/anthropic") && debug.contains("Secret(<redacted>)"));
        assert!(!debug.contains(SECRET), "{debug}");
        let debug = format!("{:?}", scoped(false));
        assert!(
            debug.contains(REPO) && debug.contains("write: false"),
            "{debug}"
        );
        assert!(!debug.contains(SECRET), "{debug}");

        let bad = GatewayRoute::new(
            "/g",
            "example.com",
            443,
            "x-api-key",
            Secret::from("evil\r\nX: y"),
        )
        .unwrap();
        let err = bad
            .rewrite_head(&parsed("GET /g HTTP/1.1\r\nHost: h"))
            .unwrap_err();
        assert!(!err.contains("evil"), "{err}");
        let empty =
            GatewayRoute::new("/g", "example.com", 443, "x-api-key", Secret::from("")).unwrap();
        assert!(
            empty
                .rewrite_head(&parsed("GET /g HTTP/1.1\r\nHost: h"))
                .is_err()
        );
        assert!(
            route()
                .rewrite_head(&parsed("CONNECT a.com:1 HTTP/1.1"))
                .is_err()
        );
    }

    #[test]
    fn new_validates_prefix_host_port_and_header() {
        let secret = || Secret::from(SECRET);
        for (prefix, host, port, header) in [
            ("anthropic", "a.com", 443, "x"),
            ("/", "a.com", 443, "x"),
            ("/a/", "a.com", 443, "x"),
            ("/a b", "a.com", 443, "x"),
            ("/a?x", "a.com", 443, "x"),
            ("/a", "a_b.com", 443, "x"),
            ("/a", "", 443, "x"),
            ("/a", "a.com", 0, "x"),
            ("/a", "a.com", 443, ""),
            ("/a", "a.com", 443, "x api"),
        ] {
            let err = GatewayRoute::new(prefix, host, port, header, secret()).unwrap_err();
            let text = err.to_string();
            assert!(
                matches!(err, Error::InvalidGateway { .. }),
                "{prefix} {host}"
            );
            assert!(!text.contains(SECRET), "{text}");
        }
        let ip = GatewayRoute::new("/a", "127.0.0.1", 8080, "x", secret()).unwrap();
        assert_eq!(ip.target().to_string(), "127.0.0.1:8080");
        assert_eq!(ip.prefix(), "/a");
    }
    const REPO: &str = "/hexrift/WardOS.git";
    const API: &str = "/repos/hexrift/WardOS";

    fn scoped(write: bool) -> GatewayRoute {
        GatewayRoute::new(
            "/github",
            "github.com",
            443,
            "Authorization",
            Secret::from(SECRET),
        )
        .unwrap()
        .scope([REPO, API], write)
    }

    #[test]
    fn permits_checks_scope_paths_at_segment_boundaries() {
        let r = scoped(true);
        for p in [
            REPO,
            "/hexrift/WardOS.git/",
            "/hexrift/WardOS.git/info/refs?service=git-upload-pack",
            "/hexrift/WardOS.git?x=1",
            API,
            "/repos/hexrift/WardOS/pulls?state=open",
        ] {
            assert_eq!(r.permits("GET", p), Ok(()), "{p}");
        }
        for p in [
            "/hexrift/WardOS.gitx",
            "/hexrift/WardOS.gi",
            "/hexrift/WardOS",
            "/hexrift/other.git/info/refs",
            "/other/WardOS.git",
            "/repos/hexrift/WardOSx",
            "/repos/hexrift",
            "/",
            "/?path=/hexrift/WardOS.git",
            "hexrift/WardOS.git",
        ] {
            assert_eq!(r.permits("GET", p), Err(ScopeDenial::OutsideScope), "{p}");
        }
        // Path before method: a push to another repository is "outside
        // scope", not "write not granted".
        assert_eq!(
            scoped(false).permits("POST", "/hexrift/other.git/git-receive-pack"),
            Err(ScopeDenial::OutsideScope)
        );
    }

    #[test]
    fn permits_read_only_method_matrix() {
        let ro = scoped(false);
        let refs = "/hexrift/WardOS.git/info/refs?service=git-upload-pack";
        for verb in ["GET", "HEAD", "OPTIONS"] {
            assert_eq!(ro.permits(verb, refs), Ok(()), "{verb}");
            assert_eq!(ro.permits(verb, API), Ok(()), "{verb}");
        }
        // A fetch is a POST and still a read; the query does not matter.
        assert_eq!(
            ro.permits("POST", "/hexrift/WardOS.git/git-upload-pack"),
            Ok(())
        );
        assert_eq!(
            ro.permits("POST", "/hexrift/WardOS.git/git-upload-pack?x=1"),
            Ok(())
        );
        for (verb, path) in [
            ("POST", "/hexrift/WardOS.git/git-receive-pack"),
            ("POST", "/hexrift/WardOS.git/git-upload-packx"),
            ("POST", "/hexrift/WardOS.git/git-upload-pack/x"),
            ("POST", "/hexrift/WardOS.git?git-upload-pack"),
            ("POST", "/repos/hexrift/WardOS/issues"),
            ("PUT", "/repos/hexrift/WardOS/contents/x"),
            ("PATCH", "/repos/hexrift/WardOS"),
            ("DELETE", "/repos/hexrift/WardOS"),
            ("get", REPO),
            ("PROPFIND", REPO),
        ] {
            assert_eq!(
                ro.permits(verb, path),
                Err(ScopeDenial::WriteNotGranted),
                "{verb} {path}"
            );
        }
        let rw = scoped(true);
        for (verb, path) in [
            ("POST", "/hexrift/WardOS.git/git-receive-pack"),
            ("PUT", "/repos/hexrift/WardOS/contents/x"),
            ("DELETE", "/repos/hexrift/WardOS"),
        ] {
            assert_eq!(rw.permits(verb, path), Ok(()), "{verb} {path}");
        }
        assert_eq!(
            ScopeDenial::OutsideScope.to_string(),
            "outside credential scope"
        );
        assert_eq!(
            ScopeDenial::WriteNotGranted.to_string(),
            "write not granted"
        );
    }

    #[test]
    fn empty_scope_permits_every_path_and_an_unscoped_route_everything() {
        // No `scope` call: the model-API routes keep working unchanged.
        let open = route();
        for (verb, path) in [("POST", "/v1/messages"), ("DELETE", "/anything?x")] {
            assert_eq!(open.permits(verb, path), Ok(()), "{verb} {path}");
        }
        // Empty list: every path, but the write flag still applies.
        let ro = route().scope(Vec::<String>::new(), false);
        assert_eq!(ro.permits("GET", "/v1/models"), Ok(()));
        assert_eq!(
            ro.permits("POST", "/v1/messages"),
            Err(ScopeDenial::WriteNotGranted)
        );
        // A bare `/` covers everything; a trailing slash is not a stricter
        // prefix; a missing leading slash is supplied.
        assert_eq!(route().scope(["/"], true).permits("GET", "/x"), Ok(()));
        let trailing = route().scope(["/hexrift/WardOS.git/"], true);
        assert_eq!(trailing.permits("GET", REPO), Ok(()));
        assert_eq!(
            trailing.permits("GET", "/hexrift/WardOS.git/info/refs"),
            Ok(())
        );
        assert_eq!(
            trailing.permits("GET", "/hexrift/WardOS.gitx"),
            Err(ScopeDenial::OutsideScope)
        );
        let bare = route().scope(["hexrift/WardOS.git"], true);
        assert_eq!(bare.permits("GET", REPO), Ok(()));
        // A second call replaces the first.
        let replaced = route().scope([REPO], false).scope([API], true);
        assert_eq!(replaced.permits("DELETE", API), Ok(()));
        assert_eq!(
            replaced.permits("GET", REPO),
            Err(ScopeDenial::OutsideScope)
        );
    }
}
