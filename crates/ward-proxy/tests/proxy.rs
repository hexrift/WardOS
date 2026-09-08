#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end: a real proxy, a real loopback upstream, real sockets.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ward_proxy::{
    Config, Decision, GatewayRoute, Handle, Method, NetworkCapability, Observer, Proxy, Request,
    Secret, StaticResolver,
};

/// Records every decision the proxy reports.
#[derive(Default)]
struct Recorder(Mutex<Vec<(Request, Decision, String)>>);

impl Observer for Recorder {
    fn decision(&self, req: &Request, decision: Decision, reason: &str) {
        self.0
            .lock()
            .unwrap()
            .push((req.clone(), decision, reason.to_owned()));
    }
}

impl Recorder {
    fn last(&self) -> (Request, Decision, String) {
        self.0.lock().unwrap().last().cloned().expect("a decision")
    }
}

/// A loopback TCP server that echoes every byte back on each connection.
fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut rx = stream.try_clone().unwrap();
                let mut tx = stream;
                let mut buf = [0u8; 4096];
                while let Ok(n) = rx.read(&mut buf) {
                    if n == 0 || tx.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = tx.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

/// A loopback HTTP/1.1 server that answers one request with its request line.
fn spawn_http() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let body = text.trim_end().lines().collect::<Vec<_>>().join("|");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(Shutdown::Write);
            });
        }
    });
    addr
}

fn custom_localhost() -> Config {
    let set: BTreeSet<String> = ["localhost".to_owned()].into_iter().collect();
    Config::new(NetworkCapability::Custom(set)).allow_loopback(true)
}

fn start(config: Config) -> (Handle, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let handle = Proxy::spawn(config, recorder.clone()).expect("proxy starts");
    (handle, recorder)
}

fn client(handle: &Handle) -> TcpStream {
    let s = TcpStream::connect(handle.local_addr().expect("tcp listener")).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Read until the blank line that ends a response head.
fn read_head(stream: &mut impl Read) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).unwrap(), 1, "eof before head");
        buf.push(byte[0]);
    }
    String::from_utf8(buf).unwrap()
}

/// Read a whole `Connection: close` response.
fn read_all(stream: &mut impl Read) -> String {
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn connect_tunnel_to_loopback_echoes_bytes() {
    let echo = spawn_echo();
    let (proxy, recorder) = start(custom_localhost());

    for target in [
        format!("127.0.0.1:{}", echo.port()),
        format!("localhost:{}", echo.port()),
    ] {
        let mut c = client(&proxy);
        c.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .unwrap();
        let head = read_head(&mut c);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");

        let payload = b"ward-proxy tunnel \x16\x03\x01 bytes";
        c.write_all(payload).unwrap();
        let mut echoed = vec![0u8; payload.len()];
        c.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, payload);

        let (req, decision, reason) = recorder.last();
        assert_eq!(decision, Decision::Allow);
        assert_eq!(req.method, Method::Connect);
        assert_eq!(req.target.port, echo.port());
        assert!(reason.starts_with("pinned "), "{reason}");

        c.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        c.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }
}

#[test]
fn offline_connect_is_403_and_observed_as_deny() {
    let (proxy, recorder) = start(Config::new(NetworkCapability::Offline));
    let mut c = client(&proxy);
    c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .unwrap();
    let response = read_all(&mut c);
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert!(response.contains("not permitted"), "{response}");
    assert!(!response.contains("example.com"), "leaks host: {response}");

    let (req, decision, reason) = recorder.last();
    assert_eq!(decision, Decision::Deny);
    assert_eq!(req.to_string(), "CONNECT example.com:443");
    assert_eq!(reason, "session network mode is offline");
}

#[test]
fn private_and_metadata_destinations_are_403_in_every_mode() {
    let (proxy, recorder) = start(Config::new(NetworkCapability::Unrestricted));
    for target in [
        "10.0.0.1:80",
        "169.254.169.254:80",
        "[fd00:ec2::254]:80",
        "[::1]:80",
    ] {
        let mut c = client(&proxy);
        c.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        assert!(read_all(&mut c).starts_with("HTTP/1.1 403"), "{target}");
        assert_eq!(recorder.last().1, Decision::Deny, "{target}");
    }
}

#[test]
fn plain_http_forward_rewrites_to_origin_form() {
    let http = spawn_http();
    let (proxy, recorder) = start(custom_localhost());
    let mut c = client(&proxy);
    c.write_all(
        format!(
            "GET http://localhost:{}/hello?x=1 HTTP/1.1\r\n\
             Host: spoofed.invalid\r\n\
             Proxy-Connection: keep-alive\r\n\
             Accept: text/plain\r\n\r\n",
            http.port()
        )
        .as_bytes(),
    )
    .unwrap();
    let response = read_all(&mut c);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    let body = response.rsplit("\r\n\r\n").next().unwrap();
    assert_eq!(
        body,
        format!(
            "GET /hello?x=1 HTTP/1.1|Host: localhost:{}|Accept: text/plain|Connection: close",
            http.port()
        )
    );
    let (req, decision, _) = recorder.last();
    assert_eq!(decision, Decision::Allow);
    assert!(
        matches!(req.method, Method::Forward { ref verb, ref path } if verb == "GET" && path == "/hello?x=1")
    );
}

#[test]
fn malformed_requests_are_400_without_a_decision() {
    let (proxy, recorder) = start(Config::new(NetworkCapability::Unrestricted));
    let cases: Vec<Vec<u8>> = vec![
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        b"CONNECT example.com HTTP/1.1\r\n\r\n".to_vec(),
        b"CONNECT example.com:443 HTTP/1.1\nHost: x\n\n".to_vec(),
        b"GET https://example.com/ HTTP/1.1\r\n\r\n".to_vec(),
        {
            let mut huge = b"CONNECT example.com:443 HTTP/1.1\r\nX: ".to_vec();
            huge.extend(std::iter::repeat_n(b'a', 9000));
            huge.extend_from_slice(b"\r\n\r\n");
            huge
        },
    ];
    for case in cases {
        let mut c = client(&proxy);
        c.write_all(&case).unwrap();
        // Half-close so a head that never terminates is seen as truncated.
        c.shutdown(Shutdown::Write).unwrap();
        let response = read_all(&mut c);
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{response}"
        );
    }
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[test]
fn capacity_is_bounded_with_503() {
    let echo = spawn_echo();
    let (proxy, _) = start(custom_localhost().max_connections(1));
    let mut first = client(&proxy);
    first
        .write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo.port()).as_bytes())
        .unwrap();
    assert!(read_head(&mut first).starts_with("HTTP/1.1 200"));

    let mut second = client(&proxy);
    let response = read_all(&mut second);
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    drop(first);
}

#[test]
fn shutdown_stops_the_listener_and_open_tunnels() {
    let echo = spawn_echo();
    let (proxy, _) = start(custom_localhost());
    let addr = proxy.local_addr().unwrap();
    let mut c = client(&proxy);
    c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo.port()).as_bytes())
        .unwrap();
    assert!(read_head(&mut c).starts_with("HTTP/1.1 200"));

    proxy.shutdown();
    // The tunnel is closed by the relay noticing the flag.
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).unwrap();
    // Nothing accepts any more.
    let refused = TcpStream::connect_timeout(&addr, Duration::from_secs(1));
    assert!(refused.is_err() || read_all(&mut refused.unwrap()).is_empty());
}

/// A short, unique socket path under the system temp dir (`sun_path` is small).
fn socket_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("wp-{tag}-{}.sock", std::process::id()))
}

#[test]
fn unix_listener_tunnels_exactly_like_tcp() {
    let echo = spawn_echo();
    let path = socket_path("tunnel");
    let (proxy, recorder) = start(custom_localhost().listen_unix(&path));
    assert_eq!(proxy.local_addr(), None);
    assert_eq!(proxy.unix_path(), Some(path.as_path()));

    let mut c = UnixStream::connect(&path).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let target = format!("127.0.0.1:{}", echo.port());
    c.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .unwrap();
    let head = read_head(&mut c);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    let payload = b"over a unix socket \x16\x03\x01";
    c.write_all(payload).unwrap();
    let mut echoed = vec![0u8; payload.len()];
    c.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, payload);

    let (req, decision, reason) = recorder.last();
    assert_eq!(decision, Decision::Allow);
    assert_eq!(req.method, Method::Connect);
    assert_eq!(req.target.port, echo.port());
    assert!(reason.starts_with("pinned "), "{reason}");

    c.shutdown(Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());

    // Policy is the same policy: a denial over Unix is the same 403.
    let mut d = UnixStream::connect(&path).unwrap();
    d.write_all(b"CONNECT 10.0.0.1:80 HTTP/1.1\r\n\r\n")
        .unwrap();
    assert!(read_all(&mut d).starts_with("HTTP/1.1 403"));
    assert_eq!(recorder.last().1, Decision::Deny);
}

#[test]
fn unix_shutdown_unlinks_the_socket_and_closes_tunnels() {
    let echo = spawn_echo();
    let path = socket_path("shutdown");
    let (proxy, _) = start(custom_localhost().listen_unix(&path));
    let mut c = UnixStream::connect(&path).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo.port()).as_bytes())
        .unwrap();
    assert!(read_head(&mut c).starts_with("HTTP/1.1 200"));

    proxy.shutdown();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).unwrap();
    assert!(!path.exists(), "socket file left behind");
    assert!(UnixStream::connect(&path).is_err());
    // Idempotent: a second shutdown (and the eventual drop) is a no-op.
    proxy.shutdown();
}

const REAL_KEY: &str = "sk-ant-api03-the-real-key";
const PLACEHOLDER: &str = "placeholder-token";

/// A loopback HTTP/1.1 upstream for gateway tests: records the full request
/// (head and body, by `Content-Length` or chunked-until-`0\r\n\r\n`) and
/// answers with a response streamed in two parts, `gap` apart.
fn spawn_gateway_upstream(gap: Duration) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let log = log.clone();
            thread::spawn(move || {
                stream.set_nodelay(true).unwrap();
                let mut req = Vec::new();
                let mut byte = [0u8; 1];
                let mut body_len = None;
                let mut head_end = None;
                while stream.read(&mut byte).unwrap_or(0) == 1 {
                    req.push(byte[0]);
                    if head_end.is_none() && req.ends_with(b"\r\n\r\n") {
                        head_end = Some(req.len());
                        let head = String::from_utf8_lossy(&req).into_owned();
                        let len = head.lines().find_map(|l| {
                            l.strip_prefix("Content-Length: ")
                                .map(|v| v.parse::<usize>().unwrap())
                        });
                        body_len = Some(len.unwrap_or(0));
                        if head.contains("chunked") {
                            body_len = None;
                        }
                    }
                    if let Some(end) = head_end {
                        let done = match body_len {
                            Some(n) => req.len() >= end + n,
                            None => req.ends_with(b"0\r\n\r\n"),
                        };
                        if done {
                            break;
                        }
                    }
                }
                log.lock().unwrap().push(req);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: part1\n\n",
                );
                let _ = stream.flush();
                thread::sleep(gap);
                let _ = stream.write_all(b"data: part2\n\n");
                let _ = stream.shutdown(Shutdown::Write);
            });
        }
    });
    (addr, seen)
}

fn gateway_route(upstream: SocketAddr) -> GatewayRoute {
    GatewayRoute::new(
        "/anthropic",
        "127.0.0.1",
        upstream.port(),
        "x-api-key",
        Secret::from(REAL_KEY),
    )
    .unwrap()
    .strip_headers(["authorization", "x-api-key"])
    .plain_upstream(true)
}

#[test]
fn gateway_rewrites_injects_and_streams_the_response() {
    let gap = Duration::from_millis(400);
    let (upstream, seen) = spawn_gateway_upstream(gap);
    let (proxy, recorder) = start(custom_localhost().gateway(gateway_route(upstream)));
    let body = r#"{"model":"claude","stream":true}"#;
    let mut c = client(&proxy);
    c.write_all(
        format!(
            "POST /anthropic/v1/messages?beta=true HTTP/1.1\r\n\
             Host: 127.0.0.1:3128\r\n\
             Authorization: Bearer {PLACEHOLDER}\r\n\
             X-Api-Key: {PLACEHOLDER}\r\n\
             Proxy-Connection: keep-alive\r\n\
             anthropic-version: 2023-06-01\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    let started = std::time::Instant::now();

    // The first part must come through before the upstream has even sent
    // the second: nothing is buffered.
    let head = read_head(&mut c);
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    let mut first = [0u8; 64];
    let n = c.read(&mut first).unwrap();
    assert_eq!(&first[..n], b"data: part1\n\n");
    assert!(started.elapsed() < gap, "first part was held back");
    let rest = read_all(&mut c);
    assert_eq!(rest, "data: part2\n\n");
    assert!(started.elapsed() >= gap);

    let seen = seen.lock().unwrap();
    let upstream_req = String::from_utf8(seen[0].clone()).unwrap();
    let (u_head, u_body) = upstream_req.split_once("\r\n\r\n").unwrap();
    assert_eq!(u_body, body);
    let lines: Vec<&str> = u_head.lines().collect();
    assert_eq!(lines[0], "POST /v1/messages?beta=true HTTP/1.1");
    assert_eq!(lines[1], format!("Host: 127.0.0.1:{}", upstream.port()));
    assert!(
        lines.contains(&format!("x-api-key: {REAL_KEY}").as_str()),
        "{u_head}"
    );
    assert!(lines.contains(&"anthropic-version: 2023-06-01"), "{u_head}");
    assert_eq!(lines.last(), Some(&"Connection: close"));
    assert!(
        !u_head.contains(PLACEHOLDER),
        "placeholder forwarded: {u_head}"
    );
    assert!(!u_head.contains("Authorization"), "{u_head}");
    assert!(!u_head.contains("Proxy-"), "{u_head}");
    assert!(!u_head.contains("/anthropic"), "{u_head}");

    let (req, decision, reason) = recorder.last();
    assert_eq!(decision, Decision::Allow);
    assert_eq!(reason, "gateway /anthropic");
    assert_eq!(req.target.port, upstream.port());
    assert!(
        matches!(req.method, Method::Forward { ref verb, ref path } if verb == "POST" && path == "/v1/messages?beta=true")
    );
    assert!(!reason.contains(REAL_KEY) && !req.to_string().contains(REAL_KEY));
}

#[test]
fn gateway_forwards_chunked_bodies_and_absolute_form() {
    let (upstream, seen) = spawn_gateway_upstream(Duration::ZERO);
    let (proxy, _) = start(custom_localhost().gateway(gateway_route(upstream)));
    let mut c = client(&proxy);
    c.write_all(
        b"POST http://127.0.0.1:3128/anthropic/v1/messages HTTP/1.1\r\n\
          Host: 127.0.0.1:3128\r\n\
          Transfer-Encoding: chunked\r\n\r\n\
          5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    )
    .unwrap();
    let response = read_all(&mut c);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("data: part1\n\ndata: part2\n\n"));
    let seen = seen.lock().unwrap();
    let upstream_req = String::from_utf8(seen[0].clone()).unwrap();
    assert!(upstream_req.starts_with("POST /v1/messages HTTP/1.1\r\n"));
    assert!(upstream_req.ends_with("\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"));
    assert!(upstream_req.contains(&format!("x-api-key: {REAL_KEY}\r\n")));
}

#[test]
fn gateway_upstream_is_host_chosen_and_prefix_is_exact() {
    let (upstream, seen) = spawn_gateway_upstream(Duration::ZERO);
    // The host configured the route, so the sandbox's allowlist does not
    // apply to its upstream: `localhost_only` still reaches it. A route whose
    // upstream does not resolve is the usual 403, secret unused.
    let resolver = Arc::new(StaticResolver::new());
    let unresolvable = GatewayRoute::new(
        "/openai",
        "api.openai.invalid",
        443,
        "Authorization",
        Secret::from(REAL_KEY),
    )
    .unwrap();
    let (proxy, recorder) = start(
        Config::new(NetworkCapability::LocalhostOnly)
            .resolver(resolver)
            .gateway(gateway_route(upstream))
            .gateway(unresolvable),
    );

    let mut denied = client(&proxy);
    denied
        .write_all(b"GET /openai/v1/models HTTP/1.1\r\nHost: 127.0.0.1:3128\r\n\r\n")
        .unwrap();
    let response = read_all(&mut denied);
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(!response.contains(REAL_KEY));
    let (req, decision, reason) = recorder.last();
    assert_eq!(decision, Decision::Deny);
    assert_eq!(reason, "host did not resolve");
    assert_eq!(
        req.to_string(),
        "GET http://api.openai.invalid:443/v1/models"
    );

    let mut allowed = client(&proxy);
    allowed.write_all(
        b"GET /anthropic/v1/models HTTP/1.1\r\nHost: 127.0.0.1:3128\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert!(read_head(&mut allowed).starts_with("HTTP/1.1 200"));
    let _ = read_all(&mut allowed);
    assert_eq!(recorder.last().2, "gateway /anthropic");

    // Offline is still offline, gateway or not.
    let (offline, recorder_off) =
        start(Config::new(NetworkCapability::Offline).gateway(gateway_route(upstream)));
    let mut off = client(&offline);
    off.write_all(b"GET /anthropic/v1/models HTTP/1.1\r\nHost: 127.0.0.1:3128\r\n\r\n")
        .unwrap();
    assert!(read_all(&mut off).starts_with("HTTP/1.1 403"));
    assert_eq!(recorder_off.last().2, "session network mode is offline");

    // `/anthropicx` is not under `/anthropic`; with no route it is not a
    // proxy request at all, and no decision is recorded for it.
    let before = recorder.0.lock().unwrap().len();
    let mut n = client(&proxy);
    n.write_all(b"GET /anthropicx/v1 HTTP/1.1\r\nHost: 127.0.0.1:3128\r\n\r\n")
        .unwrap();
    assert!(read_all(&mut n).starts_with("HTTP/1.1 400"));
    assert_eq!(recorder.0.lock().unwrap().len(), before);

    // CONNECT to the upstream is a plain tunnel, never a gateway: the bytes
    // that arrive upstream are exactly the client's, without a credential.
    let mut t = client(&proxy);
    t.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", upstream.port()).as_bytes())
        .unwrap();
    assert!(read_head(&mut t).starts_with("HTTP/1.1 200"));
    t.write_all(b"GET /anthropic/v1/models HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        .unwrap();
    let _ = read_all(&mut t);
    assert_eq!(recorder.last().2, format!("pinned 127.0.0.1"));
    let seen = seen.lock().unwrap();
    let tunnelled = String::from_utf8(seen.last().unwrap().clone()).unwrap();
    assert!(tunnelled.starts_with("GET /anthropic/v1/models HTTP/1.1\r\n"));
    assert!(!tunnelled.contains(REAL_KEY));
}

/// A `/github` route granting one repository (git over HTTPS and the REST
/// API), read-only or read-write.
fn github_route(upstream: SocketAddr, write: bool) -> GatewayRoute {
    GatewayRoute::new(
        "/github",
        "127.0.0.1",
        upstream.port(),
        "Authorization",
        Secret::from(format!("Bearer {REAL_KEY}")),
    )
    .unwrap()
    .strip_headers(["authorization"])
    .scope(["/hexrift/WardOS.git", "/repos/hexrift/WardOS"], write)
    .plain_upstream(true)
}

fn send(proxy: &Handle, head: &str) -> String {
    let mut c = client(proxy);
    c.write_all(head.as_bytes()).unwrap();
    read_all(&mut c)
}

const REFUSED: &str = "request outside credential scope";

#[test]
fn gateway_scope_admits_an_in_scope_read_with_the_credential() {
    let (upstream, seen) = spawn_gateway_upstream(Duration::ZERO);
    let (proxy, recorder) = start(custom_localhost().gateway(github_route(upstream, false)));
    let response = send(
        &proxy,
        "GET /github/hexrift/WardOS.git/info/refs?service=git-upload-pack HTTP/1.1\r\n\
         Host: 127.0.0.1:3128\r\n\
         Authorization: Basic placeholder\r\n\
         Git-Protocol: version=2\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("data: part1\n\ndata: part2\n\n"));

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let upstream_req = String::from_utf8(seen[0].clone()).unwrap();
    let lines: Vec<&str> = upstream_req.lines().collect();
    assert_eq!(
        lines[0],
        "GET /hexrift/WardOS.git/info/refs?service=git-upload-pack HTTP/1.1"
    );
    assert!(
        lines.contains(&format!("Authorization: Bearer {REAL_KEY}").as_str()),
        "{upstream_req}"
    );
    assert!(lines.contains(&"Git-Protocol: version=2"), "{upstream_req}");
    assert!(!upstream_req.contains("placeholder"), "{upstream_req}");
    let (req, decision, reason) = recorder.last();
    assert_eq!(decision, Decision::Allow);
    assert_eq!(reason, "gateway /github");
    assert!(
        matches!(req.method, Method::Forward { ref verb, ref path } if verb == "GET" && path == "/hexrift/WardOS.git/info/refs?service=git-upload-pack")
    );
}

#[test]
fn gateway_scope_refuses_another_repository_before_any_upstream_contact() {
    let (upstream, seen) = spawn_gateway_upstream(Duration::ZERO);
    let (proxy, recorder) = start(custom_localhost().gateway(github_route(upstream, true)));
    for path in [
        "/github/hexrift/other.git/info/refs?service=git-upload-pack",
        "/github/hexrift/WardOS.gitx/info/refs",
        "/github/repos/hexrift/other/pulls",
        "/github/user",
        "/github",
    ] {
        let response = send(
            &proxy,
            &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:3128\r\n\r\n"),
        );
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
            "{response}"
        );
        assert!(
            response.ends_with(&format!("\r\n\r\n{REFUSED}\n")),
            "{response}"
        );
        assert!(!response.contains(REAL_KEY), "{response}");
        let (req, decision, reason) = recorder.last();
        assert_eq!(decision, Decision::Deny, "{path}");
        assert_eq!(reason, "gateway /github: outside credential scope");
        assert!(!req.to_string().contains(REAL_KEY));
    }
    // The upstream never heard from the proxy: no connection, no secret.
    thread::sleep(Duration::from_millis(100));
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn gateway_scope_read_only_refuses_a_push_that_a_write_route_forwards() {
    let (upstream, seen) = spawn_gateway_upstream(Duration::ZERO);
    let push = "POST /github/hexrift/WardOS.git/git-receive-pack HTTP/1.1\r\n\
                Host: 127.0.0.1:3128\r\n\
                Content-Type: application/x-git-receive-pack-request\r\n\
                Content-Length: 4\r\n\r\npack";
    let (read_only, recorder) = start(custom_localhost().gateway(github_route(upstream, false)));
    for head in [
        push,
        "DELETE /github/repos/hexrift/WardOS HTTP/1.1\r\nHost: 127.0.0.1:3128\r\n\r\n",
        "PATCH /github/repos/hexrift/WardOS HTTP/1.1\r\nHost: 127.0.0.1:3128\r\nContent-Length: 0\r\n\r\n",
    ] {
        let response = send(&read_only, head);
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
            "{response}"
        );
        assert!(
            response.ends_with(&format!("\r\n\r\n{REFUSED}\n")),
            "{response}"
        );
        let (_, decision, reason) = recorder.last();
        assert_eq!(decision, Decision::Deny);
        assert_eq!(reason, "gateway /github: write not granted");
    }
    thread::sleep(Duration::from_millis(100));
    assert!(
        seen.lock().unwrap().is_empty(),
        "read-only route reached upstream"
    );

    // A fetch is a POST too, and is a read.
    let fetch = "POST /github/hexrift/WardOS.git/git-upload-pack HTTP/1.1\r\n\
                 Host: 127.0.0.1:3128\r\n\
                 Content-Length: 4\r\n\r\nwant";
    let response = send(&read_only, fetch);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert_eq!(recorder.last().2, "gateway /github");
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let text = String::from_utf8(seen[0].clone()).unwrap();
        assert!(text.starts_with("POST /hexrift/WardOS.git/git-upload-pack HTTP/1.1\r\n"));
        assert!(text.ends_with("\r\n\r\nwant"));
    }

    // The same push on a write route reaches the upstream with the credential.
    let (write, recorder_w) = start(custom_localhost().gateway(github_route(upstream, true)));
    let response = send(&write, push);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert_eq!(recorder_w.last().1, Decision::Allow);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    let text = String::from_utf8(seen[1].clone()).unwrap();
    assert!(text.starts_with("POST /hexrift/WardOS.git/git-receive-pack HTTP/1.1\r\n"));
    assert!(text.contains(&format!("Authorization: Bearer {REAL_KEY}\r\n")));
    assert!(text.ends_with("\r\n\r\npack"));
}

#[test]
fn config_debug_never_reveals_the_secret() {
    let config = Config::new(NetworkCapability::Development).gateway(
        GatewayRoute::new(
            "/anthropic",
            "api.anthropic.com",
            443,
            "x-api-key",
            Secret::from(REAL_KEY),
        )
        .unwrap(),
    );
    let debug = format!("{config:?}");
    assert!(debug.contains("/anthropic") && debug.contains("Secret(<redacted>)"));
    assert!(!debug.contains(REAL_KEY), "{debug}");
}

#[test]
fn unix_request_timeout_drops_a_silent_client() {
    let path = socket_path("timeout");
    let (proxy, recorder) = start(
        custom_localhost()
            .listen_unix(&path)
            .request_timeout(Duration::from_millis(300)),
    );
    let mut c = UnixStream::connect(&path).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let started = std::time::Instant::now();
    // Never send a head: the proxy must hang up, not wait forever.
    assert!(read_all(&mut c).is_empty());
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(recorder.0.lock().unwrap().is_empty());
    drop(proxy);
    assert!(!path.exists());
}
