#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end: a real proxy, a real loopback upstream, real sockets.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ward_proxy::{Config, Decision, Handle, Method, NetworkCapability, Observer, Proxy, Request};

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
    let s = TcpStream::connect(handle.local_addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Read until the blank line that ends a response head.
fn read_head(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).unwrap(), 1, "eof before head");
        buf.push(byte[0]);
    }
    String::from_utf8(buf).unwrap()
}

/// Read a whole `Connection: close` response.
fn read_all(stream: &mut TcpStream) -> String {
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
    let addr = proxy.local_addr();
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
