#![allow(clippy::unwrap_used, clippy::expect_used)]
//! A gateway route bound to a credential lease (#267): once the lease's
//! deadline has passed the proxy refuses the route before it resolves,
//! connects to or injects anything, and a renewal that moves the shared
//! deadline lets the same route through again.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ward_proxy::{
    Config, Decision, GatewayRoute, Handle, LeaseDeadline, NetworkCapability, Observer, Proxy,
    Request, Secret,
};

const LEASED: &str = "leased-token-value-0001";

#[derive(Default)]
struct Recorder(Mutex<Vec<(Decision, String)>>);

impl Observer for Recorder {
    fn decision(&self, _req: &Request, decision: Decision, reason: &str) {
        self.0.lock().unwrap().push((decision, reason.to_owned()));
    }
}

/// A loopback upstream that counts the connections it accepted and keeps
/// every request head it read.
fn spawn_upstream() -> (SocketAddr, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let heads = Arc::new(Mutex::new(Vec::new()));
    let (count, log) = (accepted.clone(), heads.clone());
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            count.fetch_add(1, Ordering::SeqCst);
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).into_owned());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (addr, accepted, heads)
}

fn start(route: GatewayRoute) -> (Handle, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let observer: Arc<dyn Observer> = recorder.clone();
    let config = Config::new(NetworkCapability::Custom(BTreeSet::from([
        "localhost".to_owned()
    ])))
    .allow_loopback(true)
    .gateway(route);
    let handle = Proxy::spawn(config, observer).unwrap();
    (handle, recorder)
}

fn send(proxy: &Handle) -> String {
    let mut c = TcpStream::connect(proxy.local_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(
        b"GET /leased/v1/items HTTP/1.1\r\nHost: 127.0.0.1:3128\r\n\
          Authorization: Bearer placeholder\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).unwrap();
    out
}

fn route(upstream: SocketAddr, deadline: &LeaseDeadline) -> GatewayRoute {
    GatewayRoute::new(
        "/leased",
        "127.0.0.1",
        upstream.port(),
        "authorization",
        Secret::from(format!("Bearer {LEASED}")),
    )
    .unwrap()
    .strip_headers(["authorization"])
    .until(deadline.clone())
    .plain_upstream(true)
}

#[test]
fn an_expired_lease_is_refused_before_any_upstream_contact() {
    let (upstream, accepted, _) = spawn_upstream();
    let deadline = LeaseDeadline::at(UNIX_EPOCH + Duration::from_secs(1));
    assert!(deadline.expired_at(SystemTime::now()));
    let (proxy, recorder) = start(route(upstream, &deadline));

    let response = send(&proxy);
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert!(response.contains("credential lease expired"), "{response}");
    assert!(!response.contains(LEASED), "{response}");
    let (decision, reason) = recorder.0.lock().unwrap().last().cloned().unwrap();
    assert_eq!(decision, Decision::Deny);
    assert_eq!(reason, "gateway /leased: credential lease expired");
    // The refusal is decided and answered before the serving thread ever
    // resolves or connects: nothing reached the upstream.
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
}

#[test]
fn a_renewed_deadline_lets_the_same_route_through_and_a_shortened_one_stops_it() {
    let (upstream, _, heads) = spawn_upstream();
    let deadline = LeaseDeadline::at(UNIX_EPOCH + Duration::from_secs(1));
    let (proxy, _recorder) = start(route(upstream, &deadline));
    assert!(send(&proxy).starts_with("HTTP/1.1 403"));

    // A renewal moves the deadline every clone of it shares.
    deadline.set(SystemTime::now() + Duration::from_secs(600));
    assert!(!deadline.expired_at(SystemTime::now()));
    let response = send(&proxy);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    let head = heads.lock().unwrap().last().cloned().unwrap();
    assert!(
        head.contains(&format!("authorization: Bearer {LEASED}")),
        "{head}"
    );
    assert!(!head.contains("placeholder"), "{head}");

    // Expiring it again (a revocation, or the end of the lease) refuses anew.
    deadline.set(UNIX_EPOCH);
    assert!(send(&proxy).starts_with("HTTP/1.1 403"));
}

#[test]
fn a_route_without_a_lease_never_expires() {
    let (upstream, _, _) = spawn_upstream();
    let route = GatewayRoute::new(
        "/leased",
        "127.0.0.1",
        upstream.port(),
        "authorization",
        Secret::from("Bearer static"),
    )
    .unwrap()
    .plain_upstream(true);
    let (proxy, _recorder) = start(route);
    assert!(send(&proxy).starts_with("HTTP/1.1 200 OK\r\n"));
}
