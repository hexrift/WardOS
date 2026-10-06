#![allow(clippy::unwrap_used, clippy::expect_used)]
//! A hold (#415): a caller's veto on requests the policy allows, consulted before anything
//! is resolved, connected or injected, and lifted only by the caller.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ward_proxy::{
    Config, Decision, GatewayRoute, Handle, Held, Hold, Host, NetworkCapability, Observer, Proxy,
    Request, Secret, Target,
};

const INJECTED: &str = "hold-test-injected-value";

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

/// Holds every request until released, and remembers what it was asked about.
#[derive(Debug, Default)]
struct Gate {
    released: AtomicBool,
    asked: Mutex<Vec<(String, Option<String>)>>,
}

impl Hold for Gate {
    fn held(&self, target: &Target, route: Option<&str>) -> Option<Held> {
        let host = match &target.host {
            Host::Name(name) => name.clone(),
            Host::Ip(ip) => ip.to_string(),
        };
        self.asked
            .lock()
            .unwrap()
            .push((host, route.map(str::to_owned)));
        (!self.released.load(Ordering::Acquire)).then(|| Held {
            reason: "hold:held:1".to_owned(),
            body: "held for approval",
        })
    }
}

impl Gate {
    fn asked(&self) -> Vec<(String, Option<String>)> {
        self.asked.lock().unwrap().clone()
    }
}

/// A loopback server answering every request with a fixed response, counting connections
/// and keeping what it was sent.
fn spawn_upstream() -> (SocketAddr, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (counted, kept) = (count.clone(), seen.clone());
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::AcqRel);
            let kept = kept.clone();
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                kept.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).into_owned());
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nreached",
                );
                let _ = stream.shutdown(Shutdown::Write);
            });
        }
    });
    (addr, count, seen)
}

fn config(hosts: &[&str]) -> Config {
    let set: BTreeSet<String> = hosts.iter().map(|h| (*h).to_owned()).collect();
    Config::new(NetworkCapability::Custom(set)).allow_loopback(true)
}

fn start(config: Config) -> (Handle, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let handle = Proxy::spawn(config, recorder.clone()).unwrap();
    (handle, recorder)
}

fn send(proxy: &Handle, head: &str) -> String {
    let mut stream = TcpStream::connect(proxy.local_addr().unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(head.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    out
}

#[test]
fn a_held_host_is_refused_403_before_it_is_resolved_or_connected_until_released() {
    let (upstream, connections, _) = spawn_upstream();
    let gate = Arc::new(Gate::default());
    let (proxy, recorder) = start(config(&["localhost"]).hold(gate.clone()));
    let forward = format!(
        "GET http://localhost:{}/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        upstream.port()
    );

    let refused = send(&proxy, &forward);
    assert!(
        refused.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{refused}"
    );
    assert!(refused.ends_with("held for approval\n"), "{refused}");
    assert_eq!(connections.load(Ordering::Acquire), 0);
    let (req, decision, reason) = recorder.last();
    assert_eq!(decision, Decision::Deny);
    assert_eq!(reason, "hold:held:1");
    assert_eq!(req.target.port, upstream.port());
    assert_eq!(gate.asked(), vec![("localhost".to_owned(), None)]);

    gate.released.store(true, Ordering::Release);
    let reached = send(&proxy, &forward);
    assert!(reached.starts_with("HTTP/1.1 200 OK\r\n"), "{reached}");
    assert!(reached.ends_with("reached"), "{reached}");
    assert_eq!(connections.load(Ordering::Acquire), 1);
    assert_eq!(recorder.last().1, Decision::Allow);
}

#[test]
fn a_held_tunnel_is_refused_before_it_is_established() {
    let (upstream, connections, _) = spawn_upstream();
    let gate = Arc::new(Gate::default());
    let (proxy, recorder) = start(config(&["localhost"]).hold(gate.clone()));
    let refused = send(
        &proxy,
        &format!(
            "CONNECT localhost:{0} HTTP/1.1\r\nHost: localhost:{0}\r\n\r\n",
            upstream.port()
        ),
    );
    assert!(
        refused.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{refused}"
    );
    assert!(refused.ends_with("held for approval\n"), "{refused}");
    assert_eq!(connections.load(Ordering::Acquire), 0);
    assert_eq!(recorder.last().1, Decision::Deny);
}

#[test]
fn what_the_policy_refuses_is_refused_by_the_policy_without_asking_the_hold() {
    let gate = Arc::new(Gate::default());
    let (proxy, recorder) = start(config(&["localhost"]).hold(gate.clone()));
    let refused = send(
        &proxy,
        "CONNECT other.example:443 HTTP/1.1\r\nHost: other.example:443\r\n\r\n",
    );
    assert!(
        refused.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{refused}"
    );
    assert!(
        refused.ends_with("destination not permitted by session policy\n"),
        "{refused}"
    );
    assert_ne!(recorder.last().2, "hold:held:1");
    assert!(gate.asked().is_empty());
}

#[test]
fn a_paused_proxy_refuses_without_asking_the_hold() {
    let gate = Arc::new(Gate::default());
    let (proxy, _) = start(config(&["localhost"]).hold(gate.clone()));
    proxy.set_paused(true);
    let refused = send(
        &proxy,
        "GET http://localhost:1/x HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(refused.starts_with("HTTP/1.1 503"), "{refused}");
    assert!(gate.asked().is_empty());
}

#[test]
fn a_held_route_never_injects_its_credential_until_released() {
    let (upstream, connections, seen) = spawn_upstream();
    let route = GatewayRoute::new(
        "/artifacts",
        "127.0.0.1",
        upstream.port(),
        "authorization",
        Secret::from(INJECTED),
    )
    .unwrap()
    .plain_upstream(true);
    let gate = Arc::new(Gate::default());
    let (proxy, recorder) = start(config(&["localhost"]).gateway(route).hold(gate.clone()));
    let request = "GET /artifacts/v1/data HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    let refused = send(&proxy, request);
    assert!(
        refused.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{refused}"
    );
    assert!(refused.ends_with("held for approval\n"), "{refused}");
    assert!(!refused.contains(INJECTED));
    assert_eq!(connections.load(Ordering::Acquire), 0);
    assert_eq!(recorder.last().1, Decision::Deny);
    assert_eq!(
        gate.asked(),
        vec![("127.0.0.1".to_owned(), Some("/artifacts".to_owned()))]
    );

    gate.released.store(true, Ordering::Release);
    let reached = send(&proxy, request);
    assert!(reached.starts_with("HTTP/1.1 200 OK\r\n"), "{reached}");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].contains(&format!("authorization: {INJECTED}")),
        "{}",
        seen[0]
    );
}

#[test]
fn a_proxy_without_a_hold_is_unchanged() {
    let (upstream, connections, _) = spawn_upstream();
    let (proxy, _) = start(config(&["localhost"]));
    let reached = send(
        &proxy,
        &format!(
            "GET http://localhost:{}/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            upstream.port()
        ),
    );
    assert!(reached.starts_with("HTTP/1.1 200 OK\r\n"), "{reached}");
    assert_eq!(connections.load(Ordering::Acquire), 1);
    assert!(format!("{:?}", config(&["localhost"])).contains("hold: false"));
}
