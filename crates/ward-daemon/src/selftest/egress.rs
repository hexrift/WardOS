//! The egress and surface probes of ADR-0019 decision 6, run inside a real
//! sandbox against a session proxy the self-test controls: ST-022 (TLS
//! interception), ST-026 (raw TCP, SOCKS and UDP paths), ST-027 (host loopback
//! and control surfaces) and ST-028 (DNS rebinding and pinning).
//!
//! Unlike the exit-code probes these print `key=value` facts, and the verdict is
//! reached host-side by comparing them with what the self-test's own loopback
//! servers, resolver and proxy recorder saw. A probe that could not run, or a
//! fact this host cannot produce (no IPv6, no UDP egress), is
//! [`Verdict::CannotMeasure`] with the reason — never a pass.
//!
//! The sandbox is the same bubblewrap construction a session launch uses, handed
//! a proxy socket and a hook socket the same way. The proxy is the real
//! `ward-proxy` in `localhost_only` mode with an injected resolver, so an
//! allowlisted name (`*.localhost`) can be made to answer with a private address
//! or to change its answer between two requests, and so the host's own loopback
//! servers stand in for allowed destinations.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use ward_policy::{NetworkCapability, ObserverMode};
use ward_proxy::{Host, Resolver};

use super::{ProbeResult, Verdict};
use crate::egress::{Egress, Recorded};
use crate::error::{Error, Result};
use crate::hooks::Hooks;
use crate::sandbox::Launch;

/// Wall-clock budget for one probe script; every socket in it times out sooner.
const RUN_BUDGET: Duration = Duration::from_secs(60);
/// The allowlisted name whose answer flips to a private address (ST-028).
const PIN: &str = "pin.localhost";
/// A name outside the allowlist that resolves to loopback: what a second hop
/// inside a tunnel could reach if the tunnel were a proxy (ST-022).
const DENIED: &str = "denied.example";
/// Allowlisted names staged to answer with an address no mode may reach.
const EVIL: [&str; 4] = [
    "rebind.localhost",
    "metadata.localhost",
    "mapped.localhost",
    "mixed.localhost",
];

/// Facts a probe printed, one `key=value` per line.
type Facts = BTreeMap<String, String>;

/// Shared by every script: the sockets, the proxy exchange and the fact line.
const PRELUDE: &str = r"
import errno, glob, os, socket, ssl, sys
SOCK = '/run/ward/proxy.sock'
HOOKS = '/run/ward/hooks.sock'
def out(k, v):
    print('%s=%s' % (k, v), flush=True)
def errname(e):
    return errno.errorcode.get(getattr(e, 'errno', None) or -1, str(e))
def proxy():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(SOCK)
    return s
def recv_head(s):
    head = b''
    while b'\r\n\r\n' not in head:
        try:
            c = s.recv(4096)
        except socket.timeout:
            break
        if not c:
            break
        head += c
    return head
def status(head):
    return head.split(b'\r\n', 1)[0].decode('ascii', 'replace')
def readall(s):
    data = b''
    while True:
        try:
            c = s.recv(65536)
        except (socket.timeout, OSError):
            break
        if not c:
            break
        data += c
    return data
def connect(s, target):
    s.sendall(('CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' % (target, target)).encode())
    return recv_head(s)
def exchange(target):
    s = proxy()
    head = connect(s, target)
    if head.startswith(b'HTTP/1.1 200'):
        s.close()
        return head
    return head + readall(s)
def tcp(family, addr):
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
    except OSError as e:
        return 'nosocket:' + errname(e)
    s.settimeout(3)
    try:
        s.connect(addr)
        return 'connected'
    except socket.timeout:
        return 'timeout'
    except OSError as e:
        return 'error:' + errname(e)
    finally:
        s.close()
out('probe', 'ready')
";

/// ST-022. Arguments: port of marker server A, of marker server B, of the TLS
/// server, the TLS server's certificate as PEM (hex), the denied name.
///
/// (a) `CONNECT` to A, then a request for B inside the tunnel; (c) `CONNECT` to
/// A, then an absolute-URI request for the denied name inside the tunnel, which
/// is what `curl --proxy` would send to a second proxy; (b) a sandbox-written CA
/// file named by `SSL_CERT_FILE`, `SSL_CERT_DIR` and `NODE_EXTRA_CA_CERTS`, then
/// TLS through a `CONNECT` to the TLS server: the peer certificate and the
/// response are reported byte for byte.
const ST_022: &str = r"
A, B, T, PEM, DENIED = sys.argv[1:6]
s = proxy()
head = connect(s, '127.0.0.1:' + A)
out('a_connect', status(head))
if head.startswith(b'HTTP/1.1 200'):
    s.sendall(('GET / HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nConnection: close\r\n\r\n' % B).encode())
    out('a_response', readall(s).hex())
s.close()
s = proxy()
head = connect(s, '127.0.0.1:' + A)
out('c_connect', status(head))
if head.startswith(b'HTTP/1.1 200'):
    s.sendall(('GET http://%s:%s/ HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' % (DENIED, B, DENIED, B)).encode())
    out('c_response', readall(s).hex())
s.close()
ca = '/tmp/ward-selftest-ca.pem'
with open(ca, 'w') as f:
    f.write(bytes.fromhex(PEM).decode())
os.environ['SSL_CERT_FILE'] = ca
os.environ['SSL_CERT_DIR'] = '/tmp'
os.environ['NODE_EXTRA_CA_CERTS'] = ca
out('b_ca_writable', os.access(ca, os.W_OK))
s = proxy()
head = connect(s, '127.0.0.1:' + T)
out('b_connect', status(head))
if head.startswith(b'HTTP/1.1 200'):
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=ca)
    try:
        t = ctx.wrap_socket(s, server_hostname='localhost')
        out('b_peer_cert', t.getpeercert(True).hex())
        t.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
        out('b_response', readall(t).hex())
    except ssl.SSLError as e:
        out('b_tls_error', str(e).replace('\n', ' '))
";

/// ST-026. No arguments: raw `connect(2)` to public and private IPv4 and to a
/// public IPv6 address, a SOCKS5 greeting on the proxy socket, a DNS query over
/// UDP to `1.1.1.1:53`.
const ST_026: &str = r"
out('tcp4_dns', tcp(socket.AF_INET, ('8.8.8.8', 53)))
out('tcp4_private', tcp(socket.AF_INET, ('10.0.0.1', 80)))
out('tcp6_dns', tcp(socket.AF_INET6, ('2001:4860:4860::8888', 53, 0, 0)))
try:
    s = proxy()
    s.sendall(b'\x05\x01\x00')
    s.shutdown(socket.SHUT_WR)
    out('socks5', readall(s)[:64].hex())
except OSError as e:
    out('socks5', 'error:' + errname(e))
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    q = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    u.sendto(q, ('1.1.1.1', 53))
    out('udp_send', 'sent')
    try:
        r, _ = u.recvfrom(512)
        out('udp_reply', r[:2].hex())
    except socket.timeout:
        out('udp_reply', 'none')
except OSError as e:
    out('udp_send', 'error:' + errname(e))
";

/// ST-027. Arguments: a port the host listens on, the host's abstract socket
/// name, a port the host verified free, the daemon's control socket path (or
/// `-`). Host run-directory sockets by path; the host's loopback listener by
/// connect and by binding its port; a port bound inside the sandbox seen from
/// the host through the proxy's own connect; the host's abstract sockets; a
/// control-protocol `approve` on the hook socket.
const ST_027: &str = r#"
P, N, F, C = sys.argv[1:5]
paths = ['/run/docker.sock', '/var/run/docker.sock', '/run/podman/podman.sock', '/run/user']
if C != '-':
    paths.append(C)
found = [p for p in paths if os.path.exists(p)] + glob.glob('/run/user/*')
out('run_paths', ','.join(found) or 'none')
out('lo_connect_host_port', tcp(socket.AF_INET, ('127.0.0.1', int(P))))
try:
    l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    l.bind(('127.0.0.1', int(P)))
    l.listen(1)
    out('lo_bind_host_port', 'bound')
except OSError as e:
    out('lo_bind_host_port', 'error:' + errname(e))
try:
    l2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    l2.bind(('127.0.0.1', int(F)))
    l2.listen(1)
    l2.settimeout(1)
    out('lo_bind_free_port', 'bound')
    s = proxy()
    head = connect(s, '127.0.0.1:' + F)
    out('lo_host_view', status(head))
    if head.startswith(b'HTTP/1.1 200'):
        try:
            c, _ = l2.accept()
            out('lo_host_reached_us', 'yes')
        except socket.timeout:
            out('lo_host_reached_us', 'no')
except OSError as e:
    out('lo_bind_free_port', 'error:' + errname(e))
def abstract(name):
    a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    a.settimeout(2)
    try:
        a.connect('\0' + name)
        return 'connected'
    except OSError as e:
        return 'error:' + errname(e)
    finally:
        a.close()
out('abstract_nonce', abstract(N))
out('abstract_x11', abstract('/tmp/.X11-unix/X0'))
try:
    h = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    h.settimeout(5)
    h.connect(HOOKS)
    h.sendall(b'{"req":"approve","id":1,"decision":"allow"}\n')
    h.shutdown(socket.SHUT_WR)
    out('hook_forge_reply', readall(h).hex())
except OSError as e:
    out('hook_forge_reply', 'error:' + errname(e))
"#;

/// ST-028. Arguments: the flipping name, marker server A's port, the staged
/// names (comma-separated). The private literal's refusal, each staged name's
/// refusal, then two `CONNECT`s to the flipping name with a request inside the
/// first tunnel.
const ST_028: &str = r"
PIN, A = sys.argv[1], sys.argv[2]
EVIL = sys.argv[3].split(',')
out('literal', exchange('10.0.0.1:80').hex())
for i, name in enumerate(EVIL):
    out('evil%d' % i, exchange(name + ':80').hex())
s = proxy()
head = connect(s, PIN + ':' + A)
out('pin_first', status(head))
if head.startswith(b'HTTP/1.1 200'):
    s.sendall(('GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % PIN).encode())
    out('pin_first_response', readall(s).hex())
s.close()
out('pin_second', exchange(PIN + ':' + A).hex())
";

/// Run the egress and surface probes against `worktree`. `control_socket` is
/// the host path of the session's control socket, when there is a session, so
/// ST-027 can look for it by name as well.
pub fn selftest_egress(worktree: &Path, control_socket: Option<&Path>) -> Result<Vec<ProbeResult>> {
    let nonce = super::canary_suffix();
    let a = MarkerServer::spawn(format!("ward-selftest-a-{nonce}"))?;
    let b = MarkerServer::spawn(format!("ward-selftest-b-{nonce}"))?;
    let tls = TlsServer::spawn(&nonce)?;
    let resolver = Arc::new(staged_resolver());
    let rig = Rig::start(worktree, resolver.clone())?;
    let host = HostSurfaces::bind(&nonce)?;

    let mut out = probe_tls_interception(&rig, &a, &b, &tls)?;
    out.extend(probe_raw_paths(&rig)?);
    out.extend(probe_surfaces(&rig, &host, control_socket)?);
    out.extend(probe_rebinding(&rig, &a, &resolver)?);

    drop(host);
    rig.stop();
    Ok(out)
}

/// ST-022 against the two marker servers and the TLS server.
fn probe_tls_interception(
    rig: &Rig,
    a: &MarkerServer,
    b: &MarkerServer,
    tls: &TlsServer,
) -> Result<Vec<ProbeResult>> {
    let run = rig.run(
        ST_022,
        &[
            a.port.to_string(),
            b.port.to_string(),
            tls.port.to_string(),
            hex(tls.cert_pem.as_bytes()),
            DENIED.to_owned(),
        ],
    )?;
    rig.egress.drain_decisions();
    Ok(judge(
        run,
        &[
            "ST-022 tunnel-host-switch",
            "ST-022 tls-end-to-end",
            "ST-022 proxy-inside-tunnel",
        ],
        |f| {
            vec![
                tunnel_host_switch(f, "a_", &a.marker, &b.marker, b.seen()),
                tls_end_to_end(f, &tls.cert_der, &tls.response),
                tunnel_host_switch(f, "c_", &a.marker, &b.marker, b.seen()),
            ]
        },
    ))
}

/// ST-026: the paths that are not the proxy's HTTP grammar.
fn probe_raw_paths(rig: &Rig) -> Result<Vec<ProbeResult>> {
    let run = rig.run(ST_026, &[])?;
    rig.egress.drain_decisions();
    Ok(judge(
        run,
        &[
            "ST-026 raw-tcp-ipv4",
            "ST-026 raw-tcp-ipv6",
            "ST-026 socks5-on-proxy",
            "ST-026 udp-egress",
        ],
        |f| {
            vec![
                raw_tcp(f, &["tcp4_dns", "tcp4_private"]),
                raw_tcp(f, &["tcp6_dns"]),
                socks5(f),
                udp(f),
            ]
        },
    ))
}

/// ST-027 against what the host holds open.
fn probe_surfaces(
    rig: &Rig,
    host: &HostSurfaces,
    control_socket: Option<&Path>,
) -> Result<Vec<ProbeResult>> {
    let control =
        control_socket.map_or_else(|| "-".to_owned(), |p| p.to_string_lossy().into_owned());
    let run = rig.run(
        ST_027,
        &[
            host.port.to_string(),
            host.abstract_name.clone(),
            host.free_port.to_string(),
            control,
        ],
    )?;
    let claims = rig.hooks.drain_events().len();
    rig.egress.drain_decisions();
    Ok(judge(
        run,
        &[
            "ST-027 host-run-sockets",
            "ST-027 host-loopback",
            "ST-027 host-abstract-socket",
            "ST-027 hook-socket-forgery",
        ],
        |f| {
            vec![
                run_paths(f),
                host_loopback(f),
                abstract_sockets(f, &host.abstract_name),
                hook_forgery(f, claims),
            ]
        },
    ))
}

/// ST-028 against the staged resolver, judged with the proxy's own record.
fn probe_rebinding(
    rig: &Rig,
    a: &MarkerServer,
    resolver: &StagedResolver,
) -> Result<Vec<ProbeResult>> {
    let run = rig.run(
        ST_028,
        &[PIN.to_owned(), a.port.to_string(), EVIL.join(",")],
    )?;
    let decisions = rig.egress.drain_decisions();
    let calls = resolver.calls(PIN);
    Ok(judge(
        run,
        &["ST-028 rebind-to-private", "ST-028 pinned-tunnel"],
        |f| {
            vec![
                rebind_to_private(f, &EVIL, &decisions),
                pinned_tunnel(f, &a.marker, calls, &decisions),
            ]
        },
    ))
}

/// The names the self-test's resolver answers, and how.
fn staged_resolver() -> StagedResolver {
    let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
    let loopback = v4(127, 0, 0, 1);
    let private = v4(10, 0, 0, 1);
    StagedResolver::default()
        .with("rebind.localhost", vec![vec![private]])
        .with("metadata.localhost", vec![vec![v4(169, 254, 169, 254)]])
        .with(
            "mapped.localhost",
            vec![vec![IpAddr::V6(
                Ipv4Addr::new(192, 168, 0, 1).to_ipv6_mapped(),
            )]],
        )
        .with("mixed.localhost", vec![vec![loopback, private]])
        .with(PIN, vec![vec![loopback], vec![private]])
        .with(DENIED, vec![vec![loopback]])
}

/// One row per name: the judge's verdicts when the probe ran, or the reason it
/// could not for every row.
fn judge(
    run: std::result::Result<Facts, String>,
    names: &[&'static str],
    verdicts: impl FnOnce(&Facts) -> Vec<Verdict>,
) -> Vec<ProbeResult> {
    let verdicts = match run {
        Ok(facts) => verdicts(&facts),
        Err(why) => names
            .iter()
            .map(|_| Verdict::CannotMeasure(why.clone()))
            .collect(),
    };
    names
        .iter()
        .zip(verdicts)
        .map(|(name, verdict)| ProbeResult { name, verdict })
        .collect()
}

// ---- verdicts: pure functions over the facts and what the host saw ---------

/// A fact, or why it is missing.
fn fact<'a>(facts: &'a Facts, key: &str) -> std::result::Result<&'a str, Verdict> {
    facts.get(key).map(String::as_str).ok_or_else(|| {
        let tail = facts
            .get("stderr")
            .map(|e| format!(" ({e})"))
            .unwrap_or_default();
        Verdict::CannotMeasure(format!("the probe reported no `{key}`{tail}"))
    })
}

/// A hex-encoded fact as text (lossy).
fn text_fact(facts: &Facts, key: &str) -> std::result::Result<String, Verdict> {
    let bytes = unhex(fact(facts, key)?)
        .ok_or_else(|| Verdict::CannotMeasure(format!("`{key}` is not hex")))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn is_ok(status: &str) -> bool {
    status.starts_with("HTTP/1.1 200")
}

/// ST-022 (a) and (c): a request for another host inside an established tunnel
/// reaches only the tunnel's `CONNECT` target.
fn tunnel_host_switch(
    facts: &Facts,
    prefix: &str,
    marker_a: &str,
    marker_b: &str,
    b_seen: usize,
) -> Verdict {
    let go = || {
        let connect = fact(facts, &format!("{prefix}connect"))?;
        if !is_ok(connect) {
            return Err(Verdict::CannotMeasure(format!(
                "CONNECT to the self-test's loopback server answered `{connect}`"
            )));
        }
        let response = text_fact(facts, &format!("{prefix}response"))?;
        if response.contains(marker_b) || b_seen > 0 {
            return Err(Verdict::Reached(
                "the tunnel delivered the request to the host named inside it".into(),
            ));
        }
        if response.contains(marker_a) {
            Ok(())
        } else {
            Err(Verdict::CannotMeasure(
                "the tunnel answered with neither server's marker".into(),
            ))
        }
    };
    go().map_or_else(|v| v, |()| Verdict::Denied)
}

/// ST-022 (b): with a sandbox-writable CA trusted by the agent, the certificate
/// and the response seen through the tunnel are exactly the destination's.
fn tls_end_to_end(facts: &Facts, cert_der: &[u8], response: &[u8]) -> Verdict {
    let go = || {
        let connect = fact(facts, "b_connect")?;
        if !is_ok(connect) {
            return Err(Verdict::CannotMeasure(format!(
                "CONNECT to the self-test's TLS server answered `{connect}`"
            )));
        }
        if fact(facts, "b_ca_writable")? != "True" {
            return Err(Verdict::CannotMeasure(
                "the sandbox could not write its own CA file".into(),
            ));
        }
        if let Some(err) = facts.get("b_tls_error") {
            return Err(if err.contains("CERTIFICATE_VERIFY_FAILED") {
                Verdict::Reached(format!("the TLS peer is not the destination: {err}"))
            } else {
                Verdict::CannotMeasure(format!(
                    "the TLS handshake through the tunnel failed: {err}"
                ))
            });
        }
        let peer = unhex(fact(facts, "b_peer_cert")?).unwrap_or_default();
        if peer != cert_der {
            return Err(Verdict::Reached(
                "the certificate seen through the tunnel is not the destination's".into(),
            ));
        }
        let seen = unhex(fact(facts, "b_response")?).unwrap_or_default();
        if seen != response {
            return Err(Verdict::Reached(
                "the HTTPS response was altered in transit".into(),
            ));
        }
        Ok(())
    };
    go().map_or_else(|v| v, |()| Verdict::Denied)
}

/// Errors that mean "the sandbox has no such path": no route, nothing there,
/// or a filter said no.
fn is_no_path(err: &str) -> bool {
    matches!(
        err,
        "ENETUNREACH" | "EHOSTUNREACH" | "ECONNREFUSED" | "EPERM" | "EACCES"
    )
}

/// ST-026: raw `connect(2)` results for `keys`.
fn raw_tcp(facts: &Facts, keys: &[&str]) -> Verdict {
    let mut unmeasured = Vec::new();
    for key in keys {
        let value = match fact(facts, key) {
            Ok(v) => v,
            Err(v) => return v,
        };
        match value.split_once(':') {
            _ if value == "connected" => {
                return Verdict::Reached(format!("{key}: a raw TCP connection succeeded"));
            }
            Some(("error", err)) if is_no_path(err) => {}
            Some(("nosocket", "EAFNOSUPPORT")) => {
                unmeasured.push(format!("{key}: this kernel has no IPv6 sockets"));
            }
            Some(("error", "EADDRNOTAVAIL")) => {
                unmeasured.push(format!("{key}: the sandbox loopback has no IPv6 address"));
            }
            _ => unmeasured.push(format!("{key}: {value}")),
        }
    }
    if unmeasured.is_empty() {
        Verdict::Denied
    } else {
        Verdict::CannotMeasure(unmeasured.join("; "))
    }
}

/// ST-026: a SOCKS5 greeting on the proxy socket gets no SOCKS answer.
fn socks5(facts: &Facts) -> Verdict {
    let value = match fact(facts, "socks5") {
        Ok(v) => v,
        Err(v) => return v,
    };
    if let Some(err) = value.strip_prefix("error:") {
        return Verdict::CannotMeasure(format!("the proxy socket could not be used: {err}"));
    }
    let reply = unhex(value).unwrap_or_default();
    if reply.first() == Some(&5) {
        Verdict::Reached("the proxy answered the SOCKS5 greeting".into())
    } else if reply.is_empty() || reply.starts_with(b"HTTP/1.1 4") {
        Verdict::Denied
    } else {
        Verdict::CannotMeasure(format!("unexpected reply to the SOCKS5 greeting: {value}"))
    }
}

/// ST-026: a UDP datagram to a public resolver has no route.
fn udp(facts: &Facts) -> Verdict {
    let sent = match fact(facts, "udp_send") {
        Ok(v) => v,
        Err(v) => return v,
    };
    match (sent, sent.strip_prefix("error:")) {
        (_, Some(err)) if is_no_path(err) => Verdict::Denied,
        ("sent", _) => match facts.get("udp_reply").map(String::as_str) {
            Some("none") => Verdict::CannotMeasure(
                "the datagram left the sandbox but nothing answered: UDP egress cannot be measured here".into(),
            ),
            Some(_) => Verdict::Reached("a DNS reply arrived from 1.1.1.1".into()),
            None => Verdict::CannotMeasure("the probe reported no `udp_reply`".into()),
        },
        _ => Verdict::CannotMeasure(format!("udp_send: {sent}")),
    }
}

/// ST-027: host run-directory sockets by path.
fn run_paths(facts: &Facts) -> Verdict {
    match fact(facts, "run_paths") {
        Ok("none") => Verdict::Denied,
        Ok(list) => Verdict::Reached(format!("visible in the sandbox: {list}")),
        Err(v) => v,
    }
}

/// ST-027: the sandbox loopback is its own: the host's listener is unreachable
/// and its port is free inside, and a port bound inside is invisible to the
/// host (the proxy's own connect from the host side is refused).
fn host_loopback(facts: &Facts) -> Verdict {
    let go = || {
        let connect = fact(facts, "lo_connect_host_port")?;
        if connect == "connected" {
            return Err(Verdict::Reached(
                "the host's loopback listener answered from inside the sandbox".into(),
            ));
        }
        let bind = fact(facts, "lo_bind_host_port")?;
        if bind == "error:EADDRINUSE" {
            return Err(Verdict::Reached(
                "the sandbox shares the host's loopback port space".into(),
            ));
        }
        let free = fact(facts, "lo_bind_free_port")?;
        if free != "bound" {
            return Err(Verdict::CannotMeasure(format!(
                "the sandbox could not bind a loopback port: {free}"
            )));
        }
        let view = fact(facts, "lo_host_view")?;
        if is_ok(view) || facts.get("lo_host_reached_us").map(String::as_str) == Some("yes") {
            return Err(Verdict::Reached(
                "the host connected to a port bound inside the sandbox".into(),
            ));
        }
        if connect == "error:ECONNREFUSED" && bind == "bound" && view.starts_with("HTTP/1.1 502") {
            Ok(())
        } else {
            Err(Verdict::CannotMeasure(format!(
                "connect to the host port: {connect}; bind of it: {bind}; the host's view of a sandbox port: {view}"
            )))
        }
    };
    go().map_or_else(|v| v, |()| Verdict::Denied)
}

/// ST-027: the host's abstract Unix sockets are in another namespace.
fn abstract_sockets(facts: &Facts, name: &str) -> Verdict {
    let go = || {
        let nonce = fact(facts, "abstract_nonce")?;
        if nonce == "connected" {
            return Err(Verdict::Reached(format!(
                "the host's abstract socket @{name} answered"
            )));
        }
        if fact(facts, "abstract_x11")? == "connected" {
            return Err(Verdict::Reached(
                "the host's X server socket @/tmp/.X11-unix/X0 answered".into(),
            ));
        }
        match nonce {
            "error:ECONNREFUSED" | "error:ENOENT" => Ok(()),
            other => Err(Verdict::CannotMeasure(format!(
                "connect to the host's abstract socket: {other}"
            ))),
        }
    };
    go().map_or_else(|v| v, |()| Verdict::Denied)
}

/// ST-027: a control-protocol `approve` on the hook socket gets no control
/// answer and leaves no record.
fn hook_forgery(facts: &Facts, claims: usize) -> Verdict {
    let value = match fact(facts, "hook_forge_reply") {
        Ok(v) => v,
        Err(v) => return v,
    };
    if let Some(err) = value.strip_prefix("error:") {
        return Verdict::CannotMeasure(format!("the hook socket could not be used: {err}"));
    }
    let reply = String::from_utf8_lossy(&unhex(value).unwrap_or_default()).into_owned();
    if reply.contains("\"resp\"") {
        Verdict::Reached("the hook socket answered a control-protocol request".into())
    } else if claims > 0 {
        Verdict::Reached("the hook socket turned the forged line into a record".into())
    } else if reply.is_empty() {
        Verdict::Denied
    } else {
        Verdict::CannotMeasure(format!("unexpected reply on the hook socket: {reply}"))
    }
}

/// The proxy's recorded decision for `name`, if any.
fn decision_for<'a>(decisions: &'a [Recorded], name: &str) -> Option<&'a Recorded> {
    decisions
        .iter()
        .find(|d| matches!(&d.host, Host::Name(n) if n == name))
}

/// ST-028: every staged name gets the private literal's refusal, and the proxy
/// recorded each as an address-class denial.
fn rebind_to_private(facts: &Facts, names: &[&str], decisions: &[Recorded]) -> Verdict {
    let go = || {
        let literal = text_fact(facts, "literal")?;
        if !literal.starts_with("HTTP/1.1 403") {
            return Err(
                if literal.starts_with("HTTP/1.1 200") || literal.starts_with("HTTP/1.1 502") {
                    Verdict::Reached("a private literal was attempted".into())
                } else {
                    Verdict::CannotMeasure(format!("the private literal answered `{literal}`"))
                },
            );
        }
        for (i, name) in names.iter().enumerate() {
            let response = text_fact(facts, &format!("evil{i}"))?;
            if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.1 502") {
                return Err(Verdict::Reached(format!(
                    "`{name}`, whose answer is private, was attempted"
                )));
            }
            if response != literal {
                return Err(Verdict::Reached(format!(
                    "the refusal for `{name}` differs from the private literal's"
                )));
            }
            match decision_for(decisions, name) {
                Some(d) if d.allowed => {
                    return Err(Verdict::Reached(format!("the proxy allowed `{name}`")));
                }
                Some(d)
                    if d.reason.contains("private range")
                        || d.reason.contains("cloud metadata") => {}
                Some(d) => {
                    return Err(Verdict::CannotMeasure(format!(
                        "`{name}` was refused for `{}`, not for its address",
                        d.reason
                    )));
                }
                None => {
                    return Err(Verdict::CannotMeasure(format!(
                        "the proxy recorded no decision for `{name}`"
                    )));
                }
            }
        }
        Ok(())
    };
    go().map_or_else(|v| v, |()| Verdict::Denied)
}

/// ST-028: a tunnel stays with the address it was pinned to, the name is
/// resolved exactly once per request, and the flipped answer refuses the next.
fn pinned_tunnel(facts: &Facts, marker_a: &str, calls: usize, decisions: &[Recorded]) -> Verdict {
    let go = || {
        let first = fact(facts, "pin_first")?;
        if !is_ok(first) {
            return Err(Verdict::CannotMeasure(format!(
                "the first CONNECT to `{PIN}` answered `{first}`"
            )));
        }
        if !text_fact(facts, "pin_first_response")?.contains(marker_a) {
            return Err(Verdict::CannotMeasure(
                "the pinned tunnel did not reach the self-test's server".into(),
            ));
        }
        let second = text_fact(facts, "pin_second")?;
        if second.starts_with("HTTP/1.1 200") || second.starts_with("HTTP/1.1 502") {
            return Err(Verdict::Reached(format!(
                "a CONNECT to `{PIN}` after its answer flipped to a private address was attempted"
            )));
        }
        if !second.starts_with("HTTP/1.1 403") {
            return Err(Verdict::CannotMeasure(format!(
                "the second CONNECT to `{PIN}` answered `{}`",
                second.lines().next().unwrap_or_default()
            )));
        }
        if calls > 2 {
            return Err(Verdict::Reached(format!(
                "the proxy resolved `{PIN}` {calls} times for two requests: the data path re-resolves"
            )));
        }
        if calls < 2 {
            return Err(Verdict::CannotMeasure(format!(
                "the proxy resolved `{PIN}` {calls} times for two requests"
            )));
        }
        let mut pin = decisions
            .iter()
            .filter(|d| matches!(&d.host, Host::Name(n) if n == PIN));
        match (pin.next(), pin.next()) {
            (Some(one), Some(two))
                if one.allowed
                    && one.reason.starts_with("pinned 127.0.0.1")
                    && !two.allowed
                    && two.reason.contains("private range") =>
            {
                Ok(())
            }
            _ => Err(Verdict::CannotMeasure(
                "the proxy's record of the two requests is not one pinned allow then one private-range deny".into(),
            )),
        }
    };
    go().map_or_else(|v| v, |()| Verdict::Denied)
}

// ---- the rig: sandbox, proxy, hook socket ---------------------------------

/// A proxy and a hook socket in a private directory, and the sandbox launches
/// that get them, exactly as a session's launches do.
struct Rig {
    dir: PathBuf,
    worktree: PathBuf,
    egress: Egress,
    hooks: Hooks,
}

impl Rig {
    fn start(worktree: &Path, resolver: Arc<dyn Resolver>) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("ward-st-{}", super::canary_suffix()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| Error::io(&dir, e))?;
        let egress = Egress::start_with(
            &dir,
            &NetworkCapability::LocalhostOnly,
            Vec::new(),
            resolver,
        )?;
        let hooks = Hooks::start(&dir, ObserverMode::Live, Vec::new())?;
        Ok(Self {
            dir,
            worktree: worktree.to_path_buf(),
            egress,
            hooks,
        })
    }

    /// Run one probe script; `Err` is why it could not run at all.
    fn run(&self, script: &str, args: &[String]) -> Result<std::result::Result<Facts, String>> {
        let mut command = vec![
            "python3".to_owned(),
            "-c".to_owned(),
            format!("{PRELUDE}\n{script}"),
        ];
        command.extend(args.iter().cloned());
        let outcome = Launch::new(&self.worktree, command)
            .egress(self.egress.socket())
            .hooks(self.hooks.socket())
            .budget(RUN_BUDGET)
            .run()?;
        let mut facts = parse_facts(&outcome.stdout);
        if let Some(last) = outcome.stderr.lines().rev().find(|l| !l.trim().is_empty()) {
            facts.insert("stderr".into(), last.trim().to_owned());
        }
        if outcome.timed_out {
            return Ok(Err("the probe outran its budget".into()));
        }
        if facts.get("probe").map(String::as_str) != Some("ready") {
            let why = facts
                .get("stderr")
                .cloned()
                .unwrap_or_else(|| "python3 is not available in the sandbox".into());
            return Ok(Err(format!("the probe could not start: {why}")));
        }
        Ok(Ok(facts))
    }

    fn stop(self) {
        self.egress.stop();
        self.hooks.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn parse_facts(stdout: &str) -> Facts {
    stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

/// Answers under the self-test's control: one list per call for a name, the
/// last repeating, so a name can change its mind between two requests. Every
/// resolution is counted.
#[derive(Default)]
struct StagedResolver {
    table: HashMap<String, Vec<Vec<IpAddr>>>,
    calls: Mutex<HashMap<String, usize>>,
}

impl StagedResolver {
    fn with(mut self, name: &str, answers: Vec<Vec<IpAddr>>) -> Self {
        self.table.insert(name.to_ascii_lowercase(), answers);
        self
    }

    /// How many times `name` has been resolved.
    fn calls(&self, name: &str) -> usize {
        self.calls
            .lock()
            .map(|c| c.get(&name.to_ascii_lowercase()).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

impl Resolver for StagedResolver {
    fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let host = host.to_ascii_lowercase();
        let answers = self
            .table
            .get(&host)
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "no such host"))?;
        let n = self.calls.lock().map_or(0, |mut c| {
            let n = c.entry(host).or_insert(0);
            *n += 1;
            *n - 1
        });
        Ok(answers[n.min(answers.len() - 1)].clone())
    }
}

// ---- the host's side: what the sandbox is trying to reach ------------------

/// A loopback listener served on its own thread until dropped.
struct Served {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Served {
    /// Serve `listener` with `handle`, one connection at a time (the probes
    /// are sequential), polling for the stop flag between accepts.
    fn spawn(listener: TcpListener, handle: impl Fn(TcpStream) + Send + 'static) -> Result<Self> {
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::Sandbox(format!("selftest server: {e}")))?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("ward-selftest-server".into())
            .spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if stream.set_nonblocking(false).is_ok() {
                                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                                handle(stream);
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|e| Error::Sandbox(format!("selftest server thread: {e}")))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn bind_loopback() -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| Error::Sandbox(format!("selftest listener: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::Sandbox(format!("selftest listener: {e}")))?
        .port();
    Ok((listener, port))
}

/// Read a request head (bounded), returning it without the blank line.
fn read_request_head(stream: &mut impl Read) -> io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).trim_end().to_owned())
}

/// A plain HTTP server that signs every response with its marker and echoes
/// the request line, remembering every head it received.
struct MarkerServer {
    port: u16,
    marker: String,
    heads: Arc<Mutex<Vec<String>>>,
    _served: Served,
}

impl MarkerServer {
    fn spawn(marker: String) -> Result<Self> {
        let (listener, port) = bind_loopback()?;
        let heads = Arc::new(Mutex::new(Vec::new()));
        let seen = heads.clone();
        let sign = marker.clone();
        let served = Served::spawn(listener, move |mut stream| {
            let Ok(head) = read_request_head(&mut stream) else {
                return;
            };
            let line = head.lines().next().unwrap_or_default().to_owned();
            if let Ok(mut v) = seen.lock() {
                v.push(head);
            }
            let body = format!("{sign} {line}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nX-Ward-Selftest: {sign}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Write);
        })?;
        Ok(Self {
            port,
            marker,
            heads,
            _served: served,
        })
    }

    /// Requests received so far.
    fn seen(&self) -> usize {
        self.heads.lock().map(|v| v.len()).unwrap_or(0)
    }
}

/// A TLS server on loopback with a certificate for `localhost` made for this
/// run; its one response is fixed so the sandbox's copy can be compared.
struct TlsServer {
    port: u16,
    cert_der: Vec<u8>,
    cert_pem: String,
    response: Vec<u8>,
    _served: Served,
}

impl TlsServer {
    fn spawn(nonce: &str) -> Result<Self> {
        let tls_err = |e: String| Error::Sandbox(format!("selftest TLS server: {e}"));
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .map_err(|e| tls_err(e.to_string()))?;
        let cert_der = key.cert.der().to_vec();
        let cert_pem = key.cert.pem();
        let signing =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| tls_err(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(vec![key.cert.der().clone()], signing)
            .map_err(|e| tls_err(e.to_string()))?;
        let config = Arc::new(config);
        let response = format!(
            "HTTP/1.1 200 OK\r\nX-Ward-Selftest: tls-{nonce}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        )
        .into_bytes();
        let (listener, port) = bind_loopback()?;
        let reply = response.clone();
        let served = Served::spawn(listener, move |stream| {
            let Ok(conn) = ServerConnection::new(config.clone()) else {
                return;
            };
            let mut tls = StreamOwned::new(conn, stream);
            if read_request_head(&mut tls).is_err() {
                return;
            }
            let _ = tls.write_all(&reply);
            tls.conn.send_close_notify();
            let _ = tls.flush();
        })?;
        Ok(Self {
            port,
            cert_der,
            cert_pem,
            response,
            _served: served,
        })
    }
}

/// What the host holds open while ST-027 runs: a loopback listener, a port
/// known to be free on the host, and an abstract Unix socket.
struct HostSurfaces {
    port: u16,
    free_port: u16,
    abstract_name: String,
    _listener: TcpListener,
    _abstract: UnixListener,
}

impl HostSurfaces {
    fn bind(nonce: &str) -> Result<Self> {
        let (listener, port) = bind_loopback()?;
        // Bound and released: free on the host when the sandbox binds it.
        let free_port = bind_loopback()?.1;
        let abstract_name = format!("ward-selftest-{nonce}");
        let addr = UnixAddr::from_abstract_name(abstract_name.as_bytes())
            .map_err(|e| Error::Sandbox(format!("abstract socket name: {e}")))?;
        let abstract_listener = UnixListener::bind_addr(&addr)
            .map_err(|e| Error::Sandbox(format!("abstract socket: {e}")))?;
        Ok(Self {
            port,
            free_port,
            abstract_name,
            _listener: listener,
            _abstract: abstract_listener,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn facts(pairs: &[(&str, &str)]) -> Facts {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn recorded(name: &str, allowed: bool, reason: &str) -> Recorded {
        Recorded {
            at: std::time::SystemTime::now(),
            host: Host::Name(name.into()),
            port: 80,
            allowed,
            reason: reason.into(),
        }
    }

    fn reached(v: &Verdict) -> bool {
        matches!(v, Verdict::Reached(_))
    }

    fn unmeasured(v: &Verdict) -> bool {
        matches!(v, Verdict::CannotMeasure(_))
    }

    #[test]
    fn facts_parse_and_hex_round_trips() {
        let f = parse_facts("probe=ready\nnoise\na_connect=HTTP/1.1 200 Connection established\n");
        assert_eq!(f.get("probe").unwrap(), "ready");
        assert_eq!(
            f.get("a_connect").unwrap(),
            "HTTP/1.1 200 Connection established"
        );
        assert_eq!(f.len(), 2);
        assert_eq!(unhex(&hex(b"\x00\xffab")).unwrap(), b"\x00\xffab");
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
        assert!(matches!(
            fact(&facts(&[("stderr", "boom")]), "x"),
            Err(Verdict::CannotMeasure(why)) if why.contains("`x`") && why.contains("boom")
        ));
    }

    #[test]
    fn tunnel_host_switch_reads_the_marker_that_answered() {
        let a = "mark-a";
        let b = "mark-b";
        let ok = facts(&[
            ("a_connect", "HTTP/1.1 200 OK"),
            ("a_response", &hex(b"HTTP/1.1 200 OK\r\n\r\nmark-a GET /")),
        ]);
        assert_eq!(tunnel_host_switch(&ok, "a_", a, b, 0), Verdict::Denied);
        let other = facts(&[
            ("a_connect", "HTTP/1.1 200 OK"),
            ("a_response", &hex(b"mark-b GET /")),
        ]);
        assert!(reached(&tunnel_host_switch(&other, "a_", a, b, 0)));
        assert!(
            reached(&tunnel_host_switch(&ok, "a_", a, b, 1)),
            "B saw a request"
        );
        let refused = facts(&[("a_connect", "HTTP/1.1 403 Forbidden")]);
        assert!(unmeasured(&tunnel_host_switch(&refused, "a_", a, b, 0)));
        let neither = facts(&[
            ("a_connect", "HTTP/1.1 200 OK"),
            ("a_response", &hex(b"nothing")),
        ]);
        assert!(unmeasured(&tunnel_host_switch(&neither, "a_", a, b, 0)));
    }

    #[test]
    fn tls_end_to_end_requires_the_destination_certificate_and_bytes() {
        let cert = b"\x30\x82cert";
        let resp = b"HTTP/1.1 200 OK\r\nX-Ward-Selftest: tls\r\n\r\nok";
        let good = facts(&[
            ("b_connect", "HTTP/1.1 200 Connection established"),
            ("b_ca_writable", "True"),
            ("b_peer_cert", &hex(cert)),
            ("b_response", &hex(resp)),
        ]);
        assert_eq!(tls_end_to_end(&good, cert, resp), Verdict::Denied);
        let mut other_cert = good.clone();
        other_cert.insert("b_peer_cert".into(), hex(b"proxy-made"));
        assert!(reached(&tls_end_to_end(&other_cert, cert, resp)));
        let mut injected = good.clone();
        injected.insert(
            "b_response".into(),
            hex(b"HTTP/1.1 200 OK\r\nVia: ward\r\n\r\nok"),
        );
        assert!(reached(&tls_end_to_end(&injected, cert, resp)));
        let mut verify_failed = good.clone();
        verify_failed.insert(
            "b_tls_error".into(),
            "[SSL: CERTIFICATE_VERIFY_FAILED] x".into(),
        );
        assert!(reached(&tls_end_to_end(&verify_failed, cert, resp)));
        let mut handshake = good.clone();
        handshake.insert("b_tls_error".into(), "EOF occurred".into());
        assert!(unmeasured(&tls_end_to_end(&handshake, cert, resp)));
        let mut no_tunnel = good;
        no_tunnel.insert("b_connect".into(), "HTTP/1.1 502 Bad Gateway".into());
        assert!(unmeasured(&tls_end_to_end(&no_tunnel, cert, resp)));
    }

    #[test]
    fn raw_paths_distinguish_no_route_from_no_ipv6() {
        let f = facts(&[
            ("tcp4_dns", "error:ENETUNREACH"),
            ("tcp4_private", "error:ECONNREFUSED"),
        ]);
        assert_eq!(raw_tcp(&f, &["tcp4_dns", "tcp4_private"]), Verdict::Denied);
        let f = facts(&[
            ("tcp4_dns", "connected"),
            ("tcp4_private", "error:ENETUNREACH"),
        ]);
        assert!(reached(&raw_tcp(&f, &["tcp4_dns", "tcp4_private"])));
        let f = facts(&[("tcp6_dns", "nosocket:EAFNOSUPPORT")]);
        assert!(
            matches!(raw_tcp(&f, &["tcp6_dns"]), Verdict::CannotMeasure(w) if w.contains("IPv6"))
        );
        let f = facts(&[("tcp6_dns", "timeout")]);
        assert!(unmeasured(&raw_tcp(&f, &["tcp6_dns"])));
        assert!(unmeasured(&raw_tcp(&facts(&[]), &["tcp6_dns"])));
    }

    #[test]
    fn socks_and_udp_verdicts() {
        assert_eq!(
            socks5(&facts(&[("socks5", &hex(b"HTTP/1.1 400 Bad Request\r\n"))])),
            Verdict::Denied
        );
        assert_eq!(socks5(&facts(&[("socks5", "")])), Verdict::Denied);
        assert!(reached(&socks5(&facts(&[("socks5", "0500")]))));
        assert!(unmeasured(&socks5(&facts(&[("socks5", "error:ENOENT")]))));
        assert!(unmeasured(&socks5(&facts(&[("socks5", &hex(b"junk"))]))));

        assert_eq!(
            udp(&facts(&[("udp_send", "error:ENETUNREACH")])),
            Verdict::Denied
        );
        assert!(unmeasured(&udp(&facts(&[
            ("udp_send", "sent"),
            ("udp_reply", "none")
        ]))));
        assert!(reached(&udp(&facts(&[
            ("udp_send", "sent"),
            ("udp_reply", "1234")
        ]))));
        assert!(unmeasured(&udp(&facts(&[("udp_send", "error:EINVAL")]))));
    }

    #[test]
    fn surface_verdicts() {
        assert_eq!(run_paths(&facts(&[("run_paths", "none")])), Verdict::Denied);
        assert!(reached(&run_paths(&facts(&[(
            "run_paths",
            "/run/user/1000"
        )]))));

        let good = facts(&[
            ("lo_connect_host_port", "error:ECONNREFUSED"),
            ("lo_bind_host_port", "bound"),
            ("lo_bind_free_port", "bound"),
            ("lo_host_view", "HTTP/1.1 502 Bad Gateway"),
        ]);
        assert_eq!(host_loopback(&good), Verdict::Denied);
        for (k, v) in [
            ("lo_connect_host_port", "connected"),
            ("lo_bind_host_port", "error:EADDRINUSE"),
            ("lo_host_view", "HTTP/1.1 200 Connection established"),
            ("lo_host_reached_us", "yes"),
        ] {
            let mut f = good.clone();
            f.insert(k.into(), v.into());
            assert!(reached(&host_loopback(&f)), "{k}");
        }
        let mut odd = good.clone();
        odd.insert("lo_host_view".into(), "HTTP/1.1 403 Forbidden".into());
        assert!(unmeasured(&host_loopback(&odd)));

        let f = facts(&[
            ("abstract_nonce", "error:ECONNREFUSED"),
            ("abstract_x11", "error:ECONNREFUSED"),
        ]);
        assert_eq!(abstract_sockets(&f, "n"), Verdict::Denied);
        let f = facts(&[
            ("abstract_nonce", "connected"),
            ("abstract_x11", "error:ECONNREFUSED"),
        ]);
        assert!(reached(&abstract_sockets(&f, "n")));
        let f = facts(&[
            ("abstract_nonce", "error:ECONNREFUSED"),
            ("abstract_x11", "connected"),
        ]);
        assert!(reached(&abstract_sockets(&f, "n")));

        assert_eq!(
            hook_forgery(&facts(&[("hook_forge_reply", "")]), 0),
            Verdict::Denied
        );
        assert!(reached(&hook_forgery(
            &facts(&[("hook_forge_reply", "")]),
            1
        )));
        let control = hex(br#"{"resp":"ok"}"#);
        assert!(reached(&hook_forgery(
            &facts(&[("hook_forge_reply", &control)]),
            0
        )));
        assert!(unmeasured(&hook_forgery(
            &facts(&[("hook_forge_reply", "error:ENOENT")]),
            0
        )));
    }

    #[test]
    fn rebinding_verdicts_compare_with_the_literal_and_the_record() {
        let refusal = hex(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 44\r\n\r\ndestination not permitted by session policy\n");
        let f = facts(&[
            ("literal", &refusal),
            ("evil0", &refusal),
            ("evil1", &refusal),
        ]);
        let names = ["a.localhost", "b.localhost"];
        let ok = [
            recorded("a.localhost", false, "destination is a private range"),
            recorded(
                "b.localhost",
                false,
                "destination is a cloud metadata endpoint",
            ),
        ];
        assert_eq!(rebind_to_private(&f, &names, &ok), Verdict::Denied);
        let allowed = [
            recorded("a.localhost", true, "pinned 10.0.0.1"),
            ok[1].clone(),
        ];
        assert!(reached(&rebind_to_private(&f, &names, &allowed)));
        assert!(unmeasured(&rebind_to_private(&f, &names, &ok[..1])));
        let wrong_reason = [
            recorded("a.localhost", false, "host did not resolve"),
            ok[1].clone(),
        ];
        assert!(unmeasured(&rebind_to_private(&f, &names, &wrong_reason)));
        let mut attempted = f.clone();
        attempted.insert("evil1".into(), hex(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"));
        assert!(reached(&rebind_to_private(&attempted, &names, &ok)));
        let mut differs = f.clone();
        differs.insert(
            "evil0".into(),
            hex(b"HTTP/1.1 403 Forbidden\r\n\r\nno such host\n"),
        );
        assert!(reached(&rebind_to_private(&differs, &names, &ok)));
        let mut literal_open = f;
        literal_open.insert(
            "literal".into(),
            hex(b"HTTP/1.1 200 Connection established\r\n\r\n"),
        );
        assert!(reached(&rebind_to_private(&literal_open, &names, &ok)));
    }

    #[test]
    fn pinning_verdicts_need_one_allow_one_deny_and_two_resolutions() {
        let f = facts(&[
            ("pin_first", "HTTP/1.1 200 Connection established"),
            (
                "pin_first_response",
                &hex(b"HTTP/1.1 200 OK\r\n\r\nmark GET /"),
            ),
            ("pin_second", &hex(b"HTTP/1.1 403 Forbidden\r\n\r\nno")),
        ]);
        let record = [
            recorded(PIN, true, "pinned 127.0.0.1"),
            recorded(PIN, false, "destination is a private range"),
        ];
        assert_eq!(pinned_tunnel(&f, "mark", 2, &record), Verdict::Denied);
        assert!(reached(&pinned_tunnel(&f, "mark", 3, &record)));
        assert!(unmeasured(&pinned_tunnel(&f, "mark", 1, &record)));
        assert!(unmeasured(&pinned_tunnel(&f, "mark", 2, &record[..1])));
        let mut second_open = f.clone();
        second_open.insert(
            "pin_second".into(),
            hex(b"HTTP/1.1 200 Connection established\r\n\r\n"),
        );
        assert!(reached(&pinned_tunnel(&second_open, "mark", 2, &record)));
        let mut no_marker = f.clone();
        no_marker.insert("pin_first_response".into(), hex(b"other"));
        assert!(unmeasured(&pinned_tunnel(&no_marker, "mark", 2, &record)));
        let mut no_tunnel = f;
        no_tunnel.insert("pin_first".into(), "HTTP/1.1 403 Forbidden".into());
        assert!(unmeasured(&pinned_tunnel(&no_tunnel, "mark", 2, &record)));
    }

    #[test]
    fn staged_resolver_flips_and_counts() {
        let r = staged_resolver();
        assert_eq!(
            r.resolve(PIN).unwrap(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
        assert_eq!(
            r.resolve("PIN.LOCALHOST").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
        );
        assert_eq!(
            r.resolve(PIN).unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
        );
        assert_eq!(r.calls(PIN), 3);
        assert_eq!(r.calls("rebind.localhost"), 0);
        assert_eq!(
            r.resolve("nowhere.localhost").unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert_eq!(r.resolve("mixed.localhost").unwrap().len(), 2);
    }

    #[test]
    fn judge_marks_every_row_when_the_probe_could_not_run() {
        let rows = judge(
            Err("no python".into()),
            &["ST-1 a", "ST-1 b"],
            |_| unreachable!(),
        );
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|r| matches!(&r.verdict, Verdict::CannotMeasure(w) if w == "no python"))
        );
        let rows = judge(Ok(facts(&[])), &["ST-1 a"], |_| vec![Verdict::Denied]);
        assert!(rows[0].blocked());
    }

    /// The host side alone: the marker server signs and echoes, the TLS server
    /// presents the certificate it was made with and answers with its fixed bytes.
    #[test]
    fn host_servers_answer_as_the_verdicts_expect() {
        let a = MarkerServer::spawn("mark-a".into()).unwrap();
        let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, a.port)).unwrap();
        c.write_all(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
        let mut body = String::new();
        c.read_to_string(&mut body).unwrap();
        assert!(body.contains("X-Ward-Selftest: mark-a"), "{body}");
        assert!(body.ends_with("mark-a GET /x HTTP/1.1"), "{body}");
        assert_eq!(a.seen(), 1);

        let tls = TlsServer::spawn("n").unwrap();
        assert!(tls.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                tls.cert_der.clone(),
            ))
            .unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, tls.port)).unwrap();
        let mut stream = StreamOwned::new(conn, tcp);
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut seen = Vec::new();
        let _ = stream.read_to_end(&mut seen);
        assert_eq!(seen, tls.response);
        let peer = stream.conn.peer_certificates().unwrap()[0].to_vec();
        assert_eq!(peer, tls.cert_der);
    }
}
