//! The node protocol over TCP with mutual TLS (#262, ADR-0038).
//!
//! With `--listen-tls <addr>` the node serves, besides its Unix socket, the exact same
//! JSON-lines protocol inside TLS 1.3 sessions on a TCP listener. The operator provisions
//! the node's server identity (`--tls-cert`, `--tls-key`) and the CA its clients'
//! certificates must chain to (`--tls-client-ca`), optionally narrowed to pinned client
//! keys (`--tls-client-pin sha256:<hex>`, the SHA-256 of the certificate's DER
//! `SubjectPublicKeyInfo`). Every file is read once at start, owned by the node's user,
//! never a symlink, the key readable by no one else and the rest writable by no one else;
//! any unsafe, unreadable or inconsistent input stops the node.
//!
//! A client is served only when its certificate chains to the client CA for client
//! authentication, is within its validity window give or take [`CLOCK_SKEW`], carries a
//! pinned key when pins are configured, and the session negotiated [`ALPN`]. There is no
//! session resumption, so every connection verifies its certificate afresh. That identity
//! replaces the peer-credential gate of the socket ([`crate::peer`]) and nothing else:
//! `admit` still needs a trusted issuer signature (ADR-0030 §2).
//!
//! Each accepted TCP connection gets a thread of its own for the handshake, at most
//! [`MAX_TLS_CONNECTIONS`] at once, bounded by [`HANDSHAKE_TIMEOUT`]; the request is then
//! served under the same one-at-a-time lock as the socket's. Refused handshakes are
//! reported on stderr at most once per peer address per [`REPORT_INTERVAL`], served ones
//! at most once per client key, each with the count it did not report.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, RootCertStore,
    ServerConfig, ServerConnection, SignatureScheme, StreamOwned,
};
use thiserror::Error;
use ward_credentials::provider::open_private;

use crate::peer::ReportLimit;
use crate::{ANSWER_TIMEOUT, Connection, NodeService, REQUEST_TIMEOUT, one_at_a_time};

/// The application protocol a client must negotiate (ALPN).
pub const ALPN: &[u8] = b"ward-node";

/// How far a certificate's validity window is stretched on either side for a clock that
/// disagrees with its issuer's.
pub const CLOCK_SKEW: Duration = Duration::from_secs(60);

/// Bound on a TLS handshake, from accept.
pub const HANDSHAKE_TIMEOUT: Duration = REQUEST_TIMEOUT;

/// TCP connections in progress at once (handshaking, waiting to be served or served);
/// one past it is closed at accept and reported.
pub const MAX_TLS_CONNECTIONS: usize = 32;

/// Bound on each of the node's TLS files.
pub const MAX_TLS_FILE_BYTES: usize = 64 * 1024;

/// At most one report per peer address (refused) or client key (served) in this long.
pub const REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// How many peer addresses and client keys the reports track at once.
pub const MAX_TRACKED_REPORTS: usize = 256;

/// A TLS input the node cannot use.
#[derive(Debug, Error)]
pub enum TlsConfigError {
    /// The file is missing, unreadable, not the node user's own regular file, a symlink,
    /// too open for what it holds, or larger than [`MAX_TLS_FILE_BYTES`].
    #[error("{0}")]
    File(String),
    /// The file holds no usable PEM item of the kind it is for.
    #[error("{path}: {reason}")]
    Pem {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// The private key is not the key of the certificate's public key.
    #[error("the key in {key} does not match the certificate in {cert}")]
    KeyMismatch {
        /// The certificate chain file.
        cert: PathBuf,
        /// The key file.
        key: PathBuf,
    },
    /// A `--tls-client-pin` is not `sha256:` and 64 lowercase hex digits.
    #[error("client pin {0:?} is not sha256: followed by 64 lowercase hex digits")]
    Pin(String),
    /// The same pin was listed twice.
    #[error("client pin {0} is listed twice")]
    DuplicatePin(SpkiPin),
    /// rustls refused the assembled configuration.
    #[error("TLS configuration: {0}")]
    Tls(String),
}

/// The SHA-256 of a certificate's DER `SubjectPublicKeyInfo`, spelled `sha256:<hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpkiPin([u8; 32]);

impl SpkiPin {
    /// Parse `sha256:` followed by 64 lowercase hex digits.
    ///
    /// # Errors
    ///
    /// Returns [`TlsConfigError::Pin`] for anything else.
    pub fn parse(value: &str) -> Result<Self, TlsConfigError> {
        let invalid = || TlsConfigError::Pin(value.to_owned());
        let hex = value.strip_prefix("sha256:").ok_or_else(invalid)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid());
        }
        let mut digest = [0_u8; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte =
                u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
        }
        Ok(Self(digest))
    }

    /// The pin of a DER `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn of_spki(spki: &[u8]) -> Self {
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, spki).as_ref());
        Self(digest)
    }

    /// The pin of a certificate's key.
    ///
    /// # Errors
    ///
    /// Returns the parse failure for a certificate that is not DER X.509.
    pub fn of_certificate(cert: &CertificateDer<'_>) -> Result<Self, webpki::Error> {
        let cert = webpki::EndEntityCert::try_from(cert)?;
        Ok(Self::of_spki(cert.subject_public_key_info().as_ref()))
    }
}

impl fmt::Display for SpkiPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The client keys a node serves on its TLS listener; empty serves every key its client
/// CA certified.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientPins(BTreeSet<SpkiPin>);

impl ClientPins {
    /// Parse each `--tls-client-pin` into one set.
    ///
    /// # Errors
    ///
    /// Returns [`TlsConfigError`] for a malformed pin or one listed twice.
    pub fn parse<I, S>(values: I) -> Result<Self, TlsConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut pins = BTreeSet::new();
        for value in values {
            let pin = SpkiPin::parse(value.as_ref())?;
            if !pins.insert(pin) {
                return Err(TlsConfigError::DuplicatePin(pin));
            }
        }
        Ok(Self(pins))
    }

    /// Whether `pin` is served: listed, or no pin is listed at all.
    #[must_use]
    pub fn serves(&self, pin: SpkiPin) -> bool {
        self.0.is_empty() || self.0.contains(&pin)
    }
}

/// The operator's TLS files.
#[derive(Debug, Clone, Copy)]
pub struct TlsFiles<'a> {
    /// The node's certificate chain, leaf first (`--tls-cert`).
    pub cert: &'a Path,
    /// The node's private key, PKCS#8, SEC1 or PKCS#1 PEM (`--tls-key`).
    pub key: &'a Path,
    /// The CA certificates a client's certificate must chain to (`--tls-client-ca`).
    pub client_ca: &'a Path,
}

/// A loaded, consistent server configuration, ready to bind.
#[derive(Debug, Clone)]
pub struct NodeTls {
    config: Arc<ServerConfig>,
}

impl NodeTls {
    /// Read and check the operator's files and assemble the server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TlsConfigError`] for an unsafe, unreadable, empty or malformed file, a
    /// key that does not match the certificate, or a configuration rustls refuses.
    pub fn load(files: TlsFiles<'_>, pins: ClientPins) -> Result<Self, TlsConfigError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let chain = certificates(files.cert, 0o022)?;
        let key_bytes = read(files.key, 0o077)?;
        let key =
            PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|error| TlsConfigError::Pem {
                path: files.key.to_owned(),
                reason: format!("holds no usable PEM private key ({error})"),
            })?;
        let signing = provider
            .key_provider
            .load_private_key(key.clone_key())
            .map_err(|error| TlsConfigError::Pem {
                path: files.key.to_owned(),
                reason: format!("the key cannot sign ({error})"),
            })?;
        CertifiedKey::new(chain.clone(), signing)
            .keys_match()
            .map_err(|_| TlsConfigError::KeyMismatch {
                cert: files.cert.to_owned(),
                key: files.key.to_owned(),
            })?;

        let mut roots = RootCertStore::empty();
        for ca in certificates(files.client_ca, 0o022)? {
            roots.add(ca).map_err(|error| TlsConfigError::Pem {
                path: files.client_ca.to_owned(),
                reason: format!("holds a certificate that is not a usable CA ({error})"),
            })?;
        }
        let verifier = ClientVerifier::new(roots, pins, Arc::clone(&provider))?;

        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| TlsConfigError::Tls(error.to_string()))?
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(chain, key)
            .map_err(|error| TlsConfigError::Tls(error.to_string()))?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Bind the TCP listener at `addr`.
    ///
    /// # Errors
    ///
    /// Returns the bind failure.
    pub fn bind(self, addr: SocketAddr) -> io::Result<TlsListener> {
        Ok(TlsListener {
            listener: TcpListener::bind(addr)?,
            config: self.config,
        })
    }
}

fn read(path: &Path, forbidden_mode: u32) -> Result<Vec<u8>, TlsConfigError> {
    let bytes = open_private(path, forbidden_mode)
        .map_err(TlsConfigError::File)?
        .ok_or_else(|| TlsConfigError::File(format!("{}: no such file", path.display())))?;
    if bytes.len() > MAX_TLS_FILE_BYTES {
        return Err(TlsConfigError::File(format!(
            "{}: larger than {} KiB",
            path.display(),
            MAX_TLS_FILE_BYTES / 1024
        )));
    }
    Ok(bytes.to_vec())
}

fn certificates(
    path: &Path,
    forbidden_mode: u32,
) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let bytes = read(path, forbidden_mode)?;
    let pem = |reason: String| TlsConfigError::Pem {
        path: path.to_owned(),
        reason,
    };
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| pem(format!("holds malformed PEM ({error})")))?;
    if certificates.is_empty() {
        return Err(pem("holds no PEM certificate".to_owned()));
    }
    Ok(certificates)
}

/// The client-certificate check: the client CA's chain for client authentication, with
/// [`CLOCK_SKEW`] on either side of the validity window, then the pins.
#[derive(Debug)]
struct ClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    pins: ClientPins,
}

impl ClientVerifier {
    fn new(
        roots: RootCertStore,
        pins: ClientPins,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, TlsConfigError> {
        let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .clear_root_hint_subjects()
            .build()
            .map_err(|error| TlsConfigError::Tls(error.to_string()))?;
        Ok(Self { inner, pins })
    }
}

/// `now` moved by `skew`, later or earlier.
fn shifted(now: UnixTime, skew: Duration, later: bool) -> UnixTime {
    let now = Duration::from_secs(now.as_secs());
    UnixTime::since_unix_epoch(if later {
        now.saturating_add(skew)
    } else {
        now.saturating_sub(skew)
    })
}

#[derive(Debug, Error)]
#[error("the client key {0} is not pinned with --tls-client-pin")]
struct NotPinned(SpkiPin);

impl ClientCertVerifier for ClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = match self
            .inner
            .verify_client_cert(end_entity, intermediates, now)
        {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. },
            )) => self.inner.verify_client_cert(
                end_entity,
                intermediates,
                shifted(now, CLOCK_SKEW, true),
            ),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::Expired | CertificateError::ExpiredContext { .. },
            )) => self.inner.verify_client_cert(
                end_entity,
                intermediates,
                shifted(now, CLOCK_SKEW, false),
            ),
            verified => verified,
        }?;
        let pin = SpkiPin::of_certificate(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if !self.pins.serves(pin) {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(NotPinned(pin))),
            )));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A bound TLS listener, served by [`crate::serve_node`].
#[derive(Debug)]
pub struct TlsListener {
    listener: TcpListener,
    config: Arc<ServerConfig>,
}

impl TlsListener {
    /// The address the listener is bound to.
    ///
    /// # Errors
    ///
    /// Returns the socket's failure to say.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

impl Connection for StreamOwned<ServerConnection, TcpStream> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_write_timeout(timeout)
    }
}

/// Why a TLS connection was not served.
#[derive(Debug)]
enum Refusal {
    Busy,
    TimedOut,
    Closed,
    Io(io::ErrorKind),
    Tls(rustls::Error),
    NoProtocol,
    NoCertificate,
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => write!(
                formatter,
                "{MAX_TLS_CONNECTIONS} TLS connections are already in progress"
            ),
            Self::TimedOut => write!(
                formatter,
                "the handshake did not complete within {} s",
                HANDSHAKE_TIMEOUT.as_secs()
            ),
            Self::Closed => formatter.write_str("the peer closed the connection in the handshake"),
            Self::Io(kind) => write!(formatter, "the handshake failed: {kind}"),
            Self::Tls(rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(
                error,
            )))) => write!(formatter, "invalid peer certificate: {error}"),
            Self::Tls(error) => write!(formatter, "{error}"),
            Self::NoProtocol => formatter.write_str(
                "the client did not negotiate the ward-node application protocol (ALPN)",
            ),
            Self::NoCertificate => formatter.write_str("the client presented no certificate"),
        }
    }
}

/// The rate-limited reports of one listener.
#[derive(Debug)]
struct Reports {
    refused: ReportLimit<IpAddr>,
    served: ReportLimit<SpkiPin>,
}

impl Reports {
    fn new() -> Self {
        Self {
            refused: ReportLimit::new(REPORT_INTERVAL, MAX_TRACKED_REPORTS),
            served: ReportLimit::new(REPORT_INTERVAL, MAX_TRACKED_REPORTS),
        }
    }
}

fn since_last(suppressed: u64) -> String {
    if suppressed == 0 {
        String::new()
    } else {
        format!(" ({suppressed} more since the last report)")
    }
}

fn report(line: &str) {
    let _ = writeln!(io::stderr().lock(), "{line}");
}

fn report_refusal(reports: &Mutex<Reports>, peer: SocketAddr, refusal: &Refusal) {
    let suppressed = reports
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .refused
        .record(peer.ip(), Instant::now());
    if let Some(suppressed) = suppressed {
        report(&format!(
            "ward-node: refused a TLS connection from {}: {refusal}{}",
            peer.ip(),
            since_last(suppressed)
        ));
    }
}

fn report_served(reports: &Mutex<Reports>, peer: SocketAddr, client: SpkiPin) {
    let suppressed = reports
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .served
        .record(client, Instant::now());
    if let Some(suppressed) = suppressed {
        report(&format!(
            "ward-node: served a TLS client {client} from {}{}",
            peer.ip(),
            since_last(suppressed)
        ));
    }
}

/// One TCP connection counted against [`MAX_TLS_CONNECTIONS`] until dropped.
struct InProgress(Arc<AtomicUsize>);

impl InProgress {
    fn take(count: &Arc<AtomicUsize>) -> Option<Self> {
        count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (current < MAX_TLS_CONNECTIONS).then_some(current + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(count)))
    }
}

impl Drop for InProgress {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept TLS connections on `listener` on a thread of its own, forever: each one is
/// handshaken on a thread of its own and then served under `serving`.
pub(crate) fn spawn(
    listener: TlsListener,
    service: NodeService,
    serving: Arc<Mutex<()>>,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name("ward-node-tls".to_owned())
        .spawn(move || accept(&listener, &service, &serving))
        .map(drop)
}

fn accept(listener: &TlsListener, service: &NodeService, serving: &Arc<Mutex<()>>) {
    let reports = Arc::new(Mutex::new(Reports::new()));
    let in_progress = Arc::new(AtomicUsize::new(0));
    for connection in listener.listener.incoming() {
        let tcp = match connection {
            Ok(tcp) => tcp,
            Err(error) => {
                report(&format!(
                    "ward-node: accepting a TLS connection failed: {error}"
                ));
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let Ok(peer) = tcp.peer_addr() else {
            continue;
        };
        let Some(slot) = InProgress::take(&in_progress) else {
            drop(tcp);
            report_refusal(&reports, peer, &Refusal::Busy);
            continue;
        };
        let config = Arc::clone(&listener.config);
        let service = service.clone();
        let serving = Arc::clone(serving);
        let connection_reports = Arc::clone(&reports);
        let spawned = std::thread::Builder::new()
            .name("ward-node-tls-connection".to_owned())
            .spawn(move || {
                let _slot = slot;
                match handshake(tcp, config) {
                    Ok((stream, client)) => {
                        report_served(&connection_reports, peer, client);
                        serve(stream, &service, &serving);
                    }
                    Err(refusal) => report_refusal(&connection_reports, peer, &refusal),
                }
            });
        if spawned.is_err() {
            report_refusal(&reports, peer, &Refusal::Busy);
        }
    }
}

type TlsStream = StreamOwned<ServerConnection, TcpStream>;

/// Complete the handshake within [`HANDSHAKE_TIMEOUT`] of accept, sending the peer the
/// alert of a refusal, and name the client by its key.
fn handshake(
    mut tcp: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<(TlsStream, SpkiPin), Refusal> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    tcp.set_nodelay(true)
        .map_err(|error| Refusal::Io(error.kind()))?;
    let mut connection = ServerConnection::new(config).map_err(Refusal::Tls)?;
    while connection.is_handshaking() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(Refusal::TimedOut)?;
        tcp.set_read_timeout(Some(remaining))
            .and_then(|()| tcp.set_write_timeout(Some(remaining)))
            .map_err(|error| Refusal::Io(error.kind()))?;
        if connection.wants_write() {
            connection
                .write_tls(&mut tcp)
                .map_err(|error| io_refusal(&error))?;
            continue;
        }
        if connection
            .read_tls(&mut tcp)
            .map_err(|error| io_refusal(&error))?
            == 0
        {
            return Err(Refusal::Closed);
        }
        if let Err(error) = connection.process_new_packets() {
            let _ = connection.write_tls(&mut tcp);
            return Err(Refusal::Tls(error));
        }
    }
    if connection.alpn_protocol() != Some(ALPN) {
        connection.send_close_notify();
        let _ = connection.write_tls(&mut tcp);
        return Err(Refusal::NoProtocol);
    }
    let client = connection
        .peer_certificates()
        .and_then(<[CertificateDer<'_>]>::first)
        .and_then(|leaf| SpkiPin::of_certificate(leaf).ok())
        .ok_or(Refusal::NoCertificate)?;
    Ok((StreamOwned::new(connection, tcp), client))
}

fn io_refusal(error: &io::Error) -> Refusal {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Refusal::TimedOut,
        kind => Refusal::Io(kind),
    }
}

/// Serve one request under the one-at-a-time lock, then end the session cleanly so the
/// client reads a close, not a truncation, whether or not it was answered.
fn serve(mut stream: TlsStream, service: &NodeService, serving: &Mutex<()>) {
    {
        let _one_at_a_time = one_at_a_time(serving);
        let _ = service.serve_stream(&mut stream);
    }
    stream.conn.send_close_notify();
    let _ = stream.sock.set_write_timeout(Some(ANSWER_TIMEOUT));
    while stream.conn.wants_write() {
        if stream.conn.write_tls(&mut stream.sock).is_err() {
            break;
        }
    }
    let _ = stream.sock.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_pin_is_sha256_and_64_lowercase_hex_digits() {
        let hex = "0123456789abcdef".repeat(4);
        let pin = SpkiPin::parse(&format!("sha256:{hex}")).unwrap();
        assert_eq!(pin.to_string(), format!("sha256:{hex}"));
        for value in [
            String::new(),
            hex.clone(),
            format!("sha256:{}", &hex[1..]),
            format!("sha256:{hex}0"),
            format!("sha256:{}", hex.to_uppercase()),
            format!("SHA256:{hex}"),
            format!("sha512:{hex}"),
            format!("sha256:{}g", &hex[1..]),
            format!("sha256: {}", &hex[1..]),
        ] {
            assert!(
                matches!(SpkiPin::parse(&value), Err(TlsConfigError::Pin(ref v)) if *v == value),
                "{value:?}"
            );
        }
    }

    #[test]
    fn pins_refuse_a_duplicate_and_an_empty_list_serves_every_key() {
        let one = format!("sha256:{}", "1".repeat(64));
        let two = format!("sha256:{}", "2".repeat(64));
        assert!(matches!(
            ClientPins::parse([&one, &two, &one]),
            Err(TlsConfigError::DuplicatePin(pin)) if pin.to_string() == one
        ));
        let pins = ClientPins::parse([&one]).unwrap();
        assert!(pins.serves(SpkiPin::parse(&one).unwrap()));
        assert!(!pins.serves(SpkiPin::parse(&two).unwrap()));
        assert!(ClientPins::default().serves(SpkiPin::parse(&two).unwrap()));
    }

    #[test]
    fn a_pin_is_the_sha256_of_the_spki_bytes() {
        let pin = SpkiPin::of_spki(b"abc");
        assert_eq!(
            pin.to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(SpkiPin::of_certificate(&CertificateDer::from(vec![0_u8; 4])).is_err());
    }

    #[test]
    fn the_skew_moves_the_verification_time_either_way_and_saturates() {
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_000));
        assert_eq!(shifted(now, CLOCK_SKEW, true).as_secs(), 1_060);
        assert_eq!(shifted(now, CLOCK_SKEW, false).as_secs(), 940);
        let epoch = UnixTime::since_unix_epoch(Duration::ZERO);
        assert_eq!(shifted(epoch, CLOCK_SKEW, false).as_secs(), 0);
    }

    #[test]
    fn the_in_progress_bound_is_taken_and_given_back() {
        let count = Arc::new(AtomicUsize::new(0));
        let held: Vec<_> = (0..MAX_TLS_CONNECTIONS)
            .map(|_| InProgress::take(&count).unwrap())
            .collect();
        assert!(InProgress::take(&count).is_none());
        drop(held);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(InProgress::take(&count).is_some());
    }

    #[test]
    fn refusal_reasons_name_what_happened() {
        assert!(Refusal::Busy.to_string().contains("already in progress"));
        assert!(Refusal::TimedOut.to_string().contains("10 s"));
        assert!(Refusal::NoProtocol.to_string().contains("ward-node"));
        assert!(
            Refusal::NoCertificate
                .to_string()
                .contains("no certificate")
        );
        assert!(Refusal::Closed.to_string().contains("closed"));
        assert!(
            Refusal::Io(io::ErrorKind::ConnectionReset)
                .to_string()
                .contains("reset")
        );
        assert_eq!(since_last(0), "");
        assert_eq!(since_last(3), " (3 more since the last report)");
    }

    #[test]
    fn errors_name_the_offending_input() {
        assert!(
            TlsConfigError::KeyMismatch {
                cert: "c.pem".into(),
                key: "k.pem".into()
            }
            .to_string()
            .contains("does not match")
        );
        let missing = read(Path::new("/nonexistent/ward-node-tls.pem"), 0o077).unwrap_err();
        assert!(missing.to_string().contains("no such file"), "{missing}");
    }
}
