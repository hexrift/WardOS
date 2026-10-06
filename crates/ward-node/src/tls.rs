//! The node protocol over TCP with mutual TLS (#262, ADR-0038).
//!
//! With `--listen-tls <addr>` the node serves, besides its Unix socket, the exact same
//! JSON-lines protocol inside TLS 1.3 sessions on a TCP listener. The operator provisions
//! the node's server identity (`--tls-cert`, `--tls-key`) and the CA its clients'
//! certificates must chain to (`--tls-client-ca`), optionally narrowed to pinned client
//! keys (`--tls-client-pin sha256:<hex>`, the SHA-256 of the certificate's DER
//! `SubjectPublicKeyInfo`), and with `--tls-client-revoked <file>` refuses the client keys
//! that file lists, one pin per line. Every file is read at start, owned by the node's
//! user, never a symlink, the key readable by no one else and the rest writable by no one
//! else; any unsafe, unreadable or inconsistent input stops the node. On `SIGHUP`
//! ([`reload_on_hangup`]) every file is read and checked again, and the new configuration
//! replaces the old one for every handshake from then on only when all of it is usable;
//! otherwise the node keeps serving the old one. Either outcome is reported on stderr.
//!
//! A client is served only when its certificate chains to the client CA for client
//! authentication, is within its validity window give or take [`CLOCK_SKEW`], carries a
//! key that is not revoked and is pinned when pins are configured, and the session
//! negotiated [`ALPN`]. There is no session resumption, so every connection verifies its
//! certificate afresh. That identity replaces the peer-credential gate of the socket
//! ([`crate::peer`]) and nothing else: `admit` still needs a trusted issuer signature
//! (ADR-0030 §2).
//!
//! Each accepted TCP connection gets a thread of its own for the handshake, at most
//! [`MAX_TLS_CONNECTIONS`] at once, bounded by [`HANDSHAKE_TIMEOUT`]; the request is then
//! served under the same one-at-a-time lock as the socket's, unless a reload revoked the
//! client's key while it waited for that lock. Refused handshakes are reported on stderr
//! at most once per peer address per [`REPORT_INTERVAL`], served ones at most once per
//! client key, each with the count it did not report.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use nix::sys::signal::{SigSet, Signal};
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
    /// A line of the revocation list is neither a pin, blank nor a comment.
    #[error(
        "{path}, line {line}: malformed revoked key {value:?} (expected sha256: followed by 64 lowercase hex digits)"
    )]
    Revocation {
        /// The revocation list.
        path: PathBuf,
        /// The line, counted from 1.
        line: usize,
        /// What the line holds, comment and surrounding blanks removed.
        value: String,
    },
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

/// The client keys a node refuses on its TLS listener even when their certificate chains
/// to the client CA and is pinned (`--tls-client-revoked`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevokedKeys(BTreeSet<SpkiPin>);

impl RevokedKeys {
    /// Parse a revocation list: one pin per line, as `--tls-client-pin` spells it, with
    /// blank lines and everything from a `#` to the end of its line ignored. A key listed
    /// twice is revoked once.
    ///
    /// # Errors
    ///
    /// Returns [`TlsConfigError::Revocation`], naming `path` and the line, for anything
    /// else on a line.
    pub fn parse(path: &Path, text: &str) -> Result<Self, TlsConfigError> {
        let mut revoked = BTreeSet::new();
        for (index, line) in text.lines().enumerate() {
            let value = line.split_once('#').map_or(line, |(value, _)| value).trim();
            if value.is_empty() {
                continue;
            }
            let pin = SpkiPin::parse(value).map_err(|_| TlsConfigError::Revocation {
                path: path.to_owned(),
                line: index + 1,
                value: value.to_owned(),
            })?;
            revoked.insert(pin);
        }
        Ok(Self(revoked))
    }

    /// Read and parse the revocation list at `path`, under the rule of the certificates:
    /// the node user's own regular file, not a symlink, writable by no one else, at most
    /// [`MAX_TLS_FILE_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`TlsConfigError`] for an unsafe, unreadable or malformed list.
    pub fn load(path: &Path) -> Result<Self, TlsConfigError> {
        let bytes = read(path, 0o022)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| TlsConfigError::File(format!("{}: not UTF-8 text", path.display())))?;
        Self::parse(path, text)
    }

    /// Whether `pin` is revoked.
    #[must_use]
    pub fn revokes(&self, pin: SpkiPin) -> bool {
        self.0.contains(&pin)
    }

    /// How many keys are revoked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no key is revoked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Where the node's TLS configuration comes from.
#[derive(Debug, Clone)]
pub struct TlsSources {
    /// The node's certificate chain, leaf first (`--tls-cert`).
    pub cert: PathBuf,
    /// The node's private key, PKCS#8, SEC1 or PKCS#1 PEM (`--tls-key`).
    pub key: PathBuf,
    /// The CA certificates a client's certificate must chain to (`--tls-client-ca`).
    pub client_ca: PathBuf,
    /// The client keys served (`--tls-client-pin`).
    pub client_pins: ClientPins,
    /// The revocation list of client keys (`--tls-client-revoked`), if any.
    pub client_revoked: Option<PathBuf>,
}

/// A loaded, consistent server configuration, ready to bind.
#[derive(Debug)]
pub struct NodeTls {
    sources: TlsSources,
    loaded: Arc<Loaded>,
}

impl NodeTls {
    /// Read and check the operator's files and assemble the server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TlsConfigError`] for an unsafe, unreadable, empty or malformed file, a
    /// key that does not match the certificate, or a configuration rustls refuses.
    pub fn load(sources: TlsSources) -> Result<Self, TlsConfigError> {
        let loaded = Arc::new(Loaded::assemble(&sources)?);
        Ok(Self { sources, loaded })
    }

    /// Bind the TCP listener at `addr`.
    ///
    /// # Errors
    ///
    /// Returns the bind failure.
    pub fn bind(self, addr: SocketAddr) -> io::Result<TlsListener> {
        Ok(TlsListener {
            listener: TcpListener::bind(addr)?,
            current: Arc::new(Current {
                sources: self.sources,
                loaded: RwLock::new(self.loaded),
            }),
        })
    }
}

/// One server configuration and what a reload compares.
#[derive(Debug)]
struct Loaded {
    config: Arc<ServerConfig>,
    revoked: Arc<RevokedKeys>,
    server_key: SpkiPin,
    server_chain: Vec<CertificateDer<'static>>,
    client_ca: Vec<CertificateDer<'static>>,
    pins: usize,
}

impl Loaded {
    fn assemble(sources: &TlsSources) -> Result<Self, TlsConfigError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let chain = certificates(&sources.cert, 0o022)?;
        let key_bytes = read(&sources.key, 0o077)?;
        let key =
            PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|error| TlsConfigError::Pem {
                path: sources.key.clone(),
                reason: format!("holds no usable PEM private key ({error})"),
            })?;
        let signing = provider
            .key_provider
            .load_private_key(key.clone_key())
            .map_err(|error| TlsConfigError::Pem {
                path: sources.key.clone(),
                reason: format!("the key cannot sign ({error})"),
            })?;
        CertifiedKey::new(chain.clone(), signing)
            .keys_match()
            .map_err(|_| TlsConfigError::KeyMismatch {
                cert: sources.cert.clone(),
                key: sources.key.clone(),
            })?;
        let server_key =
            SpkiPin::of_certificate(&chain[0]).map_err(|error| TlsConfigError::Pem {
                path: sources.cert.clone(),
                reason: format!("holds a leaf certificate that is not X.509 ({error})"),
            })?;

        let client_ca = certificates(&sources.client_ca, 0o022)?;
        let mut roots = RootCertStore::empty();
        for ca in client_ca.iter().cloned() {
            roots.add(ca).map_err(|error| TlsConfigError::Pem {
                path: sources.client_ca.clone(),
                reason: format!("holds a certificate that is not a usable CA ({error})"),
            })?;
        }
        let revoked = Arc::new(
            sources
                .client_revoked
                .as_deref()
                .map(RevokedKeys::load)
                .transpose()?
                .unwrap_or_default(),
        );
        let verifier = ClientVerifier::new(
            roots,
            sources.client_pins.clone(),
            Arc::clone(&revoked),
            Arc::clone(&provider),
        )?;

        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| TlsConfigError::Tls(error.to_string()))?
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(chain.clone(), key)
            .map_err(|error| TlsConfigError::Tls(error.to_string()))?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        Ok(Self {
            config: Arc::new(config),
            revoked,
            server_key,
            server_chain: chain,
            client_ca,
            pins: sources.client_pins.0.len(),
        })
    }
}

/// The sources of a listener's configuration and the configuration new handshakes use.
#[derive(Debug)]
struct Current {
    sources: TlsSources,
    loaded: RwLock<Arc<Loaded>>,
}

impl Current {
    fn get(&self) -> Arc<Loaded> {
        Arc::clone(&self.loaded.read().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Reloads a listener's configuration from the sources it was loaded from.
#[derive(Debug, Clone)]
pub struct TlsReloader(Arc<Current>);

impl TlsReloader {
    /// Read and check every source again and, only when all of them are usable, make the
    /// result the configuration of every handshake from now on. Sessions already
    /// authenticated keep going, except that one whose client key is now revoked is
    /// closed unserved when its request comes up.
    ///
    /// # Errors
    ///
    /// Returns what [`NodeTls::load`] returns; the configuration in use is unchanged.
    pub fn reload(&self) -> Result<Reloaded, TlsConfigError> {
        let new = Arc::new(Loaded::assemble(&self.0.sources)?);
        let mut current = self
            .0
            .loaded
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let reloaded = Reloaded::between(&current, &new);
        *current = new;
        Ok(reloaded)
    }

    fn report(&self) -> String {
        match self.reload() {
            Ok(reloaded) => format!("ward-node: reloaded the TLS configuration: {reloaded}"),
            Err(error) => format!(
                "ward-node: reloading the TLS configuration failed; still serving the previous one: {error}"
            ),
        }
    }
}

/// What a reload changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloaded {
    server_key: SpkiPin,
    server: ServerChange,
    client_ca: usize,
    client_ca_changed: bool,
    pins: usize,
    revoked: usize,
    revoked_added: usize,
    revoked_removed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerChange {
    Unchanged,
    Certificate,
    Key,
}

impl Reloaded {
    fn between(old: &Loaded, new: &Loaded) -> Self {
        let server = if old.server_key != new.server_key {
            ServerChange::Key
        } else if old.server_chain != new.server_chain {
            ServerChange::Certificate
        } else {
            ServerChange::Unchanged
        };
        Self {
            server_key: new.server_key,
            server,
            client_ca: new.client_ca.len(),
            client_ca_changed: old.client_ca != new.client_ca,
            pins: new.pins,
            revoked: new.revoked.len(),
            revoked_added: new.revoked.0.difference(&old.revoked.0).count(),
            revoked_removed: old.revoked.0.difference(&new.revoked.0).count(),
        }
    }
}

impl fmt::Display for Reloaded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let changed = |changed: bool| if changed { "changed" } else { "unchanged" };
        let server = match self.server {
            ServerChange::Unchanged => "unchanged",
            ServerChange::Certificate => "unchanged, new certificate",
            ServerChange::Key => "changed",
        };
        write!(
            formatter,
            "server key {} ({server}), client CA certificates {} ({}), pinned client keys {}, \
             revoked client keys {} (+{}, -{})",
            self.server_key,
            self.client_ca,
            changed(self.client_ca_changed),
            self.pins,
            self.revoked,
            self.revoked_added,
            self.revoked_removed
        )
    }
}

/// Block `SIGHUP` on the calling thread, and so on every thread it starts afterwards, so
/// that only [`reload_on_hangup`] takes it; call it before any thread starts.
/// `std::process::Command` clears the mask in a child.
///
/// # Errors
///
/// Returns the failure to change the signal mask.
pub fn block_hangup() -> io::Result<SigSet> {
    let mut hangup = SigSet::empty();
    hangup.add(Signal::SIGHUP);
    hangup.thread_block()?;
    Ok(hangup)
}

/// On a thread of its own, forever: reload with `reloader` on every `SIGHUP` that
/// [`block_hangup`] blocked, and report the outcome on stderr.
///
/// # Errors
///
/// Returns the failure to start the thread.
pub fn reload_on_hangup(reloader: TlsReloader, hangup: SigSet) -> io::Result<()> {
    std::thread::Builder::new()
        .name("ward-node-tls-reload".to_owned())
        .spawn(move || {
            loop {
                if let Err(error) = hangup.wait() {
                    report(&format!(
                        "ward-node: waiting for SIGHUP failed ({error}); the TLS configuration is no longer reloaded"
                    ));
                    return;
                }
                report(&reloader.report());
            }
        })
        .map(drop)
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
/// [`CLOCK_SKEW`] on either side of the validity window, then the revocation list, then
/// the pins.
#[derive(Debug)]
struct ClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    pins: ClientPins,
    revoked: Arc<RevokedKeys>,
}

impl ClientVerifier {
    fn new(
        roots: RootCertStore,
        pins: ClientPins,
        revoked: Arc<RevokedKeys>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, TlsConfigError> {
        let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .clear_root_hint_subjects()
            .build()
            .map_err(|error| TlsConfigError::Tls(error.to_string()))?;
        Ok(Self {
            inner,
            pins,
            revoked,
        })
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

#[derive(Debug, Error)]
#[error("the client key {0} is revoked by --tls-client-revoked")]
struct Revoked(SpkiPin);

fn refused_key(error: impl std::error::Error + Send + Sync + 'static) -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(error))))
}

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
        if self.revoked.revokes(pin) {
            return Err(refused_key(Revoked(pin)));
        }
        if !self.pins.serves(pin) {
            return Err(refused_key(NotPinned(pin)));
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
    current: Arc<Current>,
}

impl TlsListener {
    /// The handle that reloads this listener's configuration.
    #[must_use]
    pub fn reloader(&self) -> TlsReloader {
        TlsReloader(Arc::clone(&self.current))
    }

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
    RevokedSince(SpkiPin),
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
            Self::RevokedSince(client) => write!(
                formatter,
                "the client key {client} was revoked by --tls-client-revoked after its handshake"
            ),
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
        let config = Arc::clone(&listener.current.get().config);
        let current = Arc::clone(&listener.current);
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
                        if let Err(refusal) = serve(stream, client, &service, &serving, &current) {
                            report_refusal(&connection_reports, peer, &refusal);
                        }
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

/// Serve one request under the one-at-a-time lock unless a reload revoked the client's
/// key since its handshake, then end the session cleanly so the client reads a close, not
/// a truncation, whether or not it was answered.
fn serve(
    mut stream: TlsStream,
    client: SpkiPin,
    service: &NodeService,
    serving: &Mutex<()>,
    current: &Current,
) -> Result<(), Refusal> {
    let revoked = {
        let _one_at_a_time = one_at_a_time(serving);
        let revoked = current.get().revoked.revokes(client);
        if !revoked {
            let _ = service.serve_stream(&mut stream);
        }
        revoked
    };
    stream.conn.send_close_notify();
    let _ = stream.sock.set_write_timeout(Some(ANSWER_TIMEOUT));
    while stream.conn.wants_write() {
        if stream.conn.write_tls(&mut stream.sock).is_err() {
            break;
        }
    }
    let _ = stream.sock.shutdown(Shutdown::Both);
    if revoked {
        return Err(Refusal::RevokedSince(client));
    }
    Ok(())
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
    fn a_revocation_list_is_one_pin_per_line_with_blank_lines_and_comments() {
        let one = format!("sha256:{}", "1".repeat(64));
        let two = format!("sha256:{}", "2".repeat(64));
        let three = format!("sha256:{}", "3".repeat(64));
        let path = Path::new("revoked.list");
        let revoked = RevokedKeys::parse(
            path,
            &format!("# lost keys\r\n\n  {one}  # laptop\n\t{two}\n{one}\n"),
        )
        .unwrap();
        assert_eq!(revoked.len(), 2, "a key listed twice is revoked once");
        assert!(revoked.revokes(SpkiPin::parse(&one).unwrap()));
        assert!(revoked.revokes(SpkiPin::parse(&two).unwrap()));
        assert!(!revoked.revokes(SpkiPin::parse(&three).unwrap()));
        assert!(RevokedKeys::parse(path, "").unwrap().is_empty());
        assert!(RevokedKeys::parse(path, "#\n \n").unwrap().is_empty());
        assert!(RevokedKeys::default().is_empty());
    }

    #[test]
    fn a_malformed_revocation_line_is_named_by_its_number() {
        let one = format!("sha256:{}", "1".repeat(64));
        let path = Path::new("revoked.list");
        for (text, at, holds) in [
            (format!("{one}\nsha256:00\n"), 2, "sha256:00".to_owned()),
            (format!("# a\n\n{one} {one}"), 3, format!("{one} {one}")),
            (one.to_uppercase(), 1, one.to_uppercase()),
            ("md5:00 # old".to_owned(), 1, "md5:00".to_owned()),
        ] {
            let error = RevokedKeys::parse(path, &text).unwrap_err();
            assert!(
                matches!(
                    &error,
                    TlsConfigError::Revocation { path: p, line, value }
                        if p == path && *line == at && *value == holds
                ),
                "{text:?}: {error:?}"
            );
            let message = error.to_string();
            assert!(
                message.starts_with(&format!("revoked.list, line {at}: malformed")),
                "{message}"
            );
        }
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
    fn a_reload_says_what_it_changed() {
        let pin = SpkiPin::of_spki(b"node");
        let mut reloaded = Reloaded {
            server_key: pin,
            server: ServerChange::Unchanged,
            client_ca: 2,
            client_ca_changed: false,
            pins: 1,
            revoked: 3,
            revoked_added: 2,
            revoked_removed: 1,
        };
        assert_eq!(
            reloaded.to_string(),
            format!(
                "server key {pin} (unchanged), client CA certificates 2 (unchanged), \
                 pinned client keys 1, revoked client keys 3 (+2, -1)"
            )
        );
        reloaded.server = ServerChange::Certificate;
        reloaded.client_ca_changed = true;
        let line = reloaded.to_string();
        assert!(line.contains("(unchanged, new certificate)"), "{line}");
        assert!(
            line.contains("client CA certificates 2 (changed)"),
            "{line}"
        );
        reloaded.server = ServerChange::Key;
        assert!(
            reloaded
                .to_string()
                .starts_with(&format!("server key {pin} (changed)"))
        );
        let late = Refusal::RevokedSince(pin).to_string();
        assert!(late.contains(&pin.to_string()), "{late}");
        assert!(late.contains("after its handshake"), "{late}");
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
