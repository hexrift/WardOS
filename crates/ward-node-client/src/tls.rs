//! The node protocol over TCP with mutual TLS (node-integration.md §3, ADR-0038).
//!
//! [`TlsTransport`] reaches a node started with `--listen-tls`: TLS 1.3 only, the
//! `ward-node` application protocol, this client's certificate and key, and the node's
//! certificate checked against the operator's server CA for the expected server name and,
//! when a pin is given, for the expected key. A certificate outside its validity window by
//! more than [`CLOCK_SKEW`] is refused, as the node refuses a client's. The framing,
//! bounds and fail-closed reading of EOF are exactly the Unix transport's.

use std::io::{BufReader, Read};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, OtherError,
    RootCertStore, SignatureScheme, StreamOwned,
};
use thiserror::Error;

use crate::transport::{
    Exchange, MAX_LINE_BYTES, Timeouts, Transport, TransportError, io_error, payload,
    read_bounded_line, read_line, send,
};

/// The application protocol the node serves (ALPN).
pub const ALPN: &[u8] = b"ward-node";

/// How far a certificate's validity window is stretched on either side, as on the node.
pub const CLOCK_SKEW: Duration = Duration::from_secs(60);

/// Bound on each of the client's TLS files.
pub const MAX_TLS_FILE_BYTES: u64 = 64 * 1024;

pub(crate) type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// The TLS error an I/O error carries, if it carries one.
pub(crate) fn rustls_error(error: &std::io::Error) -> Option<&rustls::Error> {
    error.get_ref()?.downcast_ref::<rustls::Error>()
}

/// A TLS error as a reason a person reads: a verifier's own refusal by its own words.
pub(crate) fn describe(error: &rustls::Error) -> String {
    match error {
        rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
            format!("invalid peer certificate: {inner}")
        }
        other => other.to_string(),
    }
}

/// What a [`TlsTransport`] needs to reach a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsSettings {
    /// The node's `--listen-tls` address, `<host>:<port>`.
    pub address: String,
    /// The DNS name or IP address the node's certificate must be valid for.
    pub server_name: String,
    /// The CA certificates, in PEM, the node's certificate must chain to.
    pub server_ca: PathBuf,
    /// This client's certificate chain, leaf first, in PEM.
    pub client_cert: PathBuf,
    /// This client's private key in PEM: a regular file of mode 0600 or 0400.
    pub client_key: PathBuf,
    /// The node's key, `sha256:` and the 64 lowercase hex digits of the SHA-256 of its
    /// certificate's DER `SubjectPublicKeyInfo`; any key the CA certified when `None`.
    pub server_pin: Option<String>,
}

/// A TLS client configuration that cannot be used; nothing was sent.
#[derive(Debug, Error)]
pub enum TlsSetupError {
    /// The file is missing, unreadable, a symlink, not a regular file, too open for what
    /// it holds, or larger than [`MAX_TLS_FILE_BYTES`].
    #[error("{path}: {reason}")]
    File {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// The server name is neither a DNS name nor an IP address.
    #[error("server name {0:?} is neither a DNS name nor an IP address")]
    ServerName(String),
    /// The server pin is not `sha256:` and 64 lowercase hex digits.
    #[error("server pin {0:?} is not sha256: followed by 64 lowercase hex digits")]
    Pin(String),
    /// rustls refused the assembled configuration.
    #[error("TLS configuration: {0}")]
    Tls(String),
}

/// The newline-delimited JSON transport over TCP with mutual TLS.
#[derive(Clone, Debug)]
pub struct TlsTransport {
    address: String,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
    timeouts: Timeouts,
}

impl TlsTransport {
    /// Read the client's files and assemble its configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TlsSetupError`] for an unsafe or malformed file, server name or pin.
    pub fn new(settings: &TlsSettings, timeouts: Timeouts) -> Result<Self, TlsSetupError> {
        let server_name = ServerName::try_from(settings.server_name.clone())
            .map_err(|_| TlsSetupError::ServerName(settings.server_name.clone()))?;
        let pin = settings.server_pin.as_deref().map(parse_pin).transpose()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        for ca in certificates(&settings.server_ca)? {
            roots.add(ca).map_err(|error| TlsSetupError::File {
                path: settings.server_ca.clone(),
                reason: format!("holds a certificate that is not a usable CA ({error})"),
            })?;
        }
        let inner =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(|error| TlsSetupError::Tls(error.to_string()))?;
        let chain = certificates(&settings.client_cert)?;
        let key_bytes = read(&settings.client_key, true)?;
        let key =
            PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|error| TlsSetupError::File {
                path: settings.client_key.clone(),
                reason: format!("holds no usable PEM private key ({error})"),
            })?;
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| TlsSetupError::Tls(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerVerifier { inner, pin }))
            .with_client_auth_cert(chain, key)
            .map_err(|error| TlsSetupError::Tls(error.to_string()))?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        Ok(Self {
            address: settings.address.clone(),
            server_name,
            config: Arc::new(config),
            timeouts,
        })
    }

    /// The node's address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The configured timeouts.
    #[must_use]
    pub const fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    fn connect(&self, lines: &[&str]) -> Result<BufReader<TlsStream>, TransportError> {
        let payload = payload(lines)?;
        let deadline = Instant::now() + self.timeouts.connect;
        let mut tcp = self.tcp()?;
        let mut connection =
            ClientConnection::new(Arc::clone(&self.config), self.server_name.clone())
                .map_err(|error| TransportError::Tls(describe(&error)))?;
        while connection.is_handshaking() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(TransportError::TimedOut)?;
            tcp.set_read_timeout(Some(remaining))
                .and_then(|()| tcp.set_write_timeout(Some(remaining)))
                .map_err(TransportError::Io)?;
            match connection.complete_io(&mut tcp) {
                Ok((0, 0)) if connection.is_handshaking() => {
                    return Err(TransportError::ClosedWithoutResponse);
                }
                Ok(_) => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        if connection.alpn_protocol() != Some(ALPN) {
            return Err(TransportError::Tls(
                "the node did not negotiate the ward-node application protocol".to_owned(),
            ));
        }
        tcp.set_write_timeout(Some(self.timeouts.connect))
            .map_err(TransportError::Io)?;
        let mut stream = StreamOwned::new(connection, tcp);
        send(&mut stream, &payload)?;
        Ok(BufReader::new(stream))
    }

    fn tcp(&self) -> Result<TcpStream, TransportError> {
        let mut last = None;
        for addr in self
            .address
            .to_socket_addrs()
            .map_err(TransportError::Connect)?
        {
            match TcpStream::connect_timeout(&addr, self.timeouts.connect) {
                Ok(tcp) => {
                    tcp.set_nodelay(true).map_err(TransportError::Io)?;
                    return Ok(tcp);
                }
                Err(error) => last = Some(error),
            }
        }
        Err(TransportError::Connect(last.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} resolves to no address", self.address),
            )
        })))
    }
}

impl Transport for TlsTransport {
    fn handshake(&self, hello: &str) -> Result<String, TransportError> {
        let mut reader = self.connect(&[hello])?;
        read_line(&mut reader, self.timeouts.connect)?.ok_or(TransportError::ClosedWithoutResponse)
    }

    fn exchange(&self, hello: &str, request: &str) -> Result<Exchange, TransportError> {
        self.exchange_with_response_bound(hello, request, MAX_LINE_BYTES)
    }

    fn exchange_with_response_bound(
        &self,
        hello: &str,
        request: &str,
        response_bound: usize,
    ) -> Result<Exchange, TransportError> {
        let mut reader = self.connect(&[hello, request])?;
        let handshake = read_line(&mut reader, self.timeouts.connect)?
            .ok_or(TransportError::ClosedWithoutResponse)?;
        let response = read_bounded_line(&mut reader, self.timeouts.request, response_bound)?;
        Ok(Exchange {
            handshake,
            response,
        })
    }
}

fn parse_pin(value: &str) -> Result<[u8; 32], TlsSetupError> {
    let invalid = || TlsSetupError::Pin(value.to_owned());
    let hex = value.strip_prefix("sha256:").ok_or_else(invalid)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let mut pin = [0_u8; 32];
    for (index, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(pin)
}

fn spki_sha256(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let cert = webpki::EndEntityCert::try_from(cert).ok()?;
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(
        ring::digest::digest(
            &ring::digest::SHA256,
            cert.subject_public_key_info().as_ref(),
        )
        .as_ref(),
    );
    Some(digest)
}

/// Read a file that is not a symlink, is a regular file and is writable by no one else;
/// a key must also be readable by no one else (mode 0600 or 0400).
fn read(path: &Path, key: bool) -> Result<Vec<u8>, TlsSetupError> {
    let refuse = |reason: String| TlsSetupError::File {
        path: path.to_owned(),
        reason,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|error| refuse(format!("cannot open ({error}; a symlink is refused)")))?;
    let metadata = file.metadata().map_err(|error| refuse(error.to_string()))?;
    if !metadata.is_file() {
        return Err(refuse("not a regular file".to_owned()));
    }
    let mode = metadata.mode() & 0o777;
    if key && mode != 0o600 && mode != 0o400 {
        return Err(refuse(format!(
            "mode {mode:o} is too open for a key (0600 or 0400)"
        )));
    }
    if mode & 0o022 != 0 {
        return Err(refuse(format!("mode {mode:o} is writable by others")));
    }
    if metadata.len() > MAX_TLS_FILE_BYTES {
        return Err(refuse(format!(
            "larger than {} KiB",
            MAX_TLS_FILE_BYTES / 1024
        )));
    }
    let mut bytes = Vec::new();
    file.take(MAX_TLS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refuse(error.to_string()))?;
    Ok(bytes)
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsSetupError> {
    let bytes = read(path, false)?;
    let refuse = |reason: String| TlsSetupError::File {
        path: path.to_owned(),
        reason,
    };
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| refuse(format!("holds malformed PEM ({error})")))?;
    if certificates.is_empty() {
        return Err(refuse("holds no PEM certificate".to_owned()));
    }
    Ok(certificates)
}

fn shifted(now: UnixTime, skew: Duration, later: bool) -> UnixTime {
    let now = Duration::from_secs(now.as_secs());
    UnixTime::since_unix_epoch(if later {
        now.saturating_add(skew)
    } else {
        now.saturating_sub(skew)
    })
}

#[derive(Debug, Error)]
#[error("the node's key is not the pinned one")]
struct NotPinned;

/// The server CA's chain for the expected name, with [`CLOCK_SKEW`] on either side of the
/// validity window, then the pin.
#[derive(Debug)]
struct ServerVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pin: Option<[u8; 32]>,
}

impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verify = |at| {
            self.inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, at)
        };
        let verified = match verify(now) {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. },
            )) => verify(shifted(now, CLOCK_SKEW, true)),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::Expired | CertificateError::ExpiredContext { .. },
            )) => verify(shifted(now, CLOCK_SKEW, false)),
            verified => verified,
        }?;
        if let Some(pin) = self.pin
            && spki_sha256(end_entity) != Some(pin)
        {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(NotPinned)),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn a_server_pin_is_sha256_and_64_lowercase_hex_digits() {
        let hex = "0123456789abcdef".repeat(4);
        let pin = parse_pin(&format!("sha256:{hex}")).unwrap();
        assert_eq!(pin[0], 0x01);
        assert_eq!(pin[31], 0xef);
        for value in [
            String::new(),
            hex.clone(),
            format!("sha256:{}", &hex[1..]),
            format!("sha256:{}", hex.to_uppercase()),
            format!("sha1:{hex}"),
            format!("sha256:{hex}00"),
        ] {
            assert!(
                matches!(parse_pin(&value), Err(TlsSetupError::Pin(ref v)) if *v == value),
                "{value:?}"
            );
        }
    }

    #[test]
    fn the_skew_moves_the_verification_time_either_way() {
        let now = UnixTime::since_unix_epoch(Duration::from_secs(500));
        assert_eq!(shifted(now, CLOCK_SKEW, true).as_secs(), 560);
        assert_eq!(shifted(now, CLOCK_SKEW, false).as_secs(), 440);
        assert!(spki_sha256(&CertificateDer::from(vec![1_u8, 2, 3])).is_none());
    }

    #[test]
    fn files_are_refused_unless_regular_private_enough_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str, mode: u32, len: usize| {
            let path = dir.path().join(name);
            std::fs::write(&path, vec![b'x'; len]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        assert!(read(&file("key-600", 0o600, 3), true).is_ok());
        assert!(read(&file("key-400", 0o400, 3), true).is_ok());
        let open = read(&file("key-640", 0o640, 3), true).unwrap_err();
        assert!(open.to_string().contains("too open"), "{open}");
        assert!(read(&file("cert-644", 0o644, 3), false).is_ok());
        let writable = read(&file("cert-664", 0o664, 3), false).unwrap_err();
        assert!(writable.to_string().contains("writable"), "{writable}");
        let large = usize::try_from(MAX_TLS_FILE_BYTES).unwrap() + 1;
        assert!(read(&file("large", 0o644, large), false).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("cert-644"), &link).unwrap();
        assert!(
            read(&link, false)
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        assert!(read(dir.path(), false).is_err());
        assert!(read(&dir.path().join("missing"), false).is_err());
        let empty = certificates(&file("empty", 0o644, 0)).unwrap_err();
        assert!(empty.to_string().contains("no PEM certificate"), "{empty}");
    }

    #[test]
    fn rustls_errors_are_found_inside_io_errors() {
        let wrapped = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer),
        );
        assert!(rustls_error(&wrapped).is_some());
        assert!(rustls_error(&std::io::Error::other("plain")).is_none());
    }
}
