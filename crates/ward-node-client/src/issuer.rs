//! The issuer signing key of node-integration.md §2.3 and §7.4.
//!
//! An [`IssuerKey`] is an Ed25519 key pair held by the control plane. It signs the exact
//! UTF-8 bytes of the serialised envelope (`envelope_json`) with pure Ed25519 (RFC 8032)
//! and names itself by its key id, `BLAKE3-256` over the 32 raw public-key bytes. The
//! signed bytes travel verbatim in the `admit` request; nothing is re-serialised after
//! signing, so a [`SignedEnvelope`] can be persisted and replayed byte for byte.
//!
//! The seed is read only from a private regular file (mode `0600` or `0400`, exactly 32
//! bytes); any other mode is refused so a readable copy of the key is never used.

use std::fmt::{Debug, Formatter};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ward_events::{Blake3Hash, PrincipalId};
use ward_node_protocol::{
    AdmissionEnvelopeJson, IssuerProof, IssuerSignature, TaskAdmissionEnvelope, TaskAdmissionError,
};

/// Length of an Ed25519 seed in bytes.
pub const SEED_LEN: usize = 32;

/// Why an issuer key could not be loaded or used. Every case fails closed.
#[derive(Debug, Error)]
pub enum IssuerKeyError {
    /// The seed file could not be read.
    #[error("issuer seed file could not be read: {0}")]
    Io(#[from] std::io::Error),
    /// The seed path is not a regular file.
    #[error("issuer seed is not a regular file")]
    NotARegularFile,
    /// The seed file is not mode `0600` or `0400`.
    #[error("issuer seed file mode {mode:o} is not 0600 or 0400")]
    InsecureMode {
        /// The file's permission bits.
        mode: u32,
    },
    /// The seed file does not hold exactly [`SEED_LEN`] bytes.
    #[error("issuer seed file holds {found} bytes, not {SEED_LEN}")]
    WrongLength {
        /// The file's length in bytes.
        found: u64,
    },
    /// The seed bytes are not a usable Ed25519 seed.
    #[error("issuer seed is not a valid Ed25519 seed")]
    InvalidSeed,
    /// The envelope could not be serialised within its bounds.
    #[error("admission envelope cannot be signed: {0}")]
    Envelope(#[from] TaskAdmissionError),
}

/// A signed admission envelope: the exact bytes that were signed and their proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    /// The serialised envelope, exactly as signed and as sent.
    pub envelope_json: AdmissionEnvelopeJson,
    /// The detached issuer proof over `envelope_json`.
    pub proof: IssuerProof,
}

/// An issuer's Ed25519 signing key.
pub struct IssuerKey {
    pair: Ed25519KeyPair,
    public: [u8; 32],
}

impl Debug for IssuerKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuerKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl IssuerKey {
    /// Derive the key pair from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns [`IssuerKeyError::InvalidSeed`] if the seed cannot be used.
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Result<Self, IssuerKeyError> {
        let pair =
            Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| IssuerKeyError::InvalidSeed)?;
        let public = <[u8; 32]>::try_from(pair.public_key().as_ref())
            .map_err(|_| IssuerKeyError::InvalidSeed)?;
        Ok(Self { pair, public })
    }

    /// Read a 32-byte seed from a private regular file (mode `0600` or `0400`).
    ///
    /// # Errors
    ///
    /// Returns [`IssuerKeyError::InsecureMode`] for any other mode,
    /// [`IssuerKeyError::WrongLength`] unless the file holds exactly 32 bytes, and
    /// [`IssuerKeyError::NotARegularFile`] or [`IssuerKeyError::Io`] for anything that is
    /// not a readable regular file.
    pub fn from_seed_file(path: &Path) -> Result<Self, IssuerKeyError> {
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(IssuerKeyError::NotARegularFile);
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 && mode != 0o400 {
            return Err(IssuerKeyError::InsecureMode { mode });
        }
        if metadata.len() != SEED_LEN as u64 {
            return Err(IssuerKeyError::WrongLength {
                found: metadata.len(),
            });
        }
        let mut bytes = Vec::with_capacity(SEED_LEN + 1);
        file.take(SEED_LEN as u64 + 1).read_to_end(&mut bytes)?;
        let seed = <[u8; SEED_LEN]>::try_from(bytes.as_slice()).map_err(|_| {
            IssuerKeyError::WrongLength {
                found: bytes.len() as u64,
            }
        })?;
        Self::from_seed(seed)
    }

    /// The raw 32-byte public key.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The public key as 64 lowercase hex digits, as a trust store spells it (§2.2).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        Blake3Hash::from_bytes(self.public).to_hex()
    }

    /// The key id: `BLAKE3-256` of the 32 public-key bytes (§2.3).
    #[must_use]
    pub fn key_id(&self) -> Blake3Hash {
        Blake3Hash::hash(&self.public)
    }

    /// The trust-store line binding this key to `principal` (§2.2).
    #[must_use]
    pub fn trust_store_line(&self, principal: PrincipalId) -> String {
        format!(
            "{} {} {principal}",
            self.public_key_hex(),
            self.key_id().to_hex()
        )
    }

    /// Sign already-serialised envelope bytes exactly as given (§7.4).
    #[must_use]
    pub fn sign_json(&self, envelope_json: AdmissionEnvelopeJson) -> SignedEnvelope {
        let signature = self.pair.sign(envelope_json.as_bytes());
        let mut bytes = [0_u8; IssuerSignature::LEN];
        for (target, source) in bytes.iter_mut().zip(signature.as_ref()) {
            *target = *source;
        }
        SignedEnvelope {
            envelope_json,
            proof: IssuerProof::new(self.key_id(), IssuerSignature::from_bytes(bytes)),
        }
    }

    /// Serialise `envelope` once and sign those bytes (§7.4).
    ///
    /// # Errors
    ///
    /// Returns [`IssuerKeyError::Envelope`] if the envelope does not fit its wire bound.
    pub fn sign(&self, envelope: &TaskAdmissionEnvelope) -> Result<SignedEnvelope, IssuerKeyError> {
        Ok(self.sign_json(AdmissionEnvelopeJson::encode(envelope)?))
    }
}
