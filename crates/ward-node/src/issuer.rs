//! Trusted admission issuers (ADR-0030 §2).
//!
//! The node admits an envelope only with a detached Ed25519 signature made by a key in its
//! configured trust store. A key is named by its identifier: the `BLAKE3` hash of the
//! 32-byte public key. The identifier an [`IssuerProof`] carries is therefore derived from
//! the key itself, never a free label, and a store entry whose stated identifier does not
//! match its key is refused.
//!
//! The trust-store file lists one issuer per line as the lowercase or uppercase hex of the
//! 32-byte Ed25519 public key, optionally followed by whitespace and the hex key id, which
//! must then equal the derived id. `#` starts a comment; blank lines are ignored. Anything
//! else, a duplicate key, a file writable by group or others, a file that is not a regular
//! file, or a file over [`MAX_TRUST_STORE_BYTES`] fails closed. An empty store trusts no
//! issuer, so every admission is refused.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ring::signature::{ED25519, UnparsedPublicKey};
use thiserror::Error;
use ward_events::Blake3Hash;
use ward_node_protocol::IssuerProof;

/// Maximum size in bytes of a trust-store file.
pub const MAX_TRUST_STORE_BYTES: u64 = 64 * 1024;

/// One Ed25519 issuer public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerPublicKey([u8; 32]);

impl IssuerPublicKey {
    /// Public key length in bytes.
    pub const LEN: usize = 32;

    /// Wrap raw Ed25519 public-key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse 64 hex characters.
    ///
    /// # Errors
    ///
    /// Returns [`IssuerKeyParseError`] for anything that is not exactly 32 hex bytes.
    pub fn from_hex(hex: &str) -> Result<Self, IssuerKeyParseError> {
        decode_hex_32(hex).map(Self).ok_or(IssuerKeyParseError)
    }

    /// The raw public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key identifier: the `BLAKE3` hash of the 32 public-key bytes.
    #[must_use]
    pub fn key_id(&self) -> Blake3Hash {
        Blake3Hash::hash(&self.0)
    }
}

/// Text that is not a 32-byte hex public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("issuer public key must be 64 hex characters")]
pub struct IssuerKeyParseError;

/// Why the trust store could not be loaded. Every case fails closed.
#[derive(Debug, Error)]
pub enum TrustStoreError {
    /// The file could not be read.
    #[error("trust store could not be read: {0}")]
    Io(#[from] std::io::Error),
    /// The path is not a regular file.
    #[error("trust store is not a regular file")]
    NotARegularFile,
    /// The file is writable by its group or by others.
    #[error("trust store must not be writable by group or others")]
    WritableByOthers,
    /// The file exceeds [`MAX_TRUST_STORE_BYTES`].
    #[error("trust store is too large")]
    TooLarge,
    /// The file is not UTF-8.
    #[error("trust store is not UTF-8")]
    NotUtf8,
    /// A line is not a public key, optionally followed by its key id.
    #[error("trust store line {line} is malformed")]
    MalformedLine {
        /// One-based line number.
        line: usize,
    },
    /// A stated key id does not equal the id derived from its key.
    #[error("trust store line {line} names a key id that does not match its key")]
    KeyIdMismatch {
        /// One-based line number.
        line: usize,
    },
    /// The same key appears twice.
    #[error("trust store line {line} repeats a key")]
    DuplicateKey {
        /// One-based line number.
        line: usize,
    },
}

/// Why an issuer proof was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum IssuerProofError {
    /// The proof names a key id the node does not trust.
    #[error("issuer key is not trusted")]
    UntrustedIssuer,
    /// The signature does not verify over the signed bytes under the trusted key.
    #[error("issuer signature does not verify")]
    InvalidSignature,
}

/// A stated key id that is not the id of its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("issuer key id does not match the key")]
pub struct KeyIdMismatch;

/// The node's configured set of trusted issuer keys, indexed by key id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedIssuers {
    keys: BTreeMap<Blake3Hash, IssuerPublicKey>,
}

impl TrustedIssuers {
    /// A store that trusts no issuer.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Trust exactly these keys, each under its derived id.
    #[must_use]
    pub fn new(keys: impl IntoIterator<Item = IssuerPublicKey>) -> Self {
        Self {
            keys: keys.into_iter().map(|key| (key.key_id(), key)).collect(),
        }
    }

    /// Trust `key` under the stated `key_id`, which must be the id derived from it.
    ///
    /// # Errors
    ///
    /// Returns [`KeyIdMismatch`] when `key_id` is not `key.key_id()`.
    pub fn insert_with_id(
        &mut self,
        key_id: Blake3Hash,
        key: IssuerPublicKey,
    ) -> Result<(), KeyIdMismatch> {
        if key_id != key.key_id() {
            return Err(KeyIdMismatch);
        }
        self.keys.insert(key_id, key);
        Ok(())
    }

    /// Parse trust-store text; see the module documentation for the format.
    ///
    /// # Errors
    ///
    /// Returns [`TrustStoreError`] for any malformed, mismatched or duplicate entry.
    pub fn parse(text: &str) -> Result<Self, TrustStoreError> {
        let mut store = Self::empty();
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let content = raw.split_once('#').map_or(raw, |(content, _)| content);
            let mut fields = content.split_whitespace();
            let Some(key) = fields.next() else {
                continue;
            };
            let key = IssuerPublicKey::from_hex(key)
                .map_err(|_| TrustStoreError::MalformedLine { line })?;
            let key_id = match fields.next() {
                None => key.key_id(),
                Some(stated) => {
                    let stated = decode_hex_32(stated)
                        .map(Blake3Hash::from_bytes)
                        .ok_or(TrustStoreError::MalformedLine { line })?;
                    if stated != key.key_id() {
                        return Err(TrustStoreError::KeyIdMismatch { line });
                    }
                    stated
                }
            };
            if fields.next().is_some() {
                return Err(TrustStoreError::MalformedLine { line });
            }
            if store.contains(key_id) {
                return Err(TrustStoreError::DuplicateKey { line });
            }
            store
                .insert_with_id(key_id, key)
                .map_err(|_| TrustStoreError::KeyIdMismatch { line })?;
        }
        Ok(store)
    }

    /// Load a trust-store file, refusing anything unsafe or malformed.
    ///
    /// # Errors
    ///
    /// Returns [`TrustStoreError`]; nothing is trusted on any error.
    pub fn load(path: &Path) -> Result<Self, TrustStoreError> {
        if !std::fs::metadata(path)?.is_file() {
            return Err(TrustStoreError::NotARegularFile);
        }
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(TrustStoreError::NotARegularFile);
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(TrustStoreError::WritableByOthers);
        }
        if metadata.len() > MAX_TRUST_STORE_BYTES {
            return Err(TrustStoreError::TooLarge);
        }
        let mut bytes = Vec::new();
        file.take(MAX_TRUST_STORE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > usize::try_from(MAX_TRUST_STORE_BYTES).unwrap_or(usize::MAX) {
            return Err(TrustStoreError::TooLarge);
        }
        let text = String::from_utf8(bytes).map_err(|_| TrustStoreError::NotUtf8)?;
        Self::parse(&text)
    }

    /// Number of trusted keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no issuer is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether `key_id` names a trusted key.
    #[must_use]
    pub fn contains(&self, key_id: Blake3Hash) -> bool {
        self.keys.contains_key(&key_id)
    }

    /// Verify `proof` over exactly `signed` under the trusted key it names.
    ///
    /// # Errors
    ///
    /// Returns [`IssuerProofError::UntrustedIssuer`] for an unknown key id and
    /// [`IssuerProofError::InvalidSignature`] when the signature does not verify.
    pub fn verify(&self, proof: &IssuerProof, signed: &[u8]) -> Result<(), IssuerProofError> {
        let key = self
            .keys
            .get(&proof.issuer_key_id())
            .ok_or(IssuerProofError::UntrustedIssuer)?;
        UnparsedPublicKey::new(&ED25519, key.as_bytes())
            .verify(signed, proof.signature().as_bytes())
            .map_err(|_| IssuerProofError::InvalidSignature)
    }
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *slot = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;

    use ring::signature::KeyPair;
    use ward_node_protocol::{IssuerProof, IssuerSignature};

    use super::*;
    use crate::test_support::{issuer_keypair, issuer_public_key, other_keypair, to_hex};

    fn write_store(dir: &Path, text: &str, mode: u32) -> std::path::PathBuf {
        let path = dir.join("trusted-issuers");
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn key_id_is_the_blake3_hash_of_the_public_key_bytes() {
        let key = issuer_public_key();
        assert_eq!(key.key_id(), Blake3Hash::hash(key.as_bytes()));
        assert_eq!(IssuerPublicKey::from_hex(&to_hex(key.as_bytes())), Ok(key));
        assert_eq!(
            IssuerPublicKey::from_hex(&to_hex(key.as_bytes()).to_uppercase()),
            Ok(key)
        );
        for bad in ["", "00", &"g".repeat(64), &"0".repeat(66)] {
            assert_eq!(IssuerPublicKey::from_hex(bad), Err(IssuerKeyParseError));
        }
    }

    #[test]
    fn a_store_entry_must_name_the_id_derived_from_its_key() {
        let key = issuer_public_key();
        let mut store = TrustedIssuers::empty();
        assert_eq!(
            store.insert_with_id(Blake3Hash::from_bytes([0x22; 32]), key),
            Err(KeyIdMismatch)
        );
        assert!(store.is_empty());
        assert_eq!(store.insert_with_id(key.key_id(), key), Ok(()));
        assert!(store.contains(key.key_id()));
        assert_eq!(store, TrustedIssuers::new([key]));
    }

    #[test]
    fn trust_store_text_allows_comments_blank_lines_and_a_matching_key_id() {
        let key = issuer_public_key();
        let other =
            IssuerPublicKey::from_bytes(other_keypair().public_key().as_ref().try_into().unwrap());
        let text = format!(
            "# local issuer\n\n  {}  # trailing comment\n{} {}\n",
            to_hex(key.as_bytes()),
            to_hex(other.as_bytes()),
            other.key_id().to_hex()
        );
        let store = TrustedIssuers::parse(&text).unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.contains(key.key_id()));
        assert!(store.contains(other.key_id()));
        assert!(
            TrustedIssuers::parse("# nothing trusted\n\n")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn malformed_mismatched_or_duplicate_trust_store_lines_fail_closed() {
        let key = to_hex(issuer_public_key().as_bytes());
        let id = issuer_public_key().key_id().to_hex();
        for (text, expected) in [
            (format!("{key}\nnot-a-key\n"), "MalformedLine { line: 2 }"),
            (format!("{}\n", &key[..62]), "MalformedLine { line: 1 }"),
            (format!("{key} {id} extra\n"), "MalformedLine { line: 1 }"),
            (
                format!("{key} {}\n", "ab".repeat(16)),
                "MalformedLine { line: 1 }",
            ),
            (
                format!("{key} {}\n", "22".repeat(32)),
                "KeyIdMismatch { line: 1 }",
            ),
            (
                format!("{key}\n# again\n{key}\n"),
                "DuplicateKey { line: 3 }",
            ),
        ] {
            let error = TrustedIssuers::parse(&text).unwrap_err();
            assert_eq!(format!("{error:?}"), expected, "{text:?}");
        }
    }

    #[test]
    fn trust_store_file_must_be_a_private_bounded_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let text = format!("{}\n", to_hex(issuer_public_key().as_bytes()));

        for mode in [0o600, 0o644, 0o400] {
            let store = TrustedIssuers::load(&write_store(dir.path(), &text, mode)).unwrap();
            assert!(
                store.contains(issuer_public_key().key_id()),
                "mode {mode:o}"
            );
        }
        for mode in [0o666, 0o646, 0o620, 0o602] {
            assert!(
                matches!(
                    TrustedIssuers::load(&write_store(dir.path(), &text, mode)),
                    Err(TrustStoreError::WritableByOthers)
                ),
                "mode {mode:o} must be refused"
            );
        }
        assert!(matches!(
            TrustedIssuers::load(dir.path()),
            Err(TrustStoreError::NotARegularFile)
        ));
        assert!(matches!(
            TrustedIssuers::load(&dir.path().join("missing")),
            Err(TrustStoreError::Io(_))
        ));
        let huge = "#".repeat(usize::try_from(MAX_TRUST_STORE_BYTES).unwrap() + 1);
        assert!(matches!(
            TrustedIssuers::load(&write_store(dir.path(), &huge, 0o600)),
            Err(TrustStoreError::TooLarge)
        ));
        assert!(matches!(
            TrustedIssuers::load(&write_store(dir.path(), "zz\n", 0o600)),
            Err(TrustStoreError::MalformedLine { line: 1 })
        ));
    }

    #[test]
    fn proofs_verify_only_under_a_trusted_key_over_the_exact_bytes() {
        let signed = br#"{"exact":"bytes"}"#;
        let key_pair = issuer_keypair();
        let proof = IssuerProof::new(
            issuer_public_key().key_id(),
            IssuerSignature::from_bytes(key_pair.sign(signed).as_ref().try_into().unwrap()),
        );
        let store = TrustedIssuers::new([issuer_public_key()]);

        assert_eq!(store.verify(&proof, signed), Ok(()));
        assert_eq!(
            store.verify(&proof, br#"{"exact": "bytes"}"#),
            Err(IssuerProofError::InvalidSignature)
        );
        assert_eq!(
            TrustedIssuers::empty().verify(&proof, signed),
            Err(IssuerProofError::UntrustedIssuer)
        );

        let forged = IssuerProof::new(
            issuer_public_key().key_id(),
            IssuerSignature::from_bytes(other_keypair().sign(signed).as_ref().try_into().unwrap()),
        );
        assert_eq!(
            store.verify(&forged, signed),
            Err(IssuerProofError::InvalidSignature)
        );

        let other_id = Blake3Hash::hash(other_keypair().public_key().as_ref());
        let untrusted = IssuerProof::new(
            other_id,
            IssuerSignature::from_bytes(other_keypair().sign(signed).as_ref().try_into().unwrap()),
        );
        assert_eq!(
            store.verify(&untrusted, signed),
            Err(IssuerProofError::UntrustedIssuer)
        );
    }
}
