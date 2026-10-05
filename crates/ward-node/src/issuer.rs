//! Trusted admission issuers (ADR-0030 §2).
//!
//! The node admits an envelope only with a detached Ed25519 signature made by a key in its
//! configured trust store. A key is named by its identifier: the `BLAKE3` hash of the
//! 32-byte public key. The identifier an [`IssuerProof`] carries is therefore derived from
//! the key itself, never a free label, and a store entry whose stated identifier does not
//! match its key is refused.
//!
//! Each trusted key is bound to exactly one issuing principal ([`PrincipalId`]): the key
//! may sign only authority whose root lease names that principal as its issuer. Several
//! keys may be bound to one principal (for key rotation); one key never speaks for two.
//!
//! The trust-store file holds one issuer per line:
//!
//! ```text
//! line       = [ws] [entry [ws]] ["#" comment]
//! entry      = public-key ws [key-id ws] principal
//! public-key = 64 lowercase hex digits: the 32-byte Ed25519 public key
//! key-id     = 64 lowercase hex digits: BLAKE3-256 of the 32 public-key bytes
//! principal  = "prn_" followed by a 26-character upper-case Crockford base32 ULID
//! ws         = one or more spaces or tabs
//! ```
//!
//! `#` starts a comment that runs to the end of the line; blank and comment-only lines are
//! ignored. Anything else, a key bound to no principal, a duplicate key, a file writable by
//! group or others, a file that is not a regular file, or a file over
//! [`MAX_TRUST_STORE_BYTES`] fails closed. An empty store trusts no issuer, so every
//! admission is refused.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ring::signature::{ED25519, UnparsedPublicKey};
use thiserror::Error;
use ward_events::{Blake3Hash, PrincipalId};
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

    /// Parse 64 lowercase hex characters.
    ///
    /// # Errors
    ///
    /// Returns [`IssuerKeyParseError`] for anything that is not exactly 32 bytes in
    /// lowercase hex.
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

/// Text that is not a 32-byte lowercase hex public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("issuer public key must be 64 lowercase hex characters")]
pub struct IssuerKeyParseError;

/// One trusted issuer key and the one principal it may issue authority as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedIssuer {
    key: IssuerPublicKey,
    principal: PrincipalId,
}

impl TrustedIssuer {
    /// Bind `key` to `principal`.
    #[must_use]
    pub const fn new(key: IssuerPublicKey, principal: PrincipalId) -> Self {
        Self { key, principal }
    }

    /// The issuer's Ed25519 public key.
    #[must_use]
    pub const fn key(&self) -> IssuerPublicKey {
        self.key
    }

    /// The principal the key is bound to: the only root-lease issuer it may sign for.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
}

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
    /// A line is not `<public-key> [<key-id>] <principal>`.
    #[error("trust store line {line} is malformed: expected `<public-key> [<key-id>] prn_…`")]
    MalformedLine {
        /// One-based line number.
        line: usize,
    },
    /// A line names a key, and possibly its key id, but no issuing principal.
    #[error(
        "trust store line {line} binds its key to no issuer: append the `prn_…` it may sign as"
    )]
    MissingIssuer {
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

/// The node's configured set of trusted issuers, indexed by key id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedIssuers {
    issuers: BTreeMap<Blake3Hash, TrustedIssuer>,
}

impl TrustedIssuers {
    /// A store that trusts no issuer.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Trust exactly these issuers, each key under its derived id.
    #[must_use]
    pub fn new(issuers: impl IntoIterator<Item = TrustedIssuer>) -> Self {
        Self {
            issuers: issuers
                .into_iter()
                .map(|issuer| (issuer.key.key_id(), issuer))
                .collect(),
        }
    }

    /// Trust `issuer` under the stated `key_id`, which must be the id derived from its key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyIdMismatch`] when `key_id` is not the id of `issuer`'s key.
    pub fn insert_with_id(
        &mut self,
        key_id: Blake3Hash,
        issuer: TrustedIssuer,
    ) -> Result<(), KeyIdMismatch> {
        if key_id != issuer.key.key_id() {
            return Err(KeyIdMismatch);
        }
        self.issuers.insert(key_id, issuer);
        Ok(())
    }

    /// Parse trust-store text; see the module documentation for the grammar.
    ///
    /// # Errors
    ///
    /// Returns [`TrustStoreError`] for any malformed, unbound, mismatched or duplicate
    /// entry.
    pub fn parse(text: &str) -> Result<Self, TrustStoreError> {
        let mut store = Self::empty();
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let content = raw.split_once('#').map_or(raw, |(content, _)| content);
            let mut fields = content.split([' ', '\t']).filter(|field| !field.is_empty());
            let Some(key) = fields.next() else {
                continue;
            };
            let key = IssuerPublicKey::from_hex(key)
                .map_err(|_| TrustStoreError::MalformedLine { line })?;
            let rest: Vec<&str> = fields.collect();
            let (stated_id, principal) = match rest.as_slice() {
                [] => return Err(TrustStoreError::MissingIssuer { line }),
                [last] => match last.parse::<PrincipalId>() {
                    Ok(principal) => (None, principal),
                    Err(_) if decode_hex_32(last).is_some() => {
                        return Err(TrustStoreError::MissingIssuer { line });
                    }
                    Err(_) => return Err(TrustStoreError::MalformedLine { line }),
                },
                [id, principal] => (
                    Some(*id),
                    principal
                        .parse::<PrincipalId>()
                        .map_err(|_| TrustStoreError::MalformedLine { line })?,
                ),
                _ => return Err(TrustStoreError::MalformedLine { line }),
            };
            let key_id = key.key_id();
            if let Some(stated) = stated_id {
                let stated = decode_hex_32(stated)
                    .map(Blake3Hash::from_bytes)
                    .ok_or(TrustStoreError::MalformedLine { line })?;
                if stated != key_id {
                    return Err(TrustStoreError::KeyIdMismatch { line });
                }
            }
            if store.contains(key_id) {
                return Err(TrustStoreError::DuplicateKey { line });
            }
            store
                .insert_with_id(key_id, TrustedIssuer::new(key, principal))
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
        self.issuers.len()
    }

    /// Whether no issuer is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.issuers.is_empty()
    }

    /// Whether `key_id` names a trusted key.
    #[must_use]
    pub fn contains(&self, key_id: Blake3Hash) -> bool {
        self.issuers.contains_key(&key_id)
    }

    /// The principal the trusted key `key_id` is bound to, if the key is trusted.
    #[must_use]
    pub fn principal(&self, key_id: Blake3Hash) -> Option<PrincipalId> {
        self.issuers.get(&key_id).map(TrustedIssuer::principal)
    }

    /// Verify `proof` over exactly `signed` under the trusted key it names, and return the
    /// principal that key is bound to: the only root-lease issuer the signed bytes may name.
    ///
    /// # Errors
    ///
    /// Returns [`IssuerProofError::UntrustedIssuer`] for an unknown key id and
    /// [`IssuerProofError::InvalidSignature`] when the signature does not verify.
    pub fn verify(
        &self,
        proof: &IssuerProof,
        signed: &[u8],
    ) -> Result<PrincipalId, IssuerProofError> {
        let issuer = self
            .issuers
            .get(&proof.issuer_key_id())
            .ok_or(IssuerProofError::UntrustedIssuer)?;
        UnparsedPublicKey::new(&ED25519, issuer.key.as_bytes())
            .verify(signed, proof.signature().as_bytes())
            .map_err(|_| IssuerProofError::InvalidSignature)?;
        Ok(issuer.principal)
    }
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
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
    use crate::test_support::{ISSUER, issuer_keypair, issuer_public_key, other_keypair, to_hex};

    const OTHER_ISSUER: PrincipalId = PrincipalId::from_u128(9);

    fn other_public_key() -> IssuerPublicKey {
        IssuerPublicKey::from_bytes(other_keypair().public_key().as_ref().try_into().unwrap())
    }

    fn trusted() -> TrustedIssuer {
        TrustedIssuer::new(issuer_public_key(), ISSUER)
    }

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
        let upper = to_hex(key.as_bytes()).to_uppercase();
        for bad in ["", "00", &"g".repeat(64), &"0".repeat(66), &upper] {
            assert_eq!(IssuerPublicKey::from_hex(bad), Err(IssuerKeyParseError));
        }
    }

    #[test]
    fn a_store_entry_must_name_the_id_derived_from_its_key() {
        let key = issuer_public_key();
        let mut store = TrustedIssuers::empty();
        assert_eq!(
            store.insert_with_id(Blake3Hash::from_bytes([0x22; 32]), trusted()),
            Err(KeyIdMismatch)
        );
        assert!(store.is_empty());
        assert_eq!(store.insert_with_id(key.key_id(), trusted()), Ok(()));
        assert!(store.contains(key.key_id()));
        assert_eq!(store.principal(key.key_id()), Some(ISSUER));
        assert_eq!(store, TrustedIssuers::new([trusted()]));
    }

    #[test]
    fn trust_store_text_allows_comments_blank_lines_and_a_matching_key_id() {
        let key = issuer_public_key();
        let other = other_public_key();
        let text = format!(
            "# local issuer\n\n  {} {ISSUER}  # trailing comment\n{}\t{} {OTHER_ISSUER}\n",
            to_hex(key.as_bytes()),
            to_hex(other.as_bytes()),
            other.key_id().to_hex()
        );
        let store = TrustedIssuers::parse(&text).unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.contains(key.key_id()));
        assert!(store.contains(other.key_id()));
        assert_eq!(store.principal(key.key_id()), Some(ISSUER));
        assert_eq!(store.principal(other.key_id()), Some(OTHER_ISSUER));
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
            (
                format!("{key} {ISSUER}\nnot-a-key {ISSUER}\n"),
                "MalformedLine { line: 2 }",
            ),
            (
                format!("{} {ISSUER}\n", &key[..62]),
                "MalformedLine { line: 1 }",
            ),
            (
                format!("{key} {id} {ISSUER} extra\n"),
                "MalformedLine { line: 1 }",
            ),
            (
                format!("{key} {} {ISSUER}\n", "ab".repeat(16)),
                "MalformedLine { line: 1 }",
            ),
            (
                format!("{key} {} {ISSUER}\n", "22".repeat(32)),
                "KeyIdMismatch { line: 1 }",
            ),
            (
                format!("{key} {ISSUER}\n# again\n{key} {OTHER_ISSUER}\n"),
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
        let text = format!("{} {ISSUER}\n", to_hex(issuer_public_key().as_bytes()));

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
        let store = TrustedIssuers::new([trusted()]);

        assert_eq!(store.verify(&proof, signed), Ok(ISSUER));
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

    #[test]
    fn every_trusted_key_is_bound_to_exactly_one_issuer_principal() {
        let key = to_hex(issuer_public_key().as_bytes());
        let id = issuer_public_key().key_id().to_hex();
        let agent = ward_events::AgentId::from_u128(2);
        for (text, expected) in [
            (format!("{key}\n"), "MissingIssuer { line: 1 }"),
            (format!("{key} {id}\n"), "MissingIssuer { line: 1 }"),
            (format!("{key} # {ISSUER}\n"), "MissingIssuer { line: 1 }"),
            (format!("{key} {agent}\n"), "MalformedLine { line: 1 }"),
            (format!("{key} {id} {agent}\n"), "MalformedLine { line: 1 }"),
            (
                format!("{key} {ISSUER} {id}\n"),
                "MalformedLine { line: 1 }",
            ),
            (format!("{ISSUER} {key}\n"), "MalformedLine { line: 1 }"),
            (
                format!("{key} {ISSUER} {ISSUER}\n"),
                "MalformedLine { line: 1 }",
            ),
            (format!("{key} prn_\n"), "MalformedLine { line: 1 }"),
            (format!("{key} {ISSUER}0\n"), "MalformedLine { line: 1 }"),
            (
                format!("{key} prn_01m1rq16g00000y3rf1w7gy3rf\n"),
                "MalformedLine { line: 1 }",
            ),
            (
                format!("{key}\u{a0}{ISSUER}\n"),
                "MalformedLine { line: 1 }",
            ),
            (
                format!("{} {ISSUER}\n", key.to_uppercase()),
                "MalformedLine { line: 1 }",
            ),
            (
                format!("{key} {} {ISSUER}\n", id.to_uppercase()),
                "MalformedLine { line: 1 }",
            ),
        ] {
            let error = TrustedIssuers::parse(&text).unwrap_err();
            assert_eq!(format!("{error:?}"), expected, "{text:?}");
        }

        let lettered: PrincipalId = "prn_01M1RQ16G00000Y3RF1W7GY3RF".parse().unwrap();
        assert_eq!(
            TrustedIssuers::parse(&format!("{key} {lettered}\n"))
                .unwrap()
                .principal(issuer_public_key().key_id()),
            Some(lettered)
        );

        let rotated = TrustedIssuers::parse(&format!(
            "{key} {ISSUER}\n{} {ISSUER}\n",
            to_hex(other_public_key().as_bytes())
        ))
        .unwrap();
        assert_eq!(
            rotated.principal(issuer_public_key().key_id()),
            Some(ISSUER)
        );
        assert_eq!(rotated.principal(other_public_key().key_id()), Some(ISSUER));
        assert_eq!(rotated.principal(Blake3Hash::from_bytes([0x22; 32])), None);
    }

    #[test]
    fn a_verified_proof_names_the_principal_its_key_is_bound_to() {
        let signed = br#"{"exact":"bytes"}"#;
        let store = TrustedIssuers::new([
            trusted(),
            TrustedIssuer::new(other_public_key(), OTHER_ISSUER),
        ]);
        for (key_pair, principal) in [(issuer_keypair(), ISSUER), (other_keypair(), OTHER_ISSUER)] {
            let proof = IssuerProof::new(
                Blake3Hash::hash(key_pair.public_key().as_ref()),
                IssuerSignature::from_bytes(key_pair.sign(signed).as_ref().try_into().unwrap()),
            );
            assert_eq!(store.verify(&proof, signed), Ok(principal));
        }
    }
}
