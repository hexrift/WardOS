//! The issuer signer reproduces the node-integration.md §7.4 test vector byte for byte and
//! reads its seed only from a private file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ward_events::{Blake3Hash, PrincipalId};
use ward_node_client::{IssuerKey, IssuerKeyError};
use ward_node_protocol::AdmissionEnvelopeJson;

const VECTOR_PUBLIC_KEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const VECTOR_KEY_ID: &str = "0871f3aabc26e4582c508af5c03884e6a96f0989d1dd8cfb49cd17ed25792433";
const VECTOR_SIGNATURE: &str = "c2336bf71cc42af7222a4f736ac991c830cb560d1aa1af8241a3356ab58a8f23cb236ef558b113832d81ca3114de958b55c24eb6e45b317db3c05fac5bc26002";
const VECTOR_ENVELOPE: &str = r#"{"binding":{"task":"task_01M45YYRG00001249248SK6H24","attempt":"exec_01M45YYRG00005ANB6CSVQF248","lease":"lease_01M45YYRG00009K6DANAXVQK6C"},"agent":"agent_01M43CJ1G0000DVQFEXVZZY001","node":"node_01M3KY5QG0000028T5CY4TQKFF","session":"sess_01M45YYRG0000FXQ5TK1V58CGG","authority":{"lease":{"id":"lease_01M45YYRG00009K6DANAXVQK6C","delegation_id":"deleg_01M45YYRG000016NWVVWJ6HB70","issuer":"prn_01M1RQ16G00000Y3RF1W7GY3RF","subject":"agent_01M43CJ1G0000DVQFEXVZZY001","task":"task_01M45YYRG00001249248SK6H24","parent_lease_id":null,"delegated_by":null,"grants":[{"capability":"repo.read","resource":"repo:example/project","delegable":false},{"capability":"repo.write","resource":"repo:example/project","delegable":false}],"issued_at_unix_ms":1791201600000,"expires_at_unix_ms":1791205200000,"version":1},"lineage":[]},"workload":{"argv":["sh","-c","make test"],"capability_manifest":{"hash":"eb3e889be30ae8dd712a52c33e37aaca72e52ccff1aa770ecbd962d0cdb0d0c3","bytes":"7b226e6574776f726b223a226f66666c696e65227d"},"snapshot":"c19c769fdd8644df9167a36d0133289c9fa44a8c768cd0aafa1756a13fb3e33b","wall_clock_budget_ms":600000},"issued_at_unix_ms":1791201600000,"expires_at_unix_ms":1791202500000,"version":1}"#;

fn vector_key() -> IssuerKey {
    IssuerKey::from_seed([7; 32]).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[test]
fn the_section_7_4_vector_reproduces_exactly() {
    let key = vector_key();
    assert_eq!(key.public_key_hex(), VECTOR_PUBLIC_KEY);
    assert_eq!(key.key_id(), Blake3Hash::from_hex(VECTOR_KEY_ID).unwrap());
    assert_eq!(VECTOR_ENVELOPE.len(), 1203);

    let json = AdmissionEnvelopeJson::new(VECTOR_ENVELOPE.to_owned()).unwrap();
    let signed = key.sign_json(json.clone());
    assert_eq!(signed.envelope_json, json);
    assert_eq!(signed.proof.issuer_key_id().to_hex(), VECTOR_KEY_ID);
    assert_eq!(hex(signed.proof.signature().as_bytes()), VECTOR_SIGNATURE);

    let decoded = json.decode().unwrap();
    let resigned = key.sign(&decoded).unwrap();
    assert_eq!(
        resigned, signed,
        "encoding the decoded vector gives the same bytes"
    );
}

#[test]
fn another_seed_signs_differently_and_names_another_key() {
    let other = IssuerKey::from_seed([8; 32]).unwrap();
    assert_ne!(other.public_key_hex(), VECTOR_PUBLIC_KEY);
    let json = AdmissionEnvelopeJson::new(VECTOR_ENVELOPE.to_owned()).unwrap();
    let signed = other.sign_json(json);
    assert_ne!(hex(signed.proof.signature().as_bytes()), VECTOR_SIGNATURE);
    assert_eq!(signed.proof.issuer_key_id(), other.key_id());
}

#[test]
fn the_trust_store_line_binds_the_key_to_one_principal() {
    let principal = PrincipalId::from_u128(2);
    assert_eq!(
        vector_key().trust_store_line(principal),
        format!("{VECTOR_PUBLIC_KEY} {VECTOR_KEY_ID} {principal}")
    );
}

fn seed_file(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn a_seed_file_is_read_only_when_private_and_exactly_32_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let private = seed_file(dir.path(), "private", &[7; 32], 0o600);
    assert_eq!(
        IssuerKey::from_seed_file(&private)
            .unwrap()
            .public_key_hex(),
        VECTOR_PUBLIC_KEY
    );
    let read_only = seed_file(dir.path(), "read-only", &[7; 32], 0o400);
    assert!(IssuerKey::from_seed_file(&read_only).is_ok());

    for (name, mode) in [
        ("group", 0o640),
        ("world", 0o644),
        ("exec", 0o700),
        ("other-read", 0o604),
    ] {
        let path = seed_file(dir.path(), name, &[7; 32], mode);
        assert!(
            matches!(
                IssuerKey::from_seed_file(&path),
                Err(IssuerKeyError::InsecureMode { mode: found }) if found == mode
            ),
            "{name}"
        );
    }

    let short = seed_file(dir.path(), "short", &[7; 31], 0o600);
    assert!(matches!(
        IssuerKey::from_seed_file(&short),
        Err(IssuerKeyError::WrongLength { found: 31 })
    ));
    let long = seed_file(dir.path(), "long", &[7; 33], 0o600);
    assert!(matches!(
        IssuerKey::from_seed_file(&long),
        Err(IssuerKeyError::WrongLength { found: 33 })
    ));
    assert!(matches!(
        IssuerKey::from_seed_file(&dir.path().join("missing")),
        Err(IssuerKeyError::Io(_))
    ));
    let directory = dir.path().join("directory");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        IssuerKey::from_seed_file(&directory),
        Err(IssuerKeyError::NotARegularFile)
    ));
}
