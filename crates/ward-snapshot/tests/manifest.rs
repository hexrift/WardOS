//! Canonical encoding, strict parsing, hostile names.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::cast_possible_truncation
)]

mod common;

use common::rp;
use ward_snapshot::error::PathError;
use ward_snapshot::{ContentHash, Entry, EntryKind, Error, Manifest, RelPath, SnapshotId};

const GOLDEN: &[u8] = include_bytes!("golden/manifest_v1.golden");
const GOLDEN_ID: &str = include_str!("golden/manifest_v1.id");

/// The manifest that `tests/golden/manifest_v1.golden` was generated from (by an
/// independent Python BLAKE3 implementation, see the fixture's provenance in the
/// experiment notes).
fn golden_manifest() -> Manifest {
    Manifest::from_entries(vec![
        Entry::dir(rp("dir"), 0o755),
        Entry::file(rp("dir/hello.txt"), 0o644, 5, ContentHash::of(b"hello")),
        Entry::file(rp("empty exec"), 0o755, 0, ContentHash::of(b"")),
        Entry::symlink(rp("link"), b"/etc/passwd"),
        Entry::file(rp("new\nline"), 0o644, 1, ContentHash::of(b"x")),
        Entry::file(
            RelPath::new(b"n\xffame".to_vec()).unwrap(),
            0o644,
            3,
            ContentHash::of(b"abc"),
        ),
        Entry::unsupported(rp("pipe"), 0o644),
        Entry::file(rp("setuid"), 0o4755, 2, ContentHash::of(b"hi")),
        Entry::file(rp("\u{e9}.txt"), 0o644, 3, ContentHash::of(b"nfc")),
        Entry::file(rp("e\u{301}.txt"), 0o644, 3, ContentHash::of(b"nfd")),
    ])
    .unwrap()
}

#[test]
fn golden_canonical_encoding_matches_fixture() {
    let m = golden_manifest();
    assert_eq!(
        m.to_canonical_bytes(),
        GOLDEN,
        "canonical bytes differ from fixture"
    );
    let expected: SnapshotId = GOLDEN_ID.trim().parse().unwrap();
    assert_eq!(m.id(), expected);
    assert_eq!(SnapshotId::of_manifest_bytes(GOLDEN), expected);
}

#[test]
fn golden_fixture_parses_back_to_same_manifest() {
    let parsed = Manifest::parse(GOLDEN).unwrap();
    assert_eq!(parsed, golden_manifest());
    assert_eq!(parsed.id(), GOLDEN_ID.trim().parse::<SnapshotId>().unwrap());
}

#[test]
fn golden_fixture_has_documented_record_layout() {
    // Independent of the encoder: every record is `<type> <mode> <size> <hash> <path>`.
    let records: Vec<&[u8]> = GOLDEN.split(|b| *b == 0).collect();
    assert_eq!(records.last(), Some(&&b""[..]), "trailing NUL");
    let records = &records[..records.len() - 1];
    assert_eq!(records.len(), 10);
    for r in records {
        let fields: Vec<&[u8]> = r.splitn(5, |b| *b == b' ').collect();
        assert_eq!(fields.len(), 5, "record {:?}", String::from_utf8_lossy(r));
        assert!(matches!(
            fields[0],
            b"file" | b"dir" | b"symlink" | b"unsupported"
        ));
        assert_eq!(fields[1].len(), 4);
        assert_eq!(fields[3].len(), 64);
    }
    // Sorted bytewise by path.
    let paths: Vec<&[u8]> = records
        .iter()
        .map(|r| r.splitn(5, |b| *b == b' ').nth(4).unwrap())
        .collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted);
}

#[test]
fn unicode_normalisation_forms_are_distinct_paths() {
    let m = golden_manifest();
    assert!(m.get(&rp("\u{e9}.txt")).is_some());
    assert!(m.get(&rp("e\u{301}.txt")).is_some());
    assert_ne!(m.get(&rp("\u{e9}.txt")), m.get(&rp("e\u{301}.txt")));
}

#[test]
fn hostile_names_roundtrip_through_encoding() {
    let long = "x".repeat(4000);
    let names: Vec<Vec<u8>> = vec![
        b"a b".to_vec(),
        b"tab\there".to_vec(),
        b"new\nline".to_vec(),
        b"\xff\xfe\xfd".to_vec(),
        b"\xc3\x28invalid-utf8".to_vec(),
        long.as_bytes().to_vec(),
        b"-leading-dash".to_vec(),
        b"...".to_vec(),
        b"..a".to_vec(),
        b"a/..b/c".to_vec(),
        b"\x01\x7f".to_vec(),
        b"\xe2\x80\xae rtl-override".to_vec(),
    ];
    let entries = names
        .iter()
        .map(|n| {
            Entry::file(
                RelPath::new(n.clone()).unwrap(),
                0o644,
                0,
                ContentHash::of(b""),
            )
        })
        .collect();
    let m = Manifest::from_entries(entries).unwrap();
    let bytes = m.to_canonical_bytes();
    let back = Manifest::parse(&bytes).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.id(), m.id());
}

#[test]
fn from_entries_orders_bytewise_not_by_locale() {
    let m = Manifest::from_entries(vec![
        Entry::dir(rp("b"), 0o755),
        Entry::dir(rp("B"), 0o755),
        Entry::dir(rp("a"), 0o755),
        Entry::dir(rp("a-b"), 0o755),
        Entry::dir(rp("a/b"), 0o755),
        Entry::dir(rp("\u{e9}"), 0o755),
    ])
    .unwrap();
    assert_eq!(
        common::paths(&m),
        vec!["B", "a", "a-b", "a/b", "b", "\u{e9}"]
    );
}

fn reject(bytes: &[u8]) -> Error {
    Manifest::parse(bytes).expect_err("must be rejected")
}

fn record(kind: &str, mode: &str, size: &str, hash: &str, path: &[u8]) -> Vec<u8> {
    let mut v = format!("{kind} {mode} {size} {hash} ").into_bytes();
    v.extend_from_slice(path);
    v.push(0);
    v
}

fn h(bytes: &[u8]) -> String {
    ContentHash::of(bytes).to_hex()
}

#[test]
fn parse_rejects_dotdot_absolute_empty_and_nul() {
    let e = reject(&record("file", "0644", "0", &h(b""), b"../escape"));
    assert!(
        matches!(
            e,
            Error::InvalidPath {
                reason: PathError::DotDotComponent,
                ..
            }
        ),
        "{e}"
    );
    let e = reject(&record("file", "0644", "0", &h(b""), b"a/../b"));
    assert!(
        matches!(
            e,
            Error::InvalidPath {
                reason: PathError::DotDotComponent,
                ..
            }
        ),
        "{e}"
    );
    let e = reject(&record("file", "0644", "0", &h(b""), b"/etc/passwd"));
    assert!(
        matches!(
            e,
            Error::InvalidPath {
                reason: PathError::Absolute,
                ..
            }
        ),
        "{e}"
    );
    let e = reject(&record("file", "0644", "0", &h(b""), b"a//b"));
    assert!(
        matches!(
            e,
            Error::InvalidPath {
                reason: PathError::EmptyComponent,
                ..
            }
        ),
        "{e}"
    );
    let e = reject(&record("file", "0644", "0", &h(b""), b"./a"));
    assert!(
        matches!(
            e,
            Error::InvalidPath {
                reason: PathError::DotComponent,
                ..
            }
        ),
        "{e}"
    );
    // A NUL inside the path terminates the record early: the remainder is garbage.
    let e = reject(&record("file", "0644", "0", &h(b""), b"a\0b"));
    assert!(matches!(e, Error::ManifestParse { .. }), "{e}");
    // An empty path.
    let e = reject(&record("file", "0644", "0", &h(b""), b""));
    assert!(
        matches!(
            e,
            Error::InvalidPath {
                reason: PathError::Empty,
                ..
            }
        ),
        "{e}"
    );
}

#[test]
fn parse_rejects_malformed_fields() {
    let e = reject(&record("blob", "0644", "0", &h(b""), b"a"));
    assert!(matches!(e, Error::ManifestParse { index: 0, .. }), "{e}");
    let e = reject(&record("file", "644", "0", &h(b""), b"a"));
    assert!(matches!(e, Error::ManifestParse { .. }), "{e}");
    let e = reject(&record("file", "0644", "007", &h(b""), b"a"));
    assert!(matches!(e, Error::ManifestParse { .. }), "{e}");
    let e = reject(&record("file", "0644", "0", "abc", b"a"));
    assert!(matches!(e, Error::ManifestParse { .. }), "{e}");
    let upper = h(b"").to_uppercase();
    let e = reject(&record("file", "0644", "0", &upper, b"a"));
    assert!(matches!(e, Error::ManifestParse { .. }), "{e}");
    // Missing trailing NUL.
    let mut r = record("file", "0644", "0", &h(b""), b"a");
    r.pop();
    let e = reject(&r);
    assert!(matches!(e, Error::ManifestParse { .. }), "{e}");
    // Directory with a content hash / size.
    let e = reject(&record("dir", "0755", "0", &h(b""), b"d"));
    assert!(matches!(e, Error::ManifestParse { .. }), "{e}");
    let e = reject(&record("dir", "0755", "1", &"0".repeat(64), b"d"));
    assert!(matches!(e, Error::ManifestParse { .. }), "{e}");
    // File with the "no content" hash.
    let e = reject(&record("file", "0644", "0", &"0".repeat(64), b"f"));
    assert!(matches!(e, Error::ManifestParse { .. }), "{e}");
    // Error index points at the failing record.
    let mut two = record("file", "0644", "0", &h(b""), b"a");
    two.extend(record("file", "0644", "0", &h(b""), b"b/../c"));
    let e = reject(&two);
    assert!(matches!(e, Error::InvalidPath { .. }), "{e}");
    let mut two = record("file", "0644", "0", &h(b""), b"a");
    two.extend(record("nope", "0644", "0", &h(b""), b"b"));
    let e = reject(&two);
    assert!(matches!(e, Error::ManifestParse { index: 1, .. }), "{e}");
}

#[test]
fn parse_rejects_unsorted_and_duplicate() {
    let mut unsorted = record("file", "0644", "0", &h(b""), b"b");
    unsorted.extend(record("file", "0644", "0", &h(b""), b"a"));
    let e = reject(&unsorted);
    assert!(matches!(e, Error::ManifestParse { index: 1, .. }), "{e}");

    let mut dup = record("file", "0644", "0", &h(b""), b"a");
    dup.extend(record("dir", "0755", "0", &"0".repeat(64), b"a"));
    let e = reject(&dup);
    assert!(matches!(e, Error::DuplicatePath { .. }), "{e}");

    let e = Manifest::from_entries(vec![
        Entry::dir(rp("a"), 0o755),
        Entry::file(rp("a"), 0o644, 0, ContentHash::of(b"")),
    ])
    .expect_err("duplicate");
    assert!(matches!(e, Error::DuplicatePath { .. }), "{e}");
}

#[test]
fn parse_of_canonical_bytes_preserves_id() {
    let m = golden_manifest();
    let bytes = m.to_canonical_bytes();
    let parsed = Manifest::parse(&bytes).unwrap();
    assert_eq!(parsed.to_canonical_bytes(), bytes);
    assert_eq!(parsed.id(), SnapshotId::of_manifest_bytes(&bytes));
}

#[test]
fn id_changes_with_any_field() {
    let base = golden_manifest();
    let mut entries = base.entries().to_vec();
    entries[1].mode = 0o600;
    let mode_changed = Manifest::from_entries(entries.clone()).unwrap();
    assert_ne!(mode_changed.id(), base.id());
    entries[1].mode = 0o644;
    entries[1].hash = ContentHash::of(b"HELLO");
    let content_changed = Manifest::from_entries(entries.clone()).unwrap();
    assert_ne!(content_changed.id(), base.id());
    entries[1].hash = ContentHash::of(b"hello");
    entries[1].size = 6;
    let size_changed = Manifest::from_entries(entries.clone()).unwrap();
    assert_ne!(size_changed.id(), base.id());
    entries[1].size = 5;
    entries[1].kind = EntryKind::Symlink;
    let kind_changed = Manifest::from_entries(entries).unwrap();
    assert_ne!(kind_changed.id(), base.id());
}

#[test]
fn symlink_entry_hashes_target_bytes() {
    let e = Entry::symlink(rp("l"), b"/nonexistent/target");
    assert_eq!(e.size, 19);
    assert_eq!(e.hash, ContentHash::of(b"/nonexistent/target"));
    assert_eq!(e.mode, 0o777);
}

#[test]
fn manifest_lookup_and_totals() {
    let m = golden_manifest();
    assert_eq!(m.len(), 10);
    assert!(!m.is_empty());
    assert_eq!(m.get(&rp("setuid")).map(|e| e.mode), Some(0o4755));
    assert!(m.get(&rp("missing")).is_none());
    assert_eq!(m.total_file_bytes(), 5 + 1 + 3 + 2 + 3 + 3);
}
