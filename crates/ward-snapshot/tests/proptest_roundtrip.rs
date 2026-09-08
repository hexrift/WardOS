//! Property tests: generated trees survive capture → store → materialise → capture.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::cast_possible_truncation
)]

mod common;

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use proptest::prelude::*;
use ward_snapshot::{Capture, CapturePolicy, IngestOptions, Manifest, Store, diff, materialise};

#[derive(Debug, Clone)]
enum Node {
    File { mode: u32, content: Vec<u8> },
    Dir,
    Symlink { target: Vec<u8> },
}

#[derive(Debug, Clone)]
struct Spec {
    path: Vec<Vec<u8>>,
    node: Node,
}

fn name() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        4 => "[a-z]{1,6}".prop_map(String::into_bytes),
        1 => prop::collection::vec(any::<u8>(), 1..8),
        1 => Just(b"sp ace".to_vec()),
        1 => Just(b"new\nline".to_vec()),
        1 => Just("\u{e9}".as_bytes().to_vec()),
        1 => Just("e\u{301}".as_bytes().to_vec()),
        1 => Just(b"..hidden".to_vec()),
        1 => Just(vec![b'x'; 200]),
    ]
    .prop_filter("valid component", |n| {
        !n.contains(&b'/') && !n.contains(&0) && n != b"." && n != b".."
    })
}

fn node() -> impl Strategy<Value = Node> {
    prop_oneof![
        5 => (
            prop::sample::select(vec![0o644u32, 0o755, 0o600, 0o400, 0o4755, 0o2755]),
            prop::collection::vec(any::<u8>(), 0..300),
        )
            .prop_map(|(mode, content)| Node::File { mode, content }),
        2 => Just(Node::Dir),
        2 => prop_oneof![
            prop::collection::vec(any::<u8>(), 1..40),
            Just(b"/etc/passwd".to_vec()),
            Just(b"../../outside".to_vec()),
            Just(b"loop".to_vec()),
        ]
        .prop_filter("target without NUL", |t| !t.contains(&0))
        .prop_map(|target| Node::Symlink { target }),
    ]
}

fn spec() -> impl Strategy<Value = Spec> {
    (prop::collection::vec(name(), 1..4), node()).prop_map(|(path, node)| Spec { path, node })
}

/// Build the tree on disk. Entries that would have to be created through a symlink or
/// under a regular file are skipped; the tree that ends up on disk is what is tested.
fn build(root: &Path, specs: &[Spec]) {
    let mut symlinks: HashSet<Vec<u8>> = HashSet::new();
    for s in specs {
        let mut rel = Vec::new();
        let mut through_link = false;
        for (i, c) in s.path.iter().enumerate() {
            if i > 0 {
                rel.push(b'/');
            }
            rel.extend_from_slice(c);
            if i + 1 < s.path.len() && symlinks.contains(&rel) {
                through_link = true;
            }
        }
        if through_link {
            continue;
        }
        let abs = root.join(OsStr::from_bytes(&rel));
        if std::fs::symlink_metadata(&abs).is_ok() {
            continue;
        }
        if let Some(parent) = abs.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            continue;
        }
        match &s.node {
            Node::File { mode, content } => {
                if std::fs::write(&abs, content).is_ok() {
                    let _ = std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(*mode));
                }
            }
            Node::Dir => {
                let _ = std::fs::create_dir(&abs);
            }
            Node::Symlink { target } => {
                if std::os::unix::fs::symlink(OsStr::from_bytes(target), &abs).is_ok() {
                    symlinks.insert(rel);
                }
            }
        }
    }
}

fn relax_permissions(root: &Path) {
    for e in walkdir::WalkDir::new(root).into_iter().flatten() {
        if e.file_type().is_dir() {
            let _ = std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o755));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 40, .. ProptestConfig::default() })]

    #[test]
    fn roundtrip_preserves_snapshot_id(specs in prop::collection::vec(spec(), 0..25)) {
        let t = common::tmp();
        let work = t.path().join("work");
        std::fs::create_dir(&work).unwrap();
        build(&work, &specs);

        let policy = CapturePolicy { include_ignored: true, ..CapturePolicy::default() };
        let m1 = Capture::run(&work, &policy, None).unwrap();

        // Canonical bytes parse back to the same manifest.
        let bytes = m1.to_canonical_bytes();
        let parsed = Manifest::parse(&bytes).unwrap();
        prop_assert_eq!(&parsed, &m1);

        let store = Store::open(t.path().join("cas")).unwrap();
        let id = store.put_manifest(&m1).unwrap();
        store.ingest(&work, &m1, IngestOptions::default()).unwrap();

        let dest = t.path().join("out");
        materialise(&store, &id, &dest).unwrap();
        let m2 = Capture::run(&dest, &policy, None).unwrap();

        // Special bits are masked on materialisation, so compare after masking.
        let masked = Manifest::from_entries(
            m1.entries().iter().map(|e| {
                let mut e = e.clone();
                if e.kind != ward_snapshot::EntryKind::Symlink { e.mode &= 0o777; }
                e
            }).collect(),
        ).unwrap();
        let d = diff(&masked, &m2);
        prop_assert!(d.is_empty(), "diff not empty: {d:#?}");
        prop_assert_eq!(m2.id(), masked.id());

        // And a second materialisation from the same store is identical again.
        let dest2 = t.path().join("out2");
        materialise(&store, &id, &dest2).unwrap();
        prop_assert_eq!(Capture::run(&dest2, &policy, None).unwrap().id(), masked.id());

        relax_permissions(&work);
        relax_permissions(&dest);
        relax_permissions(&dest2);
    }

    #[test]
    fn canonical_encoding_is_injective_and_stable(specs in prop::collection::vec(spec(), 0..25)) {
        let t = common::tmp();
        let work = t.path().join("work");
        std::fs::create_dir(&work).unwrap();
        build(&work, &specs);
        let policy = CapturePolicy { include_ignored: true, ..CapturePolicy::default() };
        let a = Capture::run(&work, &policy, None).unwrap();
        let b = Capture::run(&work, &policy, None).unwrap();
        prop_assert_eq!(a.to_canonical_bytes(), b.to_canonical_bytes());
        prop_assert_eq!(a.id(), b.id());
        // Every path is unique and sorted.
        let paths: Vec<&[u8]> = a.entries().iter().map(|e| e.path.as_bytes()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        sorted.dedup();
        prop_assert_eq!(paths, sorted);
        relax_permissions(&work);
    }
}
