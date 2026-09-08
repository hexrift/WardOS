//! Materialisation safety: fresh dest, symlinks as symlinks, no traversal, mode masking.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::cast_possible_truncation
)]

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{capture, capture_and_store, chmod, mkdir, rp, symlink, tmp, write, write_bytes};
use ward_snapshot::{
    ContentHash, Entry, Error, Manifest, Store, materialise, materialise_manifest,
};

#[test]
fn roundtrip_capture_store_materialise_capture_gives_same_id() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "a.txt", b"hello");
    write(&work, "deep/er/file", b"x");
    write_bytes(&work, b"weird \xff\nname", b"bytes");
    mkdir(&work, "empty");
    symlink(&work, "outside", b"/etc/passwd");
    symlink(&work, "rel", b"a.txt");
    let e = write(&work, "exec", b"#!/bin/sh\n");
    chmod(&e, 0o755);
    let d = mkdir(&work, "private");
    write(&work, "private/inner", b"i");
    chmod(&d, 0o700);

    let (store, m) = capture_and_store(&work, &t.path().join("cas"));
    let dest = t.path().join("out");
    let report = materialise(&store, &m.id(), &dest).unwrap();
    assert_eq!(report.files, 5);
    assert_eq!(report.symlinks, 2);
    assert!(report.skipped_unsupported.is_empty());

    let again = capture(&dest);
    assert_eq!(again.id(), m.id());
    assert_eq!(
        std::fs::read_link(dest.join("outside"))
            .unwrap()
            .as_os_str(),
        "/etc/passwd"
    );
    assert!(dest.join("empty").is_dir());
    assert_eq!(
        std::fs::metadata(dest.join("exec"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[test]
fn dest_must_be_fresh() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "f", b"x");
    let (store, m) = capture_and_store(&work, &t.path().join("cas"));

    // Non-empty directory.
    let busy = t.path().join("busy");
    write(&busy, "existing", b"");
    let e = materialise(&store, &m.id(), &busy).unwrap_err();
    assert!(matches!(e, Error::DestinationNotEmpty(_)), "{e}");

    // A file.
    let f = write(t.path(), "afile", b"");
    let e = materialise(&store, &m.id(), &f).unwrap_err();
    assert!(matches!(e, Error::DestinationNotEmpty(_)), "{e}");

    // A symlink to an empty directory is refused too (never write through a link).
    let empty = mkdir(t.path(), "empty");
    let link = symlink(
        t.path(),
        "link-to-empty",
        empty.as_os_str().as_encoded_bytes(),
    );
    let e = materialise(&store, &m.id(), &link).unwrap_err();
    assert!(matches!(e, Error::DestinationNotEmpty(_)), "{e}");
    assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0);

    // Missing directory is created; an existing empty one is used.
    materialise(&store, &m.id(), &t.path().join("new/nested")).unwrap();
    materialise(&store, &m.id(), &empty).unwrap();
    assert!(empty.join("f").is_file());
}

#[test]
fn dotdot_is_rejected_at_parse_and_cannot_reach_materialise() {
    let t = tmp();
    let store = Store::open(t.path().join("cas")).unwrap();
    let (h, _) = store.put_blob_bytes(b"evil").unwrap();
    let mut bytes = format!("file 0644 4 {} ", h.to_hex()).into_bytes();
    bytes.extend_from_slice(b"../../escape\0");
    let e = Manifest::parse(&bytes).unwrap_err();
    assert!(matches!(e, Error::InvalidPath { .. }), "{e}");
    // The manifest file itself is stored canonically; feed a corrupted one via the store.
    let id = ward_snapshot::SnapshotId::of_manifest_bytes(&bytes);
    std::fs::write(store.manifest_path(&id), &bytes).unwrap();
    let e = materialise(&store, &id, &t.path().join("out")).unwrap_err();
    assert!(matches!(e, Error::InvalidPath { .. }), "{e}");
    assert!(!t.path().join("escape").exists());
}

#[test]
fn refuses_entries_through_a_symlink_component() {
    let t = tmp();
    let store = Store::open(t.path().join("cas")).unwrap();
    let escape = t.path().join("escape-target");
    std::fs::create_dir_all(&escape).unwrap();
    let (blob, _) = store.put_blob_bytes(b"payload").unwrap();
    let (target, _) = store
        .put_blob_bytes(escape.as_os_str().as_encoded_bytes())
        .unwrap();
    let m = Manifest::from_entries(vec![
        Entry {
            kind: ward_snapshot::EntryKind::Symlink,
            mode: 0o777,
            size: escape.as_os_str().len() as u64,
            hash: target,
            path: rp("a"),
        },
        Entry::file(rp("a/b"), 0o644, 7, blob),
    ])
    .unwrap();
    let dest = t.path().join("out");
    let e = materialise_manifest(&store, &m, &dest).unwrap_err();
    assert!(matches!(e, Error::PathThroughSymlink { .. }), "{e}");
    assert!(!escape.join("b").exists(), "wrote through symlink");
    assert_eq!(std::fs::read_dir(&escape).unwrap().count(), 0);
}

#[test]
fn refuses_file_whose_parent_is_a_symlink_to_dir_via_deeper_path() {
    let t = tmp();
    let store = Store::open(t.path().join("cas")).unwrap();
    let (blob, _) = store.put_blob_bytes(b"x").unwrap();
    let (target, _) = store.put_blob_bytes(b"/tmp").unwrap();
    let m = Manifest::from_entries(vec![
        Entry::dir(rp("d"), 0o755),
        Entry {
            kind: ward_snapshot::EntryKind::Symlink,
            mode: 0o777,
            size: 4,
            hash: target,
            path: rp("d/link"),
        },
        Entry::file(rp("d/link/deep/file"), 0o644, 1, blob),
    ])
    .unwrap();
    let e = materialise_manifest(&store, &m, &t.path().join("out")).unwrap_err();
    assert!(matches!(e, Error::PathThroughSymlink { .. }), "{e}");
    assert!(!std::path::Path::new("/tmp/deep").exists());
}

#[test]
fn symlinks_are_created_as_symlinks_and_never_followed() {
    let t = tmp();
    let work = t.path().join("work");
    let secret = write(t.path(), "secret", b"do not copy");
    symlink(&work, "s", secret.as_os_str().as_encoded_bytes());
    symlink(&work, "dangling", b"/does/not/exist");
    symlink(&work, "loop", b"loop");
    let (store, m) = capture_and_store(&work, &t.path().join("cas"));
    let dest = t.path().join("out");
    let r = materialise(&store, &m.id(), &dest).unwrap();
    assert_eq!(r.symlinks, 3);
    assert_eq!(r.files, 0);
    for name in ["s", "dangling", "loop"] {
        assert!(
            std::fs::symlink_metadata(dest.join(name))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    assert_eq!(
        std::fs::read_link(dest.join("dangling"))
            .unwrap()
            .as_os_str(),
        "/does/not/exist"
    );
    // The secret was never copied into the store.
    assert!(!store.has_blob(&ContentHash::of(b"do not copy")));
}

#[test]
fn special_mode_bits_are_masked() {
    let t = tmp();
    let work = t.path().join("work");
    let s = write(&work, "suid", b"");
    chmod(&s, 0o4755);
    let g = write(&work, "sgid", b"");
    chmod(&g, 0o2755);
    let d = mkdir(&work, "sticky");
    chmod(&d, 0o1777);
    let (store, m) = capture_and_store(&work, &t.path().join("cas"));
    assert_eq!(m.get(&rp("suid")).unwrap().mode, 0o4755);
    let dest = t.path().join("out");
    materialise(&store, &m.id(), &dest).unwrap();
    let mode = |n: &str| {
        std::fs::metadata(dest.join(n))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode("suid"), 0o755);
    assert_eq!(mode("sgid"), 0o755);
    assert_eq!(mode("sticky"), 0o777);
}

#[test]
fn read_only_directories_do_not_block_their_children() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "ro/inner/file", b"x");
    chmod(&work.join("ro/inner"), 0o500);
    chmod(&work.join("ro"), 0o500);
    let (store, m) = capture_and_store(&work, &t.path().join("cas"));
    let dest = t.path().join("out");
    materialise(&store, &m.id(), &dest).unwrap();
    assert_eq!(
        std::fs::metadata(dest.join("ro"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o500
    );
    assert!(dest.join("ro/inner/file").is_file());
    // Cleanup so the tempdir can be removed.
    chmod(&dest.join("ro"), 0o755);
    chmod(&dest.join("ro/inner"), 0o755);
    chmod(&work.join("ro"), 0o755);
    chmod(&work.join("ro/inner"), 0o755);
}

#[test]
fn unsupported_entries_are_skipped_and_reported() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "f", b"x");
    if !common::mkfifo(&work.join("fifo")) {
        eprintln!("mkfifo unavailable; skipping");
        return;
    }
    let (store, m) = capture_and_store(&work, &t.path().join("cas"));
    let dest = t.path().join("out");
    let r = materialise(&store, &m.id(), &dest).unwrap();
    assert_eq!(r.skipped_unsupported, vec![rp("fifo")]);
    assert!(!dest.join("fifo").exists());
    assert!(dest.join("f").is_file());
}

#[test]
fn missing_blob_is_an_error() {
    let t = tmp();
    let store = Store::open(t.path().join("cas")).unwrap();
    let m = Manifest::from_entries(vec![Entry::file(
        rp("f"),
        0o644,
        1,
        ContentHash::of(b"absent"),
    )])
    .unwrap();
    let e = materialise_manifest(&store, &m, &t.path().join("out")).unwrap_err();
    assert!(matches!(e, Error::MissingBlob(_)), "{e}");
}

#[test]
fn implicit_parents_are_created_for_files_without_dir_entries() {
    let t = tmp();
    let store = Store::open(t.path().join("cas")).unwrap();
    let (h, _) = store.put_blob_bytes(b"x").unwrap();
    let m = Manifest::from_entries(vec![Entry::file(rp("a/b/c"), 0o600, 1, h)]).unwrap();
    let dest = t.path().join("out");
    let r = materialise_manifest(&store, &m, &dest).unwrap();
    assert_eq!(r.dirs, 2);
    assert_eq!(std::fs::read(dest.join("a/b/c")).unwrap(), b"x");
    assert_eq!(
        std::fs::metadata(dest.join("a/b/c"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn materialised_tree_is_independent_of_the_store() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "f", b"original");
    let (store, m) = capture_and_store(&work, &t.path().join("cas"));
    let dest = t.path().join("out");
    materialise(&store, &m.id(), &dest).unwrap();
    // Writing to the materialised copy (a verifier scratch tree) must not alter the blob.
    chmod(&dest.join("f"), 0o644);
    std::fs::write(dest.join("f"), b"modified").unwrap();
    assert_eq!(
        store.read_blob(&ContentHash::of(b"original")).unwrap(),
        b"original"
    );
}
