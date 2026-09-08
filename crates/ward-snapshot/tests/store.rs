//! CAS: atomic blobs, dedupe, manifests, metadata, references, GC.
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
use std::time::{Duration, SystemTime};

use common::{capture, capture_and_store, rp, symlink, tmp, write};
use ward_snapshot::meta::{CaptureMode, Role, SnapshotMeta};
use ward_snapshot::{ContentHash, Error, IngestOptions, Manifest, Store};

#[test]
fn open_creates_layout() {
    let t = tmp();
    let store = Store::open(t.path().join("cas")).unwrap();
    for sub in ["blobs", "manifests", "meta", "refs", "tmp"] {
        assert!(store.root().join(sub).is_dir(), "{sub}");
    }
    // Reopening is fine.
    Store::open(t.path().join("cas")).unwrap();
}

#[test]
fn blob_bytes_roundtrip_dedupe_and_layout() {
    let t = tmp();
    let store = Store::open(t.path()).unwrap();
    let (h, new) = store.put_blob_bytes(b"content").unwrap();
    assert!(new);
    assert_eq!(h, ContentHash::of(b"content"));
    let (h2, new2) = store.put_blob_bytes(b"content").unwrap();
    assert_eq!(h, h2);
    assert!(!new2);
    let p = store.blob_path(&h);
    let hex = h.to_hex();
    assert_eq!(p, t.path().join("blobs").join(&hex[..2]).join(&hex));
    assert!(store.has_blob(&h));
    assert_eq!(store.read_blob(&h).unwrap(), b"content");
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o444
    );
    // tmp/ is clean after a successful write.
    assert_eq!(std::fs::read_dir(t.path().join("tmp")).unwrap().count(), 0);
}

#[test]
fn missing_blob_is_typed_error() {
    let t = tmp();
    let store = Store::open(t.path()).unwrap();
    let e = store.read_blob(&ContentHash::of(b"nope")).unwrap_err();
    assert!(matches!(e, Error::MissingBlob(_)), "{e}");
}

#[test]
fn put_blob_from_path_with_and_without_reflink() {
    let t = tmp();
    let store = Store::open(t.path().join("cas")).unwrap();
    let src = write(t.path(), "src", b"payload");
    for use_reflink in [true, false] {
        let s = Store::open(t.path().join(format!("cas-{use_reflink}"))).unwrap();
        let opts = IngestOptions {
            use_reflink,
            verify: false,
            ..IngestOptions::default()
        };
        let (h, written, _reflinked) = s.put_blob_from_path(&src, None, opts).unwrap();
        assert!(written);
        assert_eq!(h, ContentHash::of(b"payload"));
        assert_eq!(s.read_blob(&h).unwrap(), b"payload");
    }
    // With an expected hash that is wrong and verify on: mismatch is caught.
    let opts = IngestOptions {
        use_reflink: true,
        verify: true,
        ..IngestOptions::default()
    };
    let e = store
        .put_blob_from_path(&src, Some(ContentHash::of(b"other")), opts)
        .unwrap_err();
    assert!(matches!(e, Error::HashMismatch { .. }), "{e}");
    assert!(!store.has_blob(&ContentHash::of(b"other")));
    assert_eq!(
        std::fs::read_dir(store.root().join("tmp")).unwrap().count(),
        0
    );
}

#[test]
fn ingest_stores_every_file_and_symlink_target_and_dedupes() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "a", b"same");
    write(&work, "b", b"same");
    write(&work, "c/d", b"other");
    symlink(&work, "l", b"/outside");
    let store = Store::open(t.path().join("cas")).unwrap();
    let m = capture(&work);
    let r = store.ingest(&work, &m, IngestOptions::default()).unwrap();
    assert_eq!(r.files, 3);
    assert_eq!(r.blobs_written, 2, "{r:?}");
    assert_eq!(r.blobs_existing, 0);
    assert_eq!(r.bytes_written, 4 + 5);
    assert_eq!(r.reflinked + r.copied, 2);
    assert!(store.has_blob(&ContentHash::of(b"same")));
    assert!(store.has_blob(&ContentHash::of(b"other")));
    assert_eq!(
        store.read_blob(&ContentHash::of(b"/outside")).unwrap(),
        b"/outside"
    );

    // Second ingest writes nothing.
    let r2 = store.ingest(&work, &m, IngestOptions::default()).unwrap();
    assert_eq!(r2.blobs_written, 0);
    assert_eq!(r2.blobs_existing, 2);

    // No-reflink path gives the same store content.
    let store2 = Store::open(t.path().join("cas2")).unwrap();
    let r3 = store2
        .ingest(
            &work,
            &m,
            IngestOptions {
                use_reflink: false,
                verify: true,
                ..IngestOptions::default()
            },
        )
        .unwrap();
    assert_eq!(r3.blobs_written, 2);
    assert_eq!(r3.reflinked, 0);
    assert_eq!(r3.copied, 2);
}

#[test]
fn ingest_with_verify_detects_tree_changed_after_capture() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "f", b"before");
    let m = capture(&work);
    write(&work, "f", b"after!");
    let store = Store::open(t.path().join("cas")).unwrap();
    let e = store
        .ingest(
            &work,
            &m,
            IngestOptions {
                use_reflink: true,
                verify: true,
                ..IngestOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(e, Error::HashMismatch { .. }), "{e}");
    // Symlink targets are always verified.
    symlink(&work, "l", b"one");
    let m = capture(&work);
    std::fs::remove_file(work.join("l")).unwrap();
    symlink(&work, "l", b"two");
    let e = store
        .ingest(&work, &m, IngestOptions::default())
        .unwrap_err();
    assert!(matches!(e, Error::HashMismatch { .. }), "{e}");
}

#[test]
fn manifest_put_get_and_corruption_detected() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "f", b"x");
    let store = Store::open(t.path().join("cas")).unwrap();
    let m = capture(&work);
    let id = store.put_manifest(&m).unwrap();
    assert_eq!(id, m.id());
    assert!(store.has_manifest(&id));
    assert_eq!(store.put_manifest(&m).unwrap(), id);
    assert_eq!(store.get_manifest(&id).unwrap(), m);
    assert_eq!(
        store.manifest_path(&id),
        t.path().join("cas/manifests").join(id.to_hex())
    );

    // Missing.
    let bogus = ward_snapshot::SnapshotId::of_manifest_bytes(b"bogus");
    assert!(matches!(
        store.get_manifest(&bogus),
        Err(Error::MissingManifest(_))
    ));

    // Tamper with stored bytes: id mismatch.
    let p = store.manifest_path(&id);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[0] = b'd';
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&p, &bytes).unwrap();
    let e = store.get_manifest(&id).unwrap_err();
    assert!(matches!(e, Error::IdMismatch { .. }), "{e}");
}

#[test]
fn meta_roundtrip() {
    let t = tmp();
    let store = Store::open(t.path()).unwrap();
    let id = ward_snapshot::SnapshotId::of_manifest_bytes(b"");
    let meta = SnapshotMeta::new(
        id,
        "proj_1",
        Role::Entry,
        "sess_1",
        "wardd 0.1.0",
        CaptureMode::FrozenCopy,
    )
    .with_git_context(ward_snapshot::GitContext {
        head: Some("abc".into()),
        branch: Some("main".into()),
        dirty: Some(true),
    });
    assert!(matches!(
        store.get_meta(&id),
        Err(Error::MissingManifest(_))
    ));
    store.put_meta(&meta).unwrap();
    let back = store.get_meta(&id).unwrap();
    assert_eq!(back, meta);
    assert!(back.created.ends_with('Z'));
    assert_eq!(back.created.len(), 24);
    // Role updates overwrite.
    let accepted = SnapshotMeta {
        role: Role::Accepted,
        ..meta
    };
    store.put_meta(&accepted).unwrap();
    assert_eq!(store.get_meta(&id).unwrap().role, Role::Accepted);
    let json = std::fs::read_to_string(t.path().join("meta").join(format!("{}.json", id.to_hex())))
        .unwrap();
    assert!(json.contains("\"capture_mode\": \"frozen-copy\""));
    assert!(json.contains("\"role\": \"accepted\""));
}

#[test]
fn references_are_per_session_and_validated() {
    let t = tmp();
    let store = Store::open(t.path()).unwrap();
    let a = ward_snapshot::SnapshotId::of_manifest_bytes(b"a");
    let b = ward_snapshot::SnapshotId::of_manifest_bytes(b"b");
    store.add_reference("sess_1", &a).unwrap();
    store.add_reference("sess_1", &b).unwrap();
    store.add_reference("sess_1", &a).unwrap();
    store.add_reference("sess_2", &b).unwrap();
    let refs = store.references().unwrap();
    assert_eq!(refs["sess_1"].len(), 2);
    assert_eq!(refs["sess_2"].len(), 1);
    store.remove_session("sess_1").unwrap();
    store.remove_session("sess_1").unwrap();
    assert!(!store.references().unwrap().contains_key("sess_1"));
    for bad in ["", "../x", ".hidden", "a/b", "with space", "nul\0"] {
        assert!(
            matches!(store.add_reference(bad, &a), Err(Error::InvalidSession(_))),
            "{bad:?}"
        );
    }
}

fn age(path: &std::path::Path, secs: u64) {
    let old = SystemTime::now() - Duration::from_secs(secs);
    let f = std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap_or_else(|_| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
            std::fs::File::options().write(true).open(path).unwrap()
        });
    f.set_modified(old).unwrap();
}

#[test]
fn gc_keeps_referenced_content_and_removes_old_unreferenced() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "keep", b"keep-me");
    write(&work, "shared", b"shared");
    let (store, m_keep) = capture_and_store(&work, &t.path().join("cas"));
    let id_keep = m_keep.id();

    // Second snapshot with an extra file; then it becomes unreferenced.
    write(&work, "drop", b"drop-me");
    let m_drop = capture(&work);
    let id_drop = store.put_manifest(&m_drop).unwrap();
    store
        .ingest(&work, &m_drop, IngestOptions::default())
        .unwrap();
    store.add_reference("sess_1", &id_keep).unwrap();

    // Age everything so retention does not protect it.
    for e in walkdir::WalkDir::new(store.root()).into_iter().flatten() {
        if e.file_type().is_file() {
            age(e.path(), 100 * 86_400);
        }
    }

    // Retention longer than the age keeps everything.
    let r = store.gc(Duration::from_secs(365 * 86_400)).unwrap();
    assert_eq!(r.manifests_removed, 0);
    assert_eq!(r.blobs_removed, 0);

    let r = store.gc(Duration::from_secs(30 * 86_400)).unwrap();
    assert_eq!(r.manifests_removed, 1);
    assert_eq!(r.manifests_kept, 1);
    assert_eq!(r.blobs_removed, 1, "{r:?}");
    assert_eq!(r.bytes_freed, 7);
    assert!(store.has_manifest(&id_keep));
    assert!(!store.has_manifest(&id_drop));
    assert!(store.has_blob(&ContentHash::of(b"keep-me")));
    assert!(store.has_blob(&ContentHash::of(b"shared")));
    assert!(!store.has_blob(&ContentHash::of(b"drop-me")));

    // Materialising the kept snapshot still works after gc.
    let dest = t.path().join("out");
    ward_snapshot::materialise(&store, &id_keep, &dest).unwrap();
    assert_eq!(std::fs::read(dest.join("keep")).unwrap(), b"keep-me");

    // Dropping the last reference and running gc again removes the rest.
    store.remove_session("sess_1").unwrap();
    let r = store.gc(Duration::ZERO).unwrap();
    assert_eq!(r.manifests_removed, 1);
    assert_eq!(r.blobs_removed, 2);
}

#[test]
fn gc_retention_protects_young_objects() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "f", b"young");
    let (store, m) = capture_and_store(&work, &t.path().join("cas"));
    let r = store.gc(Duration::from_secs(3600)).unwrap();
    assert_eq!(r.manifests_removed, 0);
    assert_eq!(r.blobs_removed, 0);
    assert!(store.has_manifest(&m.id()));
}

#[test]
fn blob_disk_usage_reports() {
    let t = tmp();
    let store = Store::open(t.path()).unwrap();
    store.put_blob_bytes(&[1u8; 10_000]).unwrap();
    let (allocated, logical) = store.blob_disk_usage().unwrap();
    assert_eq!(logical, 10_000);
    assert!(allocated >= 4096);
}

#[test]
fn stored_manifest_bytes_are_canonical() {
    let t = tmp();
    let store = Store::open(t.path()).unwrap();
    let m = Manifest::from_entries(vec![
        ward_snapshot::Entry::file(rp("z"), 0o644, 1, ContentHash::of(b"z")),
        ward_snapshot::Entry::dir(rp("a"), 0o755),
    ])
    .unwrap();
    let id = store.put_manifest(&m).unwrap();
    let bytes = std::fs::read(store.manifest_path(&id)).unwrap();
    assert_eq!(bytes, m.to_canonical_bytes());
    assert!(bytes.starts_with(b"dir 0755 0 "));
}

#[test]
fn deferred_fsync_ingest_then_sync_and_verify_blob() {
    let t = tmp();
    let work = t.path().join("work");
    write(&work, "a", b"alpha");
    write(&work, "b", b"beta");
    let store = Store::open(t.path().join("cas")).unwrap();
    let m = capture(&work);
    let r = store
        .ingest(
            &work,
            &m,
            IngestOptions {
                use_reflink: false,
                verify: false,
                fsync_each: false,
            },
        )
        .unwrap();
    assert_eq!(r.blobs_written, 2);
    store.sync().unwrap();
    store.verify_blob(&ContentHash::of(b"alpha")).unwrap();
    store.verify_blob(&ContentHash::of(b"beta")).unwrap();
    assert!(matches!(
        store.verify_blob(&ContentHash::of(b"absent")),
        Err(Error::MissingBlob(_))
    ));
    // Corrupt a blob in place: verify_blob catches it.
    let p = store.blob_path(&ContentHash::of(b"alpha"));
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&p, b"ALPHA").unwrap();
    assert!(matches!(
        store.verify_blob(&ContentHash::of(b"alpha")),
        Err(Error::HashMismatch { .. })
    ));
}
