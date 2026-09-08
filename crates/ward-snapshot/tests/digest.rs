//! Digest-only capture (ADR-0019 decision 1): the id a worktree would get,
//! computed without writing to the CAS, and cheap the second time.
#![allow(clippy::unwrap_used, clippy::missing_panics_doc)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::tempdir;
use ward_snapshot::{
    CaptureOptions, CaptureStats, HashCache, SnapshotRole, SnapshotStore, digest_manifest,
    digest_worktree,
};

/// A small worktree: nested files, a symlink, an executable, an ignored file
/// and a `.git` directory.
fn populate(root: &Path) {
    fs::create_dir_all(root.join("src/deep")).unwrap();
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join("README.md"), b"# demo\n").unwrap();
    fs::write(root.join("src/lib.rs"), b"pub fn f() {}\n").unwrap();
    fs::write(root.join("src/deep/x.rs"), b"// x\n").unwrap();
    fs::write(root.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join(".gitignore"), b"target/\n").unwrap();
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join("target/out"), b"ignored").unwrap();
    fs::write(root.join("run.sh"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(root.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("src/lib.rs", root.join("link")).unwrap();
}

fn blob_count(cas: &Path) -> usize {
    let mut n = 0;
    for shard in fs::read_dir(cas.join("blobs")).unwrap() {
        n += fs::read_dir(shard.unwrap().path()).unwrap().count();
    }
    n
}

#[test]
fn the_digest_is_the_id_a_capture_would_store_and_writes_nothing() {
    let work = tempdir().unwrap();
    let cas = tempdir().unwrap();
    populate(work.path());
    let store = SnapshotStore::open(cas.path()).unwrap();
    let opts = CaptureOptions::default();

    let mut cache = HashCache::new();
    let digested = digest_worktree(work.path(), opts, &mut cache).unwrap();
    assert_eq!(blob_count(cas.path()), 0, "a digest stores no blob");
    assert!(
        fs::read_dir(cas.path().join("manifests"))
            .unwrap()
            .next()
            .is_none(),
        "nor a manifest"
    );

    let stored = store
        .store_snapshot(work.path(), SnapshotRole::Candidate, opts)
        .unwrap();
    assert_eq!(digested, stored, "the same walk, the same Merkle root");
    assert!(blob_count(cas.path()) > 0, "the capture did store");

    // The digest sees a change exactly as a capture would, and agrees again.
    fs::write(work.path().join("src/lib.rs"), b"pub fn f() { 1; }\n").unwrap();
    let after = digest_worktree(work.path(), opts, &mut cache).unwrap();
    assert_ne!(after, stored);
    let stored_after = store
        .store_snapshot(work.path(), SnapshotRole::Candidate, opts)
        .unwrap();
    assert_eq!(after, stored_after);

    // The manifest behind the id is the stored one, entry for entry.
    let mut stats = CaptureStats::default();
    let manifest = digest_manifest(work.path(), opts, &mut cache, &mut stats).unwrap();
    assert_eq!(manifest.id(), stored_after);
    assert_eq!(manifest, store.manifest(stored_after).unwrap());
    assert!(
        manifest.get(b"target/out").is_none(),
        "ignore rules apply to the digest too"
    );
    assert!(manifest.get(b".git/HEAD").is_some());
    assert!(manifest.get(b"link").is_some(), "symlinks are digested too");
}

#[test]
fn the_hash_cache_makes_the_second_digest_cheap() {
    let work = tempdir().unwrap();
    let cas = tempdir().unwrap();
    populate(work.path());
    let opts = CaptureOptions {
        incremental: true,
        ..CaptureOptions::default()
    };
    let mut cache = HashCache::new();

    let mut cold = CaptureStats::default();
    let first = digest_manifest(work.path(), opts, &mut cache, &mut cold).unwrap();
    assert_eq!(
        cold.files_total, 6,
        "README, lib, x, HEAD, .gitignore, run.sh"
    );
    assert_eq!(cold.files_hashed, 6);
    assert_eq!(cold.files_cached, 0);
    assert_eq!(cache.len(), 6);

    let mut warm = CaptureStats::default();
    let second = digest_manifest(work.path(), opts, &mut cache, &mut warm).unwrap();
    assert_eq!(second, first);
    assert_eq!(warm.files_hashed, 0, "nothing re-read");
    assert_eq!(warm.files_cached, 6);
    assert_eq!(warm.bytes_hashed, 0);

    // One edit: one file re-hashed, the rest served from the cache.
    fs::write(work.path().join("README.md"), b"# demo, edited\n").unwrap();
    let mut edited = CaptureStats::default();
    let third = digest_manifest(work.path(), opts, &mut cache, &mut edited).unwrap();
    assert_ne!(third.id(), first.id());
    assert_eq!(edited.files_hashed, 1);
    assert_eq!(edited.files_cached, 5);

    // A capture into the CAS reuses the cache the digest warmed, and still
    // stores every blob a cold capture would.
    let store = SnapshotStore::open(cas.path()).unwrap();
    let mut stats = CaptureStats::default();
    let meta = store
        .capture_with_cache(
            work.path(),
            SnapshotRole::Candidate,
            opts,
            &mut cache,
            &mut stats,
        )
        .unwrap();
    assert_eq!(meta.id, third.id());
    assert_eq!(stats.files_cached, 6, "the cache is shared both ways");
    assert_eq!(stats.files_hashed, 0);
    for entry in third.entries().iter().filter(|e| e.content.is_some()) {
        let rel = Path::new(std::str::from_utf8(&entry.path).unwrap());
        assert!(store.cat(meta.id, rel).is_ok(), "{rel:?} is stored");
    }
}
