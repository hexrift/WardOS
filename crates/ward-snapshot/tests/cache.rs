//! TreeCache: hits, detection guarantees, and the documented limitation.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::cast_possible_truncation
)]

mod common;

use std::time::{Duration, SystemTime};

use common::{rp, tmp, write};
use ward_snapshot::cache::FileIdentity;
use ward_snapshot::{Capture, CapturePolicy, ContentHash, TreeCache};

fn run(
    root: &std::path::Path,
    cache: &mut TreeCache,
) -> (ward_snapshot::Manifest, ward_snapshot::CaptureStats) {
    Capture::run_with_stats(root, &CapturePolicy::default(), Some(cache)).unwrap()
}

#[test]
fn second_capture_hits_cache_and_gives_same_id() {
    let t = tmp();
    write(t.path(), "a", b"aaa");
    write(t.path(), "d/b", b"bbb");
    let mut cache = TreeCache::new();
    let (m1, s1) = run(t.path(), &mut cache);
    assert_eq!(s1.cache_hits, 0);
    assert_eq!(s1.cache_misses, 2);
    assert_eq!(cache.len(), 2);
    let (m2, s2) = run(t.path(), &mut cache);
    assert_eq!(s2.cache_hits, 2);
    assert_eq!(s2.cache_misses, 0);
    assert_eq!(s2.bytes_hashed, 0);
    assert_eq!(m1.id(), m2.id());
    // Cached capture equals uncached capture.
    assert_eq!(
        m2,
        Capture::run(t.path(), &CapturePolicy::default(), None).unwrap()
    );
}

#[test]
fn size_change_is_detected() {
    let t = tmp();
    write(t.path(), "a", b"short");
    let mut cache = TreeCache::new();
    let (m1, _) = run(t.path(), &mut cache);
    write(t.path(), "a", b"longer!!");
    let (m2, s2) = run(t.path(), &mut cache);
    assert_eq!(s2.cache_misses, 1);
    assert_ne!(m1.id(), m2.id());
    assert_eq!(m2.get(&rp("a")).unwrap().hash, ContentHash::of(b"longer!!"));
}

#[test]
fn same_size_edit_with_newer_mtime_is_detected() {
    let t = tmp();
    let p = write(t.path(), "a", b"AAAA");
    let mut cache = TreeCache::new();
    let (m1, _) = run(t.path(), &mut cache);
    std::thread::sleep(Duration::from_millis(15));
    std::fs::write(&p, b"BBBB").unwrap();
    let (m2, s2) = run(t.path(), &mut cache);
    assert_eq!(s2.cache_misses, 1, "{s2:?}");
    assert_ne!(m1.id(), m2.id());
    assert_eq!(m2.get(&rp("a")).unwrap().hash, ContentHash::of(b"BBBB"));
}

#[test]
fn same_size_edit_with_forged_mtime_is_detected_via_ctime() {
    // An agent can restore mtime with utimensat(2); it cannot restore ctime.
    let t = tmp();
    let p = write(t.path(), "a", b"AAAA");
    let mut cache = TreeCache::new();
    let (m1, _) = run(t.path(), &mut cache);
    let before = std::fs::metadata(&p).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(15));
    std::fs::write(&p, b"BBBB").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(before)
        .unwrap();
    assert_eq!(std::fs::metadata(&p).unwrap().modified().unwrap(), before);
    let (m2, s2) = run(t.path(), &mut cache);
    assert_eq!(s2.cache_misses, 1, "forged mtime fooled the cache: {s2:?}");
    assert_ne!(m1.id(), m2.id());
}

#[test]
fn delete_and_recreate_is_detected() {
    let t = tmp();
    let p = write(t.path(), "a", b"AAAA");
    let mut cache = TreeCache::new();
    let (m1, _) = run(t.path(), &mut cache);
    std::fs::remove_file(&p).unwrap();
    std::thread::sleep(Duration::from_millis(15));
    write(t.path(), "a", b"BBBB");
    let (m2, s2) = run(t.path(), &mut cache);
    assert_eq!(s2.cache_misses, 1);
    assert_ne!(m1.id(), m2.id());
}

#[test]
fn mode_change_does_not_use_stale_mode() {
    // Mode is not part of the cache record: it is read fresh from stat every time.
    let t = tmp();
    let p = write(t.path(), "a", b"AAAA");
    let mut cache = TreeCache::new();
    let (m1, _) = run(t.path(), &mut cache);
    common::chmod(&p, 0o755);
    let (m2, _) = run(t.path(), &mut cache);
    assert_ne!(m1.id(), m2.id());
    assert_eq!(m2.get(&rp("a")).unwrap().mode, 0o755);
}

#[test]
fn removed_files_are_dropped_from_the_cache() {
    let t = tmp();
    write(t.path(), "a", b"x");
    write(t.path(), "b", b"y");
    let mut cache = TreeCache::new();
    run(t.path(), &mut cache);
    assert_eq!(cache.len(), 2);
    std::fs::remove_file(t.path().join("b")).unwrap();
    run(t.path(), &mut cache);
    assert_eq!(cache.len(), 1);
    assert!(cache.get(&rp("a")).is_some());
    assert!(cache.get(&rp("b")).is_none());
}

#[test]
fn documented_limitation_cache_is_trusted_blindly_on_identity_match() {
    // KNOWN LIMITATION (see src/cache.rs): the cache does not re-read content when
    // (dev, ino, size, mtime, ctime) all match. An edit that keeps the size and lands in
    // the same timestamp tick as the previous observation is invisible. We cannot
    // provoke that race deterministically, so we pin the behaviour it rests on: a record
    // whose identity matches is used without reading the file. This is why `wardd` must
    // treat the cache as an optimisation and never as evidence for an accepted snapshot.
    let t = tmp();
    let p = write(t.path(), "a", b"real");
    let identity = FileIdentity::from_metadata(&std::fs::metadata(&p).unwrap());
    let mut cache = TreeCache::new();
    let fake = ContentHash::of(b"stale");
    cache.insert(rp("a"), identity, fake);
    let (m, s) = run(t.path(), &mut cache);
    assert_eq!(s.cache_hits, 1);
    assert_eq!(
        m.get(&rp("a")).unwrap().hash,
        fake,
        "cache was consulted, as designed"
    );
    // Without the cache the truth comes back.
    let truth = Capture::run(t.path(), &CapturePolicy::default(), None).unwrap();
    assert_eq!(truth.get(&rp("a")).unwrap().hash, ContentHash::of(b"real"));
}

#[test]
fn cache_file_roundtrip_and_corruption_handling() {
    let t = tmp();
    write(t.path(), "a", b"x");
    write(t.path(), "sub/\u{e9}", b"y");
    let mut cache = TreeCache::new();
    run(t.path(), &mut cache);
    let file = t.path().join("cache.bin");
    cache.save(&file).unwrap();
    let loaded = TreeCache::load(&file).unwrap();
    assert_eq!(loaded, cache);
    let (_, s) = run(t.path(), &mut loaded.clone());
    assert_eq!(s.cache_hits, 2);

    std::fs::write(&file, b"garbage").unwrap();
    assert!(matches!(
        TreeCache::load(&file),
        Err(ward_snapshot::Error::Serde { .. })
    ));
    assert!(TreeCache::load(&t.path().join("missing")).is_err());
}

#[test]
fn cache_lookup_requires_exact_identity() {
    let mut cache = TreeCache::new();
    let id = FileIdentity {
        dev: 1,
        ino: 2,
        size: 3,
        mtime: 4,
        mtime_nsec: 5,
        ctime: 6,
        ctime_nsec: 7,
    };
    let h = ContentHash::of(b"h");
    cache.insert(rp("p"), id, h);
    assert_eq!(cache.lookup(&rp("p"), &id), Some(h));
    for changed in [
        FileIdentity { dev: 9, ..id },
        FileIdentity { ino: 9, ..id },
        FileIdentity { size: 9, ..id },
        FileIdentity { mtime: 9, ..id },
        FileIdentity {
            mtime_nsec: 9,
            ..id
        },
        FileIdentity { ctime: 9, ..id },
        FileIdentity {
            ctime_nsec: 9,
            ..id
        },
    ] {
        assert_eq!(cache.lookup(&rp("p"), &changed), None, "{changed:?}");
    }
    assert_eq!(cache.lookup(&rp("q"), &id), None);
    cache.clear();
    assert!(cache.is_empty());
}

#[test]
fn cache_identity_captures_ctime_after_utimensat() {
    let t = tmp();
    let p = write(t.path(), "a", b"x");
    let before = FileIdentity::from_metadata(&std::fs::metadata(&p).unwrap());
    std::thread::sleep(Duration::from_millis(15));
    std::fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000))
        .unwrap();
    let after = FileIdentity::from_metadata(&std::fs::metadata(&p).unwrap());
    assert_ne!(before.mtime, after.mtime);
    assert!((after.ctime, after.ctime_nsec) > (before.ctime, before.ctime_nsec));
}
