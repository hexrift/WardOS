//! End-to-end tests: capture -> store -> materialize, plus traversal safety.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::tempdir;
use ward_snapshot::{
    CaptureOptions, CaptureStats, Digest, HashCache, SnapshotError, SnapshotId, SnapshotRole,
    SnapshotStore,
};

fn p(bytes: &[u8]) -> &Path {
    Path::new(std::ffi::OsStr::from_bytes(bytes))
}

/// Write a file (creating parents) at raw-byte relative path `rel`.
fn write_file(root: &Path, rel: &[u8], content: &[u8]) {
    let full = root.join(p(rel));
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&full, content).unwrap();
}

/// A normalised view of a tree for byte-for-byte comparison.
#[derive(Debug, PartialEq, Eq)]
enum Node {
    File(u32, Vec<u8>),
    Dir(u32),
    Symlink(Vec<u8>),
}

fn collect(root: &Path) -> BTreeMap<Vec<u8>, Node> {
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<Vec<u8>, Node>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec();
        let meta = fs::symlink_metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o7777;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&path).unwrap();
            out.insert(rel, Node::Symlink(target.as_os_str().as_bytes().to_vec()));
        } else if meta.is_dir() {
            out.insert(rel, Node::Dir(mode));
            walk(root, &path, out);
        } else {
            out.insert(rel, Node::File(mode, fs::read(&path).unwrap()));
        }
    }
}

#[test]
fn roundtrip_is_byte_identical_including_hostile_names_and_symlinks() {
    let src = tempdir().unwrap();
    let root = src.path();

    write_file(root, b"README.md", b"hello\n");
    write_file(root, b"src/lib.rs", b"fn main() {}\n");
    write_file(root, b"empty", b"");
    // Hostile names: spaces, an embedded newline, unicode, dotted names that are
    // NOT `..` traversals.
    write_file(root, b"a file with spaces.txt", b"x");
    write_file(root, b"embedded\nnewline", b"y");
    write_file(root, "unicode-\u{2764}\u{fe0f}-name".as_bytes(), b"z");
    write_file(root, b"a..b", b"literal double dot in name");
    write_file(root, b"dir/..hidden", b"leading double dot segment tail");
    // Empty directory must round-trip.
    fs::create_dir(root.join("empty_dir")).unwrap();
    // A relative in-tree symlink and one pointing outside the tree.
    std::os::unix::fs::symlink("README.md", root.join("link-to-readme")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", root.join("escape-link")).unwrap();

    let cas = tempdir().unwrap();
    let store = SnapshotStore::open(cas.path()).unwrap();
    let id = store
        .store_snapshot(root, SnapshotRole::Entry, CaptureOptions::default())
        .unwrap();

    let dest = tempdir().unwrap();
    store.materialize(id, dest.path()).unwrap();

    assert_eq!(
        collect(root),
        collect(dest.path()),
        "materialized tree differs from source"
    );

    // The out-of-tree symlink is stored as its target string, never followed:
    // `cat` returns the target bytes, not the contents of /etc/hostname.
    let stored = store.cat(id, Path::new("escape-link")).unwrap();
    assert_eq!(stored, b"/etc/hostname");
    let meta = fs::symlink_metadata(dest.path().join("escape-link")).unwrap();
    assert!(meta.file_type().is_symlink());
}

#[test]
fn identical_trees_have_identical_ids_regardless_of_creation_order() {
    let files: [(&[u8], &[u8]); 4] = [
        (b"a", b"1"),
        (b"b/c", b"2"),
        (b"b/d", b"3"),
        (b"z/y/x", b"4"),
    ];

    let cas = tempdir().unwrap();
    let store = SnapshotStore::open(cas.path()).unwrap();

    let one = tempdir().unwrap();
    for (rel, c) in files {
        write_file(one.path(), rel, c);
    }
    let two = tempdir().unwrap();
    for (rel, c) in files.iter().rev() {
        write_file(two.path(), rel, c);
    }

    let id1 = store
        .store_snapshot(one.path(), SnapshotRole::Entry, CaptureOptions::default())
        .unwrap();
    let id2 = store
        .store_snapshot(two.path(), SnapshotRole::Entry, CaptureOptions::default())
        .unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn a_single_changed_byte_changes_the_id() {
    let cas = tempdir().unwrap();
    let store = SnapshotStore::open(cas.path()).unwrap();

    let dir = tempdir().unwrap();
    write_file(dir.path(), b"file", b"content-A");
    let id1 = store
        .store_snapshot(dir.path(), SnapshotRole::Entry, CaptureOptions::default())
        .unwrap();

    write_file(dir.path(), b"file", b"content-B");
    let id2 = store
        .store_snapshot(dir.path(), SnapshotRole::Entry, CaptureOptions::default())
        .unwrap();
    assert_ne!(id1, id2, "changing a file byte must change the Merkle root");
}

#[test]
fn diff_reports_added_removed_and_changed() {
    let cas = tempdir().unwrap();
    let store = SnapshotStore::open(cas.path()).unwrap();

    let dir = tempdir().unwrap();
    write_file(dir.path(), b"keep", b"same");
    write_file(dir.path(), b"gone", b"old");
    write_file(dir.path(), b"edit", b"before");
    let a = store
        .store_snapshot(dir.path(), SnapshotRole::Entry, CaptureOptions::default())
        .unwrap();

    fs::remove_file(dir.path().join("gone")).unwrap();
    write_file(dir.path(), b"edit", b"after");
    write_file(dir.path(), b"new", b"fresh");
    let b = store
        .store_snapshot(
            dir.path(),
            SnapshotRole::Candidate,
            CaptureOptions::default(),
        )
        .unwrap();

    let d = store.diff(a, b).unwrap();
    assert_eq!(d.added, vec![b"new".to_vec()]);
    assert_eq!(d.removed, vec![b"gone".to_vec()]);
    assert_eq!(d.changed, vec![b"edit".to_vec()]);
}

#[test]
fn incremental_capture_reuses_cached_hashes_for_unchanged_files() {
    let cas = tempdir().unwrap();
    let store = SnapshotStore::open(cas.path()).unwrap();
    let dir = tempdir().unwrap();
    for i in 0..5 {
        write_file(dir.path(), format!("f{i}").as_bytes(), b"data");
    }
    let opts = CaptureOptions {
        incremental: true,
        ..CaptureOptions::default()
    };

    let mut cache = HashCache::new();
    let mut s1 = CaptureStats::default();
    let m1 = store
        .capture_with_cache(dir.path(), SnapshotRole::Entry, opts, &mut cache, &mut s1)
        .unwrap();
    assert_eq!(s1.files_hashed, 5);
    assert_eq!(s1.files_cached, 0);

    let mut s2 = CaptureStats::default();
    let m2 = store
        .capture_with_cache(dir.path(), SnapshotRole::Entry, opts, &mut cache, &mut s2)
        .unwrap();
    assert_eq!(s2.files_hashed, 0, "unchanged files must not be re-hashed");
    assert_eq!(s2.files_cached, 5);
    assert_eq!(m1.id, m2.id, "cached capture must produce the same id");
}

#[test]
fn gitignore_excludes_by_default_and_policy_can_include() {
    let cas = tempdir().unwrap();
    let store = SnapshotStore::open(cas.path()).unwrap();
    let dir = tempdir().unwrap();
    write_file(dir.path(), b".gitignore", b"*.log\nbuild/\n");
    write_file(dir.path(), b"keep.rs", b"code");
    write_file(dir.path(), b"noise.log", b"junk");
    write_file(dir.path(), b"build/out", b"artifact");

    let excluded = store
        .capture(dir.path(), SnapshotRole::Entry, CaptureOptions::default())
        .unwrap();
    let m = store.manifest(excluded.id).unwrap();
    assert!(m.get(b"keep.rs").is_some());
    assert!(m.get(b"noise.log").is_none(), "*.log should be ignored");
    assert!(m.get(b"build").is_none(), "build/ dir should be ignored");
    assert!(m.get(b"build/out").is_none());

    let opts = CaptureOptions {
        include_ignored: true,
        ..CaptureOptions::default()
    };
    let included = store
        .capture(dir.path(), SnapshotRole::Entry, opts)
        .unwrap();
    let m = store.manifest(included.id).unwrap();
    assert!(m.get(b"noise.log").is_some());
    assert!(m.get(b"build/out").is_some());
}

/// A crafted manifest whose entry path is a real `..` traversal must be refused
/// when materialised — the manifest fails to parse rather than escaping `dest`.
#[test]
fn materialize_refuses_a_dotdot_traversal_entry() {
    let cas = tempdir().unwrap();
    let store = SnapshotStore::open(cas.path()).unwrap();

    let mut bytes = b"ward-snapshot-manifest/1\n".to_vec();
    bytes.extend_from_slice(b"file 644 0 blake3:");
    bytes.extend_from_slice("00".repeat(32).as_bytes());
    bytes.extend_from_slice(b" ../evil\0");
    let id = SnapshotId(Digest::of(&bytes));

    let manifests = cas.path().join("manifests");
    fs::create_dir_all(&manifests).unwrap();
    fs::write(manifests.join(id.digest().to_hex()), &bytes).unwrap();

    let dest = tempdir().unwrap();
    let err = store.materialize(id, dest.path()).unwrap_err();
    assert!(matches!(err, SnapshotError::UnsafePath(_)), "got {err:?}");
    assert!(!dest.path().parent().unwrap().join("evil").exists());
}

/// Materialisation must never write *through* a symlink: an entry placed under
/// a symlinked ancestor is refused (ST-015 at materialise time).
#[test]
fn materialize_refuses_writing_through_a_symlink_ancestor() {
    let cas = tempdir().unwrap();
    let store = SnapshotStore::open(cas.path()).unwrap();

    // Blob for the symlink target and for the file we try to smuggle under it.
    let target = b"/tmp";
    let file_body = b"pwned";
    write_blob(cas.path(), target);
    write_blob(cas.path(), file_body);

    let mut bytes = b"ward-snapshot-manifest/1\n".to_vec();
    // Sorted bytewise: "link" precedes "link/pwn".
    bytes.extend_from_slice(
        format!("symlink 777 {} {} link\0", target.len(), Digest::of(target)).as_bytes(),
    );
    bytes.extend_from_slice(
        format!(
            "file 644 {} {} link/pwn\0",
            file_body.len(),
            Digest::of(file_body)
        )
        .as_bytes(),
    );
    let id = SnapshotId(Digest::of(&bytes));
    let manifests = cas.path().join("manifests");
    fs::create_dir_all(&manifests).unwrap();
    fs::write(manifests.join(id.digest().to_hex()), &bytes).unwrap();

    let dest = tempdir().unwrap();
    let err = store.materialize(id, dest.path()).unwrap_err();
    assert!(matches!(err, SnapshotError::UnsafePath(_)), "got {err:?}");
    // The link exists but nothing was written through it.
    assert!(!Path::new("/tmp/pwn").exists());
}

fn write_blob(cas_root: &Path, bytes: &[u8]) {
    let hex = Digest::of(bytes).to_hex();
    let dir = cas_root.join("blobs").join(&hex[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&hex), bytes).unwrap();
}
