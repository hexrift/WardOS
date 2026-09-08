//! Manifest diff classification.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::cast_possible_truncation
)]

mod common;

use common::{capture, chmod, mkdir, rp, symlink, tmp, write};
use ward_snapshot::{ContentHash, Entry, EntryKind, Manifest, diff};

fn file(p: &str, mode: u32, content: &[u8]) -> Entry {
    Entry::file(rp(p), mode, content.len() as u64, ContentHash::of(content))
}

#[test]
fn identical_manifests_have_empty_diff() {
    let m =
        Manifest::from_entries(vec![file("a", 0o644, b"x"), Entry::dir(rp("d"), 0o755)]).unwrap();
    let d = diff(&m, &m);
    assert!(d.is_empty());
    assert_eq!(d.change_count(), 0);
    assert_eq!(d.unchanged, 2);
}

#[test]
fn classifies_every_kind_of_change() {
    let a = Manifest::from_entries(vec![
        file("removed", 0o644, b"r"),
        file("modified", 0o644, b"before"),
        file("mode", 0o644, b"same"),
        file("type", 0o644, b"was-file"),
        file("both", 0o644, b"before"),
        file("same", 0o644, b"same"),
        Entry::dir(rp("dir"), 0o755),
    ])
    .unwrap();
    let b = Manifest::from_entries(vec![
        file("added", 0o644, b"a"),
        file("modified", 0o644, b"after!"),
        file("mode", 0o755, b"same"),
        Entry::symlink(rp("type"), b"target"),
        file("both", 0o755, b"after"),
        file("same", 0o644, b"same"),
        Entry::dir(rp("dir"), 0o755),
    ])
    .unwrap();
    let d = diff(&a, &b);
    assert_eq!(
        common::paths(&Manifest::from_entries(d.added.clone()).unwrap()),
        vec!["added"]
    );
    assert_eq!(
        d.removed
            .iter()
            .map(|e| e.path.to_string())
            .collect::<Vec<_>>(),
        vec!["removed"]
    );
    let modified: Vec<String> = d
        .modified
        .iter()
        .map(|p| p.after.path.to_string())
        .collect();
    assert_eq!(modified, vec!["both", "modified"]);
    assert_eq!(d.mode_changed.len(), 1);
    assert_eq!(d.mode_changed[0].before.mode, 0o644);
    assert_eq!(d.mode_changed[0].after.mode, 0o755);
    assert_eq!(d.type_changed.len(), 1);
    assert_eq!(d.type_changed[0].before.kind, EntryKind::File);
    assert_eq!(d.type_changed[0].after.kind, EntryKind::Symlink);
    assert_eq!(d.unchanged, 2);
    assert_eq!(d.change_count(), 6);
}

#[test]
fn diff_is_directional() {
    let a = Manifest::from_entries(vec![file("only-a", 0o644, b"")]).unwrap();
    let b = Manifest::from_entries(vec![file("only-b", 0o644, b"")]).unwrap();
    let ab = diff(&a, &b);
    let ba = diff(&b, &a);
    assert_eq!(ab.added[0].path, rp("only-b"));
    assert_eq!(ab.removed[0].path, rp("only-a"));
    assert_eq!(ba.added[0].path, rp("only-a"));
    assert_eq!(ba.removed[0].path, rp("only-b"));
}

#[test]
fn diff_against_empty_manifest() {
    let m = Manifest::from_entries(vec![file("a", 0o644, b""), file("b", 0o644, b"")]).unwrap();
    let empty = Manifest::default();
    assert_eq!(diff(&empty, &m).added.len(), 2);
    assert_eq!(diff(&m, &empty).removed.len(), 2);
    assert!(diff(&empty, &empty).is_empty());
}

#[test]
fn diff_of_real_captures_shows_git_rewrites_and_content_changes() {
    let t = tmp();
    write(t.path(), ".git/HEAD", b"ref: refs/heads/main\n");
    write(t.path(), ".git/refs/heads/main", b"aaaa\n");
    write(t.path(), "src/lib.rs", b"fn a() {}\n");
    write(t.path(), "README", b"r");
    mkdir(t.path(), "empty");
    let entry = capture(t.path());

    // Agent rewrites HEAD, edits a file, deletes one, adds one, changes a mode, swaps a
    // file for a symlink, removes an empty dir.
    write(t.path(), ".git/refs/heads/main", b"bbbb\n");
    write(t.path(), "src/lib.rs", b"fn a() { evil() }\n");
    std::fs::remove_file(t.path().join("README")).unwrap();
    write(t.path(), "NEW", b"n");
    let m = write(t.path(), "script", b"#!/bin/sh\n");
    chmod(&m, 0o644);
    std::fs::remove_dir(t.path().join("empty")).unwrap();
    let mid = capture(t.path());
    chmod(&m, 0o755);
    std::fs::remove_file(t.path().join("NEW")).unwrap();
    symlink(t.path(), "NEW", b"/etc/passwd");
    let candidate = capture(t.path());

    let d = diff(&entry, &candidate);
    let names = |v: &[Entry]| v.iter().map(|e| e.path.to_string()).collect::<Vec<_>>();
    assert_eq!(names(&d.added), vec!["NEW", "script"]);
    assert_eq!(names(&d.removed), vec!["README", "empty"]);
    let modified: Vec<String> = d
        .modified
        .iter()
        .map(|p| p.after.path.to_string())
        .collect();
    assert_eq!(modified, vec![".git/refs/heads/main", "src/lib.rs"]);
    assert!(d.type_changed.is_empty());

    let d2 = diff(&mid, &candidate);
    assert_eq!(d2.mode_changed.len(), 1);
    assert_eq!(d2.mode_changed[0].after.path, rp("script"));
    assert_eq!(d2.type_changed.len(), 1);
    assert_eq!(d2.type_changed[0].after.path, rp("NEW"));
    assert_eq!(d2.change_count(), 2);
}
