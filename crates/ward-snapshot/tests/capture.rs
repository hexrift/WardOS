//! Capture engine: walking, ignore rules, symlinks, limits, freezer.
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
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{capture, capture_with, chmod, mkdir, paths, rp, symlink, tmp, write, write_bytes};
use ward_snapshot::error::Limit;
use ward_snapshot::meta::GitContext;
use ward_snapshot::{
    Capture, CapturePolicy, CgroupV2Freezer, ContentHash, EntryKind, Error, Freezer, NoopFreezer,
    capture_with_freezer,
};

#[test]
fn captures_files_dirs_and_empty_dirs() {
    let t = tmp();
    write(t.path(), "a.txt", b"hello");
    write(t.path(), "sub/b.txt", b"world");
    mkdir(t.path(), "empty");
    mkdir(t.path(), "sub/empty2");
    let m = capture(t.path());
    assert_eq!(
        paths(&m),
        vec!["a.txt", "empty", "sub", "sub/b.txt", "sub/empty2"]
    );
    let a = m.get(&rp("a.txt")).unwrap();
    assert_eq!(a.kind, EntryKind::File);
    assert_eq!(a.size, 5);
    assert_eq!(a.hash, ContentHash::of(b"hello"));
    assert_eq!(m.get(&rp("empty")).unwrap().kind, EntryKind::Dir);
}

#[test]
fn identical_trees_give_identical_ids_regardless_of_location_and_mtime() {
    let t1 = tmp();
    let t2 = tmp();
    for t in [&t1, &t2] {
        write(t.path(), "x/y/z.txt", b"same");
        write(t.path(), "top", b"");
        symlink(t.path(), "l", b"x/y/z.txt");
    }
    std::thread::sleep(Duration::from_millis(20));
    write(t2.path(), "top", b""); // bump mtime only
    assert_eq!(capture(t1.path()).id(), capture(t2.path()).id());
}

#[test]
fn symlink_outside_tree_is_stored_as_symlink_never_followed() {
    let t = tmp();
    symlink(t.path(), "passwd", b"/etc/passwd");
    symlink(t.path(), "up", b"../../../../etc");
    symlink(t.path(), "dangling", b"nowhere/at/all");
    let m = capture(t.path());
    for (name, target) in [
        ("passwd", &b"/etc/passwd"[..]),
        ("up", &b"../../../../etc"[..]),
        ("dangling", &b"nowhere/at/all"[..]),
    ] {
        let e = m.get(&rp(name)).unwrap();
        assert_eq!(e.kind, EntryKind::Symlink);
        assert_eq!(e.hash, ContentHash::of(target));
        assert_eq!(e.size, target.len() as u64);
    }
    // Nothing from /etc leaked in.
    assert_eq!(m.len(), 3);
}

#[test]
fn symlink_to_directory_is_not_descended() {
    let t = tmp();
    write(t.path(), "real/file", b"x");
    symlink(t.path(), "alias", b"real");
    let m = capture(t.path());
    assert_eq!(paths(&m), vec!["alias", "real", "real/file"]);
    assert_eq!(m.get(&rp("alias")).unwrap().kind, EntryKind::Symlink);
}

#[test]
fn symlink_loops_terminate() {
    let t = tmp();
    symlink(t.path(), "a", b"b");
    symlink(t.path(), "b", b"a");
    symlink(t.path(), "self", b"self");
    symlink(t.path(), "d/up", b"..");
    let m = capture(t.path());
    assert_eq!(paths(&m), vec!["a", "b", "d", "d/up", "self"]);
}

#[test]
fn hardlinks_are_independent_files_with_same_hash() {
    let t = tmp();
    let p = write(t.path(), "one", b"shared");
    std::fs::hard_link(&p, t.path().join("two")).unwrap();
    let m = capture(t.path());
    let one = m.get(&rp("one")).unwrap();
    let two = m.get(&rp("two")).unwrap();
    assert_eq!(one.kind, EntryKind::File);
    assert_eq!(two.kind, EntryKind::File);
    assert_eq!(one.hash, two.hash);
    assert_eq!(m.total_file_bytes(), 12);
}

#[test]
fn hostile_file_names_are_captured_as_raw_bytes() {
    let t = tmp();
    let names: Vec<&[u8]> = vec![
        b"sp ace",
        b"new\nline",
        b"\xff\xfe",
        b"\xc3\xa9.nfc",
        b"e\xcc\x81.nfd",
        b"dir with space/inner\ttab",
    ];
    for n in &names {
        write_bytes(t.path(), n, b"c");
    }
    let long = vec![b'L'; 255];
    write_bytes(t.path(), &long, b"c");
    let m = capture(t.path());
    for n in &names {
        assert!(
            m.get(&ward_snapshot::RelPath::new(n.to_vec()).unwrap())
                .is_some(),
            "missing {:?}",
            String::from_utf8_lossy(n)
        );
    }
    assert!(m.get(&ward_snapshot::RelPath::new(long).unwrap()).is_some());
    // Re-parse stability.
    let bytes = m.to_canonical_bytes();
    assert_eq!(ward_snapshot::Manifest::parse(&bytes).unwrap().id(), m.id());
}

#[test]
fn unsupported_entries_are_recorded_by_name_only() {
    let t = tmp();
    write(t.path(), "f", b"x");
    if !common::mkfifo(&t.path().join("pipe")) {
        eprintln!("mkfifo unavailable; skipping");
        return;
    }
    let m = capture(t.path());
    let e = m.get(&rp("pipe")).unwrap();
    assert_eq!(e.kind, EntryKind::Unsupported);
    assert_eq!(e.size, 0);
    assert!(e.hash.is_none());
    let (_, stats) = Capture::run_with_stats(t.path(), &CapturePolicy::default(), None).unwrap();
    assert_eq!(stats.unsupported, 1);
    assert_eq!(stats.files, 1);
}

#[test]
fn modes_are_recorded_with_special_bits() {
    let t = tmp();
    let p = write(t.path(), "exec", b"#!/bin/sh\n");
    chmod(&p, 0o4755);
    let d = mkdir(t.path(), "sticky");
    chmod(&d, 0o1777);
    let r = write(t.path(), "ro", b"");
    chmod(&r, 0o400);
    let m = capture(t.path());
    assert_eq!(m.get(&rp("exec")).unwrap().mode, 0o4755);
    assert_eq!(m.get(&rp("sticky")).unwrap().mode, 0o1777);
    assert_eq!(m.get(&rp("ro")).unwrap().mode, 0o400);
}

#[test]
fn gitignore_is_honoured_by_default_and_git_dir_always_included() {
    let t = tmp();
    write(t.path(), ".gitignore", b"*.log\nbuild/\n");
    write(t.path(), "keep.txt", b"k");
    write(t.path(), "noise.log", b"n");
    write(t.path(), "build/out.o", b"o");
    write(t.path(), "sub/.gitignore", b"secret\n");
    write(t.path(), "sub/secret", b"s");
    write(t.path(), "sub/open", b"o");
    write(t.path(), ".git/HEAD", b"ref: refs/heads/main\n");
    write(t.path(), ".git/info/exclude", b"excluded.txt\n");
    write(t.path(), ".git/objects/ab/cdef", b"blob");
    write(t.path(), "excluded.txt", b"e");

    let m = capture(t.path());
    let p = paths(&m);
    assert!(p.contains(&"keep.txt".to_owned()));
    assert!(p.contains(&".gitignore".to_owned()));
    assert!(p.contains(&"sub/open".to_owned()));
    assert!(!p.contains(&"noise.log".to_owned()));
    assert!(!p.contains(&"build".to_owned()));
    assert!(!p.contains(&"build/out.o".to_owned()));
    assert!(!p.contains(&"sub/secret".to_owned()));
    assert!(!p.contains(&"excluded.txt".to_owned()));
    assert!(p.contains(&".git".to_owned()));
    assert!(p.contains(&".git/HEAD".to_owned()));
    assert!(p.contains(&".git/objects/ab/cdef".to_owned()));

    let all = capture_with(
        t.path(),
        &CapturePolicy {
            include_ignored: true,
            ..CapturePolicy::default()
        },
    );
    let p = paths(&all);
    assert!(p.contains(&"noise.log".to_owned()));
    assert!(p.contains(&"build/out.o".to_owned()));
    assert!(p.contains(&"sub/secret".to_owned()));
    assert!(p.contains(&"excluded.txt".to_owned()));
    assert!(p.contains(&".git/HEAD".to_owned()));
}

#[test]
fn git_dir_is_included_even_when_an_ignore_rule_matches_it() {
    let t = tmp();
    write(t.path(), ".gitignore", b"*\n");
    write(t.path(), ".git/HEAD", b"x");
    write(t.path(), "hidden-by-star", b"x");
    let m = capture(t.path());
    let p = paths(&m);
    assert!(p.contains(&".git/HEAD".to_owned()));
    assert!(!p.contains(&"hidden-by-star".to_owned()));
}

#[test]
fn git_dir_can_be_excluded_by_policy() {
    let t = tmp();
    write(t.path(), ".git/HEAD", b"x");
    write(t.path(), "f", b"x");
    for include_ignored in [false, true] {
        let m = capture_with(
            t.path(),
            &CapturePolicy {
                include_git_dir: false,
                include_ignored,
                ..CapturePolicy::default()
            },
        );
        assert_eq!(paths(&m), vec!["f"]);
    }
}

#[test]
fn git_file_of_linked_worktree_is_captured_as_a_file() {
    let t = tmp();
    write(
        t.path(),
        ".git",
        b"gitdir: /somewhere/else/.git/worktrees/x\n",
    );
    write(t.path(), "f", b"x");
    let m = capture(t.path());
    assert_eq!(paths(&m), vec![".git", "f"]);
    assert_eq!(m.get(&rp(".git")).unwrap().kind, EntryKind::File);
}

#[test]
fn nested_git_dirs_are_ordinary_bytes() {
    let t = tmp();
    write(t.path(), "sub/.git/HEAD", b"ref: refs/heads/dev\n");
    write(t.path(), "sub/file", b"x");
    let m = capture(t.path());
    assert!(paths(&m).contains(&"sub/.git/HEAD".to_owned()));
}

#[test]
fn max_entries_is_enforced_not_truncated() {
    let t = tmp();
    for i in 0..10 {
        write(t.path(), &format!("f{i}"), b"x");
    }
    let policy = CapturePolicy {
        max_entries: 5,
        ..CapturePolicy::default()
    };
    let e = Capture::run(t.path(), &policy, None).expect_err("limit");
    assert!(
        matches!(
            e,
            Error::LimitExceeded {
                limit: Limit::Entries,
                value: 5,
                ..
            }
        ),
        "{e}"
    );
    let policy = CapturePolicy {
        max_entries: 10,
        ..CapturePolicy::default()
    };
    assert_eq!(Capture::run(t.path(), &policy, None).unwrap().len(), 10);
}

#[test]
fn max_bytes_is_enforced_not_truncated() {
    let t = tmp();
    write(t.path(), "a", &[0u8; 600]);
    write(t.path(), "b", &[0u8; 600]);
    let policy = CapturePolicy {
        max_bytes: 1000,
        ..CapturePolicy::default()
    };
    let e = Capture::run(t.path(), &policy, None).expect_err("limit");
    assert!(
        matches!(
            e,
            Error::LimitExceeded {
                limit: Limit::Bytes,
                value: 1000,
                ..
            }
        ),
        "{e}"
    );
    let policy = CapturePolicy {
        max_bytes: 1200,
        ..CapturePolicy::default()
    };
    assert!(Capture::run(t.path(), &policy, None).is_ok());
}

#[test]
fn root_must_be_a_directory() {
    let t = tmp();
    let f = write(t.path(), "file", b"");
    assert!(Capture::run(&f, &CapturePolicy::default(), None).is_err());
    assert!(Capture::run(&t.path().join("missing"), &CapturePolicy::default(), None).is_err());
}

#[test]
fn unreadable_file_is_an_error_not_a_silent_skip() {
    if is_root() {
        eprintln!("running as root; permission test skipped");
        return;
    }
    let t = tmp();
    let p = write(t.path(), "secret", b"x");
    chmod(&p, 0o000);
    let r = Capture::run(t.path(), &CapturePolicy::default(), None);
    chmod(&p, 0o644);
    assert!(matches!(r, Err(Error::Io { .. })));
}

fn is_root() -> bool {
    std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
        .unwrap_or(false)
}

#[test]
fn large_file_uses_mmap_path_and_matches_small_path() {
    let t = tmp();
    let big = vec![7u8; (ward_snapshot::hash::MMAP_THRESHOLD + 12345) as usize];
    write(t.path(), "big", &big);
    let m = capture(t.path());
    let e = m.get(&rp("big")).unwrap();
    assert_eq!(e.hash, ContentHash::of(&big));
    assert_eq!(e.size, big.len() as u64);
}

#[test]
fn stats_are_reported() {
    let t = tmp();
    write(t.path(), "a", b"12345");
    write(t.path(), "d/b", b"678");
    symlink(t.path(), "l", b"a");
    let (m, stats) = Capture::run_with_stats(t.path(), &CapturePolicy::default(), None).unwrap();
    assert_eq!(stats.entries, m.len() as u64);
    assert_eq!(stats.files, 2);
    assert_eq!(stats.dirs, 1);
    assert_eq!(stats.symlinks, 1);
    assert_eq!(stats.bytes_total, 8);
    assert_eq!(stats.bytes_hashed, 8);
    assert_eq!(stats.cache_misses, 2);
    assert!(stats.frozen_for.is_none());
    assert!(stats.skipped_foreign_fs.is_empty());
}

struct CountingFreezer {
    freezes: AtomicUsize,
    thaws: AtomicUsize,
    fail_freeze: bool,
}

impl Freezer for CountingFreezer {
    fn freeze(&self) -> ward_snapshot::Result<()> {
        self.freezes.fetch_add(1, Ordering::SeqCst);
        if self.fail_freeze {
            return Err(Error::Freezer("nope".into()));
        }
        Ok(())
    }

    fn thaw(&self) -> ward_snapshot::Result<()> {
        self.thaws.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn capture_with_freezer_freezes_then_thaws_even_on_failure() {
    let t = tmp();
    write(t.path(), "f", b"x");
    let fz = CountingFreezer {
        freezes: AtomicUsize::new(0),
        thaws: AtomicUsize::new(0),
        fail_freeze: false,
    };
    let (m, stats) = capture_with_freezer(t.path(), &CapturePolicy::default(), None, &fz).unwrap();
    assert_eq!(m.len(), 1);
    assert!(stats.frozen_for.is_some());
    assert_eq!(fz.freezes.load(Ordering::SeqCst), 1);
    assert_eq!(fz.thaws.load(Ordering::SeqCst), 1);

    // Capture failure (limit) still thaws.
    let policy = CapturePolicy {
        max_entries: 0,
        ..CapturePolicy::default()
    };
    assert!(capture_with_freezer(t.path(), &policy, None, &fz).is_err());
    assert_eq!(fz.freezes.load(Ordering::SeqCst), 2);
    assert_eq!(fz.thaws.load(Ordering::SeqCst), 2);

    // Freeze failure: no capture, no thaw.
    let failing = CountingFreezer {
        freezes: AtomicUsize::new(0),
        thaws: AtomicUsize::new(0),
        fail_freeze: true,
    };
    let e = capture_with_freezer(t.path(), &CapturePolicy::default(), None, &failing).unwrap_err();
    assert!(matches!(e, Error::Freezer(_)));
    assert_eq!(failing.thaws.load(Ordering::SeqCst), 0);

    let (m2, _) =
        capture_with_freezer(t.path(), &CapturePolicy::default(), None, &NoopFreezer).unwrap();
    assert_eq!(m2.id(), m.id());
}

#[test]
fn cgroup_freezer_writes_freeze_file_and_waits_for_events() {
    let cg = tmp();
    std::fs::write(cg.path().join("cgroup.freeze"), "0").unwrap();
    std::fs::write(cg.path().join("cgroup.events"), "populated 1\nfrozen 1\n").unwrap();
    let fz = CgroupV2Freezer::new(cg.path());
    fz.freeze().unwrap();
    assert_eq!(
        std::fs::read_to_string(cg.path().join("cgroup.freeze")).unwrap(),
        "1"
    );

    // Thaw waits for `frozen 0`; the fake events file still says 1, so it times out.
    let slow = CgroupV2Freezer {
        path: cg.path().to_path_buf(),
        settle_timeout: Duration::from_millis(30),
    };
    let e = slow.thaw().unwrap_err();
    assert!(matches!(e, Error::Freezer(_)), "{e}");
    assert_eq!(
        std::fs::read_to_string(cg.path().join("cgroup.freeze")).unwrap(),
        "0"
    );

    std::fs::write(cg.path().join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
    slow.thaw().unwrap();

    // Without cgroup.events the wait is skipped.
    std::fs::remove_file(cg.path().join("cgroup.events")).unwrap();
    fz.freeze().unwrap();
    fz.thaw().unwrap();

    // A missing cgroup is an error, not a panic.
    let missing = CgroupV2Freezer::new(cg.path().join("nope"));
    assert!(matches!(missing.freeze(), Err(Error::Freezer(_))));
}

#[test]
fn git_context_is_read_textually_and_best_effort() {
    let t = tmp();
    assert_eq!(GitContext::read(t.path()), GitContext::default());

    let sha = "0123456789abcdef0123456789abcdef01234567";
    write(t.path(), ".git/HEAD", b"ref: refs/heads/feature/x\n");
    write(
        t.path(),
        ".git/refs/heads/feature/x",
        format!("{sha}\n").as_bytes(),
    );
    let ctx = GitContext::read(t.path());
    assert_eq!(ctx.branch.as_deref(), Some("feature/x"));
    assert_eq!(ctx.head.as_deref(), Some(sha));
    assert_eq!(ctx.dirty, None);

    // packed-refs fallback.
    std::fs::remove_file(t.path().join(".git/refs/heads/feature/x")).unwrap();
    write(
        t.path(),
        ".git/packed-refs",
        format!("# pack-refs with: peeled\n{sha} refs/heads/feature/x\n").as_bytes(),
    );
    assert_eq!(GitContext::read(t.path()).head.as_deref(), Some(sha));

    // Detached.
    write(t.path(), ".git/HEAD", format!("{sha}\n").as_bytes());
    let ctx = GitContext::read(t.path());
    assert_eq!(ctx.branch.as_deref(), Some("detached"));
    assert_eq!(ctx.head.as_deref(), Some(sha));

    // Garbage HEAD: no panic, no fields.
    write(t.path(), ".git/HEAD", b"ref: ../../etc/passwd\n");
    let ctx = GitContext::read(t.path());
    assert_eq!(ctx.head, None);

    write(t.path(), ".git/HEAD", b"\xff\xfe not text");
    assert_eq!(GitContext::read(t.path()), GitContext::default());
}

#[test]
fn permission_bits_do_not_leak_type_bits() {
    let t = tmp();
    write(t.path(), "f", b"");
    let m = capture(t.path());
    let mode = m.get(&rp("f")).unwrap().mode;
    assert_eq!(mode & !0o7777, 0);
    let actual = std::fs::metadata(t.path().join("f"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, actual);
}

#[test]
fn capture_root_symlink_components_do_not_matter() {
    // Capturing through a symlinked root path still works (walkdir resolves the root).
    let t = tmp();
    write(t.path(), "real/f", b"x");
    let link = t.path().join("link");
    std::os::unix::fs::symlink(Path::new("real"), &link).unwrap();
    let via_link = std::fs::canonicalize(&link).unwrap();
    assert_eq!(
        capture(&via_link).id(),
        capture(&t.path().join("real")).id()
    );
}
