//! Property tests for manifest canonicalisation with hostile path bytes.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::redundant_clone
)]

use proptest::prelude::*;
use ward_snapshot::{Digest, Entry, EntryType, Manifest};

/// A path segment of 1-4 bytes, never containing `/` or NUL and never `..`.
fn seg() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec((1u8..=250).prop_filter("no slash", |b| *b != b'/'), 1..=4)
        .prop_filter("not dotdot", |s| s != b"..")
}

fn path() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(seg(), 1..=4).prop_map(|segs| segs.join(&b'/'))
}

fn entry() -> impl Strategy<Value = Entry> {
    let kind = prop_oneof![
        Just(EntryType::File),
        Just(EntryType::Dir),
        Just(EntryType::Symlink),
        Just(EntryType::SubmoduleWorktree),
        Just(EntryType::Unsupported),
    ];
    (path(), kind, 0u32..=0o7777, any::<u64>(), any::<Vec<u8>>()).prop_map(
        |(path, kind, mode, size, seed)| {
            let has_content = matches!(kind, EntryType::File | EntryType::Symlink);
            Entry {
                path,
                kind,
                mode,
                size,
                content: has_content.then(|| Digest::of(&seed)),
            }
        },
    )
}

/// Entries de-duplicated by path (a manifest rejects duplicates).
fn entries() -> impl Strategy<Value = Vec<Entry>> {
    prop::collection::vec(entry(), 0..12).prop_map(|es| {
        let mut by_path = std::collections::BTreeMap::new();
        for e in es {
            by_path.insert(e.path.clone(), e);
        }
        by_path.into_values().collect()
    })
}

proptest! {
    /// Canonical form is independent of input order, and serialisation
    /// round-trips through parse even with spaces/newlines/high bytes in paths.
    #[test]
    fn canonical_form_is_order_independent_and_reparses(es in entries()) {
        let m1 = Manifest::from_entries(es.clone()).unwrap();
        let mut rev = es;
        rev.reverse();
        let m2 = Manifest::from_entries(rev).unwrap();

        prop_assert_eq!(m1.serialize(), m2.serialize());
        prop_assert_eq!(m1.id(), m2.id());

        let reparsed = Manifest::parse(&m1.serialize()).unwrap();
        prop_assert_eq!(reparsed.serialize(), m1.serialize());
    }

    /// Changing any leaf content digest changes the manifest (Merkle) id.
    #[test]
    fn changing_a_leaf_changes_the_id(es in entries()) {
        let m1 = Manifest::from_entries(es.clone()).unwrap();
        let idx = es.iter().position(|e| e.content.is_some());
        prop_assume!(idx.is_some());
        let idx = idx.unwrap();

        let mut mutated = es;
        let cur = mutated[idx].content.unwrap();
        let mut n = 0u64;
        let fresh = loop {
            let d = Digest::of(&n.to_le_bytes());
            if d != cur {
                break d;
            }
            n += 1;
        };
        mutated[idx].content = Some(fresh);

        let m2 = Manifest::from_entries(mutated).unwrap();
        prop_assert_ne!(m1.id(), m2.id());
    }

    /// A `..` component is rejected at manifest construction time.
    #[test]
    fn dotdot_component_is_rejected(prefix in seg(), suffix in seg()) {
        let mut path = prefix;
        path.push(b'/');
        path.extend_from_slice(b"..");
        path.push(b'/');
        path.extend_from_slice(&suffix);
        let e = Entry { path, kind: EntryType::Dir, mode: 0o755, size: 0, content: None };
        prop_assert!(Manifest::from_entries(vec![e]).is_err());
    }
}
