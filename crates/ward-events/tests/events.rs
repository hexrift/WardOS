//! Behavioural tests for `ward-events`: sanitisation, the hash chain, and the wire format.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::wildcard_imports,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]

use std::time::Duration;

use proptest::prelude::*;
use ward_events::sanitise::MAX_TEXT_CHARS;
use ward_events::*;

fn bidi(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

fn hash(tag: &str) -> Blake3Hash {
    Blake3Hash::hash(tag.as_bytes())
}

fn chain() -> Chain {
    Chain::new(SessionId::new("sess_test"), hash("genesis"))
}

// --- sanitisation ---------------------------------------------------------

#[test]
fn bounded_text_strips_control_and_bidi() {
    let bt = BoundedText::new("a\u{7}\n\u{202E}evil\u{2069}b");
    assert_eq!(bt.as_str(), "aevilb");
    assert!(!bt.is_truncated());
}

#[test]
fn bounded_text_truncation_retains_original_hash() {
    let long = "x".repeat(MAX_TEXT_CHARS + 50);
    let bt = BoundedText::new(&long);
    assert_eq!(bt.as_str().chars().count(), MAX_TEXT_CHARS);
    assert!(bt.is_truncated());
    assert_eq!(bt.original_hash(), Some(&Blake3Hash::hash(long.as_bytes())));
}

#[test]
fn bounded_text_replaces_invalid_utf8() {
    let bt = BoundedText::from_bytes(&[b'a', 0xFF, 0xFE, b'b']);
    assert_eq!(bt.as_str(), "a\u{FFFD}\u{FFFD}b");
}

#[test]
fn bounded_argv_hashes_original_when_over_capacity() {
    let raw: Vec<String> = (0..2000).map(|i| format!("arg{i}")).collect();
    let argv = BoundedArgv::new(&raw);
    assert_eq!(argv.args().len(), 1024);
    assert!(argv.is_truncated());
    assert!(argv.original_hash().is_some());

    let small = BoundedArgv::new(["ls", "-la"]);
    assert_eq!(small.args().len(), 2);
    assert!(!small.is_truncated());
}

#[test]
fn sandbox_path_rejects_traversal_and_escape() {
    assert_eq!(
        SandboxPath::new(PathRoot::Work, "../etc"),
        Err(PathError::ParentTraversal)
    );
    assert_eq!(
        SandboxPath::new(PathRoot::Work, "a/../b"),
        Err(PathError::ParentTraversal)
    );
    assert_eq!(
        SandboxPath::new(PathRoot::Work, "/abs"),
        Err(PathError::Outside)
    );
    assert_eq!(SandboxPath::parse("/etc/passwd"), Err(PathError::Outside));
    assert_eq!(
        SandboxPath::parse("/work/../env"),
        Err(PathError::ParentTraversal)
    );

    let p = SandboxPath::new(PathRoot::Work, "src/main.rs").unwrap();
    assert_eq!(p.to_string(), "/work/src/main.rs");
    // Full-path parse round-trips through the canonical rendering.
    assert_eq!(SandboxPath::parse("/work/src/main.rs").unwrap(), p);
    assert_eq!(SandboxPath::parse("/env").unwrap().to_string(), "/env");
}

#[test]
fn hostname_lowercases_and_strips() {
    let h = HostName::new("Git\u{202E}Hub.COM\n");
    assert_eq!(h.as_str(), "github.com");
}

// --- hash chain -----------------------------------------------------------

fn sample_events() -> Vec<WardEvent> {
    vec![
        WardEvent::AgentStateChanged {
            state: AgentState::Working,
        },
        WardEvent::CommandStarted {
            pid: Pid(10),
            parent: Pid(1),
            argv: BoundedArgv::new(["cargo", "test"]),
            cwd: SandboxPath::new(PathRoot::Work, "").unwrap(),
            exe_digest: Some(hash("cargo")),
        },
        WardEvent::CommandFinished {
            pid: Pid(10),
            exit: ExitStatus {
                code: Some(0),
                signal: None,
            },
            duration: Duration::from_secs(3),
        },
    ]
}

fn build(events: Vec<WardEvent>) -> Vec<EventRecord> {
    let mut c = chain();
    events
        .into_iter()
        .map(|e| {
            c.append(Origin::Kernel, Duration::from_millis(1), None, e)
                .unwrap()
        })
        .collect()
}

#[test]
fn chain_assigns_dense_seq_and_links() {
    let recs = build(sample_events());
    assert_eq!(
        recs.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(recs[1].prev, recs[0].hash);
    assert_eq!(recs[2].prev, recs[1].hash);
    assert_eq!(Chain::verify(&recs), Ok(()));
}

#[test]
fn chain_detects_hash_and_link_tamper() {
    let mut recs = build(sample_events());
    recs[1].event = WardEvent::AgentStateChanged {
        state: AgentState::Blocked,
    };
    let err = Chain::verify(&recs).unwrap_err();
    assert_eq!(err, VerifyError::HashMismatch { seq: 1 });
    assert_eq!(err.seq(), 1);

    let mut recs = build(sample_events());
    recs[2].prev = hash("wrong");
    assert_eq!(
        Chain::verify(&recs).unwrap_err(),
        VerifyError::BrokenLink { seq: 2 }
    );

    let mut recs = build(sample_events());
    recs[2].seq = 5;
    assert_eq!(
        Chain::verify(&recs).unwrap_err(),
        VerifyError::SequenceGap { seq: 5 }
    );
}

// --- wire format ----------------------------------------------------------

#[test]
fn wire_roundtrips_and_is_version_prefixed() {
    let rec = &build(sample_events())[1];
    let bytes = to_bytes(rec).unwrap();
    assert_eq!(bytes[0], FORMAT_VERSION);
    let back: EventRecord = from_bytes(&bytes).unwrap();
    assert_eq!(&back, rec);
}

#[test]
fn wire_decoder_is_defensive() {
    assert!(matches!(
        from_bytes::<EventRecord>(&[]),
        Err(WireError::Empty)
    ));
    assert!(matches!(
        from_bytes::<EventRecord>(&[9, 0, 0]),
        Err(WireError::Version {
            found: 9,
            expected: 1
        })
    ));
    let huge = vec![FORMAT_VERSION; MAX_WIRE_BYTES + 1];
    assert!(matches!(
        from_bytes::<EventRecord>(&huge),
        Err(WireError::TooLarge { .. })
    ));
}

#[test]
fn wire_decoder_resanitises_bounded_text() {
    // A hostile encoder puts control + bidi characters into a BoundedText's wire shape
    // (a `{ text, original }` struct, encoded here as an equivalent tuple).
    let raw = ("a\u{7}\u{202E}b".to_string(), Option::<[u8; 32]>::None);
    let mut bytes = vec![FORMAT_VERSION];
    bytes.extend_from_slice(&postcard::to_allocvec(&raw).unwrap());
    let bt: BoundedText = from_bytes(&bytes).unwrap();
    assert_eq!(bt.as_str(), "ab");
}

#[test]
fn wire_decoder_rejects_bad_sandbox_path() {
    let mut bytes = vec![FORMAT_VERSION];
    bytes.extend_from_slice(&postcard::to_allocvec(&"/work/../secret".to_string()).unwrap());
    assert!(from_bytes::<SandboxPath>(&bytes).is_err());
}

#[test]
fn credential_granted_carries_scope_and_expiry_only() {
    // The type has no field that could hold token material; this pins that shape.
    let ev = WardEvent::CredentialGranted {
        service: ServiceId::new("github"),
        scope: Scope::new("contents:read"),
        expires: Duration::from_secs(600),
        delivery: CredentialDelivery::ProxyInjected,
    };
    match ev {
        WardEvent::CredentialGranted {
            service,
            scope,
            expires,
            delivery,
        } => {
            assert_eq!(service.as_str(), "github");
            assert_eq!(scope.0.as_str(), "contents:read");
            assert_eq!(expires, Duration::from_secs(600));
            assert_eq!(delivery, CredentialDelivery::ProxyInjected);
        }
        _ => unreachable!(),
    }
}

// --- property tests -------------------------------------------------------

proptest! {
    /// (a) Any single-record tamper is caught, at that record's seq.
    #[test]
    fn prop_chain_detects_single_tamper(vals in prop::collection::vec(0u32..1000, 1..24),
                                        idx in 0usize..24) {
        let events: Vec<WardEvent> = vals.iter().map(|&v| WardEvent::CommandFinished {
            pid: Pid(v as i32),
            exit: ExitStatus { code: Some(0), signal: None },
            duration: Duration::from_secs(u64::from(v)),
        }).collect();
        let mut recs = build(events);
        let i = idx % recs.len();
        // Replace the event without re-sealing: the stored hash no longer matches.
        recs[i].event = WardEvent::AgentStateChanged { state: AgentState::Finished };
        let err = Chain::verify(&recs).unwrap_err();
        prop_assert_eq!(err, VerifyError::HashMismatch { seq: i as u64 });
    }

    /// (b) Sanitisation emits no control/bidi characters, stays within the cap, and is
    /// idempotent on the produced text.
    #[test]
    fn prop_sanitise_is_clean_and_idempotent(
        chars in prop::collection::vec(
            prop_oneof![
                any::<char>(),
                Just('\u{202E}'), Just('\u{2066}'), Just('\u{0007}'), Just('\n'), Just('\t'),
            ], 0..80)) {
        let input: String = chars.into_iter().collect();
        let once = BoundedText::new(&input);
        for c in once.as_str().chars() {
            prop_assert!(!c.is_control(), "control char leaked: {:?}", c);
            prop_assert!(!bidi(c), "bidi control leaked: {:?}", c);
        }
        prop_assert!(once.as_str().chars().count() <= MAX_TEXT_CHARS);
        let twice = BoundedText::new(once.as_str());
        prop_assert_eq!(once.as_str(), twice.as_str());
    }
}
