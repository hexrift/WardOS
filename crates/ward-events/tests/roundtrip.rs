//! Property tests: sanitiser invariants, serde roundtrips, chain and wire roundtrips, and
//! an end-to-end pass over every variant of the event catalogue.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;

use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use ward_events::chain::{Chain, Timestamp, verify};
use ward_events::event::{
    Acceptor, AgentIdentity, AgentKind, AgentState, CapabilityKind, CapabilityRequest, CaptureMode,
    ClaimKind, CredentialDelivery, Decision, DecisionSource, DeniedDst, DenyReason, EndReason,
    EventKind, ExitStatus, FileChangeKind, GrantScope, PauseMethod, PolicySubject, ProcessRef,
    RevokeReason, Scope, SignatureBytes, SnapshotRole, StepStatus, TamperWardSig, VerifyRequester,
    VerifySummary, WardEvent,
};
use ward_events::ids::{
    Blake3Hash, ImageDigest, Pid, ProjectId, RuleRef, ServiceId, SessionId, SnapshotId,
};
use ward_events::log::{FsyncPolicy, LogReader, LogWriter};
use ward_events::origin::Origin;
use ward_events::text::{BoundedArgv, BoundedText, FSI, HostName, PDI, SandboxPath, SandboxRoot};
use ward_events::wire::{
    Filter, Subscribe, decode_record, decode_subscribe, encode_record, encode_subscribe,
};

type T64 = BoundedText<64>;

fn text<const N: usize>(s: &str) -> BoundedText<N> {
    BoundedText::new(s)
}

fn is_forbidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{AD}'
                | '\u{61C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{FFFE}'
                | '\u{FFFF}'
        )
}

fn assert_render_safe(text: &str) {
    let inner = text
        .strip_prefix(FSI)
        .and_then(|s| s.strip_suffix(PDI))
        .unwrap_or(text);
    assert!(
        !inner.chars().any(is_forbidden),
        "forbidden char in {text:?}"
    );
    if inner.is_ascii() {
        assert_eq!(inner, text, "ASCII text must not be isolated");
    } else {
        assert_ne!(inner, text, "non-ASCII text must be isolated");
    }
}

fn postcard_roundtrip<T>(v: &T) -> T
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let bytes = postcard::to_allocvec(v).unwrap();
    postcard::from_bytes(&bytes).unwrap()
}

// A byte-string strategy biased toward the interesting cases: control bytes, invalid
// UTF-8, bidi controls, and long runs.
fn nasty_bytes() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        3 => "[a-zA-Z0-9 ./_-]{0,12}".prop_map(String::into_bytes),
        1 => prop::collection::vec(any::<u8>(), 0..8),
        1 => Just(b"\x1b[31m".to_vec()),
        1 => Just("\u{202e}".as_bytes().to_vec()),
        1 => Just("\u{2068}".as_bytes().to_vec()),
        1 => Just("שלום".as_bytes().to_vec()),
        1 => Just(b"\r\n".to_vec()),
        1 => Just(b"..".to_vec()),
        1 => Just(b"/".to_vec()),
        1 => Just(vec![0u8]),
        1 => Just(b"x".repeat(70)),
    ];
    prop::collection::vec(piece, 0..8).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn bounded_text_is_capped_render_safe_idempotent_and_roundtrips(bytes in nasty_bytes()) {
        let t = T64::from_bytes(&bytes);
        prop_assert!(t.len() <= T64::MAX_BYTES);
        assert_render_safe(t.as_str());
        // Idempotent: re-sanitising the stored text yields the same text.
        let again = T64::new(t.as_str());
        prop_assert_eq!(again.as_str(), t.as_str());
        if t.is_truncated() {
            prop_assert_eq!(t.original_hash(), Some(Blake3Hash::hash(&bytes)));
        }
        if t.original_hash().is_none() {
            // Only the (reversible) isolate wrapper may differ from the input.
            prop_assert_eq!(t.content().as_bytes(), bytes.as_slice());
        }
        prop_assert_eq!(postcard_roundtrip(&t), t);
    }

    #[test]
    fn argv_is_capped_and_roundtrips(args in prop::collection::vec(nasty_bytes(), 0..12)) {
        let a = BoundedArgv::from_bytes(args.iter().map(Vec::as_slice));
        prop_assert!(a.len() <= BoundedArgv::MAX_ARGS);
        let total: usize = a.args().iter().map(BoundedText::len).sum();
        prop_assert!(total <= BoundedArgv::MAX_TOTAL_BYTES);
        for arg in a.args() {
            assert_render_safe(arg.as_str());
        }
        prop_assert_eq!(a.len() + a.omitted() as usize, args.len());
        prop_assert_eq!(a.is_truncated(), a.original_hash().is_some() && (a.omitted() > 0 || a.args().iter().any(BoundedText::is_truncated)));
        prop_assert_eq!(postcard_roundtrip(&a), a);
    }

    #[test]
    fn sandbox_path_invariants(bytes in nasty_bytes()) {
        if let Ok(p) = SandboxPath::from_bytes(SandboxRoot::Work, &bytes) {
            {
                prop_assert!(!bytes.contains(&0));
                prop_assert!(bytes.first() != Some(&b'/'));
                prop_assert!(!p.relative().starts_with('/'));
                prop_assert!(!p.relative().ends_with('/'));
                prop_assert!(!p.relative().contains("//"));
                prop_assert!(p.components().all(|c| c != ".." && c != "." && !c.is_empty()));
                prop_assert!(!p.relative().chars().any(is_forbidden));
                prop_assert!(p.relative().len() <= SandboxPath::MAX_BYTES);
                // Canonical: rebuilding from the stored form changes nothing.
                let again = SandboxPath::new(SandboxRoot::Work, if p.is_root() { "." } else { p.relative() }).unwrap();
                prop_assert_eq!(again.relative(), p.relative());
                prop_assert_eq!(postcard_roundtrip(&p), p);
            }
        } else {
            {
                let text = String::from_utf8_lossy(&bytes);
                let bad = bytes.is_empty()
                    || bytes.contains(&0)
                    || bytes.first() == Some(&b'/')
                    || text.split('/').any(|c| c == "..")
                    || text.len() > SandboxPath::MAX_BYTES
                    || text.split('/').all(|c| c.is_empty() || c == "." || c.chars().all(is_forbidden))
                    || text.split('/').any(|c| c.chars().filter(|ch| !is_forbidden(*ch)).collect::<String>() == "..");
                prop_assert!(bad, "unexpected rejection of {text:?}");
            }
        }
    }

    #[test]
    fn host_names_are_lowercase_and_stable(s in "[A-Za-z0-9.-]{1,40}") {
        if let Ok(h) = HostName::new(&s) {
            prop_assert_eq!(h.as_str(), h.as_str().to_ascii_lowercase());
            prop_assert!(h.as_str().len() <= HostName::MAX_BYTES);
            prop_assert_eq!(HostName::new(h.as_str()).unwrap(), h.clone());
            prop_assert_eq!(postcard_roundtrip(&h), h);
        }
    }

    #[test]
    fn chain_of_random_events_verifies_and_roundtrips(
        events in prop::collection::vec(any_event(), 1..24),
        origins in prop::collection::vec(any_origin(), 24),
        flip in (0usize..10_000, 0u8..=255),
    ) {
        let session = SessionId::from_u128(0xabc);
        let manifest = Blake3Hash::hash(b"m");
        let mut chain = Chain::genesis(session, manifest);
        let mut records = Vec::new();
        for (i, (ev, origin)) in events.into_iter().zip(origins).enumerate() {
            let ts = Timestamp::mono(Duration::from_micros(i as u64));
            records.push(chain.append(origin, ev, ts).unwrap());
        }
        let head = verify(&records).unwrap();
        prop_assert_eq!(head, chain.head());
        prop_assert_eq!(head.genesis, manifest);

        let mut stream = Vec::new();
        for r in &records {
            let bytes = encode_record(r).unwrap();
            let (back, n) = decode_record(&bytes).unwrap();
            prop_assert_eq!(n, bytes.len());
            prop_assert_eq!(&back, r);
            stream.extend_from_slice(&bytes);
        }
        let mut off = 0;
        let mut decoded = Vec::new();
        while off < stream.len() {
            let (r, n) = decode_record(&stream[off..]).unwrap();
            decoded.push(r);
            off += n;
        }
        prop_assert_eq!(&decoded, &records);

        // Flip one byte of one frame: decoding must fail, or the surviving record must
        // agree with the original on every hash-covered field.
        let idx = flip.0 % records.len();
        let frame = encode_record(&records[idx]).unwrap();
        let pos = 8 + (flip.0 % (frame.len() - 8));
        let mut corrupted = frame.clone();
        corrupted[pos] ^= flip.1 | 1;
        if let Ok((r, _)) = decode_record(&corrupted) {
            let o = &records[idx];
            prop_assert!(r.seq == o.seq && r.origin == o.origin && r.prev == o.prev && r.event == o.event && r.hash == o.hash);
        }
    }

    #[test]
    fn subscribe_roundtrips(session in any::<u128>(), from_seq in any::<u64>(), bits in 0u8..128, kinds in 0u32..(1 << 27), notes in any::<bool>()) {
        let sub = Subscribe {
            session: SessionId::from_u128(session),
            from_seq,
            filter: Filter {
                origins: bits.try_into().unwrap(),
                kinds: kinds.try_into().unwrap(),
                exclude_agent_notes: notes,
            },
        };
        let bytes = encode_subscribe(&sub).unwrap();
        let (back, n) = decode_subscribe(&bytes).unwrap();
        prop_assert_eq!(n, bytes.len());
        prop_assert_eq!(back, sub);
    }
}

fn any_origin() -> impl Strategy<Value = Origin> {
    prop::sample::select(Origin::ALL.to_vec())
}

fn any_event() -> impl Strategy<Value = WardEvent> {
    prop_oneof![
        prop::sample::select(vec![
            AgentState::Idle,
            AgentState::Working,
            AgentState::Blocked,
            AgentState::Finished,
            AgentState::Paused
        ])
        .prop_map(|state| WardEvent::AgentStateChanged { state }),
        nasty_bytes().prop_map(|b| WardEvent::AgentClaim {
            kind: ClaimKind::Note,
            payload: BoundedText::from_bytes(&b),
        }),
        (nasty_bytes(), 1u32..1000).prop_map(|(b, pid)| {
            let path = SandboxPath::from_bytes(SandboxRoot::Work, &b)
                .unwrap_or_else(|_| SandboxPath::new(SandboxRoot::Work, "fallback").unwrap());
            WardEvent::FileModified {
                path,
                by: ProcessRef {
                    pid: Pid::new(pid).unwrap(),
                    comm: None,
                },
                kind: FileChangeKind::Write,
            }
        }),
        prop::collection::vec(nasty_bytes(), 0..6).prop_map(|args| WardEvent::CommandStarted {
            pid: Pid::new(2).unwrap(),
            parent: Pid::new(1).unwrap(),
            argv: BoundedArgv::from_bytes(args.iter().map(Vec::as_slice)),
            cwd: SandboxPath::new(SandboxRoot::Work, ".").unwrap(),
            exe_digest: None,
        }),
        (any::<u64>(), any::<bool>()).prop_map(|(seq, degraded)| WardEvent::Anchor {
            chain_head: Blake3Hash::hash(&seq.to_le_bytes()),
            seq,
            countersigned_by: None,
            degraded,
        }),
    ]
}

/// One instance of every catalogue variant, so a change to any of them is exercised
/// through the chain, the wire format, the log, and the kind mapping.
#[allow(clippy::too_many_lines)]
fn full_catalogue() -> Vec<(Origin, WardEvent)> {
    let snap = |b: &[u8]| SnapshotId::new(Blake3Hash::hash(b));
    let path = |s: &str| SandboxPath::new(SandboxRoot::Work, s).unwrap();
    let pid = |n: u32| Pid::new(n).unwrap();
    let rule = |s: &str| RuleRef::new(s).unwrap();
    let service = ServiceId::new("github").unwrap();
    let scope = Scope {
        subject: text("repo:hexrift/tamperward"),
        permissions: vec![text("contents:read")],
    };
    let proc_ref = ProcessRef {
        pid: pid(42),
        comm: Some(text("node")),
    };
    let cap = CapabilityRequest {
        kind: CapabilityKind::Network,
        target: text("api.github.com:443"),
    };
    let summary = VerifySummary {
        steps_total: 3,
        steps_passed: 2,
        steps_failed: 1,
        tests_run: 120,
        tests_failed: 1,
        duration: Duration::from_secs(42),
    };
    vec![
        (
            Origin::Wardd,
            WardEvent::SessionStarted {
                project: ProjectId::from_u128(7),
                agent: AgentIdentity {
                    kind: AgentKind::ClaudeCode,
                    name: text("claude-code"),
                    version: text("2.0.1"),
                    image: Some(ImageDigest::from_bytes([3; 32])),
                },
                manifest_hash: Blake3Hash::hash(b"manifest"),
                entry_snapshot: snap(b"entry"),
                policy_hash: Blake3Hash::hash(b"policy"),
                tool_images: vec![
                    ImageDigest::from_bytes([1; 32]),
                    ImageDigest::from_bytes([2; 32]),
                ],
            },
        ),
        (
            Origin::Wardd,
            WardEvent::AgentStateChanged {
                state: AgentState::Working,
            },
        ),
        (
            Origin::Kernel,
            WardEvent::FileRead {
                path: path("src/lib.rs"),
                by: proc_ref.clone(),
            },
        ),
        (
            Origin::Kernel,
            WardEvent::FileModified {
                path: path("src/lib.rs"),
                by: proc_ref.clone(),
                kind: FileChangeKind::Write,
            },
        ),
        (
            Origin::Kernel,
            WardEvent::CommandStarted {
                pid: pid(43),
                parent: pid(42),
                argv: BoundedArgv::from_strs(&["cargo", "test"]),
                cwd: path("."),
                exe_digest: Some(Blake3Hash::hash(b"cargo")),
            },
        ),
        (
            Origin::Kernel,
            WardEvent::CommandFinished {
                pid: pid(43),
                exit: ExitStatus::Exited { code: 0 },
                duration: Duration::from_secs(3),
            },
        ),
        (
            Origin::Kernel,
            WardEvent::CommandFinished {
                pid: pid(44),
                exit: ExitStatus::Signaled {
                    signal: 9,
                    core_dumped: false,
                },
                duration: Duration::ZERO,
            },
        ),
        (
            Origin::Proxy,
            WardEvent::NetworkRequested {
                host: HostName::new("api.github.com").unwrap(),
                port: 443,
                decision: Decision::Allow,
                rule: rule("project:network.allow[0]"),
                by: proc_ref.clone(),
            },
        ),
        (
            Origin::Proxy,
            WardEvent::NetworkDenied {
                dst: DeniedDst::Host {
                    host: HostName::new("evil.example").unwrap(),
                    port: 443,
                },
                reason: DenyReason::NotAllowlisted,
            },
        ),
        (
            Origin::Kernel,
            WardEvent::NetworkDenied {
                dst: DeniedDst::Ip {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    port: 22,
                },
                reason: DenyReason::PrivateRange,
            },
        ),
        (
            Origin::Kernel,
            WardEvent::NetworkDenied {
                dst: DeniedDst::Raw {
                    target: text("\u{1b}[2Jgarbage"),
                },
                reason: DenyReason::NonProxyEgress,
            },
        ),
        (
            Origin::Agent,
            WardEvent::CapabilityRequested {
                cap: cap.clone(),
                reason: Some(text("need the API")),
            },
        ),
        (
            Origin::User,
            WardEvent::CapabilityDecided {
                cap: cap.clone(),
                decision: Decision::Allow,
                by: DecisionSource::User,
                grant: Some(GrantScope::Until {
                    expires_in: Duration::from_secs(600),
                }),
            },
        ),
        (
            Origin::Wardd,
            WardEvent::CapabilityDecided {
                cap,
                decision: Decision::Deny,
                by: DecisionSource::Timeout,
                grant: None,
            },
        ),
        (
            Origin::Wardd,
            WardEvent::CredentialRequested {
                service: service.clone(),
                scope: scope.clone(),
            },
        ),
        (
            Origin::Wardd,
            WardEvent::CredentialGranted {
                service: service.clone(),
                scope: scope.clone(),
                expires: Duration::from_secs(600),
                delivery: CredentialDelivery::ProxyInjected,
            },
        ),
        (
            Origin::Wardd,
            WardEvent::CredentialDenied {
                service: service.clone(),
                scope,
                reason: DenyReason::PolicyDeny {
                    rule: rule("system:credentials.deny[aws-prod]"),
                },
            },
        ),
        (
            Origin::Wardd,
            WardEvent::CredentialRevoked {
                service,
                reason: RevokeReason::SessionEnded,
            },
        ),
        (
            Origin::Wardd,
            WardEvent::SnapshotCreated {
                role: SnapshotRole::Candidate,
                id: snap(b"cand"),
                entries: 1200,
                bytes: 9_000_000,
                capture: CaptureMode::FrozenCopy,
                stall: Duration::from_millis(80),
            },
        ),
        (
            Origin::TamperWard,
            WardEvent::PolicyDecision {
                subject: PolicySubject::ProtectedTests,
                decision: Decision::Allow,
                rule: rule("tw:test-deletion"),
                detail: text("no protected test removed"),
            },
        ),
        (
            Origin::TamperWard,
            WardEvent::PolicyDenied {
                subject: PolicySubject::Path {
                    path: path("scripts/verify/tamperward.sh"),
                },
                rule: rule("tw:ci-tampering"),
                detail: text("verify script modified"),
            },
        ),
        (
            Origin::TamperWard,
            WardEvent::TamperDetected {
                subject: PolicySubject::Other {
                    detail: text("ledger"),
                },
                detail: text("ledger rewritten"),
            },
        ),
        (
            Origin::User,
            WardEvent::VerificationRequested {
                candidate: snap(b"cand"),
                requested_by: VerifyRequester::User,
            },
        ),
        (
            Origin::Wardd,
            WardEvent::VerificationStarted {
                candidate: snap(b"cand"),
                pristine: snap(b"entry"),
                verifier_image: ImageDigest::from_bytes([9; 32]),
                manifest_hash: Blake3Hash::hash(b"vm"),
            },
        ),
        (
            Origin::Verifier,
            WardEvent::VerificationProgress {
                step: text("cargo test"),
                status: StepStatus::Running,
            },
        ),
        (
            Origin::Verifier,
            WardEvent::VerificationFailed {
                candidate: snap(b"cand"),
                summary,
                result_hash: Blake3Hash::hash(b"r1"),
            },
        ),
        (
            Origin::Verifier,
            WardEvent::VerificationPassed {
                candidate: snap(b"cand2"),
                summary: VerifySummary::default(),
                result_hash: Blake3Hash::hash(b"r2"),
            },
        ),
        (
            Origin::TamperWard,
            WardEvent::StateAccepted {
                snapshot: snap(b"cand2"),
                by: Acceptor::TamperWard,
            },
        ),
        (
            Origin::Agent,
            WardEvent::AgentClaim {
                kind: ClaimKind::ToolUse,
                payload: text("Edit src/lib.rs"),
            },
        ),
        (
            Origin::TamperWard,
            WardEvent::Anchor {
                chain_head: Blake3Hash::hash(b"head"),
                seq: 28,
                countersigned_by: Some(TamperWardSig {
                    key_id: Blake3Hash::hash(b"key"),
                    signature: SignatureBytes::new(vec![7; 64]).unwrap(),
                }),
                degraded: false,
            },
        ),
        (
            Origin::Wardd,
            WardEvent::SessionPaused {
                method: PauseMethod::Sigstop,
                reason: text("ward pause"),
            },
        ),
        (
            Origin::Wardd,
            WardEvent::SessionResumed {
                paused_for: Duration::from_secs(12),
            },
        ),
        (
            Origin::Wardd,
            WardEvent::EntryRestored {
                snapshot: snap(b"entry"),
                files: 3,
                backup: text(".ward/restore-1700000000"),
            },
        ),
        (
            Origin::User,
            WardEvent::SessionEnded {
                reason: EndReason::UserStop,
                final_snapshot: Some(snap(b"final")),
            },
        ),
    ]
}

#[test]
fn every_catalogue_variant_survives_chain_wire_and_log() {
    let catalogue = full_catalogue();
    let kinds: std::collections::BTreeSet<EventKind> =
        catalogue.iter().map(|(_, e)| e.kind()).collect();
    assert_eq!(
        kinds.len(),
        EventKind::ALL.len(),
        "catalogue fixture must cover every kind"
    );

    let session = SessionId::from_u128(0x5e55);
    let manifest = Blake3Hash::hash(b"manifest");
    let mut chain = Chain::genesis(session, manifest);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.log");
    let mut writer = LogWriter::create(&path, chain.head(), FsyncPolicy::DEFAULT).unwrap();

    let mut records = Vec::new();
    for (i, (origin, event)) in catalogue.into_iter().enumerate() {
        let ts = Timestamp {
            mono: Duration::from_millis(i as u64),
            wall: Some(
                std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000 + i as u64),
            ),
        };
        let record = chain.append(origin, event, ts).unwrap();
        let frame = encode_record(&record).unwrap();
        let (decoded, _) = decode_record(&frame).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(record.is_enforcement_fact(), origin != Origin::Agent);
        writer.append(&record).unwrap();
        records.push(record);
    }
    let sealed = writer.seal().unwrap();
    assert_eq!(sealed, chain.head());
    assert_eq!(verify(&records).unwrap(), sealed);

    let read: Vec<_> = LogReader::open(&path)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(read, records);

    // The sanitiser did its job on the hostile field in the fixture.
    let raw = records
        .iter()
        .find(|r| {
            matches!(
                r.event,
                WardEvent::NetworkDenied {
                    dst: DeniedDst::Raw { .. },
                    ..
                }
            )
        })
        .unwrap();
    if let WardEvent::NetworkDenied {
        dst: DeniedDst::Raw { target },
        ..
    } = &raw.event
    {
        assert_eq!(target.as_str(), "[2Jgarbage");
        assert!(target.original_hash().is_some());
    }

    // Filters agree with origins and kinds.
    let facts = records
        .iter()
        .filter(|r| Filter::enforcement_facts().matches(r))
        .count();
    assert_eq!(
        facts,
        records.iter().filter(|r| r.origin != Origin::Agent).count()
    );
    let quiet = records
        .iter()
        .filter(|r| Filter::quiet().matches(r))
        .count();
    // The nine of Quiet mode plus the three host interventions (ADR-0019 §3).
    assert_eq!(quiet, 12);
}

#[test]
fn credential_granted_has_no_secret_bearing_field() {
    // A compile-time-ish guard: constructing the variant needs exactly these fields.
    let ev = WardEvent::CredentialGranted {
        service: ServiceId::new("github").unwrap(),
        scope: Scope::default(),
        expires: Duration::from_secs(1),
        delivery: CredentialDelivery::MintedToken,
    };
    let rendered = format!("{ev:?}");
    for word in ["token", "secret", "password", "key"] {
        assert!(
            !rendered.to_ascii_lowercase().contains(&format!("{word}:")),
            "{rendered}"
        );
    }
}
