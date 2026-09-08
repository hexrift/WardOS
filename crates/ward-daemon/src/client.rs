//! `ward` as a client of a running daemon (ADR-0015): the evidence producer and
//! the observer's subscription, both over the session's control socket.
//!
//! [`append_evidence`] is `ward evidence append`: a `TamperWard`-origin record
//! appended on TamperWard's behalf (`tamperward-integration.md` §2). [`watch`] is
//! `ward watch`: [`Request::Subscribe`] and one observer row per record until the
//! daemon closes the stream, which it does when the log is sealed. Neither touches
//! the log: with no daemon they fail with [`NO_DAEMON`] instead of falling back to
//! a local writer, because a producer that opened the log itself would fork the
//! chain the daemon owns.

use std::path::{Path, PathBuf};

use ward_events::{EventKind, EventRecord, WardEvent};

use crate::control::{RemoteSink, Request, Response, SOCKET_NAME, is_evidence};
use crate::error::{Error, Result};
use crate::render;
use crate::session::{SessionMeta, session_dir};

/// The message printed when the current session has no daemon listening.
pub const NO_DAEMON: &str = "no daemon is serving this session (run ward up)";

/// The kinds `ward evidence append` accepts, in the order of the catalogue.
pub const EVIDENCE_KINDS: [EventKind; 4] = [
    EventKind::PolicyDecision,
    EventKind::PolicyDenied,
    EventKind::TamperDetected,
    EventKind::StateAccepted,
];

/// The control socket of `project_dir`'s current session, whether or not a daemon
/// listens on it.
pub fn socket_path(project_dir: &Path, state: &Path) -> Result<PathBuf> {
    let meta = SessionMeta::current(project_dir, state)?.ok_or_else(|| {
        Error::Project(format!(
            "no session for {}; run `ward up {0}` to start one",
            project_dir.display()
        ))
    })?;
    Ok(session_dir(state, &meta.id).join(SOCKET_NAME))
}

/// Connect to the daemon on `socket`; [`NO_DAEMON`] when nothing answers there.
pub fn connect(socket: &Path) -> Result<RemoteSink> {
    RemoteSink::connect(socket).ok_or_else(|| Error::Project(NO_DAEMON.to_owned()))
}

/// Parse one `WardEvent` from its serde JSON and check it is an evidence kind,
/// with the same rule the daemon applies ([`is_evidence`]), so a refused record
/// never reaches the socket.
///
/// `detail` may be given as a bare string; it is lifted to the `DetailText`
/// object (`{"text": …, "truncated": false}`) before parsing.
pub fn parse_evidence(json: &str) -> Result<WardEvent> {
    let mut value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| Error::Events(format!("evidence JSON: {e}")))?;
    lift_detail(&mut value);
    // Some fields borrow from the input, so parse text, not a `Value`.
    let text = serde_json::to_string(&value).map_err(|e| Error::Events(e.to_string()))?;
    let event: WardEvent =
        serde_json::from_str(&text).map_err(|e| Error::Events(format!("evidence JSON: {e}")))?;
    if is_evidence(&event) {
        Ok(event)
    } else {
        let allowed: Vec<String> = EVIDENCE_KINDS.iter().map(ToString::to_string).collect();
        Err(Error::Events(format!(
            "{} is not an evidence kind (one of {})",
            event.kind(),
            allowed.join(", ")
        )))
    }
}

/// `{"Kind": {"detail": "text"}}` → `{"Kind": {"detail": {"text": "text", …}}}`.
fn lift_detail(value: &mut serde_json::Value) {
    let Some(variants) = value.as_object_mut() else {
        return;
    };
    for body in variants.values_mut() {
        let Some(fields) = body.as_object_mut() else {
            continue;
        };
        if let Some(text) = fields.get("detail").and_then(serde_json::Value::as_str) {
            let text = text.to_owned();
            fields.insert(
                "detail".to_owned(),
                serde_json::json!({ "text": text, "truncated": false, "original_hash": null }),
            );
        }
    }
}

/// Append `event` with `origin = TamperWard` through the daemon.
pub fn append_evidence(sink: &mut RemoteSink, event: WardEvent) -> Result<EventRecord> {
    match sink.call(&Request::Evidence { event })? {
        Response::Record(record) => Ok(*record),
        Response::Error(e) => Err(Error::Events(format!("daemon refused evidence: {e}"))),
        other => Err(Error::Events(format!("unexpected response {other:?}"))),
    }
}

/// What `ward watch` prints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchOptions {
    /// First sequence number to deliver (records already in the log come first).
    pub from_seq: u64,
    /// Also print the kinds the compact observer view hides, as a dim kind name.
    pub all: bool,
}

/// How a watch ended. Ctrl-C is not an outcome: SIGINT terminates the process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchEnd {
    /// The daemon closed the stream: the log is sealed (or the daemon is gone).
    Closed {
        /// Records received.
        records: u64,
    },
    /// The daemon reported the seal explicitly before closing.
    Sealed {
        /// Records received.
        records: u64,
    },
}

impl WatchEnd {
    /// Records received before the stream ended.
    #[must_use]
    pub const fn records(&self) -> u64 {
        match self {
            Self::Closed { records } | Self::Sealed { records } => *records,
        }
    }
}

/// The observer row for `rec`: [`render::observer_row`], or with `all` the dim
/// [`render::kind_row`] for the kinds the compact view hides.
#[must_use]
pub fn row(rec: &EventRecord, all: bool) -> Option<String> {
    render::observer_row(rec).or_else(|| all.then(|| render::kind_row(rec)))
}

/// Subscribe from `opts.from_seq` and hand `emit` one row per record as it
/// arrives, until the daemon ends the stream.
pub fn watch(
    mut sink: RemoteSink,
    opts: WatchOptions,
    mut emit: impl FnMut(String),
) -> Result<WatchEnd> {
    // A quiet session is not a dead daemon: wait as long as the stream is open.
    sink.set_read_timeout(None)?;
    sink.send(&Request::Subscribe {
        from_seq: opts.from_seq,
    })?;
    let mut records = 0;
    loop {
        match sink.next_response()? {
            Some(Response::Record(rec)) => {
                records += 1;
                if let Some(line) = row(&rec, opts.all) {
                    emit(line);
                }
            }
            Some(Response::Ok) => {}
            Some(Response::Sealed { .. }) => return Ok(WatchEnd::Sealed { records }),
            Some(Response::Error(e)) => {
                return Err(Error::Events(format!("daemon refused subscribe: {e}")));
            }
            Some(other) => return Err(Error::Events(format!("unexpected response {other:?}"))),
            None => return Ok(WatchEnd::Closed { records }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread::JoinHandle;
    use std::time::Duration;
    use tempfile::TempDir;
    use ward_events::{
        Acceptor, AgentState, Blake3Hash, Chain, DetailText, Origin, PolicySubject, RuleRef,
        SessionId, SnapshotId, Timestamp,
    };

    const DENIED: &str = r#"{"PolicyDenied":{"subject":"ProtectedTests","rule":"protected-tests","detail":{"text":"tests/verify.rs","truncated":false}}}"#;
    const TAMPER: &str =
        r#"{"TamperDetected":{"subject":"VerifyConfig","detail":".tamperward/config.yml"}}"#;
    const ACCEPTED: &str = r#"{"StateAccepted":{"snapshot":"abababababababababababababababababababababababababababababababab","by":"TamperWard"}}"#;
    const DECISION: &str = r#"{"PolicyDecision":{"subject":"Session","decision":"Allow","rule":"session-open","detail":"ok"}}"#;

    fn plain(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn denied() -> WardEvent {
        WardEvent::PolicyDenied {
            subject: PolicySubject::ProtectedTests,
            rule: RuleRef::new("protected-tests").unwrap(),
            detail: DetailText::new("tests/verify.rs"),
        }
    }

    fn tamper() -> WardEvent {
        WardEvent::TamperDetected {
            subject: PolicySubject::VerifyConfig,
            detail: DetailText::new(".tamperward/config.yml"),
        }
    }

    fn accepted() -> WardEvent {
        WardEvent::StateAccepted {
            snapshot: SnapshotId::new(Blake3Hash::from_bytes([0xab; 32])),
            by: Acceptor::TamperWard,
        }
    }

    fn working() -> WardEvent {
        WardEvent::AgentStateChanged {
            state: AgentState::Working,
        }
    }

    /// A chain of synthetic records, one per event, one second apart.
    fn records(events: &[(Origin, WardEvent)]) -> (Chain, Vec<EventRecord>) {
        let mut chain = Chain::genesis(SessionId::from_u128(7), Blake3Hash::from_bytes([1; 32]));
        let records = events
            .iter()
            .enumerate()
            .map(|(i, (origin, event))| {
                chain
                    .append(
                        *origin,
                        event.clone(),
                        Timestamp::mono(Duration::from_secs(i as u64)),
                    )
                    .unwrap()
            })
            .collect();
        (chain, records)
    }

    /// A daemon stand-in serving one connection: `Ping` → `Ok`; `Subscribe` streams
    /// `log` from `from_seq` and closes; `Evidence` appends to `chain` and answers
    /// `Record` (or `refuse`). Returns the requests it saw.
    fn fake_daemon(
        mut chain: Chain,
        log: Vec<EventRecord>,
        refuse: Option<&'static str>,
    ) -> (TempDir, PathBuf, JoinHandle<Vec<Request>>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut seen = Vec::new();
            let reply = |writer: &mut std::os::unix::net::UnixStream, r: &Response| {
                let mut b = serde_json::to_vec(r).unwrap();
                b.push(b'\n');
                writer.write_all(&b).unwrap();
            };
            for line in BufReader::new(stream)
                .lines()
                .map_while(std::result::Result::ok)
            {
                let request: Request = serde_json::from_str(&line).unwrap();
                seen.push(request.clone());
                match request {
                    Request::Ping => reply(&mut writer, &Response::Ok),
                    Request::Subscribe { from_seq } => {
                        if let Some(e) = refuse {
                            reply(&mut writer, &Response::Error(e.into()));
                        }
                        for rec in log.iter().filter(|r| r.seq >= from_seq) {
                            reply(&mut writer, &Response::Record(Box::new(rec.clone())));
                        }
                        break;
                    }
                    Request::Evidence { event } => {
                        let response = match refuse {
                            Some(e) => Response::Error(e.into()),
                            None => Response::Record(Box::new(
                                chain
                                    .append(
                                        Origin::TamperWard,
                                        event,
                                        Timestamp::mono(Duration::from_secs(9)),
                                    )
                                    .unwrap(),
                            )),
                        };
                        reply(&mut writer, &response);
                    }
                    other => panic!("unexpected request {other:?}"),
                }
            }
            seen
        });
        (dir, socket, server)
    }

    #[test]
    fn parse_evidence_accepts_each_evidence_kind() {
        assert_eq!(parse_evidence(DENIED).unwrap(), denied());
        assert_eq!(parse_evidence(TAMPER).unwrap(), tamper());
        assert_eq!(parse_evidence(ACCEPTED).unwrap(), accepted());
        assert!(matches!(
            parse_evidence(DECISION).unwrap(),
            WardEvent::PolicyDecision {
                decision: ward_events::Decision::Allow,
                ..
            }
        ));
    }

    #[test]
    fn parse_evidence_lifts_a_bare_detail_string() {
        let long = r#"{"TamperDetected":{"subject":"VerifyConfig","detail":{"text":".tamperward/config.yml","truncated":false,"original_hash":null}}}"#;
        assert_eq!(
            parse_evidence(TAMPER).unwrap(),
            parse_evidence(long).unwrap()
        );
    }

    #[test]
    fn parse_evidence_refuses_non_evidence_kinds_client_side() {
        let json = serde_json::to_string(&working()).unwrap();
        let err = parse_evidence(&json).unwrap_err().to_string();
        assert!(
            err.contains("agent_state_changed is not an evidence kind"),
            "{err}"
        );
        assert!(err.contains("policy_decision, policy_denied, tamper_detected, state_accepted"));
        let ended = serde_json::to_string(&WardEvent::SessionEnded {
            reason: ward_events::EndReason::UserStop,
            final_snapshot: None,
        })
        .unwrap();
        assert!(parse_evidence(&ended).is_err());
        // The client-side rule is the daemon's rule.
        for json in [DENIED, TAMPER, ACCEPTED, DECISION] {
            assert!(is_evidence(&parse_evidence(json).unwrap()));
        }
    }

    #[test]
    fn parse_evidence_reports_malformed_json_and_unknown_variants() {
        let err = parse_evidence("{not json").unwrap_err().to_string();
        assert!(err.starts_with("events: evidence JSON:"), "{err}");
        let err = parse_evidence(r#"{"Bogus":{}}"#).unwrap_err().to_string();
        assert!(err.contains("evidence JSON"), "{err}");
        let err = parse_evidence(r#"{"PolicyDenied":{"subject":"ProtectedTests"}}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing field"), "{err}");
    }

    #[test]
    fn row_hides_quiet_kinds_unless_all() {
        let (_, recs) = records(&[(Origin::Wardd, working()), (Origin::TamperWard, denied())]);
        assert_eq!(row(&recs[0], false), None);
        assert_eq!(
            plain(&row(&recs[0], true).unwrap()),
            "00:00  agent_state_changed"
        );
        assert_eq!(
            plain(&row(&recs[1], false).unwrap()),
            "00:01  DENIED protected tests · rule protected-tests · tests/verify.rs"
        );
    }

    #[test]
    fn connect_reports_no_daemon_and_socket_path_needs_a_session() {
        let dir = tempfile::tempdir().unwrap();
        let err = connect(&dir.path().join(SOCKET_NAME))
            .err()
            .expect("nothing listens");
        assert_eq!(err.to_string(), NO_DAEMON);
        let state = dir.path().join("state");
        let err = socket_path(dir.path(), &state).unwrap_err().to_string();
        assert!(err.starts_with("no session for "), "{err}");
    }

    #[test]
    fn watch_yields_the_rows_in_order_and_ends_when_the_stream_closes() {
        let (chain, log) = records(&[
            (Origin::TamperWard, denied()),
            (Origin::TamperWard, tamper()),
            (Origin::TamperWard, accepted()),
        ]);
        let (_dir, socket, server) = fake_daemon(chain, log, None);
        let sink = connect(&socket).expect("fake daemon answers ping");
        let mut rows = Vec::new();
        let end = watch(sink, WatchOptions::default(), |r| rows.push(plain(&r))).unwrap();
        assert_eq!(end, WatchEnd::Closed { records: 3 });
        assert_eq!(end.records(), 3);
        assert_eq!(
            rows,
            vec![
                "00:00  DENIED protected tests · rule protected-tests · tests/verify.rs",
                "00:01  TAMPER verify config · .tamperward/config.yml",
                "00:02  ACCEPT snapshot abababababab",
            ]
        );
        let seen = server.join().unwrap();
        assert_eq!(
            seen,
            vec![Request::Ping, Request::Subscribe { from_seq: 0 }],
            "one ping, one subscribe, nothing appended"
        );
    }

    #[test]
    fn watch_honours_from_seq_and_all() {
        let events = [
            (Origin::TamperWard, denied()),
            (Origin::Wardd, working()),
            (Origin::TamperWard, accepted()),
        ];
        let (chain, log) = records(&events);
        let (_dir, socket, _) = fake_daemon(chain, log, None);
        let sink = connect(&socket).unwrap();
        let mut rows = Vec::new();
        let opts = WatchOptions {
            from_seq: 1,
            all: false,
        };
        let end = watch(sink, opts, |r| rows.push(plain(&r))).unwrap();
        assert_eq!(end.records(), 2, "seq 0 is not delivered");
        assert_eq!(rows, vec!["00:02  ACCEPT snapshot abababababab"]);

        let (chain, log) = records(&events);
        let (_dir, socket, _) = fake_daemon(chain, log, None);
        let sink = connect(&socket).unwrap();
        let mut rows = Vec::new();
        let opts = WatchOptions {
            from_seq: 1,
            all: true,
        };
        watch(sink, opts, |r| rows.push(plain(&r))).unwrap();
        assert_eq!(
            rows,
            vec![
                "00:01  agent_state_changed",
                "00:02  ACCEPT snapshot abababababab"
            ]
        );
    }

    #[test]
    fn watch_surfaces_the_daemons_refusal() {
        let (chain, log) = records(&[]);
        let (_dir, socket, _) = fake_daemon(chain, log, Some("log is sealed"));
        let sink = connect(&socket).unwrap();
        let err = watch(sink, WatchOptions::default(), |_| {}).unwrap_err();
        assert_eq!(
            err.to_string(),
            "events: daemon refused subscribe: log is sealed"
        );
    }

    #[test]
    fn evidence_is_appended_through_the_daemon_with_tamperward_origin() {
        let (chain, log) = records(&[(Origin::Wardd, working())]);
        let (_dir, socket, server) = fake_daemon(chain, log, None);
        let mut sink = connect(&socket).unwrap();
        let rec = append_evidence(&mut sink, parse_evidence(TAMPER).unwrap()).unwrap();
        assert_eq!(rec.seq, 1);
        assert_eq!(rec.origin, Origin::TamperWard);
        assert_eq!(rec.event, tamper());
        assert_eq!(
            plain(&row(&rec, false).unwrap()),
            "00:09  TAMPER verify config · .tamperward/config.yml"
        );
        drop(sink);
        let seen = server.join().unwrap();
        assert_eq!(seen[1], Request::Evidence { event: tamper() });
    }

    #[test]
    fn evidence_refused_by_the_daemon_is_an_error() {
        let (chain, log) = records(&[]);
        let (_dir, socket, _) = fake_daemon(chain, log, Some("not an evidence kind"));
        let mut sink = connect(&socket).unwrap();
        let err = append_evidence(&mut sink, denied()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "events: daemon refused evidence: not an evidence kind"
        );
    }
}
