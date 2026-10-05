//! `ward replay --stats`: the approval-load statistics experiment E-13 asks for
//! (`docs/experiments.md` E-13; #150 item 6), derived from one session log's records.
//!
//! Every `CapabilityRequested` record is paired with its terminal `CapabilityDecided`
//! record by the request's identity — its [`CapabilityRequest`] (kind and target), the
//! same key the daemon's hold remembers an `allow-session` under — never by position
//! or by how close the two records are. A decision whose identity matches no open
//! request is reported as unpaired and pairs with nothing. When several identical
//! requests are open at once the log cannot say which one a decision answers, so the
//! outcome is counted but its latency is reported as ambiguous rather than guessed.
//! A request with no terminal record by the end of the log is *censored*: still
//! pending, never a decision, never in any latency figure. Anything the log cannot
//! support is reported as unmeasured with a reason, never as zero, mirroring
//! `ward benchmark`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use ward_bench::stats::Samples;
use ward_events::{
    CapabilityRequest, Decision, DecisionSource, EventRecord, GrantScope, LogReader, SessionId,
    WardEvent,
};

use crate::replay::{self, Options};

/// Bumped whenever a field is removed or its meaning changes; additive fields do not
/// require a bump.
pub const SCHEMA_VERSION: u32 = 1;

const TOOL: &str = "ward replay --stats";
const MS_PER_HOUR: f64 = 3_600_000.0;

/// A figure the log either supports or does not.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Measure<T> {
    /// The log carried what the figure needs.
    Measured {
        /// The figure.
        value: T,
    },
    /// The log cannot support the figure; `reason` says why.
    Unmeasured {
        /// Why the figure is absent.
        reason: String,
    },
}

/// What `ward replay --verify` would have said about the log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LogFacts {
    /// Records read before the end of the log or the first break.
    pub records: u64,
    /// Whether the chain read to a clean end and matched the sealed `HEAD`.
    pub verified: bool,
    /// State of the sealed `HEAD` beside the log.
    pub sealed: &'static str,
    /// Why verification failed, if it did.
    pub failure: Option<String>,
}

/// Session wall time from the log's own monotonic timestamps.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Wall {
    /// First record to last record.
    pub span_ms: u64,
    /// Time between a pause record (settled or unsettled) and the resume that ended it;
    /// a pause still open at the end of the log runs to the last record.
    pub paused_ms: u64,
    /// `span_ms` less `paused_ms`.
    pub active_ms: u64,
    /// `active_ms` in hours: the denominator of prompts per agent-hour.
    pub agent_hours: f64,
}

/// Requests settled by a policy rule without a human.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PolicySettled {
    /// Allowed by a rule.
    pub allowed: u64,
    /// Denied by a rule.
    pub denied: u64,
}

/// How the log's `CapabilityRequested` records divide up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Requests {
    /// Every `CapabilityRequested` record.
    pub total: u64,
    /// Requests a human was asked about: `total` less the rows below.
    pub prompts: u64,
    /// Requests made while an `allow-session` for the same identity stood; the daemon
    /// answers these itself.
    pub covered_by_session_grant: u64,
    /// Requests a policy rule settled.
    pub settled_by_policy: PolicySettled,
    /// Requests `TamperWard` settled.
    pub settled_by_tamperward: u64,
    /// `CapabilityDecided` records whose identity matched no open request; paired with
    /// nothing.
    pub unpaired_decisions: u64,
}

/// Terminal outcome of every prompt.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Outcomes {
    /// Allowed for this one request.
    pub allowed_once: u64,
    /// Allowed until the session ends.
    pub allowed_session: u64,
    /// Allowed for a fixed duration.
    pub allowed_until: u64,
    /// Denied by the human.
    pub denied: u64,
    /// The ask expired unanswered (`DecisionSource::Timeout`).
    pub expired: u64,
    /// The session ended with the ask open (`DecisionSource::SessionEnded`).
    pub closed_at_session_end: u64,
    /// No terminal record by the end of the log: still pending.
    pub censored: u64,
}

/// Request-to-decision time over the prompts a human decided.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Latency {
    /// Decided prompts whose pairing was unambiguous.
    pub samples: usize,
    /// Median, milliseconds.
    pub p50_ms: f64,
    /// 99th percentile, milliseconds.
    pub p99_ms: f64,
}

/// `allow-session` answers and what they covered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SessionGrants {
    /// `allow-session` answers to a prompt.
    pub granted: u64,
    /// Later requests those answers covered (the same figure as
    /// `requests.covered_by_session_grant`).
    pub covered_later_requests: u64,
}

/// Requests the sandbox contained without asking anyone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Contained {
    /// `NetworkDenied` records plus `NetworkRequested` records decided `Deny`.
    pub network_denied: u64,
    /// `CapabilityDecided` records a policy rule denied.
    pub policy_denied: u64,
}

/// The versioned report.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StatsReport {
    /// See [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Always `"ward replay --stats"`.
    pub tool: &'static str,
    /// Session id from the records.
    pub session: Option<String>,
    /// Verification facts.
    pub log: LogFacts,
    /// Wall time.
    pub wall: Wall,
    /// Request accounting.
    pub requests: Requests,
    /// Prompts a human allowed or denied: the `allowed_*` and `denied` outcomes.
    pub decisions: u64,
    /// Terminal outcomes.
    pub outcomes: Outcomes,
    /// `requests.prompts` per agent-hour.
    pub prompts_per_agent_hour: Measure<f64>,
    /// Allowed decisions over `decisions`.
    pub approve_rate: Measure<f64>,
    /// Denied decisions over `decisions`.
    pub deny_rate: Measure<f64>,
    /// `allow-session` decisions over `decisions`.
    pub allow_session_rate: Measure<f64>,
    /// Request-to-decision time.
    pub decision_latency: Measure<Latency>,
    /// Decisions counted but not timed because several identical requests were open.
    pub decision_latency_ambiguous: u64,
    /// Requests whose identity an earlier `allow-once` had already answered.
    pub repeated_after_allow_once: u64,
    /// `allow-session` answers.
    pub session_grants: SessionGrants,
    /// Contained by the sandbox.
    pub contained: Contained,
    /// `CredentialGranted` records.
    pub credentials_granted: u64,
    /// Asks a policy line would have settled; needs the session's policy.
    pub missing_policy_requests: Measure<u64>,
    /// Switches to the unrestricted network mode; no record kind carries it.
    pub unrestricted_network_switches: Measure<u64>,
    /// Agent runs on the same host without a session; outside the log by definition.
    pub launches_outside_ward: Measure<u64>,
}

/// Rendered statistics for one log.
#[derive(Clone, Debug, PartialEq)]
pub struct Output {
    /// Whether the log verified.
    pub ok: bool,
    /// The report.
    pub report: StatsReport,
    /// JSON or text, newline-terminated.
    pub output: String,
}

struct Open {
    ts: Duration,
    key: String,
    covered: bool,
}

fn key(cap: &CapabilityRequest) -> String {
    format!("{:?} {}", cap.kind, cap.target)
}

/// Raw counters over a record stream, before rates and percentiles.
#[derive(Default)]
pub struct Collected {
    session: Option<SessionId>,
    first_ts: Option<Duration>,
    last_ts: Option<Duration>,
    pause_started: Option<Duration>,
    paused: Duration,
    open: Vec<Open>,
    active_grants: BTreeSet<String>,
    allowed_once_keys: BTreeSet<String>,
    requests: u64,
    covered: u64,
    policy: PolicySettled,
    tamperward: u64,
    unpaired: u64,
    outcomes: Outcomes,
    latencies: Vec<Duration>,
    ambiguous: u64,
    repeated: u64,
    network_denied: u64,
    credentials_granted: u64,
}

impl Collected {
    fn apply(&mut self, rec: &EventRecord) {
        let ts = rec.ts_mono;
        self.session.get_or_insert(rec.session);
        self.first_ts.get_or_insert(ts);
        self.last_ts = Some(ts);
        match &rec.event {
            WardEvent::SessionPaused { .. } | WardEvent::SessionPauseUnsettled { .. } => {
                self.pause_started.get_or_insert(ts);
            }
            WardEvent::SessionResumed { .. } => {
                if let Some(start) = self.pause_started.take() {
                    self.paused += ts.saturating_sub(start);
                }
            }
            WardEvent::CapabilityRequested { cap, .. } => self.request(key(cap), ts),
            WardEvent::CapabilityDecided {
                cap,
                decision,
                by,
                grant,
            } => self.decide(&key(cap), ts, *decision, by, *grant),
            WardEvent::NetworkDenied { .. }
            | WardEvent::NetworkRequested {
                decision: Decision::Deny,
                ..
            } => self.network_denied += 1,
            WardEvent::CredentialGranted { .. } => self.credentials_granted += 1,
            _ => {}
        }
    }

    fn request(&mut self, key: String, ts: Duration) {
        self.requests += 1;
        let covered = self.active_grants.contains(&key);
        if covered {
            self.covered += 1;
        } else if self.allowed_once_keys.contains(&key) {
            self.repeated += 1;
        }
        self.open.push(Open { ts, key, covered });
    }

    fn decide(
        &mut self,
        key: &str,
        ts: Duration,
        decision: Decision,
        by: &DecisionSource,
        grant: Option<GrantScope>,
    ) {
        let mut matching = self.open.iter().enumerate().filter(|(_, o)| o.key == key);
        let Some((index, _)) = matching.next() else {
            self.unpaired += 1;
            return;
        };
        let ambiguous = matching.next().is_some();
        let request = self.open.remove(index);
        if request.covered {
            return;
        }
        let allowed = decision == Decision::Allow;
        match by {
            DecisionSource::SessionEnded => self.outcomes.closed_at_session_end += 1,
            DecisionSource::Timeout => self.outcomes.expired += 1,
            DecisionSource::TamperWard => self.tamperward += 1,
            DecisionSource::Policy { .. } if allowed => self.policy.allowed += 1,
            DecisionSource::Policy { .. } => self.policy.denied += 1,
            DecisionSource::User => {
                match (allowed, grant) {
                    (false, _) => self.outcomes.denied += 1,
                    (true, Some(GrantScope::Session)) => {
                        self.outcomes.allowed_session += 1;
                        self.active_grants.insert(key.to_owned());
                        self.allowed_once_keys.remove(key);
                    }
                    (true, Some(GrantScope::Until { .. })) => self.outcomes.allowed_until += 1,
                    (true, Some(GrantScope::Once) | None) => {
                        self.outcomes.allowed_once += 1;
                        self.allowed_once_keys.insert(key.to_owned());
                    }
                }
                if ambiguous {
                    self.ambiguous += 1;
                } else {
                    self.latencies.push(ts.saturating_sub(request.ts));
                }
            }
        }
    }

    fn finish(&mut self) {
        self.outcomes.censored = u64::try_from(self.open.len()).unwrap_or(u64::MAX);
        if let Some((start, last)) = self.pause_started.take().zip(self.last_ts) {
            self.paused += last.saturating_sub(start);
        }
    }
}

/// Account for every record in order.
#[must_use]
pub fn collect(records: &[EventRecord]) -> Collected {
    let mut collected = Collected::default();
    for rec in records {
        collected.apply(rec);
    }
    collected.finish();
    collected
}

#[allow(clippy::cast_precision_loss)]
fn as_f64(n: u64) -> f64 {
    n as f64
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    as_f64(numerator) / as_f64(denominator)
}

fn hours(ms: u64) -> f64 {
    as_f64(ms) / MS_PER_HOUR
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn rate(numerator: u64, decisions: u64) -> Measure<f64> {
    if decisions == 0 {
        Measure::Unmeasured {
            reason: "no prompt was decided by a human".to_owned(),
        }
    } else {
        Measure::Measured {
            value: ratio(numerator, decisions),
        }
    }
}

/// Build the report from the counters and the verification facts.
#[must_use]
pub fn build(c: &Collected, log: LogFacts) -> StatsReport {
    let span = c
        .first_ts
        .zip(c.last_ts)
        .map_or(Duration::ZERO, |(first, last)| last.saturating_sub(first));
    let active = span.saturating_sub(c.paused);
    let wall = Wall {
        span_ms: ms(span),
        paused_ms: ms(c.paused),
        active_ms: ms(active),
        agent_hours: hours(ms(active)),
    };
    let prompts = c.requests - c.covered - c.policy.allowed - c.policy.denied - c.tamperward;
    let o = &c.outcomes;
    let decisions = o.allowed_once + o.allowed_session + o.allowed_until + o.denied;
    let prompts_per_agent_hour = if wall.active_ms == 0 {
        Measure::Unmeasured {
            reason: "the log spans no active time".to_owned(),
        }
    } else {
        Measure::Measured {
            value: as_f64(prompts) / wall.agent_hours,
        }
    };
    let samples = Samples {
        durations: c.latencies.clone(),
        ..Samples::default()
    };
    let decision_latency = match samples.p50_ms().zip(samples.p99_ms()) {
        Some((p50_ms, p99_ms)) => Measure::Measured {
            value: Latency {
                samples: samples.count(),
                p50_ms,
                p99_ms,
            },
        },
        None if c.ambiguous > 0 => Measure::Unmeasured {
            reason: "every decided prompt had an identical request open alongside it".to_owned(),
        },
        None => Measure::Unmeasured {
            reason: "no prompt was decided by a human".to_owned(),
        },
    };
    StatsReport {
        schema_version: SCHEMA_VERSION,
        tool: TOOL,
        session: c.session.map(|id| id.to_string()),
        log,
        wall,
        requests: Requests {
            total: c.requests,
            prompts,
            covered_by_session_grant: c.covered,
            settled_by_policy: c.policy,
            settled_by_tamperward: c.tamperward,
            unpaired_decisions: c.unpaired,
        },
        decisions,
        outcomes: o.clone(),
        prompts_per_agent_hour,
        approve_rate: rate(
            o.allowed_once + o.allowed_session + o.allowed_until,
            decisions,
        ),
        deny_rate: rate(o.denied, decisions),
        allow_session_rate: rate(o.allowed_session, decisions),
        decision_latency,
        decision_latency_ambiguous: c.ambiguous,
        repeated_after_allow_once: c.repeated,
        session_grants: SessionGrants {
            granted: o.allowed_session,
            covered_later_requests: c.covered,
        },
        contained: Contained {
            network_denied: c.network_denied,
            policy_denied: c.policy.denied,
        },
        credentials_granted: c.credentials_granted,
        missing_policy_requests: Measure::Unmeasured {
            reason: "needs the session's policy, which the log does not carry".to_owned(),
        },
        unrestricted_network_switches: Measure::Unmeasured {
            reason: "no record kind carries the network mode".to_owned(),
        },
        launches_outside_ward: Measure::Unmeasured {
            reason: "outside the log by definition (host shell history, agent logs)".to_owned(),
        },
    }
}

fn read_records(path: &Path) -> ward_daemon::Result<Vec<EventRecord>> {
    let reader = LogReader::open(path)
        .map_err(|e| ward_daemon::Error::Events(format!("cannot open {}: {e}", path.display())))?;
    Ok(reader.map_while(Result::ok).collect())
}

/// Statistics for the log at `path`, as JSON or text.
///
/// # Errors
/// [`ward_daemon::Error::Events`] if the log cannot be opened or the report cannot be
/// rendered.
pub fn run(path: &Path, json: bool) -> ward_daemon::Result<Output> {
    let verdict = replay::replay(
        path,
        Options {
            verify: true,
            json: false,
        },
    )?;
    let records = read_records(path)?;
    let facts = LogFacts {
        records: verdict.records,
        verified: verdict.ok(),
        sealed: replay::sealed_label(verdict.sealed),
        failure: verdict.failure.as_ref().map(replay::failure_text),
    };
    let report = build(&collect(&records), facts);
    let output = if json {
        let mut text = serde_json::to_string_pretty(&report)
            .map_err(|e| ward_daemon::Error::Events(format!("cannot render statistics: {e}")))?;
        text.push('\n');
        text
    } else {
        text(&report)
    };
    Ok(Output {
        ok: verdict.ok(),
        report,
        output,
    })
}

fn hms(ms: u64) -> String {
    let secs = ms / 1000;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

fn measure_text<T>(m: &Measure<T>, render: impl Fn(&T) -> String) -> String {
    match m {
        Measure::Measured { value } => render(value),
        Measure::Unmeasured { .. } => "unmeasured".to_owned(),
    }
}

fn rate_text(m: &Measure<f64>) -> String {
    measure_text(m, |v| format!("{v:.2}"))
}

/// The concise text report.
#[must_use]
pub fn text(r: &StatsReport) -> String {
    let mut out = String::new();
    let chain = if r.log.verified {
        "chain VERIFIED".to_owned()
    } else {
        r.log
            .failure
            .clone()
            .unwrap_or_else(|| "chain not verified".to_owned())
    };
    let _ = writeln!(
        out,
        "  E-13 approval load · session {} · {} records · {chain} · sealed head {}",
        r.session.as_deref().unwrap_or("unknown"),
        r.log.records,
        r.log.sealed
    );
    let _ = writeln!(
        out,
        "  wall {} active ({} paused) · {:.4} agent-hours",
        hms(r.wall.active_ms),
        hms(r.wall.paused_ms),
        r.wall.agent_hours
    );
    let q = &r.requests;
    let _ = writeln!(
        out,
        "  requests {} · prompts {} · covered by allow-session {} · settled by policy {} \
         ({} allowed / {} denied) · settled by TamperWard {} · unpaired decisions {}",
        q.total,
        q.prompts,
        q.covered_by_session_grant,
        q.settled_by_policy.allowed + q.settled_by_policy.denied,
        q.settled_by_policy.allowed,
        q.settled_by_policy.denied,
        q.settled_by_tamperward,
        q.unpaired_decisions
    );
    let o = &r.outcomes;
    let _ = writeln!(
        out,
        "  decisions {} · allowed {} (once {} · session {} · until {}) · denied {} · \
         expired {} · closed at session end {} · censored {} (still pending, not decided)",
        r.decisions,
        o.allowed_once + o.allowed_session + o.allowed_until,
        o.allowed_once,
        o.allowed_session,
        o.allowed_until,
        o.denied,
        o.expired,
        o.closed_at_session_end,
        o.censored
    );
    let _ = writeln!(
        out,
        "  prompts per agent-hour {} · approve rate {} · deny rate {} · allow-session rate {}",
        measure_text(&r.prompts_per_agent_hour, |v| format!("{v:.2}")),
        rate_text(&r.approve_rate),
        rate_text(&r.deny_rate),
        rate_text(&r.allow_session_rate)
    );
    let _ = writeln!(
        out,
        "  decision latency {} · ambiguous {}",
        measure_text(&r.decision_latency, |l| format!(
            "p50 {:.0} ms · p99 {:.0} ms · n {}",
            l.p50_ms, l.p99_ms, l.samples
        )),
        r.decision_latency_ambiguous
    );
    let _ = writeln!(
        out,
        "  repeated after allow-once {} · session grants {} covering {} later requests · \
         contained {} (network {} · policy {}) · credentials granted {}",
        r.repeated_after_allow_once,
        r.session_grants.granted,
        r.session_grants.covered_later_requests,
        r.contained.network_denied + r.contained.policy_denied,
        r.contained.network_denied,
        r.contained.policy_denied,
        r.credentials_granted
    );
    let _ = writeln!(out, "  unmeasured: {}", unmeasured(r).join(" · "));
    out
}

fn note_unmeasured<T>(into: &mut Vec<String>, name: &str, m: &Measure<T>) {
    if let Measure::Unmeasured { reason } = m {
        into.push(format!("{name} ({reason})"));
    }
}

fn unmeasured(r: &StatsReport) -> Vec<String> {
    let mut list = Vec::new();
    note_unmeasured(
        &mut list,
        "prompts per agent-hour",
        &r.prompts_per_agent_hour,
    );
    note_unmeasured(&mut list, "approve rate", &r.approve_rate);
    note_unmeasured(&mut list, "deny rate", &r.deny_rate);
    note_unmeasured(&mut list, "allow-session rate", &r.allow_session_rate);
    note_unmeasured(&mut list, "decision latency", &r.decision_latency);
    note_unmeasured(
        &mut list,
        "missing-policy requests",
        &r.missing_policy_requests,
    );
    note_unmeasured(
        &mut list,
        "unrestricted-network switches",
        &r.unrestricted_network_switches,
    );
    note_unmeasured(&mut list, "launches outside ward", &r.launches_outside_ward);
    list
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use ward_events::{
        AgentIdentity, AgentKind, Blake3Hash, CapabilityKind, Chain, CredentialDelivery, DeniedDst,
        DenyReason, EndReason, FsyncPolicy, HostName, LogWriter, NameText, Origin, PauseMethod,
        ProjectId, RuleRef, Scope, ServiceId, ShortText, SnapshotId, Timestamp,
    };

    use super::*;

    fn cap(target: &str) -> CapabilityRequest {
        CapabilityRequest {
            kind: CapabilityKind::FileWrite,
            target: ShortText::new(target),
        }
    }

    fn requested(target: &str) -> WardEvent {
        WardEvent::CapabilityRequested {
            cap: cap(target),
            reason: None,
        }
    }

    fn user(target: &str, decision: Decision, grant: Option<GrantScope>) -> WardEvent {
        WardEvent::CapabilityDecided {
            cap: cap(target),
            decision,
            by: DecisionSource::User,
            grant,
        }
    }

    fn by(target: &str, decision: Decision, by: DecisionSource) -> WardEvent {
        WardEvent::CapabilityDecided {
            cap: cap(target),
            decision,
            by,
            grant: None,
        }
    }

    fn started() -> WardEvent {
        WardEvent::SessionStarted {
            project: ProjectId::from_u128(9),
            agent: AgentIdentity {
                kind: AgentKind::Other,
                name: NameText::new("shell"),
                version: NameText::new("0.1.0"),
                image: None,
            },
            manifest_hash: Blake3Hash::hash(b"manifest"),
            entry_snapshot: SnapshotId::new(Blake3Hash::hash(b"entry")),
            policy_hash: Blake3Hash::hash(b"policy"),
            tool_images: Vec::new(),
        }
    }

    fn ended() -> WardEvent {
        WardEvent::SessionEnded {
            reason: EndReason::UserStop,
            final_snapshot: None,
        }
    }

    fn records(events: Vec<(u64, WardEvent)>) -> Vec<EventRecord> {
        let mut chain = Chain::genesis(SessionId::from_u128(42), Blake3Hash::hash(b"manifest"));
        events
            .into_iter()
            .map(|(ms, event)| {
                let ts = Timestamp::mono(Duration::from_millis(ms));
                chain.append(Origin::Wardd, event, ts).unwrap()
            })
            .collect()
    }

    fn facts() -> LogFacts {
        LogFacts {
            records: 0,
            verified: true,
            sealed: "matches",
            failure: None,
        }
    }

    fn report(events: Vec<(u64, WardEvent)>) -> StatsReport {
        let recs = records(events);
        let mut facts = facts();
        facts.records = u64::try_from(recs.len()).unwrap();
        build(&collect(&recs), facts)
    }

    fn measured<T: Clone>(m: &Measure<T>) -> T {
        match m {
            Measure::Measured { value } => value.clone(),
            Measure::Unmeasured { reason } => panic!("unmeasured: {reason}"),
        }
    }

    fn bucket_sum(r: &StatsReport) -> u64 {
        let o = &r.outcomes;
        let q = &r.requests;
        q.covered_by_session_grant
            + q.settled_by_policy.allowed
            + q.settled_by_policy.denied
            + q.settled_by_tamperward
            + o.allowed_once
            + o.allowed_session
            + o.allowed_until
            + o.denied
            + o.expired
            + o.closed_at_session_end
            + o.censored
    }

    #[test]
    fn interleaved_requests_pair_by_identity_not_order() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (2_000, requested("b")),
            (4_000, user("b", Decision::Allow, Some(GrantScope::Once))),
            (7_000, user("a", Decision::Deny, None)),
            (10_000, ended()),
        ]);
        assert_eq!(r.requests.total, 2);
        assert_eq!(r.requests.prompts, 2);
        assert_eq!(r.decisions, 2);
        assert_eq!(r.outcomes.allowed_once, 1);
        assert_eq!(r.outcomes.denied, 1);
        let latency = measured(&r.decision_latency);
        assert_eq!(latency.samples, 2);
        assert!((latency.p50_ms - 2000.0).abs() < f64::EPSILON);
        assert!((latency.p99_ms - 6000.0).abs() < f64::EPSILON);
        assert_eq!(r.decision_latency_ambiguous, 0);
        assert_eq!(r.requests.unpaired_decisions, 0);
        assert_eq!(bucket_sum(&r), r.requests.total);
    }

    #[test]
    fn a_pending_request_is_censored_never_decided() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (2_000, requested("b")),
            (3_000, user("a", Decision::Allow, Some(GrantScope::Once))),
            (9_000, ended()),
        ]);
        assert_eq!(r.outcomes.censored, 1);
        assert_eq!(r.decisions, 1);
        assert_eq!(r.requests.prompts, 2);
        assert_eq!(measured(&r.decision_latency).samples, 1);
        assert!((measured(&r.approve_rate) - 1.0).abs() < f64::EPSILON);
        assert_eq!(bucket_sum(&r), r.requests.total);
    }

    #[test]
    fn expiry_and_session_close_are_not_decisions() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (2_000, requested("b")),
            (61_000, by("a", Decision::Deny, DecisionSource::Timeout)),
            (
                70_000,
                by("b", Decision::Deny, DecisionSource::SessionEnded),
            ),
            (70_001, ended()),
        ]);
        assert_eq!(r.outcomes.expired, 1);
        assert_eq!(r.outcomes.closed_at_session_end, 1);
        assert_eq!(r.outcomes.denied, 0);
        assert_eq!(r.decisions, 0);
        assert_eq!(r.requests.prompts, 2);
        assert!(matches!(r.decision_latency, Measure::Unmeasured { .. }));
        assert!(matches!(r.approve_rate, Measure::Unmeasured { .. }));
        assert_eq!(bucket_sum(&r), r.requests.total);
    }

    #[test]
    fn a_session_grant_covers_later_identical_requests() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (3_000, user("a", Decision::Allow, Some(GrantScope::Session))),
            (4_000, requested("a")),
            (4_001, user("a", Decision::Allow, Some(GrantScope::Session))),
            (5_000, requested("a")),
            (5_001, user("a", Decision::Allow, Some(GrantScope::Session))),
            (6_000, requested("b")),
            (7_000, user("b", Decision::Deny, None)),
            (8_000, ended()),
        ]);
        assert_eq!(r.session_grants.granted, 1);
        assert_eq!(r.session_grants.covered_later_requests, 2);
        assert_eq!(r.requests.covered_by_session_grant, 2);
        assert_eq!(r.requests.prompts, 2);
        assert_eq!(r.decisions, 2);
        assert_eq!(measured(&r.decision_latency).samples, 2);
        assert!((measured(&r.allow_session_rate) - 0.5).abs() < f64::EPSILON);
        assert_eq!(r.repeated_after_allow_once, 0);
        assert_eq!(bucket_sum(&r), r.requests.total);
    }

    #[test]
    fn repeated_requests_follow_an_allow_once_until_a_session_grant() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (2_000, user("a", Decision::Allow, Some(GrantScope::Once))),
            (3_000, requested("a")),
            (4_000, user("a", Decision::Allow, Some(GrantScope::Once))),
            (5_000, requested("a")),
            (6_000, user("a", Decision::Allow, Some(GrantScope::Session))),
            (7_000, requested("a")),
            (7_001, user("a", Decision::Allow, Some(GrantScope::Session))),
            (8_000, requested("b")),
            (9_000, user("b", Decision::Deny, None)),
            (10_000, requested("b")),
            (11_000, user("b", Decision::Deny, None)),
            (12_000, ended()),
        ]);
        assert_eq!(r.repeated_after_allow_once, 2);
        assert_eq!(r.outcomes.allowed_once, 2);
        assert_eq!(r.outcomes.allowed_session, 1);
        assert_eq!(r.requests.covered_by_session_grant, 1);
        assert_eq!(r.outcomes.denied, 2);
    }

    #[test]
    fn a_decision_matching_no_open_request_pairs_with_nothing() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (2_000, user("b", Decision::Allow, Some(GrantScope::Once))),
            (3_000, ended()),
        ]);
        assert_eq!(r.requests.unpaired_decisions, 1);
        assert_eq!(r.decisions, 0);
        assert_eq!(r.outcomes.censored, 1);
        assert!(matches!(r.decision_latency, Measure::Unmeasured { .. }));
    }

    #[test]
    fn identical_open_requests_make_latency_ambiguous_not_guessed() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (2_000, requested("a")),
            (5_000, user("a", Decision::Deny, None)),
            (6_000, user("a", Decision::Deny, None)),
            (7_000, ended()),
        ]);
        assert_eq!(r.decisions, 2);
        assert_eq!(r.outcomes.denied, 2);
        assert_eq!(r.decision_latency_ambiguous, 1);
        let latency = measured(&r.decision_latency);
        assert_eq!(latency.samples, 1);
        assert!((latency.p50_ms - 4000.0).abs() < f64::EPSILON);
        assert_eq!(r.outcomes.censored, 0);
    }

    #[test]
    fn only_ambiguous_decisions_say_so() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (2_000, requested("a")),
            (5_000, user("a", Decision::Deny, None)),
            (7_000, ended()),
        ]);
        assert_eq!(r.decision_latency_ambiguous, 1);
        assert_eq!(r.outcomes.censored, 1);
        match &r.decision_latency {
            Measure::Unmeasured { reason } => assert!(reason.contains("identical"), "{reason}"),
            Measure::Measured { .. } => panic!("latency should be unmeasured"),
        }
    }

    #[test]
    fn policy_and_tamperward_settled_requests_are_not_prompts() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (
                1_001,
                by(
                    "a",
                    Decision::Deny,
                    DecisionSource::Policy {
                        rule: RuleRef::new("project:fs.deny[0]").unwrap(),
                    },
                ),
            ),
            (2_000, requested("b")),
            (
                2_001,
                by(
                    "b",
                    Decision::Allow,
                    DecisionSource::Policy {
                        rule: RuleRef::new("project:fs.allow[0]").unwrap(),
                    },
                ),
            ),
            (3_000, requested("c")),
            (3_001, by("c", Decision::Deny, DecisionSource::TamperWard)),
            (4_000, requested("d")),
            (5_000, user("d", Decision::Allow, Some(GrantScope::Once))),
            (6_000, ended()),
        ]);
        assert_eq!(r.requests.total, 4);
        assert_eq!(r.requests.prompts, 1);
        assert_eq!(r.requests.settled_by_policy.allowed, 1);
        assert_eq!(r.requests.settled_by_policy.denied, 1);
        assert_eq!(r.requests.settled_by_tamperward, 1);
        assert_eq!(r.contained.policy_denied, 1);
        assert_eq!(r.decisions, 1);
        assert_eq!(bucket_sum(&r), r.requests.total);
    }

    #[test]
    fn paused_time_is_excluded_from_agent_hours() {
        let r = report(vec![
            (0, started()),
            (
                60_000,
                WardEvent::SessionPaused {
                    method: PauseMethod::Sigstop,
                    reason: ShortText::new("lunch"),
                },
            ),
            (
                90_000,
                WardEvent::SessionResumed {
                    paused_for: Duration::from_secs(30),
                },
            ),
            (100_000, requested("a")),
            (101_000, user("a", Decision::Allow, Some(GrantScope::Once))),
            (
                300_000,
                WardEvent::SessionPauseUnsettled {
                    method: PauseMethod::Sigstop,
                    reason: ShortText::new("stuck"),
                    pending: 1,
                },
            ),
            (360_000, ended()),
        ]);
        assert_eq!(r.wall.span_ms, 360_000);
        assert_eq!(r.wall.paused_ms, 90_000);
        assert_eq!(r.wall.active_ms, 270_000);
        assert!((r.wall.agent_hours - 0.075).abs() < 1e-9);
        let per_hour = measured(&r.prompts_per_agent_hour);
        assert!((per_hour - 1.0 / 0.075).abs() < 1e-9, "{per_hour}");
    }

    #[test]
    fn a_log_without_the_kinds_reports_unmeasured_not_zero() {
        let r = report(vec![(0, started())]);
        assert_eq!(r.requests.total, 0);
        assert_eq!(r.wall.active_ms, 0);
        for m in [
            &r.prompts_per_agent_hour,
            &r.approve_rate,
            &r.deny_rate,
            &r.allow_session_rate,
        ] {
            assert!(matches!(m, Measure::Unmeasured { .. }), "{m:?}");
        }
        assert!(matches!(r.decision_latency, Measure::Unmeasured { .. }));
        assert!(matches!(
            r.missing_policy_requests,
            Measure::Unmeasured { .. }
        ));
        assert!(matches!(
            r.unrestricted_network_switches,
            Measure::Unmeasured { .. }
        ));
        assert!(matches!(
            r.launches_outside_ward,
            Measure::Unmeasured { .. }
        ));
    }

    #[test]
    fn contained_and_credential_records_are_counted() {
        let r = report(vec![
            (0, started()),
            (
                1_000,
                WardEvent::NetworkDenied {
                    dst: DeniedDst::Host {
                        host: HostName::new("evil.example").unwrap(),
                        port: 443,
                    },
                    reason: DenyReason::NotAllowlisted,
                },
            ),
            (
                2_000,
                WardEvent::CredentialGranted {
                    service: ServiceId::new("github").unwrap(),
                    scope: Scope {
                        subject: ShortText::new("repo:hexrift/wardos"),
                        permissions: vec![NameText::new("contents:read")],
                    },
                    expires: Duration::from_secs(600),
                    delivery: CredentialDelivery::ProxyInjected,
                },
            ),
            (3_000, ended()),
        ]);
        assert_eq!(r.contained.network_denied, 1);
        assert_eq!(r.credentials_granted, 1);
        assert_eq!(
            r.session.as_deref(),
            Some(SessionId::from_u128(42).to_string().as_str())
        );
    }

    #[test]
    fn json_carries_the_schema_version_and_status_tags() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (2_000, user("a", Decision::Allow, Some(GrantScope::Once))),
            (3_000, ended()),
        ]);
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["tool"], TOOL);
        assert_eq!(v["decision_latency"]["status"], "measured");
        assert_eq!(v["decision_latency"]["value"]["samples"], 1);
        assert_eq!(v["missing_policy_requests"]["status"], "unmeasured");
        assert!(v["missing_policy_requests"]["reason"].is_string());
        assert_eq!(v["log"]["verified"], true);
    }

    #[test]
    fn text_report_is_concise_and_names_each_figure() {
        let r = report(vec![
            (0, started()),
            (1_000, requested("a")),
            (2_000, requested("b")),
            (3_000, user("a", Decision::Allow, Some(GrantScope::Once))),
            (9_000, ended()),
        ]);
        let t = text(&r);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 8, "{t}");
        assert!(
            lines[0].contains("chain VERIFIED · sealed head matches"),
            "{t}"
        );
        assert_eq!(
            lines[1],
            "  wall 00:00:09 active (00:00:00 paused) · 0.0025 agent-hours"
        );
        assert!(lines[3].contains("decisions 1 ·"), "{t}");
        assert!(
            lines[3].contains("censored 1 (still pending, not decided)"),
            "{t}"
        );
        assert!(
            lines[5].contains("decision latency p50 2000 ms · p99 2000 ms · n 1"),
            "{t}"
        );
        assert!(
            lines[7].starts_with("  unmeasured: missing-policy requests"),
            "{t}"
        );
    }

    fn write_log(dir: &Path, events: Vec<(u64, WardEvent)>, seal: bool) -> PathBuf {
        let log = dir.join("events.log");
        let mut chain = Chain::genesis(SessionId::from_u128(42), Blake3Hash::hash(b"manifest"));
        let mut w = LogWriter::create(&log, chain.head(), FsyncPolicy::Never).unwrap();
        for (ms, event) in events {
            let ts = Timestamp::mono(Duration::from_millis(ms));
            let r = chain.append(Origin::Wardd, event, ts).unwrap();
            w.append(&r).unwrap();
        }
        if seal {
            w.seal().unwrap();
        }
        log
    }

    #[test]
    fn run_reports_a_sealed_log_as_verified_in_json_and_text() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(
            dir.path(),
            vec![
                (0, started()),
                (1_000, requested("a")),
                (2_000, user("a", Decision::Allow, Some(GrantScope::Once))),
                (3_000, ended()),
            ],
            true,
        );
        let json = run(&log, true).unwrap();
        assert!(json.ok);
        assert_eq!(json.report.log.records, 4);
        assert_eq!(json.report.log.sealed, "matches");
        let v: serde_json::Value = serde_json::from_str(&json.output).unwrap();
        assert_eq!(v["log"]["verified"], true);
        assert!(json.output.ends_with('\n'));
        let text = run(&log, false).unwrap();
        assert!(text.output.contains("chain VERIFIED"));
        assert_eq!(run(&log, true).unwrap().output, json.output);
    }

    #[test]
    fn run_on_an_open_log_says_the_head_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(
            dir.path(),
            vec![(0, started()), (1_000, requested("a"))],
            false,
        );
        let out = run(&log, false).unwrap();
        assert!(out.ok);
        assert_eq!(out.report.log.sealed, "absent");
        assert_eq!(out.report.outcomes.censored, 1);
    }

    #[test]
    fn run_on_a_broken_log_reports_the_readable_prefix_unverified() {
        let dir = tempfile::tempdir().unwrap();
        let log = write_log(
            dir.path(),
            vec![
                (0, started()),
                (1_000, requested("a")),
                (2_000, user("a", Decision::Allow, Some(GrantScope::Once))),
                (3_000, ended()),
            ],
            true,
        );
        let mut bytes = std::fs::read(&log).unwrap();
        bytes.truncate(bytes.len() - 3);
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&log, bytes).unwrap();
        let out = run(&log, false).unwrap();
        assert!(!out.ok);
        assert!(!out.report.log.verified);
        assert_eq!(out.report.log.records, 3);
        assert!(
            out.report
                .log
                .failure
                .as_deref()
                .unwrap()
                .contains("truncated")
        );
        assert!(out.output.contains("chain BROKEN"), "{}", out.output);
        assert_eq!(out.report.decisions, 1);
    }

    #[test]
    fn run_fails_only_when_the_log_cannot_be_opened() {
        let dir = tempfile::tempdir().unwrap();
        assert!(run(&dir.path().join("missing.log"), true).is_err());
    }
}
