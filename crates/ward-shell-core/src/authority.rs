//! The agent's current authority (ADR-0019, decision 4): temporary authority
//! stays visible while it exists.
//!
//! [`Authority`] is every temporary grant the session holds, derived from its
//! records alone: an `allow-session` answer is a `CapabilityDecided` with a
//! session grant, a credential the proxy injects is a `CredentialGranted`. The
//! trust bar reads it twice — the network segment becomes `restricted ·
//! github+` while a grant widens what the network reaches, and a `GRANTS n`
//! segment appears — and the panel behind them ([`authority_panel`]) lists
//! the filesystem, the network, every grant with its scope and lifetime, and
//! the standing denials. Nothing here is enforcement: the daemon's
//! `ward session grants` is the same list from the hold itself. `Authority`
//! itself keeps no clock: `now` enters only at [`authority_panel`], the one
//! place a grant's own recorded lifetime (a credential's `expires`, carried
//! since #315) is judged against it, so a grant past its lifetime reads
//! `· expired` there (#316) the same way the daemon's own `ward session
//! grants` already does.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ward_daemon::approvals::{host_of, service_name};
use ward_daemon::describe::SessionDescription;
use ward_daemon::render::{Tone, network_text, network_tone};
use ward_events::{CapabilityKind, Decision, EventRecord, GrantScope, WardEvent};
use ward_policy::{AccessMode, CapabilityManifest, NetworkCapability};

use crate::panel::Group;
use crate::settings::Row;
use crate::trust::Segment;

/// One temporary grant as the stream reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// `GitHub`, `Write /work/src/lib.rs`, `WebFetch api.github.com`.
    pub label: String,
    /// `contents:read, issues:read · github.com, api.github.com`, `write`.
    pub scope: String,
    /// `launch` for a credential, `session` for an answer.
    pub lifetime: &'static str,
    /// The tag the network segment shows for it (`github`, a host) when the
    /// grant widens what the network reaches.
    pub network_tag: Option<String>,
    /// When this grant's own recorded lifetime runs out, milliseconds since
    /// the Unix epoch (#316): the record's own `ts_wall` plus
    /// `WardEvent::CredentialGranted`'s `expires`, the same two materials
    /// `ward-daemon::approvals::Credential::expires_at_unix_ms` derives from
    /// (#140/#315) — no new event kind, just this projection finally reusing
    /// them too. `None` for an `allow-session` answer (a
    /// [`GrantScope::Session`] grant has no recorded expiry of its own, only
    /// ever plain or session-suspended) and for a credential grant whose
    /// record carries no wall clock at all (a mono-only fixture, or a stream
    /// that never got one) — never expires on its own, the same meaning
    /// `Credential::expires_at_unix_ms`'s own `None` carries.
    pub expires_at_unix_ms: Option<u64>,
}

impl Grant {
    /// The grant as a panel row: label, then scope and lifetime.
    #[must_use]
    pub fn row(&self) -> Row {
        Row::new(
            self.label.clone(),
            format!("{} · {}", self.scope, self.lifetime),
            Tone::Warn,
        )
    }

    /// Whether this grant's own recorded lifetime has run out by `now_unix_ms`
    /// (#316) — mirrors `ward-daemon::approvals`'s own expiry sweep
    /// (`now_unix_ms >= expires_at_unix_ms`), `false` for a grant that never
    /// expires on its own ([`Self::expires_at_unix_ms`] is `None`).
    #[must_use]
    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        self.expires_at_unix_ms
            .is_some_and(|expires| now_unix_ms >= expires)
    }
}

/// `granted`'s recorded lifetime running out (#316): `ts_wall` (when the
/// record has one) plus `expires`, saturating rather than overflowing on a
/// pathological huge duration — the same "never expires on its own" meaning
/// as being unable to compute a bound at all. Mirrors
/// `daemon.rs`'s own `granted_at_unix_ms.saturating_add(expires_ms)`, with
/// the record's own `ts_wall` standing in for the daemon's `SystemTime::now()`
/// at grant time, since this projection has no clock of its own to call.
fn expiry_unix_ms(ts_wall: Option<SystemTime>, expires: Duration) -> Option<u64> {
    let granted_at_unix_ms = ts_wall?.duration_since(UNIX_EPOCH).ok()?;
    let granted_at_unix_ms = u64::try_from(granted_at_unix_ms.as_millis()).ok()?;
    let expires_ms = u64::try_from(expires.as_millis()).ok()?;
    Some(granted_at_unix_ms.saturating_add(expires_ms))
}

/// Every temporary grant the session holds, in the order the stream granted
/// them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Authority {
    /// The grants.
    pub grants: Vec<Grant>,
    /// The session is currently paused (ADR-0019 §3, #140): every grant
    /// shows suspended in [`authority_panel`] while this is true, and plain
    /// again from the moment `SessionResumed` lands — the same single source
    /// of truth (`WardEvent::SessionPaused`/`SessionResumed`) the daemon's
    /// own `Approvals::set_paused` reacts to, never a second, parallel notion
    /// of "paused" derived here. Session-wide, not per-grant: pausing
    /// suspends every grant at once, exactly as `wardd` does.
    pub suspended: bool,
}

impl Authority {
    /// The authority `records` add up to.
    #[must_use]
    pub fn from_records(records: &[EventRecord]) -> Self {
        let mut authority = Self::default();
        for rec in records {
            authority.apply(rec);
        }
        authority
    }

    /// Account for one record.
    pub fn apply(&mut self, rec: &EventRecord) {
        match &rec.event {
            WardEvent::CapabilityDecided {
                cap,
                decision: Decision::Allow,
                grant: Some(GrantScope::Session),
                ..
            } => {
                let (label, tag) = decided_label(cap.kind, cap.target.as_str());
                if !self.grants.iter().any(|g| g.label == label) {
                    self.grants.push(Grant {
                        label,
                        scope: kind_word(cap.kind).to_owned(),
                        lifetime: "session",
                        network_tag: tag,
                        expires_at_unix_ms: None,
                    });
                }
            }
            WardEvent::CredentialGranted {
                service,
                scope,
                expires,
                ..
            } => {
                let label = service_name(service.as_str());
                let permissions = scope
                    .permissions
                    .iter()
                    .map(|p| p.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(", ");
                // The subject is the route's upstream, `host:port`.
                let subject = scope.subject.as_str();
                let host = subject.rsplit_once(':').map_or(subject, |(h, _)| h);
                if let Some(g) = self.grants.iter_mut().find(|g| g.label == label) {
                    if !g.scope.contains(host) {
                        g.scope.push_str(", ");
                        g.scope.push_str(host);
                    }
                    // The first route's expiry stands (#316): every real
                    // caller mints the same nominal lifetime for every route
                    // one launch grants at once, mirroring
                    // `Approvals::record_credential_with_expiry`'s own
                    // "ignored when merging" rule.
                } else {
                    self.grants.push(Grant {
                        label,
                        scope: format!("{permissions} · {host}"),
                        lifetime: "launch",
                        network_tag: Some(service.as_str().to_owned()),
                        expires_at_unix_ms: expiry_unix_ms(rec.ts_wall, *expires),
                    });
                }
            }
            WardEvent::CredentialRevoked { service, .. } => {
                // #140: a `ward session revoke` on a credential grant records
                // this once the daemon confirms it — drop it from the panel
                // the same moment `ward session grants` stops listing it.
                let label = service_name(service.as_str());
                self.grants.retain(|g| g.label != label);
            }
            // #140: the same pause the daemon suspends every grant for
            // (`Approvals::set_paused`) — reusing that single source of
            // truth here, not a second one.
            WardEvent::SessionPaused { .. } => self.suspended = true,
            WardEvent::SessionResumed { .. } => self.suspended = false,
            _ => {}
        }
    }

    /// Whether nothing is granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// How many grants are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// The tags of the grants that widen the network, each once, in order.
    #[must_use]
    pub fn network_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = Vec::new();
        for tag in self.grants.iter().filter_map(|g| g.network_tag.clone()) {
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        tags
    }
}

/// `Write /work/src/lib.rs` as the log records it; a network target is cut
/// to its host, as the daemon's own list shows it, and tags the segment.
fn decided_label(kind: CapabilityKind, target: &str) -> (String, Option<String>) {
    match (kind, target.split_once(' ')) {
        (CapabilityKind::Network, Some((tool, rest))) => {
            let host = host_of(rest);
            (format!("{tool} {host}"), Some(host))
        }
        _ => (target.to_owned(), None),
    }
}

/// The scope word of an answered capability.
const fn kind_word(kind: CapabilityKind) -> &'static str {
    match kind {
        CapabilityKind::Network => "network",
        CapabilityKind::FileRead => "read",
        CapabilityKind::FileWrite => "write",
        CapabilityKind::Exec => "exec",
        CapabilityKind::Credential => "credential",
        CapabilityKind::Device => "device",
        CapabilityKind::NestedContainer => "container",
        CapabilityKind::Other => "other",
    }
}

/// The network mode's one word, for the segment that carries grant tags.
#[must_use]
pub const fn network_word(network: &NetworkCapability) -> &'static str {
    match network {
        NetworkCapability::Offline => "offline",
        NetworkCapability::LocalhostOnly => "localhost",
        NetworkCapability::Registries => "registries",
        NetworkCapability::Development => "restricted",
        NetworkCapability::Custom(_) => "allowlist",
        NetworkCapability::Unrestricted => "open",
    }
}

/// The network segment's text: the mode as the panels name it, or `restricted
/// · github+` while a grant widens what the network reaches.
#[must_use]
pub fn network_segment_text(network: &NetworkCapability, authority: &Authority) -> String {
    let tags = authority.network_tags();
    if tags.is_empty() {
        network_text(network)
    } else {
        format!("{} · {}+", network_word(network), tags.join(", "))
    }
}

/// `GRANTS n`, amber while the session is live and something is granted; dim
/// once the log is sealed; `None` with nothing granted, so the bar shows no
/// segment.
#[must_use]
pub fn grants_segment(authority: &Authority, sealed: bool) -> Option<Segment> {
    if authority.is_empty() {
        return None;
    }
    let tone = if sealed { Tone::Dim } else { Tone::Warn };
    Some(Segment::new(format!("GRANTS {}", authority.len()), tone))
}

/// `/work read-write · /env read-write · home and /tmp private`, plus any
/// extra mount.
#[must_use]
pub fn filesystem_text(m: &CapabilityManifest) -> String {
    let fs = &m.filesystem;
    let mut parts = vec![
        format!("/work {}", access_word(fs.worktree)),
        format!("/env {}", access_word(fs.environment)),
        "home and /tmp private".to_owned(),
    ];
    for (path, mode) in &fs.extra {
        parts.push(format!("{} {}", path.display(), access_word(*mode)));
    }
    parts.join(" · ")
}

const fn access_word(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::ReadWrite => "read-write",
        AccessMode::ReadOnly => "read-only",
        AccessMode::None => "not mounted",
    }
}

/// The standing denials: the host's files and the private network are
/// structural (no mode and no grant reaches them); publishing and cloud
/// credentials are the manifest's rules, denied by default.
fn denials(m: &CapabilityManifest) -> Vec<Row> {
    let structural = |label: &str| Row::new(label, "denied", Tone::Ok);
    let rule = |label: &str, service: &str| {
        let value = match worst_credential_decision(m, service) {
            ward_policy::Decision::Deny => "denied",
            ward_policy::Decision::Ask => "ask",
            ward_policy::Decision::Allow => "allowed",
        };
        let tone = if value == "denied" {
            Tone::Ok
        } else {
            Tone::Warn
        };
        Row::new(label, value, tone)
    };
    debug_assert!(!m.network.permits_private_ranges());
    vec![
        structural("Host files"),
        structural("Private network"),
        rule("Cloud creds", "cloud-*"),
        rule("Publish creds", "npm-publish"),
    ]
}

/// The most restrictive [`ward_policy::Decision`] among every credential rule
/// whose service id falls under `service`'s prefix (its text with any
/// trailing `*` stripped), evaluated through
/// [`CapabilityManifest::credential_decision`].
///
/// A plain `m.credentials.get(&ServiceId(service))` lookup only ever sees a
/// rule keyed by that exact literal string, so a narrower, more restrictive
/// wildcard sharing the same prefix (e.g. `cloud-danger-*` deny alongside a
/// broader `cloud-*` ask) is invisible to it — the trust bar would then show
/// a laxer standing denial than enforcement actually applies. Scanning every
/// service under the prefix and taking the worst case keeps this panel
/// honest about what enforcement will do.
fn worst_credential_decision(m: &CapabilityManifest, service: &str) -> ward_policy::Decision {
    let prefix = service.strip_suffix('*').unwrap_or(service);
    m.credentials
        .keys()
        .filter(|id| id.0.starts_with(prefix))
        .map(|id| m.credential_decision(id))
        .max()
        .unwrap_or(ward_policy::Decision::Deny)
}

/// The "Current agent authority" panel (ADR-0019): filesystem, network,
/// every temporary grant with its scope and lifetime, the standing denials,
/// judged at `now_unix_ms` (#316) — the same deterministic seam
/// `session_panel`/`verify_panel` already take a `now_unix_ms` through, so a
/// credential grant whose own recorded lifetime has run out by then reads
/// `· expired`, mirroring `ward session grants`'s own display convention
/// (`Grant::line()` in `ward-daemon::approvals`) with no daemon round-trip.
#[must_use]
pub fn authority_panel(
    d: &SessionDescription,
    authority: &Authority,
    now_unix_ms: u64,
) -> Vec<Group> {
    let m = &d.manifest;
    let tone = if authority.network_tags().is_empty() {
        network_tone(&m.network)
    } else {
        Tone::Warn
    };
    let current = vec![
        Row::new("Filesystem", filesystem_text(m), Tone::Ink),
        Row::new("Network", network_segment_text(&m.network, authority), tone),
        Row::new(
            "Temporary grants",
            authority.len().to_string(),
            if authority.is_empty() {
                Tone::Ink
            } else {
                Tone::Warn
            },
        ),
    ];
    let grants = if authority.is_empty() {
        vec![Row::new("none", "", Tone::Dim)]
    } else {
        authority
            .grants
            .iter()
            .map(|g| {
                let mut row = g.row();
                // #316: a credential whose own recorded lifetime has run out
                // reads `expired` even while the session is paused — the
                // same precedence `ward-daemon::approvals`'s own sweep gives
                // expiry over `Suspended` (`sweep_expired_credentials`'s doc
                // comment: "Active and Suspended are otherwise-live states
                // and are equally subject to the credential's own clock").
                // #140: short of that, a grant is never shown as exercisable
                // authority for longer than the session it belongs to can
                // actually use it.
                if g.is_expired(now_unix_ms) {
                    row.value.push_str(" · expired");
                } else if authority.suspended {
                    row.value.push_str(" · suspended");
                }
                row
            })
            .collect()
    };
    vec![
        Group {
            title: "Current agent authority",
            rows: current,
        },
        Group {
            title: "Temporary grants",
            rows: grants,
        },
        Group {
            title: "Denied",
            rows: denials(m),
        },
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::feed::fixtures::{records, sequence, wardd, wardd_at_wall};
    use crate::panel::panel_text;
    use crate::trust::fixtures::description;
    use std::time::Duration;
    use ward_events::{
        CapabilityRequest, CredentialDelivery, DecisionSource, NameText, Origin, Scope, ShortText,
    };
    use ward_policy::{CredentialRule, ServiceId};

    fn decided(kind: CapabilityKind, target: &str, grant: Option<GrantScope>) -> WardEvent {
        WardEvent::CapabilityDecided {
            cap: CapabilityRequest {
                kind,
                target: ShortText::new(target),
            },
            decision: if grant.is_some() {
                Decision::Allow
            } else {
                Decision::Deny
            },
            by: DecisionSource::User,
            grant,
        }
    }

    fn credential(host: &str) -> WardEvent {
        WardEvent::CredentialGranted {
            service: ward_events::ServiceId::new("github").unwrap(),
            scope: Scope {
                subject: ShortText::new(&format!("{host}:443")),
                permissions: vec![NameText::new("contents:read"), NameText::new("issues:read")],
            },
            expires: Duration::from_secs(60),
            delivery: CredentialDelivery::ProxyInjected,
        }
    }

    fn revoked(service: &str) -> WardEvent {
        WardEvent::CredentialRevoked {
            service: ward_events::ServiceId::new(service).unwrap(),
            reason: ward_events::RevokeReason::UserRevoked,
        }
    }

    fn paused() -> WardEvent {
        WardEvent::SessionPaused {
            method: ward_events::PauseMethod::CgroupFreezer,
            reason: ShortText::new(""),
        }
    }

    fn resumed() -> WardEvent {
        WardEvent::SessionResumed {
            paused_for: Duration::from_secs(1),
        }
    }

    #[test]
    fn grants_come_from_session_answers_and_injected_credentials_and_nothing_else() {
        let mut events = sequence();
        events.extend([
            decided(
                CapabilityKind::FileWrite,
                "Write /work/src/lib.rs",
                Some(GrantScope::Once),
            ),
            decided(
                CapabilityKind::Network,
                "WebFetch https://example.org/x",
                None,
            ),
            decided(
                CapabilityKind::FileWrite,
                "Write /work/src/lib.rs",
                Some(GrantScope::Session),
            ),
            // Answered from memory: recorded again, listed once.
            decided(
                CapabilityKind::FileWrite,
                "Write /work/src/lib.rs",
                Some(GrantScope::Session),
            ),
            credential("github.com"),
            credential("api.github.com"),
            decided(
                CapabilityKind::Network,
                "WebFetch https://example.org/data.json",
                Some(GrantScope::Session),
            ),
        ]);
        let authority = Authority::from_records(&wardd(&events));
        assert_eq!(authority.len(), 3);
        assert_eq!(
            authority.grants[0],
            Grant {
                label: "Write /work/src/lib.rs".into(),
                scope: "write".into(),
                lifetime: "session",
                network_tag: None,
                expires_at_unix_ms: None,
            }
        );
        assert_eq!(
            authority.grants[1],
            Grant {
                label: "GitHub".into(),
                scope: "contents:read, issues:read · github.com, api.github.com".into(),
                lifetime: "launch",
                network_tag: Some("github".into()),
                // `wardd`'s records carry no wall clock (#316): a credential
                // grant this projection cannot judge against `now` at all
                // never expires on its own — see `expiry_unix_ms`.
                expires_at_unix_ms: None,
            }
        );
        assert_eq!(
            authority.grants[2],
            Grant {
                label: "WebFetch example.org".into(),
                scope: "network".into(),
                lifetime: "session",
                network_tag: Some("example.org".into()),
                expires_at_unix_ms: None,
            },
            "a network grant is listed by its host, never the whole URL"
        );
        assert_eq!(authority.network_tags(), ["github", "example.org"]);
        assert!(Authority::from_records(&wardd(&sequence())).is_empty());
    }

    #[test]
    fn a_credential_revoked_record_drops_the_matching_grant() {
        // #140: `ward session revoke` on a credential grant must disappear
        // from the panel and the trust bar's `GRANTS n`, not just from
        // `ward session grants` — this is what makes it so.
        let mut events = sequence();
        events.extend([
            credential("github.com"),
            decided(
                CapabilityKind::FileWrite,
                "Write /work/src/lib.rs",
                Some(GrantScope::Session),
            ),
        ]);
        let authority = Authority::from_records(&wardd(&events));
        assert_eq!(authority.len(), 2);

        let mut revoked_events = events.clone();
        revoked_events.push(revoked("github"));
        let authority = Authority::from_records(&wardd(&revoked_events));
        assert_eq!(authority.len(), 1, "{authority:?}");
        assert_eq!(authority.grants[0].label, "Write /work/src/lib.rs");

        // Revoking a service with no matching grant is a no-op.
        let mut unrelated_events = events.clone();
        unrelated_events.push(revoked("npm"));
        assert_eq!(Authority::from_records(&wardd(&unrelated_events)).len(), 2);
    }

    #[test]
    fn pausing_suspends_every_grant_in_the_panel_and_resuming_reactivates_them() {
        // #140: the shell/desktop panel projection reuses the daemon's own
        // single source of truth for "is this session paused"
        // (`SessionPaused`/`SessionResumed`), not a second, parallel notion.
        let mut events = sequence();
        events.extend([
            credential("github.com"),
            decided(
                CapabilityKind::FileWrite,
                "Write /work/src/lib.rs",
                Some(GrantScope::Session),
            ),
        ]);
        let live = Authority::from_records(&wardd(&events));
        assert!(!live.suspended);
        let d = description(NetworkCapability::Development);
        let groups = authority_panel(&d, &live, 0);
        assert!(
            groups[1]
                .rows
                .iter()
                .all(|r| !r.value.contains("suspended"))
        );

        let mut paused_events = events.clone();
        paused_events.push(paused());
        let paused_authority = Authority::from_records(&wardd(&paused_events));
        assert!(paused_authority.suspended);
        assert_eq!(paused_authority.len(), 2, "pausing drops nothing");
        let groups = authority_panel(&d, &paused_authority, 0);
        assert!(
            groups[1]
                .rows
                .iter()
                .all(|r| r.value.ends_with("· suspended")),
            "{:?}",
            groups[1].rows
        );

        let mut resumed_events = paused_events;
        resumed_events.push(resumed());
        let resumed_authority = Authority::from_records(&wardd(&resumed_events));
        assert!(!resumed_authority.suspended);
        let groups = authority_panel(&d, &resumed_authority, 0);
        assert!(
            groups[1]
                .rows
                .iter()
                .all(|r| !r.value.contains("suspended")),
            "{:?}",
            groups[1].rows
        );
    }

    /// `credential("github.com")`'s own `expires: Duration::from_secs(60)`,
    /// recorded at wall clock `start_unix_ms`.
    const GRANTED_AT_UNIX_MS: u64 = 1_000_000_000_000;
    const EXPIRES_AT_UNIX_MS: u64 = GRANTED_AT_UNIX_MS + 60_000;

    #[test]
    fn a_credential_grant_reads_expired_once_its_own_recorded_lifetime_runs_out() {
        // #316: the daemon side (#140/#315) already gives a credential's
        // `expires` real meaning (`Approvals::sweep_expired_credentials`);
        // this projection reuses the exact same materials — the record's own
        // `ts_wall` plus `CredentialGranted`'s `expires` — with no new event.
        let events = [credential("github.com")];
        let records = wardd_at_wall(&events, GRANTED_AT_UNIX_MS);
        let authority = Authority::from_records(&records);
        assert_eq!(
            authority.grants[0].expires_at_unix_ms,
            Some(EXPIRES_AT_UNIX_MS)
        );
        let d = description(NetworkCapability::Development);

        let before = authority_panel(&d, &authority, EXPIRES_AT_UNIX_MS - 1);
        assert_eq!(
            before[1].rows[0].value, "contents:read, issues:read · github.com · launch",
            "not yet expired, no suffix"
        );

        let at = authority_panel(&d, &authority, EXPIRES_AT_UNIX_MS);
        assert_eq!(
            at[1].rows[0].value, "contents:read, issues:read · github.com · launch · expired",
            "the instant its own recorded lifetime runs out, ward session \
             grants and this panel must not disagree"
        );

        let after = authority_panel(&d, &authority, EXPIRES_AT_UNIX_MS + 60_000);
        assert!(after[1].rows[0].value.ends_with("· expired"));
    }

    #[test]
    fn a_session_answer_never_reads_expired_no_matter_how_far_now_runs() {
        // #316: an `allow-session` answer has no recorded expiry of its own
        // (`ward-daemon::approvals`'s own `RevokeState::Expired` is likewise
        // never reached for a `GrantKind::Approval`) — only ever plain or
        // session-suspended.
        let events = [decided(
            CapabilityKind::FileWrite,
            "Write /work/src/lib.rs",
            Some(GrantScope::Session),
        )];
        let authority = Authority::from_records(&wardd_at_wall(&events, GRANTED_AT_UNIX_MS));
        assert_eq!(authority.grants[0].expires_at_unix_ms, None);
        let d = description(NetworkCapability::Development);
        let groups = authority_panel(&d, &authority, u64::MAX);
        assert_eq!(groups[1].rows[0].value, "write · session");
    }

    #[test]
    fn expiry_takes_precedence_over_suspended_the_same_way_the_daemons_sweep_does() {
        // #316: `ward-daemon::approvals::sweep_expired_credentials` sweeps a
        // `Suspended` credential into `Expired` exactly like an `Active` one
        // — "equally subject to the credential's own clock" — so a paused
        // session must never mask an already-expired grant behind
        // `· suspended` here either.
        let events = [credential("github.com"), paused()];
        let authority = Authority::from_records(&wardd_at_wall(&events, GRANTED_AT_UNIX_MS));
        assert!(authority.suspended);
        let d = description(NetworkCapability::Development);
        let groups = authority_panel(&d, &authority, EXPIRES_AT_UNIX_MS);
        assert!(
            groups[1].rows[0].value.ends_with("· expired"),
            "{:?}",
            groups[1].rows
        );
        assert!(!groups[1].rows[0].value.contains("suspended"));
    }

    #[test]
    fn a_second_route_of_the_same_credential_keeps_the_first_routes_expiry() {
        // #316, mirroring `Approvals::record_credential_with_expiry`'s own
        // "ignored when merging" rule: every real caller mints the same
        // nominal lifetime for every route one launch grants at once, so a
        // second host folded into an existing grant must not push its
        // expiry out to the second record's own (later) timestamp.
        let events = [credential("github.com"), credential("api.github.com")];
        let authority = Authority::from_records(&wardd_at_wall(&events, GRANTED_AT_UNIX_MS));
        assert_eq!(authority.len(), 1);
        assert_eq!(
            authority.grants[0].expires_at_unix_ms,
            Some(EXPIRES_AT_UNIX_MS),
            "the second route's record is a second later, but the grant's \
             expiry must still be the first route's"
        );
    }

    #[test]
    fn a_credential_grant_with_no_wall_clock_never_expires_on_its_own() {
        // #316: `wardd`/`records` (every fixture that predates this) carries
        // no wall clock at all — the same "cannot compute a bound" case
        // `Credential::expires_at_unix_ms` documents for the daemon side.
        let authority = Authority::from_records(&wardd(&[credential("github.com")]));
        assert_eq!(authority.grants[0].expires_at_unix_ms, None);
        let d = description(NetworkCapability::Development);
        let groups = authority_panel(&d, &authority, u64::MAX);
        assert!(!groups[1].rows[0].value.contains("expired"));
    }

    #[test]
    fn the_network_segment_carries_the_grant_tags_and_the_grants_segment_counts() {
        let none = Authority::default();
        assert_eq!(
            network_segment_text(&NetworkCapability::Development, &none),
            "restricted (dev)",
            "unchanged without a grant"
        );
        assert_eq!(grants_segment(&none, false), None);
        let github = Authority::from_records(&wardd(&[credential("github.com")]));
        assert_eq!(
            network_segment_text(&NetworkCapability::Development, &github),
            "restricted · github+"
        );
        assert_eq!(
            network_segment_text(&NetworkCapability::Offline, &github),
            "offline · github+"
        );
        assert_eq!(
            grants_segment(&github, false),
            Some(Segment::new("GRANTS 1", Tone::Warn))
        );
        assert_eq!(
            grants_segment(&github, true),
            Some(Segment::new("GRANTS 1", Tone::Dim))
        );
        // A file grant is a grant, but widens no network.
        let write = Authority::from_records(&wardd(&[decided(
            CapabilityKind::FileWrite,
            "Write /work/a.rs",
            Some(GrantScope::Session),
        )]));
        assert_eq!(
            network_segment_text(&NetworkCapability::Development, &write),
            "restricted (dev)"
        );
        assert_eq!(grants_segment(&write, false).unwrap().text, "GRANTS 1");
        for (network, word) in [
            (NetworkCapability::LocalhostOnly, "localhost"),
            (NetworkCapability::Registries, "registries"),
            (
                NetworkCapability::Custom(std::collections::BTreeSet::default()),
                "allowlist",
            ),
            (NetworkCapability::Unrestricted, "open"),
        ] {
            assert_eq!(network_word(&network), word);
        }
    }

    #[test]
    fn the_panel_lists_filesystem_network_every_grant_and_the_standing_denials() {
        let d = description(NetworkCapability::Development);
        let empty = authority_panel(&d, &Authority::default(), 0);
        let text = panel_text(&empty);
        assert!(
            text.starts_with(
                "Current agent authority\n────────────────────────\nFilesystem         /work read-write · /env read-write · home and /tmp private\nNetwork            restricted (dev)\nTemporary grants   0\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("\n\nTemporary grants\n────────────────────────\nnone   \n"),
            "{text}"
        );
        assert!(
            text.ends_with(
                "Denied\n────────────────────────\nHost files        denied\nPrivate network   denied\nCloud creds       denied\nPublish creds     denied\n"
            ),
            "{text}"
        );
        let denied = &empty[2].rows;
        assert!(denied.iter().all(|r| r.tone == Tone::Ok));

        let events = [
            credential("github.com"),
            credential("api.github.com"),
            decided(
                CapabilityKind::FileWrite,
                "Write /work/src/lib.rs",
                Some(GrantScope::Session),
            ),
        ];
        let authority = Authority::from_records(&records(
            &events
                .iter()
                .map(|e| (Origin::Wardd, e.clone()))
                .collect::<Vec<_>>(),
        ));
        let groups = authority_panel(&d, &authority, 0);
        let network = &groups[0].rows[1];
        assert_eq!(
            (network.value.as_str(), network.tone),
            ("restricted · github+", Tone::Warn)
        );
        assert_eq!(groups[0].rows[2].value, "2");
        assert_eq!(groups[0].rows[2].tone, Tone::Warn);
        assert_eq!(
            groups[1].rows,
            [
                Row::new(
                    "GitHub",
                    "contents:read, issues:read · github.com, api.github.com · launch",
                    Tone::Warn
                ),
                Row::new("Write /work/src/lib.rs", "write · session", Tone::Warn),
            ]
        );
        // A read-only worktree and an allowed cloud rule show as such.
        let mut d = description(NetworkCapability::Development);
        d.manifest.filesystem.worktree = AccessMode::ReadOnly;
        d.manifest.credentials.insert(
            ServiceId("cloud-*".into()),
            CredentialRule::Ask(ward_policy::CredentialScope::default()),
        );
        let groups = authority_panel(&d, &Authority::default(), 0);
        assert!(groups[0].rows[0].value.starts_with("/work read-only"));
        let cloud = &groups[2].rows[2];
        assert_eq!((cloud.value.as_str(), cloud.tone), ("ask", Tone::Warn));
    }

    #[test]
    fn standing_denials_reflect_the_most_restrictive_overlapping_wildcard() {
        // Regression for issue #159: a broad `cloud-*` => Ask alongside a
        // narrower, more restrictive `cloud-danger-*` => Deny must still show
        // the trust bar's "Cloud creds" row as denied, not ask — a literal
        // `credentials.get("cloud-*")` lookup would miss the narrower rule
        // entirely and disagree with what `credential_decision` enforces.
        let mut d = description(NetworkCapability::Development);
        d.manifest.credentials.insert(
            ServiceId("cloud-*".into()),
            CredentialRule::Ask(ward_policy::CredentialScope::default()),
        );
        d.manifest
            .credentials
            .insert(ServiceId("cloud-danger-*".into()), CredentialRule::Deny);
        assert_eq!(
            d.manifest
                .credential_decision(&ServiceId("cloud-danger-x".into())),
            ward_policy::Decision::Deny
        );
        assert_eq!(
            d.manifest
                .credential_decision(&ServiceId("cloud-aws".into())),
            ward_policy::Decision::Ask
        );

        let groups = authority_panel(&d, &Authority::default(), 0);
        let cloud = &groups[2].rows[2];
        assert_eq!((cloud.value.as_str(), cloud.tone), ("denied", Tone::Ok));
    }
}
