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
//! `ward session grants` is the same list from the hold itself.

use ward_daemon::approvals::{host_of, service_name};
use ward_daemon::describe::SessionDescription;
use ward_daemon::render::{Tone, network_text, network_tone};
use ward_events::{CapabilityKind, Decision, EventRecord, GrantScope, WardEvent};
use ward_policy::{AccessMode, CapabilityManifest, CredentialRule, NetworkCapability, ServiceId};

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
}

/// Every temporary grant the session holds, in the order the stream granted
/// them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Authority {
    /// The grants.
    pub grants: Vec<Grant>,
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
                    });
                }
            }
            WardEvent::CredentialGranted { service, scope, .. } => {
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
                } else {
                    self.grants.push(Grant {
                        label,
                        scope: format!("{permissions} · {host}"),
                        lifetime: "launch",
                        network_tag: Some(service.as_str().to_owned()),
                    });
                }
            }
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
        let value = match m.credentials.get(&ServiceId(service.to_owned())) {
            None | Some(CredentialRule::Deny) => "denied",
            Some(CredentialRule::Ask(_)) => "ask",
            Some(CredentialRule::Allow(_)) => "allowed",
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

/// The "Current agent authority" panel (ADR-0019): filesystem, network,
/// every temporary grant with its scope and lifetime, the standing denials.
#[must_use]
pub fn authority_panel(d: &SessionDescription, authority: &Authority) -> Vec<Group> {
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
        authority.grants.iter().map(Grant::row).collect()
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
    use crate::feed::fixtures::{records, sequence, wardd};
    use crate::panel::panel_text;
    use crate::trust::fixtures::description;
    use std::time::Duration;
    use ward_events::{
        CapabilityRequest, CredentialDelivery, DecisionSource, NameText, Origin, Scope, ShortText,
    };

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
            }
        );
        assert_eq!(
            authority.grants[1],
            Grant {
                label: "GitHub".into(),
                scope: "contents:read, issues:read · github.com, api.github.com".into(),
                lifetime: "launch",
                network_tag: Some("github".into()),
            }
        );
        assert_eq!(
            authority.grants[2],
            Grant {
                label: "WebFetch example.org".into(),
                scope: "network".into(),
                lifetime: "session",
                network_tag: Some("example.org".into()),
            },
            "a network grant is listed by its host, never the whole URL"
        );
        assert_eq!(authority.network_tags(), ["github", "example.org"]);
        assert!(Authority::from_records(&wardd(&sequence())).is_empty());
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
        let empty = authority_panel(&d, &Authority::default());
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
        let groups = authority_panel(&d, &authority);
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
        let groups = authority_panel(&d, &Authority::default());
        assert!(groups[0].rows[0].value.starts_with("/work read-only"));
        let cloud = &groups[2].rows[2];
        assert_eq!((cloud.value.as_str(), cloud.tone), ("ask", Tone::Warn));
    }
}
