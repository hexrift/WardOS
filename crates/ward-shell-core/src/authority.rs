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
//! itself keeps no clock: `now_unix_ms` is always passed in explicitly, at
//! [`authority_panel`] and at [`Authority::len`]/[`Authority::network_tags`]
//! (and so [`grants_segment`]/[`network_segment_text`]/`crate::trust::TrustBar::new`)
//! alike, so a grant past its own recorded lifetime (a
//! credential's `expires`, carried since #315) reads `· expired` in the
//! per-grant list (#316) the same way the daemon's own `ward session grants`
//! already does, while dropping out of every *current*-authority surface —
//! the grant count, the network tags/tone, and the `GRANTS n` segment (PR
//! #318 review, finding 1) — the same way `ward session grants` itself has
//! already stopped listing it. A second route of the same launch (two
//! gateways one `Session::launch` call grants at once) merges into one
//! [`Grant`] by a daemon-stamped launch identity (PR #318 review round 2,
//! finding 2) — the identity `ward-daemon::approvals::Credential::launch_key`
//! already used — so two routes appended at genuinely distinct wall-clock
//! instants still merge, while a later, independent launch granting the same
//! service and permissions again always starts its own row, however close
//! together in time the two launches land. That identity reaches this
//! projection as a second, trailing [`WardEvent::CredentialGrantedLaunch`]
//! record immediately after the `CredentialGranted` it attributes, never as a
//! field on `CredentialGranted` itself (PR #318 review round 3 reverted that
//! shape: postcard's positional enum encoding made it change the hashed bytes
//! of every `CredentialGranted` record any earlier build ever persisted, so
//! an upgraded `wardd` could no longer verify its own session's own earlier
//! log) — see [`Authority::apply`] and [`Authority::attribute_launch`] for how
//! this projection consumes that second record without ever needing the
//! daemon's own per-connection bookkeeping. [`Authority::apply`]'s own
//! provisional label+permissions+computed-expiry match (the best available
//! identity before a grant's own attribution record arrives) only ever lands
//! on a row that is itself still unattributed (PR #318 review round 4):
//! `expiry_unix_ms` truncates to milliseconds, so two independent launches
//! granting the same service, permissions, TTL and route within the same
//! millisecond is a realistic collision, and a row already attributed to one
//! launch must never provisionally absorb another launch's grant and then
//! have its own identity overwritten by that launch's own attribution record.

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
    /// The credential's raw permissions, joined (`contents:read,
    /// issues:read`) — `None` for a session-scope answer, which has no
    /// permissions concept and dedupes by label alone (PR #318 review,
    /// finding 2). Used, together with [`Self::launch_seq`], to decide
    /// whether a later `CredentialGranted` record folds into this row or
    /// starts a new one: the daemon's own dedup key is
    /// `service + permissions + launch_key`
    /// (`ward-daemon::approvals::Credential`), and permissions is the part
    /// of that key this projection always had directly on the wire.
    pub permissions: Option<String>,
    /// The daemon-stamped identity of the launch this grant's first route was
    /// recorded under (PR #318 review round 3), when one applies: the
    /// sequence number of that launch's own `CommandStarted` record, the same
    /// value `ward-daemon::approvals::Credential::launch_key` is keyed by.
    /// `CredentialGranted` itself never carries this — it arrives, when the
    /// daemon has one, via a [`WardEvent::CredentialGrantedLaunch`] record
    /// immediately after the grant it attributes, consumed by
    /// [`Authority::attribute_launch`]. `None` for a session-scope answer (the
    /// same as [`Self::permissions`]), and for a credential grant with no
    /// attribution record following it at all (recorded outside a tracked
    /// launch, a fixture, or a stream from before this mechanism existed) —
    /// [`Authority::apply`]'s own label + permissions + computed-expiry match
    /// is the fallback identity for those.
    pub launch_seq: Option<u64>,
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
    /// Index into [`Self::grants`] of the credential grant the most recently
    /// applied record either created or merged into, when that record was a
    /// `CredentialGranted` (PR #318 review round 3) — armed for exactly the
    /// next record applied and no further: [`Self::apply`] takes this at the
    /// top of every call, so only a `CredentialGrantedLaunch` immediately
    /// following a `CredentialGranted` in the ordered stream (the shape
    /// `ward-daemon::daemon::Served::handle_appendable` always produces when
    /// it can attribute a grant to an open launch) ever consumes it; any
    /// other record in between clears it, unread.
    pending_grant: Option<usize>,
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
        // A `CredentialGrantedLaunch` attributes exactly the record
        // immediately before it in the ordered stream (PR #318 review round
        // 3) — never any earlier one. Taking this up front means every arm
        // below except its own sees `None`, so attribution can only ever
        // land on the credential grant this record's own predecessor
        // actually was.
        let pending = self.pending_grant.take();
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
                        permissions: None,
                        launch_seq: None,
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
                let computed_expiry = expiry_unix_ms(rec.ts_wall, *expires);
                // `CredentialGranted` itself never carries a launch identity
                // (PR #318 review round 3 reverted that shape — see this
                // module's own doc comment and `WardEvent::CredentialGrantedLaunch`'s):
                // the daemon's real dedup key is `service + permissions +
                // launch_key` (`ward-daemon::approvals::Credential`), but the
                // `launch_key` part of it only reaches this projection via
                // the attribution record that (when the daemon has one)
                // immediately follows this one. At the moment this record
                // itself is applied, the best available signal is still
                // label + permissions + this record's own computed expiry —
                // every real route of one launch mints the same nominal
                // lifetime at essentially the same instant, so routes
                // recorded at the same instant already merge right here. A
                // route recorded at a genuinely different instant does not
                // merge yet; if it and an earlier row really do share a
                // launch, the very next record — that launch's own
                // attribution — corrects it (see [`Self::attribute_launch`]).
                let idx = if let Some(pos) = self.grants.iter().position(|g| {
                    g.label == label
                        && g.permissions.as_deref() == Some(permissions.as_str())
                        && g.expires_at_unix_ms == computed_expiry
                        // PR #318 review round 4: a row already attributed to
                        // a launch (`launch_seq: Some(_)`) is never a valid
                        // provisional home for a *different* record, no
                        // matter how well label/permissions/computed-expiry
                        // line up — `expiry_unix_ms` truncates to
                        // milliseconds, so two independent launches granting
                        // the same service/permissions/TTL/route within one
                        // millisecond is a realistic collision, not a
                        // contrived one, and merging into an attributed row
                        // here would let the next, unrelated
                        // `CredentialGrantedLaunch` overwrite that row's real
                        // identity in `Self::attribute_launch`. A new route
                        // with no attribution of its own yet may only join
                        // another row that is likewise still unattributed;
                        // it starts as its own provisional row otherwise, and
                        // its own immediately-following attribution record
                        // either claims that row or, if it turns out to
                        // belong to an already-attributed earlier row after
                        // all, merges into that one there instead (see
                        // `Self::attribute_launch`).
                        && g.launch_seq.is_none()
                }) {
                    if !self.grants[pos].scope.contains(host) {
                        self.grants[pos].scope.push_str(", ");
                        self.grants[pos].scope.push_str(host);
                    }
                    pos
                } else {
                    self.grants.push(Grant {
                        label,
                        scope: format!("{permissions} · {host}"),
                        lifetime: "launch",
                        network_tag: Some(service.as_str().to_owned()),
                        expires_at_unix_ms: computed_expiry,
                        permissions: Some(permissions),
                        launch_seq: None,
                    });
                    self.grants.len() - 1
                };
                // Armed for exactly the next record (see the `take()` above):
                // only a `CredentialGrantedLaunch` immediately following this
                // one ever consumes it.
                self.pending_grant = Some(idx);
            }
            WardEvent::CredentialGrantedLaunch { launch_seq } => {
                if let Some(idx) = pending {
                    self.attribute_launch(idx, *launch_seq);
                }
                // No preceding `CredentialGranted` to attribute (a hand-built
                // fixture, or a record from a stream missing one) — nothing
                // to do; this is no different from a grant that never got an
                // attribution record at all.
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

    /// Attaches `launch_seq` to `self.grants[idx]` — the credential grant the
    /// `CredentialGranted` record immediately before this
    /// `CredentialGrantedLaunch` created or merged into (PR #318 review round
    /// 3) — merging it into an earlier row that already carries the same
    /// `launch_seq` when [`Self::apply`]'s own provisional, computed-expiry
    /// match split what is really one launch's two routes into two rows (two
    /// routes recorded at genuinely distinct wall-clock instants, PR #318
    /// review round 2's own finding). `launch_seq` alone is enough to find
    /// that earlier row: the daemon mints it from the launch's own
    /// `CommandStarted` record's own sequence number, unique for the life of
    /// the session, so two different launches — even ones granting the very
    /// same service and permissions — never share one.
    fn attribute_launch(&mut self, idx: usize, launch_seq: u64) {
        let Some(earlier) = self
            .grants
            .iter()
            .position(|g| g.launch_seq == Some(launch_seq))
        else {
            // PR #318 review round 4: never clobber a conflicting, already-
            // attributed launch identity. `idx` is only ever unattributed
            // here in practice — `Self::apply`'s own merge-target rule now
            // refuses to land a new record on an already-attributed row — but
            // refusing the overwrite outright, rather than relying solely on
            // that invariant holding elsewhere, means this method can never
            // itself be the one that loses a row's real identity.
            if let Some(g) = self.grants.get_mut(idx)
                && g.launch_seq.is_none()
            {
                g.launch_seq = Some(launch_seq);
            }
            return;
        };
        if earlier == idx {
            // Already attributed — e.g. two routes of this launch merged at
            // `CredentialGranted`-apply time (the same-instant case), and
            // this is the second of their two attribution records.
            return;
        }
        // Fold `idx`'s host(s) into the earlier row and drop the duplicate —
        // the earlier route's own recorded identity and expiry win, exactly
        // the "ignored when merging" rule
        // `Approvals::record_credential_with_expiry` already applies on the
        // daemon's own side.
        for host in hosts_in_scope(&self.grants[idx].scope) {
            if !self.grants[earlier].scope.contains(&host) {
                self.grants[earlier].scope.push_str(", ");
                self.grants[earlier].scope.push_str(&host);
            }
        }
        self.grants.remove(idx);
    }

    /// Whether nothing is recorded at all — including a grant whose own
    /// recorded lifetime has already run out (PR #318 review, finding 1): an
    /// expired grant still belongs in the per-grant list, marked `·
    /// expired`, so this is never the right check for whether anything is
    /// *currently* granted. [`Self::len`] is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// How many grants are current authority at `now_unix_ms` (#316,
    /// PR #318 review finding 1): a grant whose own recorded lifetime has
    /// run out by then does not count, the same as
    /// `ward-daemon::approvals::Approvals::grants` no longer listing it —
    /// only [`Grant::row`]'s own per-grant `· expired` marker still shows it
    /// at all.
    #[must_use]
    pub fn len(&self, now_unix_ms: u64) -> usize {
        self.grants
            .iter()
            .filter(|g| !g.is_expired(now_unix_ms))
            .count()
    }

    /// The tags of the grants that widen the network and are still current
    /// authority at `now_unix_ms` (#316, PR #318 review finding 1), each
    /// once, in order: an expired grant no longer widens anything, so its
    /// tag must not keep the network segment or its tone reading as if it
    /// still did.
    #[must_use]
    pub fn network_tags(&self, now_unix_ms: u64) -> Vec<String> {
        let mut tags: Vec<String> = Vec::new();
        for tag in self
            .grants
            .iter()
            .filter(|g| !g.is_expired(now_unix_ms))
            .filter_map(|g| g.network_tag.clone())
        {
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        tags
    }
}

/// The host(s) after the ` · ` separator in a credential grant's own `scope`
/// string (`"permissions · host1, host2"`, [`Authority::apply`]'s own
/// format) — used only by [`Authority::attribute_launch`] to fold one row's
/// host(s) into another's once it learns, after the fact, the two actually
/// belong to the same launch.
fn hosts_in_scope(scope: &str) -> Vec<String> {
    scope
        .rsplit_once(" · ")
        .map(|(_, hosts)| hosts.split(", ").map(str::to_owned).collect())
        .unwrap_or_default()
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
/// · github+` while a grant still currently widens what the network reaches
/// at `now_unix_ms` — an expired grant's tag drops out (#316, PR #318 review
/// finding 1), the same as [`Authority::network_tags`].
#[must_use]
pub fn network_segment_text(
    network: &NetworkCapability,
    authority: &Authority,
    now_unix_ms: u64,
) -> String {
    let tags = authority.network_tags(now_unix_ms);
    if tags.is_empty() {
        network_text(network)
    } else {
        format!("{} · {}+", network_word(network), tags.join(", "))
    }
}

/// `GRANTS n`, amber while the session is live and something is currently
/// granted at `now_unix_ms`; dim once the log is sealed; `None` once nothing
/// is (#316, PR #318 review finding 1): a grant whose own recorded lifetime
/// has run out does not hold this segment up, the same as
/// [`Authority::len`].
#[must_use]
pub fn grants_segment(authority: &Authority, sealed: bool, now_unix_ms: u64) -> Option<Segment> {
    let current = authority.len(now_unix_ms);
    if current == 0 {
        return None;
    }
    let tone = if sealed { Tone::Dim } else { Tone::Warn };
    Some(Segment::new(format!("GRANTS {current}"), tone))
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
    let live = authority.len(now_unix_ms);
    let tone = if authority.network_tags(now_unix_ms).is_empty() {
        network_tone(&m.network)
    } else {
        Tone::Warn
    };
    let current = vec![
        Row::new("Filesystem", filesystem_text(m), Tone::Ink),
        Row::new(
            "Network",
            network_segment_text(&m.network, authority, now_unix_ms),
            tone,
        ),
        Row::new(
            "Temporary grants",
            live.to_string(),
            if live == 0 { Tone::Ink } else { Tone::Warn },
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
    use crate::feed::fixtures::{records, sequence, wardd, wardd_at_wall, wardd_at_walls};
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

    /// [`credential`], plus its own `WardEvent::CredentialGrantedLaunch`
    /// attribution record immediately after it (PR #318 review round 3) —
    /// the shape a real daemon append actually produces once a
    /// `CommandStarted` is open, rather than the bare, unattributed grant
    /// every other fixture here uses (a credential recorded outside a
    /// tracked launch). Two records, not one: callers push both, in order,
    /// exactly as `ward-daemon::daemon::Served::handle_appendable` does.
    fn credential_in_launch(host: &str, launch_seq: u64) -> [WardEvent; 2] {
        [
            credential(host),
            WardEvent::CredentialGrantedLaunch { launch_seq },
        ]
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
        assert_eq!(authority.len(0), 3);
        assert_eq!(
            authority.grants[0],
            Grant {
                label: "Write /work/src/lib.rs".into(),
                scope: "write".into(),
                lifetime: "session",
                network_tag: None,
                expires_at_unix_ms: None,
                permissions: None,
                launch_seq: None,
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
                permissions: Some("contents:read, issues:read".into()),
                // `credential(..)` (this fixture) carries no `launch_seq`
                // either — the same "outside a tracked launch" shape as
                // every other fixture that predates PR #318 review round 2.
                launch_seq: None,
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
                permissions: None,
                launch_seq: None,
            },
            "a network grant is listed by its host, never the whole URL"
        );
        assert_eq!(authority.network_tags(0), ["github", "example.org"]);
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
        assert_eq!(authority.len(0), 2);

        let mut revoked_events = events.clone();
        revoked_events.push(revoked("github"));
        let authority = Authority::from_records(&wardd(&revoked_events));
        assert_eq!(authority.len(0), 1, "{authority:?}");
        assert_eq!(authority.grants[0].label, "Write /work/src/lib.rs");

        // Revoking a service with no matching grant is a no-op.
        let mut unrelated_events = events.clone();
        unrelated_events.push(revoked("npm"));
        assert_eq!(Authority::from_records(&wardd(&unrelated_events)).len(0), 2);
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
        assert_eq!(paused_authority.len(0), 2, "pausing drops nothing");
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
        assert_eq!(
            before[0].rows[2].value, "1",
            "still current authority just before its own deadline"
        );
        assert_eq!(before[0].rows[2].tone, Tone::Warn);
        assert_eq!(before[0].rows[1].value, "restricted · github+");

        let at = authority_panel(&d, &authority, EXPIRES_AT_UNIX_MS);
        assert_eq!(
            at[1].rows[0].value, "contents:read, issues:read · github.com · launch · expired",
            "the instant its own recorded lifetime runs out, ward session \
             grants and this panel must not disagree"
        );
        // PR #318 review, finding 1: an expired grant reads `expired` in its
        // own row, but must not go on counting as current, exercisable
        // authority anywhere else — the "Temporary grants" count, the
        // network segment's tone and tags, and the trust bar's `GRANTS n`
        // segment must all agree with `ward session grants` having already
        // dropped it.
        assert_eq!(
            at[0].rows[2].value, "0",
            "an expired grant is no longer current authority"
        );
        assert_eq!(at[0].rows[2].tone, Tone::Ink);
        assert_eq!(
            at[0].rows[1].value, "restricted (dev)",
            "an expired grant no longer widens the network"
        );
        assert_eq!(authority.len(EXPIRES_AT_UNIX_MS), 0);
        assert!(authority.network_tags(EXPIRES_AT_UNIX_MS).is_empty());
        assert_eq!(grants_segment(&authority, false, EXPIRES_AT_UNIX_MS), None);

        let after = authority_panel(&d, &authority, EXPIRES_AT_UNIX_MS + 60_000);
        assert!(after[1].rows[0].value.ends_with("· expired"));
        assert_eq!(after[0].rows[2].value, "0");
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
    fn a_second_route_of_the_same_launch_merges_into_one_grant() {
        // #316, mirroring `Approvals::record_credential_with_expiry`'s own
        // "ignored when merging" rule: every real caller mints the same
        // nominal lifetime for every route one launch grants at once, so
        // two routes recorded at the same instant (the same launch minting
        // both at once) fold into one grant, keeping that one shared
        // expiry.
        let events = [credential("github.com"), credential("api.github.com")];
        let authority = Authority::from_records(&wardd_at_walls(&events, &[GRANTED_AT_UNIX_MS; 2]));
        assert_eq!(authority.len(0), 1);
        assert_eq!(
            authority.grants[0].expires_at_unix_ms,
            Some(EXPIRES_AT_UNIX_MS)
        );
        assert_eq!(
            authority.grants[0].scope,
            "contents:read, issues:read · github.com, api.github.com"
        );
    }

    #[test]
    fn a_later_independent_grant_for_the_same_service_gets_its_own_row_and_expiry() {
        // PR #318 review, finding 2: `Authority::apply` used to merge every
        // `CredentialGranted` by the display label alone and always kept the
        // *first* grant's expiry — so a second, wholly independent launch
        // granting the same service again (its own later, different
        // deadline) got silently folded into the first grant and inherited
        // an expiry that was never its own. The daemon's real identity is
        // `service + permissions + launch_key`; with no `launch_key` on the
        // wire, this projection's best-available proxy is: same label, same
        // permissions, *and* the same already-computed deadline (what every
        // route of one real launch actually shares). A second grant whose
        // own computed deadline differs is a different launch and must get
        // its own row with its own expiry, exactly as `ward session grants`
        // already lists it.
        let events = [credential("github.com"), credential("github.com")];
        // One second apart (`wardd_at_wall`): two records that are not the
        // same instant, so — even though the label, host and permissions
        // are identical — their own computed deadlines differ by 1 second.
        let authority = Authority::from_records(&wardd_at_wall(&events, GRANTED_AT_UNIX_MS));
        assert_eq!(
            authority.grants.len(),
            2,
            "two independent grants, not one merged row: {:?}",
            authority.grants
        );
        assert_eq!(authority.grants[0].label, "GitHub");
        assert_eq!(authority.grants[1].label, "GitHub");
        assert_eq!(
            authority.grants[0].expires_at_unix_ms,
            Some(EXPIRES_AT_UNIX_MS)
        );
        assert_eq!(
            authority.grants[1].expires_at_unix_ms,
            Some(EXPIRES_AT_UNIX_MS + 1000),
            "the second grant's own later record computes its own, later deadline"
        );

        let d = description(NetworkCapability::Development);
        // At the first grant's deadline, it alone has expired; the second,
        // genuinely later grant is still live — the exact disagreement the
        // review's reproduction describes (T0+60 must not expire a grant
        // that is only really due at T0+90).
        let groups = authority_panel(&d, &authority, EXPIRES_AT_UNIX_MS);
        assert!(
            groups[1].rows[0].value.ends_with("· expired"),
            "{:?}",
            groups[1].rows
        );
        assert!(
            !groups[1].rows[1].value.contains("expired"),
            "the second, independently-timed grant is not due yet: {:?}",
            groups[1].rows
        );
        assert_eq!(
            authority.len(EXPIRES_AT_UNIX_MS),
            1,
            "one of the two is still current authority"
        );

        // Different permissions for the same service must not merge either,
        // even recorded at the very same instant.
        let different_scope = WardEvent::CredentialGranted {
            service: ward_events::ServiceId::new("github").unwrap(),
            scope: Scope {
                subject: ShortText::new("github.com:443"),
                permissions: vec![NameText::new("contents:write")],
            },
            expires: Duration::from_secs(60),
            delivery: CredentialDelivery::ProxyInjected,
        };
        let events = [credential("github.com"), different_scope];
        let authority = Authority::from_records(&wardd_at_walls(&events, &[GRANTED_AT_UNIX_MS; 2]));
        assert_eq!(
            authority.grants.len(),
            2,
            "same instant and same label, but different permissions: still \
             two rows: {:?}",
            authority.grants
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
            network_segment_text(&NetworkCapability::Development, &none, 0),
            "restricted (dev)",
            "unchanged without a grant"
        );
        assert_eq!(grants_segment(&none, false, 0), None);
        let github = Authority::from_records(&wardd(&[credential("github.com")]));
        assert_eq!(
            network_segment_text(&NetworkCapability::Development, &github, 0),
            "restricted · github+"
        );
        assert_eq!(
            network_segment_text(&NetworkCapability::Offline, &github, 0),
            "offline · github+"
        );
        assert_eq!(
            grants_segment(&github, false, 0),
            Some(Segment::new("GRANTS 1", Tone::Warn))
        );
        assert_eq!(
            grants_segment(&github, true, 0),
            Some(Segment::new("GRANTS 1", Tone::Dim))
        );
        // PR #318 review, finding 1: once its own recorded lifetime has run
        // out, a grant holds up neither the network segment's tag nor the
        // trust bar's `GRANTS n` segment any longer.
        let expiring = Authority::from_records(&wardd_at_wall(
            &[credential("github.com")],
            GRANTED_AT_UNIX_MS,
        ));
        assert_eq!(
            network_segment_text(
                &NetworkCapability::Development,
                &expiring,
                EXPIRES_AT_UNIX_MS
            ),
            "restricted (dev)",
            "expired, so the tag drops out"
        );
        assert_eq!(grants_segment(&expiring, false, EXPIRES_AT_UNIX_MS), None);
        // A file grant is a grant, but widens no network.
        let write = Authority::from_records(&wardd(&[decided(
            CapabilityKind::FileWrite,
            "Write /work/a.rs",
            Some(GrantScope::Session),
        )]));
        assert_eq!(
            network_segment_text(&NetworkCapability::Development, &write, 0),
            "restricted (dev)"
        );
        assert_eq!(grants_segment(&write, false, 0).unwrap().text, "GRANTS 1");
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

    /// PR #318 review round 2's own production-style sequence, carried
    /// through round 3's fix: `CommandStarted`, then two separately appended
    /// same-launch `CredentialGranted` records, each followed by its own
    /// `CredentialGrantedLaunch` attribution record, with genuinely distinct
    /// daemon timestamps (`wardd_at_wall` gives every record its own, one
    /// second apart — never an artificial identical-instant shortcut) must
    /// still merge into one grant row: [`Authority::apply`]'s provisional
    /// computed-expiry match does not merge them at `CredentialGranted`-apply
    /// time (their instants genuinely differ), but the second route's own
    /// attribution record, sharing the first route's `launch_seq`, corrects
    /// that via [`Authority::attribute_launch`] the moment it arrives. A
    /// later, independent launch — its own
    /// `CommandStarted`/…/`CommandFinished` bracket — granting the same
    /// service and permissions again gets a different `launch_seq` and so its
    /// own separate row, with its own expiry, exactly as `ward session
    /// grants` already lists it.
    #[test]
    fn same_launch_routes_merge_by_launch_seq_at_distinct_instants_and_a_later_launch_gets_its_own_row()
     {
        let pid = ward_events::Pid::new(2).unwrap();
        let started = || WardEvent::CommandStarted {
            pid,
            parent: ward_events::Pid::new(1).unwrap(),
            argv: ward_events::BoundedArgv::from_strs(&["true"]),
            cwd: ward_events::SandboxPath::new(ward_events::SandboxRoot::Work, ".").unwrap(),
            exe_digest: None,
        };
        let finished = || WardEvent::CommandFinished {
            pid,
            exit: ward_events::ExitStatus::Exited { code: 0 },
            duration: Duration::from_secs(1),
        };

        let mut events = vec![started()];
        // Two routes of the first launch, each a `CredentialGranted` plus its
        // own `CredentialGrantedLaunch { launch_seq: 1 }` attribution record
        // (what a real daemon appends for every route one `Session::launch`
        // call grants), recorded at genuinely distinct instants.
        events.extend(credential_in_launch("github.com", 1));
        events.extend(credential_in_launch("api.github.com", 1));
        events.push(finished());
        // A second, independent launch, same service and permissions, its
        // own `launch_seq`.
        events.push(started());
        events.extend(credential_in_launch("github.com", 2));
        events.push(finished());
        let authority = Authority::from_records(&wardd_at_wall(&events, GRANTED_AT_UNIX_MS));

        assert_eq!(
            authority.grants.len(),
            2,
            "one merged grant for the first launch's two routes, a second, \
             separate grant for the later independent launch: {:?}",
            authority.grants
        );
        assert_eq!(
            authority.grants[0].scope, "contents:read, issues:read · github.com, api.github.com",
            "both routes of the first launch merged despite distinct \
             wall-clock instants: {:?}",
            authority.grants[0]
        );
        assert_eq!(authority.grants[0].launch_seq, Some(1));
        assert_eq!(authority.grants[1].launch_seq, Some(2));
        assert_ne!(
            authority.grants[0].expires_at_unix_ms, authority.grants[1].expires_at_unix_ms,
            "the two launches were recorded at genuinely different instants, \
             so they must not share a deadline either: {:?}",
            authority.grants
        );
        assert_eq!(authority.len(0), 2);
    }

    /// PR #318 review round 4: `expiry_unix_ms` truncates to milliseconds, so
    /// two independent launches granting the same service, permissions, TTL
    /// and route within the same millisecond is a realistic outcome, not a
    /// contrived one — and used to be merged into one row before the second
    /// launch's own `CredentialGrantedLaunch` arrived, which then overwrote
    /// the first launch's `launch_seq` outright: [`Authority::apply`]'s
    /// provisional merge matched the target by label + permissions +
    /// computed expiry alone, with no regard for whether that row was
    /// already attributed to a different launch, and
    /// [`Authority::attribute_launch`] then had nothing telling it the row
    /// it was about to stamp already belonged to someone else.
    #[test]
    fn two_independent_launches_sharing_a_millisecond_project_as_two_grants_with_their_own_launch_seq()
     {
        let pid = ward_events::Pid::new(2).unwrap();
        let started = || WardEvent::CommandStarted {
            pid,
            parent: ward_events::Pid::new(1).unwrap(),
            argv: ward_events::BoundedArgv::from_strs(&["true"]),
            cwd: ward_events::SandboxPath::new(ward_events::SandboxRoot::Work, ".").unwrap(),
            exe_digest: None,
        };
        let finished = || WardEvent::CommandFinished {
            pid,
            exit: ward_events::ExitStatus::Exited { code: 0 },
            duration: Duration::from_secs(1),
        };

        let mut events = vec![started()];
        // First launch, one route, its own attribution.
        events.extend(credential_in_launch("github.com", 1));
        events.push(finished());
        // A second, wholly independent launch, granting the very same
        // service, permissions and route again, its own different
        // `launch_seq`.
        events.push(started());
        events.extend(credential_in_launch("github.com", 2));
        events.push(finished());

        // Every record shares the exact same wall-clock millisecond — the
        // realistic same-millisecond collision the review names (two
        // launches landing within a millisecond of each other), not the
        // artificial identical-instant shortcut the same-launch tests apply
        // only to routes that really do belong to one launch.
        let walls = vec![GRANTED_AT_UNIX_MS; events.len()];
        let authority = Authority::from_records(&wardd_at_walls(&events, &walls));

        assert_eq!(
            authority.grants.len(),
            2,
            "two independent launches must project as two rows, even though \
             their computed deadlines collide to the millisecond: {:?}",
            authority.grants
        );
        assert_eq!(
            authority.grants[0].launch_seq,
            Some(1),
            "the first launch's own identity must survive: {:?}",
            authority.grants
        );
        assert_eq!(
            authority.grants[1].launch_seq,
            Some(2),
            "the second launch's own identity must land on its own row: {:?}",
            authority.grants
        );
        assert_eq!(
            authority.grants[0].expires_at_unix_ms, authority.grants[1].expires_at_unix_ms,
            "same wall clock and same TTL: the computed deadlines really do \
             collide, which is exactly what makes this reproduction real"
        );
        assert_eq!(authority.len(0), 2, "both are still live authority");
    }

    /// PR #318 review round 3, requirement 3: a `CredentialGranted` record
    /// produced by the previous (pre-#318) schema — the exact frozen bytes
    /// `crates/ward-events/tests/roundtrip.rs`'s own
    /// `a_frozen_pre_318_credential_granted_record_still_verifies_its_hash_and_replays`
    /// test freezes and proves decodes and verifies — must also replay
    /// through this projection and project safely: one grant, no
    /// `launch_seq` (this record predates the attribution mechanism, so
    /// nothing follows it), its expiry computed from its own `ts_wall` the
    /// same way any other credential grant's is.
    #[test]
    fn a_frozen_pre_318_record_replays_through_authority_and_projects_one_unattributed_grant() {
        use ward_events::wire::decode_record;

        let event = WardEvent::CredentialGranted {
            service: ward_events::ServiceId::new("github").unwrap(),
            scope: Scope {
                subject: ShortText::new("repo:hexrift/wardos"),
                permissions: vec![NameText::new("contents:read")],
            },
            expires: Duration::from_secs(600),
            delivery: CredentialDelivery::ProxyInjected,
        };
        // Frozen: `postcard::to_allocvec(&event)` for the exact event above,
        // under the plain four-field `CredentialGranted` shape -- the same
        // literal the `ward-events` fixture freezes, reproduced here so this
        // projection is proved against the identical bytes, not merely
        // against a same-shaped object this crate happens to construct the
        // same way.
        let frozen_body: &[u8] = &[
            12, 6, 103, 105, 116, 104, 117, 98, 19, 114, 101, 112, 111, 58, 104, 101, 120, 114,
            105, 102, 116, 47, 119, 97, 114, 100, 111, 115, 0, 0, 1, 13, 99, 111, 110, 116, 101,
            110, 116, 115, 58, 114, 101, 97, 100, 0, 0, 216, 4, 0, 0,
        ];

        let session = ward_events::SessionId::from_u128(0x5e58);
        let prev = ward_events::Blake3Hash::hash(b"manifest");
        let seq = 0u64;
        let origin = Origin::Wardd;
        let granted_at_unix_ms = 1_000_000_000_000u64;
        let mut hashed = Vec::new();
        hashed.extend_from_slice(prev.as_bytes());
        hashed.extend_from_slice(&seq.to_le_bytes());
        hashed.push(origin.tag());
        hashed.extend_from_slice(frozen_body);
        let hash = ward_events::Blake3Hash::hash(&hashed);
        let record = ward_events::EventRecord {
            session,
            seq,
            ts_mono: Duration::from_secs(0),
            ts_wall: Some(std::time::UNIX_EPOCH + Duration::from_millis(granted_at_unix_ms)),
            origin,
            prev,
            event,
            hash,
        };
        record.verify_hash().unwrap();

        // Round it through the wire once more, exactly as a subscriber or a
        // replayed log would hand it to this projection.
        let bytes = ward_events::wire::encode_record(&record).unwrap();
        let (decoded, _) = decode_record(&bytes).unwrap();

        let authority = Authority::from_records(std::slice::from_ref(&decoded));
        assert_eq!(authority.grants.len(), 1);
        assert_eq!(
            authority.grants[0],
            Grant {
                label: "GitHub".into(),
                // The subject this frozen fixture carries, `repo:hexrift/wardos`
                // (chosen in `ward-events`'s own fixture to exercise a subject
                // that is not a `host:port` pair), splits on its last `:` into
                // `repo`, exactly as any other subject shaped that way would.
                scope: "contents:read · repo".into(),
                lifetime: "launch",
                network_tag: Some("github".into()),
                expires_at_unix_ms: Some(granted_at_unix_ms + 600_000),
                permissions: Some("contents:read".into()),
                launch_seq: None,
            },
            "a pre-#318 record has no attribution record following it, so it \
             projects exactly as it always did: one grant, no launch_seq"
        );
    }
}
