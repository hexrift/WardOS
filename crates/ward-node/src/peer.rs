//! Peer-credential gate on the node's local socket (#262).
//!
//! The filesystem decides who can connect to the socket (its mode and group, see
//! [`crate::serve_local`]); this module decides who is served once connected. Every
//! accepted connection has its peer's `SO_PEERCRED` uid read before a byte of it is
//! processed, and only the node's own uid and the uids an operator listed with
//! `--client-uid` are served. Anyone else is closed with nothing sent, and the refusal
//! is reported at most once per uid per [`REFUSAL_REPORT_INTERVAL`], with a count of the
//! refusals that went unreported in between, so a hostile peer cannot flood the log.
//!
//! Being served is not authority: an allowed uid still needs a trusted signature for
//! `admit` (ADR-0030 §2).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::PeerCredentials;
use nix::unistd::{Gid, Group, Uid, User};
use thiserror::Error;

/// At most one refusal is reported per uid in this long; the next report carries the
/// count of the refusals it did not report.
pub const REFUSAL_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// How many refused uids are tracked at once; past it, the uid reported longest ago is
/// forgotten and its next refusal is reported like a first one.
pub const MAX_TRACKED_REFUSED_UIDS: usize = 256;

/// A `--client-uid` value the node cannot use.
#[derive(Debug, Error)]
pub enum ClientUidError {
    /// Neither a uid (decimal digits only) nor the name of a user known to the host.
    #[error("client uid {value:?} is neither a uid nor a known user")]
    Invalid {
        /// The value as given.
        value: String,
    },
    /// The same uid was listed twice, by number or by name.
    #[error("client uid {uid} is listed twice")]
    Duplicate {
        /// The uid listed twice.
        uid: u32,
    },
    /// The user database could not be consulted for a name.
    #[error("client uid {value:?} could not be looked up: {source}")]
    Lookup {
        /// The value as given.
        value: String,
        /// The lookup failure.
        #[source]
        source: nix::Error,
    },
}

/// A `--client-group` value the node cannot use.
#[derive(Debug, Error)]
pub enum ClientGroupError {
    /// Neither a gid (decimal digits only) nor the name of a group known to the host.
    #[error("client group {value:?} is neither a gid nor a known group")]
    Invalid {
        /// The value as given.
        value: String,
    },
    /// The group database could not be consulted for a name.
    #[error("client group {value:?} could not be looked up: {source}")]
    Lookup {
        /// The value as given.
        value: String,
        /// The lookup failure.
        #[source]
        source: nix::Error,
    },
}

/// The uids, besides the node's own, that the node serves on its socket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientUids(BTreeSet<u32>);

impl ClientUids {
    /// No uid besides the node's own.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Resolve each value, a uid in decimal or a user name, into one set.
    ///
    /// # Errors
    ///
    /// Returns [`ClientUidError`] for a value that is neither, for a lookup the host
    /// cannot answer, or for a uid listed twice.
    pub fn parse<I, S>(values: I) -> Result<Self, ClientUidError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut uids = BTreeSet::new();
        for value in values {
            let uid = resolve_uid(value.as_ref())?.as_raw();
            if !uids.insert(uid) {
                return Err(ClientUidError::Duplicate { uid });
            }
        }
        Ok(Self(uids))
    }

    /// Whether `uid` is listed.
    #[must_use]
    pub fn contains(&self, uid: Uid) -> bool {
        self.0.contains(&uid.as_raw())
    }

    /// How many uids are listed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no uid is listed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn resolve_uid(value: &str) -> Result<Uid, ClientUidError> {
    let invalid = || ClientUidError::Invalid {
        value: value.to_owned(),
    };
    if is_decimal(value) {
        return value.parse().map(Uid::from_raw).map_err(|_| invalid());
    }
    match User::from_name(value) {
        Ok(Some(user)) => Ok(user.uid),
        Ok(None) => Err(invalid()),
        Err(source) => Err(ClientUidError::Lookup {
            value: value.to_owned(),
            source,
        }),
    }
}

/// The group the socket is shared with (`--client-group`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientGroup(Gid);

impl ClientGroup {
    /// Resolve a gid in decimal or a group name.
    ///
    /// # Errors
    ///
    /// Returns [`ClientGroupError`] for a value that is neither, or for a lookup the host
    /// cannot answer.
    pub fn parse(value: &str) -> Result<Self, ClientGroupError> {
        let invalid = || ClientGroupError::Invalid {
            value: value.to_owned(),
        };
        if is_decimal(value) {
            return value
                .parse()
                .map(|raw| Self(Gid::from_raw(raw)))
                .map_err(|_| invalid());
        }
        match Group::from_name(value) {
            Ok(Some(group)) => Ok(Self(group.gid)),
            Ok(None) => Err(invalid()),
            Err(source) => Err(ClientGroupError::Lookup {
                value: value.to_owned(),
                source,
            }),
        }
    }

    /// The group's id.
    #[must_use]
    pub fn gid(self) -> Gid {
        self.0
    }
}

/// Whether a connected peer is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDecision {
    /// The peer is the node's own uid or a listed client uid.
    Served,
    /// Any other peer: the connection is closed with nothing sent.
    Refused,
}

/// A refused connection: who it came from and, when the rate limit allows, a line for
/// the node's log.
#[derive(Debug)]
pub struct PeerRefusal {
    peer: Option<Uid>,
    suppressed: Option<u64>,
}

impl PeerRefusal {
    /// The peer's uid, or `None` when its credentials could not be read.
    #[must_use]
    pub fn peer(&self) -> Option<Uid> {
        self.peer
    }

    /// The log line for this refusal, or `None` when one for the same uid was reported
    /// less than [`REFUSAL_REPORT_INTERVAL`] ago.
    #[must_use]
    pub fn report(&self) -> Option<String> {
        let suppressed = self.suppressed?;
        let who = match self.peer {
            Some(uid) => format!("uid {}", uid.as_raw()),
            None => "a peer whose credentials could not be read".to_owned(),
        };
        Some(if suppressed == 0 {
            format!("ward-node: refused a connection from {who}")
        } else {
            format!(
                "ward-node: refused a connection from {who} ({suppressed} more since the last report)"
            )
        })
    }
}

/// A per-key rate limit on reports: at most one per key per interval, the next one
/// carrying the count of those it did not report, over a bounded number of keys.
#[derive(Debug)]
pub struct ReportLimit<K> {
    interval: Duration,
    capacity: usize,
    entries: BTreeMap<K, Reported>,
}

#[derive(Debug)]
struct Reported {
    at: Instant,
    suppressed: u64,
}

impl<K: Ord + Clone> ReportLimit<K> {
    /// One report per key per `interval`, tracking at most `capacity` keys; past it, the
    /// key reported longest ago is forgotten and its next event is reported like a first.
    #[must_use]
    pub fn new(interval: Duration, capacity: usize) -> Self {
        Self {
            interval,
            capacity: capacity.max(1),
            entries: BTreeMap::new(),
        }
    }

    /// Record an event for `key` at `now`: `Some(n)` when it is to be reported, with the
    /// `n` events of the same key that went unreported since its last report.
    pub fn record(&mut self, key: K, now: Instant) -> Option<u64> {
        if let Some(entry) = self.entries.get_mut(&key) {
            if now.saturating_duration_since(entry.at) < self.interval {
                entry.suppressed = entry.suppressed.saturating_add(1);
                return None;
            }
            let suppressed = entry.suppressed;
            entry.at = now;
            entry.suppressed = 0;
            return Some(suppressed);
        }
        if self.entries.len() >= self.capacity {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            Reported {
                at: now,
                suppressed: 0,
            },
        );
        Some(0)
    }

    /// How many keys are tracked right now.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.entries.len()
    }
}

/// Per-uid rate limit on refusal reports.
#[derive(Debug)]
pub struct RefusalLog(ReportLimit<Option<u32>>);

impl RefusalLog {
    /// One report per uid per `interval`, tracking at most `capacity` uids.
    #[must_use]
    pub fn new(interval: Duration, capacity: usize) -> Self {
        Self(ReportLimit::new(interval, capacity))
    }

    /// Record a refusal of `peer` at `now`: `Some(n)` when it is to be reported, with
    /// the `n` refusals of the same peer that went unreported since its last report.
    pub fn record(&mut self, peer: Option<Uid>, now: Instant) -> Option<u64> {
        self.0.record(peer.map(Uid::as_raw), now)
    }

    /// How many uids are tracked right now.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.0.tracked()
    }
}

/// The gate: the node's own uid, the listed client uids and the refusal rate limit.
#[derive(Debug)]
pub struct PeerGate {
    own: Uid,
    clients: ClientUids,
    refusals: RefusalLog,
}

impl PeerGate {
    /// A gate serving `own` and `clients`.
    #[must_use]
    pub fn new(own: Uid, clients: ClientUids) -> Self {
        Self {
            own,
            clients,
            refusals: RefusalLog::new(REFUSAL_REPORT_INTERVAL, MAX_TRACKED_REFUSED_UIDS),
        }
    }

    /// The decision for a peer of uid `peer`.
    #[must_use]
    pub fn decide(&self, peer: Uid) -> PeerDecision {
        if peer == self.own || self.clients.contains(peer) {
            PeerDecision::Served
        } else {
            PeerDecision::Refused
        }
    }

    /// Read the connection's peer credentials and decide, before any byte of it is read.
    ///
    /// # Errors
    ///
    /// Returns the [`PeerRefusal`] for a peer that is not served, including one whose
    /// credentials cannot be read; the caller closes the connection without a response.
    pub fn admit(&mut self, stream: &UnixStream, now: Instant) -> Result<(), PeerRefusal> {
        let peer = getsockopt(stream, PeerCredentials)
            .ok()
            .map(|credentials| Uid::from_raw(credentials.uid()));
        if peer.is_some_and(|uid| self.decide(uid) == PeerDecision::Served) {
            return Ok(());
        }
        Err(PeerRefusal {
            peer,
            suppressed: self.refusals.record(peer, now),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use nix::unistd::{Gid, Uid};

    use super::*;

    fn uid(raw: u32) -> Uid {
        Uid::from_raw(raw)
    }

    #[test]
    fn client_uids_parse_numbers_and_user_names_into_one_set() {
        let uids = ClientUids::parse(["1000", "root", "65534"]).unwrap();
        assert!(uids.contains(uid(1000)));
        assert!(uids.contains(uid(0)));
        assert!(uids.contains(uid(65534)));
        assert!(!uids.contains(uid(1)));
        assert_eq!(uids.len(), 3);
        assert!(ClientUids::empty().is_empty());
        assert!(!uids.is_empty());
    }

    #[test]
    fn a_uid_listed_twice_by_number_or_by_name_is_refused() {
        assert!(matches!(
            ClientUids::parse(["7", "7"]),
            Err(ClientUidError::Duplicate { uid: 7 })
        ));
        assert!(matches!(
            ClientUids::parse(["root", "0"]),
            Err(ClientUidError::Duplicate { uid: 0 })
        ));
    }

    #[test]
    fn an_unknown_user_or_a_malformed_number_is_refused() {
        for input in [
            "",
            " 7",
            "-1",
            "+7",
            "4294967296",
            "no-such-user-here",
            "7 ",
            "0x10",
        ] {
            assert!(
                matches!(
                    ClientUids::parse([input]),
                    Err(ClientUidError::Invalid { ref value }) if value == input
                ),
                "{input:?}"
            );
        }
    }

    #[test]
    fn client_group_parses_a_number_or_a_group_name_and_refuses_the_rest() {
        assert_eq!(ClientGroup::parse("0").unwrap().gid(), Gid::from_raw(0));
        assert_eq!(ClientGroup::parse("root").unwrap().gid(), Gid::from_raw(0));
        assert!(ClientGroup::parse("4294967296").is_err());
        assert!(ClientGroup::parse("no-such-group-here").is_err());
        assert!(ClientGroup::parse("").is_err());
    }

    #[test]
    fn the_gate_serves_its_own_uid_and_listed_uids_and_refuses_the_rest() {
        let gate = PeerGate::new(uid(1000), ClientUids::parse(["2000"]).unwrap());
        assert_eq!(gate.decide(uid(1000)), PeerDecision::Served);
        assert_eq!(gate.decide(uid(2000)), PeerDecision::Served);
        assert_eq!(gate.decide(uid(0)), PeerDecision::Refused);
        assert_eq!(gate.decide(uid(3000)), PeerDecision::Refused);

        let own_only = PeerGate::new(uid(1000), ClientUids::empty());
        assert_eq!(own_only.decide(uid(1000)), PeerDecision::Served);
        assert_eq!(own_only.decide(uid(0)), PeerDecision::Refused);
    }

    #[test]
    fn refusals_are_reported_once_per_uid_per_interval_with_the_suppressed_count() {
        let interval = Duration::from_secs(10);
        let mut log = RefusalLog::new(interval, 4);
        let start = Instant::now();
        assert_eq!(log.record(Some(uid(5)), start), Some(0));
        assert_eq!(
            log.record(Some(uid(5)), start + Duration::from_secs(1)),
            None
        );
        assert_eq!(
            log.record(Some(uid(5)), start + Duration::from_secs(9)),
            None
        );
        assert_eq!(
            log.record(Some(uid(6)), start + Duration::from_secs(9)),
            Some(0)
        );
        assert_eq!(log.record(Some(uid(5)), start + interval), Some(2));
        assert_eq!(log.record(Some(uid(5)), start + interval), None);
        assert_eq!(log.record(None, start), Some(0));
        assert_eq!(log.record(None, start), None);
    }

    #[test]
    fn the_refusal_log_tracks_a_bounded_number_of_uids_and_forgets_the_oldest() {
        let interval = Duration::from_secs(10);
        let mut log = RefusalLog::new(interval, 2);
        let start = Instant::now();
        assert_eq!(log.record(Some(uid(1)), start), Some(0));
        assert_eq!(
            log.record(Some(uid(2)), start + Duration::from_secs(1)),
            Some(0)
        );
        assert_eq!(
            log.record(Some(uid(3)), start + Duration::from_secs(2)),
            Some(0)
        );
        assert_eq!(log.tracked(), 2);
        assert_eq!(
            log.record(Some(uid(1)), start + Duration::from_secs(3)),
            Some(0)
        );
        assert_eq!(
            log.record(Some(uid(3)), start + Duration::from_secs(3)),
            None
        );
    }

    #[test]
    fn the_gate_reads_real_peer_credentials_and_reports_refusals_rate_limited() {
        let me = Uid::effective();
        let other = Uid::from_raw(me.as_raw().wrapping_add(1));
        let now = Instant::now();

        let mut own = PeerGate::new(me, ClientUids::empty());
        let (_client, server) = UnixStream::pair().unwrap();
        assert!(own.admit(&server, now).is_ok());

        let mut foreign = PeerGate::new(other, ClientUids::empty());
        let (_client, server) = UnixStream::pair().unwrap();
        let refusal = foreign.admit(&server, now).unwrap_err();
        assert_eq!(refusal.peer(), Some(me));
        let report = refusal.report().unwrap();
        assert!(report.contains(&format!("uid {}", me.as_raw())), "{report}");
        let (_client, server) = UnixStream::pair().unwrap();
        assert!(foreign.admit(&server, now).unwrap_err().report().is_none());
        let (_client, server) = UnixStream::pair().unwrap();
        let later = foreign
            .admit(&server, now + REFUSAL_REPORT_INTERVAL)
            .unwrap_err();
        assert!(later.report().unwrap().contains("1 more"), "{later:?}");

        let mut listed = PeerGate::new(other, ClientUids::parse([me.to_string()]).unwrap());
        let (_client, server) = UnixStream::pair().unwrap();
        assert!(listed.admit(&server, now).is_ok());
    }

    #[test]
    fn errors_name_the_offending_value() {
        assert_eq!(
            ClientUidError::Duplicate { uid: 7 }.to_string(),
            "client uid 7 is listed twice"
        );
        assert!(
            ClientUids::parse(["nobody-such"])
                .unwrap_err()
                .to_string()
                .contains("nobody-such")
        );
        assert!(
            ClientGroup::parse("nogroup-such")
                .unwrap_err()
                .to_string()
                .contains("nogroup-such")
        );
    }
}
