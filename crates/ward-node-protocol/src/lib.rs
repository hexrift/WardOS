//! ward-node-protocol: dependency-light protocol contracts shared by a future
//! ward-node and its local or remote clients.
//!
//! This crate starts with version negotiation only. Task identity, authority leases,
//! authentication, lifecycle operations and transport belong to later slices of #258,
//! #259 and #262. Incompatible peers fail closed rather than falling back to the
//! per-session ward-daemon control protocol.

#![forbid(unsafe_code)]

use std::fmt::{Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// The node protocol version currently implemented by this revision.
///
/// Minor versions are backwards-compatible within one major version. The initial
/// implementation supports only 1.0; later compatible additions widen the supported
/// minor range explicitly.
pub const WARD_NODE_PROTOCOL: SupportedProtocolRange = SupportedProtocolRange::valid(1, 0, 0);

/// One negotiated node protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// Construct a protocol version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Major protocol version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Minor protocol version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// A contiguous range of minor versions supported for one major protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SupportedProtocolRange {
    major: u16,
    min_minor: u16,
    max_minor: u16,
}

impl SupportedProtocolRange {
    const fn valid(major: u16, min_minor: u16, max_minor: u16) -> Self {
        Self {
            major,
            min_minor,
            max_minor,
        }
    }

    /// Construct a supported protocol range.
    ///
    /// # Errors
    ///
    /// Returns `SupportedProtocolRangeError::InvertedMinorRange` when
    /// `min_minor` is greater than `max_minor`.
    pub const fn new(
        major: u16,
        min_minor: u16,
        max_minor: u16,
    ) -> Result<Self, SupportedProtocolRangeError> {
        if min_minor > max_minor {
            return Err(SupportedProtocolRangeError::InvertedMinorRange);
        }

        Ok(Self::valid(major, min_minor, max_minor))
    }

    /// Major protocol version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Lowest supported minor protocol version.
    #[must_use]
    pub const fn min_minor(self) -> u16 {
        self.min_minor
    }

    /// Highest supported minor protocol version.
    #[must_use]
    pub const fn max_minor(self) -> u16 {
        self.max_minor
    }
}

/// A malformed supported protocol range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportedProtocolRangeError {
    /// The advertised minimum minor version exceeds the advertised maximum.
    InvertedMinorRange,
}

impl Display for SupportedProtocolRangeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvertedMinorRange => {
                formatter.write_str("minimum supported minor exceeds maximum supported minor")
            }
        }
    }
}

impl std::error::Error for SupportedProtocolRangeError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportedProtocolRangeWire {
    major: u16,
    min_minor: u16,
    max_minor: u16,
}

impl<'de> Deserialize<'de> for SupportedProtocolRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SupportedProtocolRangeWire::deserialize(deserializer)?;
        Self::new(wire.major, wire.min_minor, wire.max_minor).map_err(D::Error::custom)
    }
}

/// The first message a node protocol client sends on a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum HandshakeRequest {
    /// Advertise the protocol range the client can speak.
    Hello {
        /// Client-supported protocol range.
        protocol: SupportedProtocolRange,
    },
}

/// Stable machine-readable reasons a node rejects protocol negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRejectionReason {
    /// The peers do not implement the same major version.
    MajorVersionMismatch,
    /// The peers share a major version but their supported minor ranges do not overlap.
    NoCommonMinor,
}

/// The node's response to a protocol handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case", deny_unknown_fields)]
pub enum HandshakeResponse {
    /// Both peers support the selected protocol version.
    Accepted {
        /// Highest protocol version both peers support.
        protocol: ProtocolVersion,
    },
    /// No compatible protocol version exists.
    Rejected {
        /// Stable rejection reason for automation and diagnostics.
        reason: ProtocolRejectionReason,
        /// Protocol range supported by the rejecting node.
        supported: SupportedProtocolRange,
    },
}

/// Negotiate the highest mutually supported protocol version.
///
/// Major versions must match exactly. Within one major version the highest common
/// minor version is selected. Incompatibility returns an explicit rejection response;
/// callers must not fall back to the per-session daemon protocol.
#[must_use]
pub const fn negotiate(
    local: SupportedProtocolRange,
    peer: SupportedProtocolRange,
) -> HandshakeResponse {
    if local.major != peer.major {
        return HandshakeResponse::Rejected {
            reason: ProtocolRejectionReason::MajorVersionMismatch,
            supported: local,
        };
    }

    let common_min = if local.min_minor > peer.min_minor {
        local.min_minor
    } else {
        peer.min_minor
    };
    let common_max = if local.max_minor < peer.max_minor {
        local.max_minor
    } else {
        peer.max_minor
    };

    if common_min > common_max {
        return HandshakeResponse::Rejected {
            reason: ProtocolRejectionReason::NoCommonMinor,
            supported: local,
        };
    }

    HandshakeResponse::Accepted {
        protocol: ProtocolVersion::new(local.major, common_max),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn range(major: u16, min_minor: u16, max_minor: u16) -> SupportedProtocolRange {
        SupportedProtocolRange::new(major, min_minor, max_minor).unwrap()
    }

    #[test]
    fn previous_minor_negotiates_to_highest_common_version() {
        let local = range(1, 1, 2);
        let previous_minor_peer = range(1, 0, 1);

        assert_eq!(
            negotiate(local, previous_minor_peer),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 1),
            }
        );
        assert_eq!(
            negotiate(local, previous_minor_peer),
            negotiate(previous_minor_peer, local)
        );
    }

    #[test]
    fn exact_minor_match_is_accepted() {
        let supported = range(1, 0, 0);

        assert_eq!(
            negotiate(supported, supported),
            HandshakeResponse::Accepted {
                protocol: ProtocolVersion::new(1, 0),
            }
        );
    }

    #[test]
    fn major_mismatch_fails_closed_with_stable_reason() {
        let local = range(1, 0, 2);
        let peer = range(2, 0, 2);

        assert_eq!(
            negotiate(local, peer),
            HandshakeResponse::Rejected {
                reason: ProtocolRejectionReason::MajorVersionMismatch,
                supported: local,
            }
        );
    }

    #[test]
    fn disjoint_minor_ranges_fail_closed_with_stable_reason() {
        let local = range(1, 2, 3);
        let peer = range(1, 0, 1);

        assert_eq!(
            negotiate(local, peer),
            HandshakeResponse::Rejected {
                reason: ProtocolRejectionReason::NoCommonMinor,
                supported: local,
            }
        );
    }

    #[test]
    fn inverted_minor_range_is_rejected_at_construction_and_deserialisation() {
        assert_eq!(
            SupportedProtocolRange::new(1, 2, 1),
            Err(SupportedProtocolRangeError::InvertedMinorRange)
        );

        let error = serde_json::from_str::<SupportedProtocolRange>(
            r#"{"major":1,"min_minor":2,"max_minor":1}"#,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("minimum supported minor exceeds maximum supported minor"),
            "{error}"
        );
    }

    #[test]
    fn handshake_wire_shape_is_stable_and_machine_readable() {
        let protocol = range(1, 0, 1);
        let request = HandshakeRequest::Hello { protocol };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"request":"hello","protocol":{"major":1,"min_minor":0,"max_minor":1}}"#
        );
        assert_eq!(
            serde_json::from_str::<HandshakeRequest>(
                r#"{"request":"hello","protocol":{"major":1,"min_minor":0,"max_minor":1}}"#,
            )
            .unwrap(),
            request
        );

        let accepted = HandshakeResponse::Accepted {
            protocol: ProtocolVersion::new(1, 1),
        };
        assert_eq!(
            serde_json::to_string(&accepted).unwrap(),
            r#"{"response":"accepted","protocol":{"major":1,"minor":1}}"#
        );

        let rejected = HandshakeResponse::Rejected {
            reason: ProtocolRejectionReason::MajorVersionMismatch,
            supported: protocol,
        };
        assert_eq!(
            serde_json::to_string(&rejected).unwrap(),
            r#"{"response":"rejected","reason":"major_version_mismatch","supported":{"major":1,"min_minor":0,"max_minor":1}}"#
        );
    }

    #[test]
    fn handshake_wire_rejects_unknown_fields() {
        for raw in [
            r#"{"request":"hello","protocol":{"major":1,"min_minor":0,"max_minor":1},"extra":true}"#,
            r#"{"request":"hello","protocol":{"major":1,"min_minor":0,"max_minor":1,"extra":true}}"#,
        ] {
            assert!(
                serde_json::from_str::<HandshakeRequest>(raw).is_err(),
                "{raw} must fail closed"
            );
        }

        for raw in [
            r#"{"response":"accepted","protocol":{"major":1,"minor":0},"extra":true}"#,
            r#"{"response":"accepted","protocol":{"major":1,"minor":0,"extra":true}}"#,
            r#"{"response":"rejected","reason":"major_version_mismatch","supported":{"major":1,"min_minor":0,"max_minor":0},"extra":true}"#,
        ] {
            assert!(
                serde_json::from_str::<HandshakeResponse>(raw).is_err(),
                "{raw} must fail closed"
            );
        }
    }

    #[test]
    fn initial_protocol_constant_is_version_one_zero_only() {
        assert_eq!(WARD_NODE_PROTOCOL.major(), 1);
        assert_eq!(WARD_NODE_PROTOCOL.min_minor(), 0);
        assert_eq!(WARD_NODE_PROTOCOL.max_minor(), 0);
    }
}
