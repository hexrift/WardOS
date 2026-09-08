//! Record origin: who produced an event, and whether it counts as an enforcement fact.

use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The component that produced a record (`event-model.md` §2).
///
/// `origin` is the single most important field of a record. Only enforcement-grade
/// origins may be used by `wardd`, the verifier, or `TamperWard` to decide anything;
/// [`Origin::Agent`] records are *claims* and are rendered with a distinct marker.
///
/// The numeric tag returned by [`Origin::tag`] (1–7) is the byte that enters the record
/// hash; it is independent of serde's variant index so that the hash layout is stable
/// even if the enum is ever reordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Origin {
    /// eBPF / fanotify / nflog / seccomp-notify facts captured from Zone 0.
    Kernel,
    /// `ward-proxy` egress decisions.
    Proxy,
    /// `wardd` itself: lifecycle, snapshots, capabilities, credentials.
    Wardd,
    /// The verifier runner, relayed by `wardd` over its result pipe.
    Verifier,
    /// `TamperWard` policy decisions and state acceptance.
    TamperWard,
    /// Agent hooks and `ward-request`. Never an enforcement fact.
    Agent,
    /// Explicit user actions (approvals, `ward stop`, `ward verify`).
    User,
}

impl Origin {
    /// Every origin, in tag order.
    pub const ALL: [Origin; 7] = [
        Origin::Kernel,
        Origin::Proxy,
        Origin::Wardd,
        Origin::Verifier,
        Origin::TamperWard,
        Origin::Agent,
        Origin::User,
    ];

    /// Stable one-byte tag used in the record hash (1–7). Zero is never a valid tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Origin::Kernel => 1,
            Origin::Proxy => 2,
            Origin::Wardd => 3,
            Origin::Verifier => 4,
            Origin::TamperWard => 5,
            Origin::Agent => 6,
            Origin::User => 7,
        }
    }

    /// Inverse of [`Origin::tag`].
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Origin::Kernel),
            2 => Some(Origin::Proxy),
            3 => Some(Origin::Wardd),
            4 => Some(Origin::Verifier),
            5 => Some(Origin::TamperWard),
            6 => Some(Origin::Agent),
            7 => Some(Origin::User),
            _ => None,
        }
    }

    /// Whether records with this origin may be used for enforcement decisions.
    ///
    /// Everything except [`Origin::Agent`] is an enforcement fact.
    #[must_use]
    pub const fn is_enforcement_fact(self) -> bool {
        !matches!(self, Origin::Agent)
    }

    /// Short lowercase label for rendering.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Origin::Kernel => "kernel",
            Origin::Proxy => "proxy",
            Origin::Wardd => "wardd",
            Origin::Verifier => "verifier",
            Origin::TamperWard => "tamperward",
            Origin::Agent => "agent",
            Origin::User => "user",
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Error returned when an [`OriginSet`] bitmask contains unknown bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("origin set contains unknown bits: {0:#04x}")]
pub struct UnknownOriginBits(pub u8);

/// A set of origins, used by subscription filters.
///
/// Bit `tag - 1` is set for each member. Serialises as a single byte; unknown bits are
/// rejected on deserialisation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct OriginSet(u8);

impl OriginSet {
    const MASK: u8 = 0b0111_1111;

    /// The empty set.
    pub const EMPTY: Self = Self(0);
    /// Every origin.
    pub const ALL: Self = Self(Self::MASK);

    /// The set of enforcement-fact origins (everything but `Agent`).
    #[must_use]
    pub const fn enforcement_facts() -> Self {
        Self(Self::MASK & !Self::bit(Origin::Agent))
    }

    const fn bit(origin: Origin) -> u8 {
        1 << (origin.tag() - 1)
    }

    /// Returns a set containing exactly `origin`.
    #[must_use]
    pub const fn only(origin: Origin) -> Self {
        Self(Self::bit(origin))
    }

    /// Returns this set with `origin` added.
    #[must_use]
    pub const fn with(self, origin: Origin) -> Self {
        Self(self.0 | Self::bit(origin))
    }

    /// Returns this set with `origin` removed.
    #[must_use]
    pub const fn without(self, origin: Origin) -> Self {
        Self(self.0 & !Self::bit(origin))
    }

    /// Whether `origin` is a member.
    #[must_use]
    pub const fn contains(self, origin: Origin) -> bool {
        self.0 & Self::bit(origin) != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Raw bitmask.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Iterates members in tag order.
    pub fn iter(self) -> impl Iterator<Item = Origin> {
        Origin::ALL.into_iter().filter(move |o| self.contains(*o))
    }
}

impl fmt::Debug for OriginSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl TryFrom<u8> for OriginSet {
    type Error = UnknownOriginBits;
    fn try_from(bits: u8) -> Result<Self, UnknownOriginBits> {
        if bits & !Self::MASK != 0 {
            return Err(UnknownOriginBits(bits));
        }
        Ok(Self(bits))
    }
}

impl From<OriginSet> for u8 {
    fn from(set: OriginSet) -> u8 {
        set.0
    }
}

impl FromIterator<Origin> for OriginSet {
    fn from_iter<I: IntoIterator<Item = Origin>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn agent_is_never_an_enforcement_fact() {
        assert!(!Origin::Agent.is_enforcement_fact());
        for o in Origin::ALL {
            assert_eq!(o.is_enforcement_fact(), o != Origin::Agent, "{o}");
        }
    }

    #[test]
    fn tags_are_dense_nonzero_and_invertible() {
        for (i, o) in Origin::ALL.iter().enumerate() {
            let tag = o.tag();
            assert_eq!(usize::from(tag), i + 1);
            assert_eq!(Origin::from_tag(tag), Some(*o));
        }
        assert_eq!(Origin::from_tag(0), None);
        assert_eq!(Origin::from_tag(8), None);
    }

    #[test]
    fn origin_set_membership_and_serde() {
        let set = OriginSet::only(Origin::Kernel).with(Origin::User);
        assert!(set.contains(Origin::Kernel));
        assert!(set.contains(Origin::User));
        assert!(!set.contains(Origin::Agent));
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![Origin::Kernel, Origin::User]
        );
        assert!(!OriginSet::enforcement_facts().contains(Origin::Agent));
        assert_eq!(
            OriginSet::enforcement_facts().with(Origin::Agent),
            OriginSet::ALL
        );
        assert_eq!(set.without(Origin::User), OriginSet::only(Origin::Kernel));

        let bytes = postcard::to_allocvec(&set).unwrap();
        assert_eq!(bytes, vec![set.bits()]);
        assert_eq!(postcard::from_bytes::<OriginSet>(&bytes).unwrap(), set);
        assert!(postcard::from_bytes::<OriginSet>(&[0x80]).is_err());
        assert_eq!(OriginSet::try_from(0xff), Err(UnknownOriginBits(0xff)));
    }
}
