//! Holds (#415, ADR-0035): a caller's veto on requests the policy allows.
//!
//! A [`Hold`] given to [`crate::Config::hold`] is asked about every request that a
//! gateway route matched without refusing it, and every other request whose host the
//! policy's first stage allows, before anything is resolved, connected to or injected. A
//! request it holds is answered `403` with the body it names and reported to the observer
//! as a deny with its reason; nothing about it leaves the proxy. What lifts a hold is the
//! caller's business: `ward-node` holds a capability until the control plane's approval of
//! the request it opened for it is recorded.

use crate::http::Target;

/// Why a held request is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    /// The observer's reason.
    pub reason: String,
    /// The body of the `403`.
    pub body: &'static str,
}

/// Decides whether a request the policy allows is held.
pub trait Hold: Send + Sync + std::fmt::Debug {
    /// `None` lets the request for `target` proceed; [`Held`] refuses it. `route` is the
    /// prefix of the gateway route the request matched, if any; `target` is then the
    /// route's upstream. Called on the request's own thread, once per request: it must not
    /// block.
    fn held(&self, target: &Target, route: Option<&str>) -> Option<Held>;
}
