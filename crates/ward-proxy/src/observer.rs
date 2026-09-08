//! Decision reporting. Every `CONNECT` or forward the proxy parses produces
//! exactly one [`Observer::decision`] call, which `wardd` turns into
//! `NetworkRequested` / `NetworkDenied` events.

use crate::http::Request;

/// The proxy's verdict on a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// The destination passed the host and address checks; a connection to a
    /// pinned address is being attempted.
    Allow,
    /// The destination was refused; the client received `403`.
    Deny,
}

/// Receives one call per policy decision.
///
/// `reason` is a short, allowlist-free explanation: for a denial the
/// [`crate::Denial`] text, for an allow the pinned address set. Implementations
/// must be cheap and must not block — they run on the connection thread.
pub trait Observer: Send + Sync {
    /// Report the verdict for `req`.
    fn decision(&self, req: &Request, decision: Decision, reason: &str);
}

/// An observer that discards every decision.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullObserver;

impl Observer for NullObserver {
    fn decision(&self, _req: &Request, _decision: Decision, _reason: &str) {}
}
