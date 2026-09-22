//! Decision reporting. Every `CONNECT` or forward the proxy parses produces
//! exactly one verdict, which `wardd` turns into `NetworkRequested` /
//! `NetworkDenied` events, and every accepted connection is announced before it
//! is served and retired exactly once — with a verdict or without one — so an
//! observer always knows what is still to be decided.

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
///
/// # Outstanding verdicts
///
/// An observer that has to account for every decision — because it is feeding a
/// log that must never have a silent gap — needs to know not only what was
/// decided but what is *still to be decided*, and it needs to learn that before
/// the deciding starts rather than after it finishes. So each accepted
/// connection is announced with [`deciding`](Observer::deciding) **before the
/// thread that serves it is spawned**, and is retired exactly once, through
/// [`decided`](Observer::decided) when it reached a verdict and
/// [`undecided`](Observer::undecided) when it ended without one.
///
/// That pairing is what lets an observer being shut down distinguish "this
/// connection's verdict is already in" from "this connection may still produce
/// one": the accept loop stops before [`crate::Handle::shutdown`] returns, so
/// once it has, the set of announced-but-not-yet-retired connections can only
/// shrink, and whatever is in it is exactly what may still be decided.
///
/// The three default implementations make this invisible to an observer that
/// does not care: it only implements [`decision`](Observer::decision), and every
/// verdict still arrives there exactly once.
pub trait Observer: Send + Sync {
    /// Report the verdict for `req`.
    fn decision(&self, req: &Request, decision: Decision, reason: &str);

    /// A connection has been accepted and may still produce exactly one verdict.
    /// Called on the acceptor thread, before the connection is served.
    ///
    /// Returns whether the observer is tracking it. When it is, that one verdict
    /// is reported through [`decided`](Observer::decided) instead of
    /// [`decision`](Observer::decision), or its absence through
    /// [`undecided`](Observer::undecided). The default is not to track, so the
    /// verdict arrives at [`decision`](Observer::decision) as before.
    fn deciding(&self) -> bool {
        false
    }

    /// The verdict for a connection [`deciding`](Observer::deciding) is tracking.
    /// Reporting it and retiring the connection are one step for the observer,
    /// which is what lets the two be made atomic against a shutdown.
    fn decided(&self, req: &Request, decision: Decision, reason: &str) {
        self.decision(req, decision, reason);
    }

    /// A connection [`deciding`](Observer::deciding) is tracking ended without
    /// reaching a verdict — it was never a valid proxy request, or the proxy was
    /// paused, or serving it unwound. Nothing was decided, so there is nothing to
    /// report; the connection is simply retired.
    fn undecided(&self) {}
}

/// An observer that discards every decision.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullObserver;

impl Observer for NullObserver {
    fn decision(&self, _req: &Request, _decision: Decision, _reason: &str) {}
}
