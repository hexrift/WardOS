//! ward-node-client: a transport-backed client, issuer signer and attempt driver for
//! external control planes that drive a local `ward-node` (node-integration.md).
//!
//! * [`UnixTransport`] speaks the Unix-socket JSON-lines framing of §3, one connection per
//!   request, with the line bounds and the fail-closed reading of EOF.
//! * [`Client`] negotiates protocol 1.3 or later (§4), reads capabilities (§5) and sends
//!   the typed lifecycle verbs (§6), checking every answer against its request.
//! * [`IssuerKey`] holds the control plane's Ed25519 issuer key and signs an envelope's
//!   exact bytes (§7.4); [`EnvelopeInput`] bounds the institution-owned inputs (§7.3)
//!   before anything is signed.
//! * [`Driver`] runs one attempt to its sealed end with caller-supplied, replayable
//!   operation ids, revokes on cancellation or an overrun budget, recovers a lost answer
//!   exactly once by inspect-and-replay (§10), and otherwise fails closed with an unknown
//!   outcome.
//!
//! The `ward-node-adapter` binary of this crate exposes the same over stdin/stdout for
//! control planes in other languages. Nothing here depends on `ward-daemon`; the only
//! transport is the local socket (remote transport and key bootstrap are #262).

#![forbid(unsafe_code)]

mod client;
mod driver;
mod envelope;
mod issuer;
mod transport;

pub use client::{
    Applied, Client, ClientError, Inspection, PROTOCOL_WINDOW, Verb, protocol_window,
};
pub use driver::{
    AppliedOperation, AttemptEvent, AttemptOutcome, AttemptReport, AttemptRequest, CancelToken,
    Driver, OperationIds, OperationIdsError, RunConfig, evidence_log_path,
};
pub use envelope::{EnvelopeError, EnvelopeInput, WorkloadInput, offline_manifest};
pub use issuer::{IssuerKey, IssuerKeyError, SEED_LEN, SignedEnvelope};
pub use transport::{Exchange, MAX_LINE_BYTES, Timeouts, Transport, TransportError, UnixTransport};
