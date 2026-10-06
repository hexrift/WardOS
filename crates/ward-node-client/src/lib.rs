//! ward-node-client: a transport-backed client, issuer signer and attempt driver for
//! external control planes that drive a local `ward-node` (node-integration.md).
//!
//! * [`UnixTransport`] speaks the Unix-socket JSON-lines framing of §3, one connection per
//!   request, with the line bounds and the fail-closed reading of EOF; [`TlsTransport`]
//!   speaks the same over TCP with mutual TLS to a node serving `--listen-tls` (ADR-0038).
//! * [`Client`] negotiates protocol 1.3 or later (§4), reads capabilities (§5) and sends
//!   the typed lifecycle verbs (§6), the read-only `result` request (§6.6) and the action
//!   channel's `actions` listing and `answer` (§6.7), checking every answer against its
//!   request.
//! * [`IssuerKey`] holds the control plane's Ed25519 issuer key and signs an envelope's
//!   exact bytes (§7.4); [`EnvelopeInput`] bounds the institution-owned inputs (§7.3)
//!   before anything is signed.
//! * [`Driver`] runs one attempt to its sealed end with caller-supplied, replayable
//!   operation ids, reads its bounded output when the manifest granted `output` (§6.6),
//!   revokes on cancellation or an overrun budget, recovers a lost answer exactly once by
//!   inspect-and-replay (§10), and otherwise fails closed with an unknown outcome.
//!
//! The `ward-node-adapter` binary of this crate exposes the same over stdin/stdout for
//! control planes in other languages. Nothing here depends on `ward-daemon`. Enrolment and
//! key bootstrap are the rest of #262: certificates and the issuer key are the operator's.

#![forbid(unsafe_code)]

mod client;
mod driver;
mod envelope;
mod issuer;
mod tls;
mod transport;

pub use client::{
    ActionsListed, AnswerApplied, Applied, Client, ClientError, Inspection, PROTOCOL_WINDOW,
    Resulted, Verb, protocol_window,
};
pub use driver::{
    AppliedOperation, AttemptEvent, AttemptOutcome, AttemptReport, AttemptRequest, CancelToken,
    Driver, OperationIds, OperationIdsError, RunConfig, evidence_log_path,
};
pub use envelope::{EnvelopeError, EnvelopeInput, WorkloadInput, offline_manifest};
pub use issuer::{IssuerKey, IssuerKeyError, SEED_LEN, SignedEnvelope};
pub use tls::{TlsSettings, TlsSetupError, TlsTransport};
pub use transport::{Exchange, MAX_LINE_BYTES, Timeouts, Transport, TransportError, UnixTransport};
