//! `ward-daemon` — the WardOS session supervisor.
//!
//! Phase 1 runs the session lifecycle in-process behind the `ward` CLI: it loads
//! and merges policy into a capability manifest ([`ward_policy`]), freezes an entry
//! snapshot ([`ward_snapshot`]), runs commands in an isolated sandbox
//! ([`sandbox`]), and records everything to the append-only event log
//! ([`ward_events`]). Since ADR-0015 a per-session `wardd` ([`daemon`]) is the one
//! writer of that log, serving the control socket protocol ([`control`]); a
//! command with no daemon to talk to writes the log itself, as before.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::struct_field_names
)]

pub mod agents;
pub mod approvals;
pub mod client;
pub mod control;
pub mod daemon;
pub mod describe;
pub mod doctor;
pub mod egress;
pub mod error;
pub mod gateway;
pub mod github;
pub mod hooks;
pub mod ids;
pub mod render;
pub mod sandbox;
pub mod selftest;
pub mod session;
pub mod snapshot;
pub mod verify;
pub mod watch;

pub use describe::SessionDescription;
pub use error::{Error, Result};
pub use selftest::{
    ProbeResult, Verdict, selftest, selftest_credentials, selftest_egress, selftest_evidence,
    selftest_verifier,
};
pub use session::{RunReport, Session, SessionMeta, VerifyReport};
pub use ward_snapshot::SnapshotRole;
pub use watch::CaptureMode;
