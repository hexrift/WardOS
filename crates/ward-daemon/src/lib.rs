//! `ward-daemon` — the WardOS session supervisor.
//!
//! Phase 1 runs the session lifecycle in-process behind the `ward` CLI: it loads
//! and merges policy into a capability manifest ([`ward_policy`]), freezes an entry
//! snapshot ([`ward_snapshot`]), runs commands in an isolated sandbox
//! ([`sandbox`]), and records everything to the append-only event log
//! ([`ward_events`]). The daemon/control-socket split (ADR-0009) lands in Phase 2;
//! the module boundaries here are drawn so that split is mechanical.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::struct_field_names
)]

pub mod agents;
pub mod egress;
pub mod error;
pub mod gateway;
pub mod hooks;
pub mod ids;
pub mod render;
pub mod sandbox;
pub mod selftest;
pub mod session;
pub mod verify;
pub mod watch;

pub use error::{Error, Result};
pub use selftest::{ProbeResult, selftest, selftest_credentials};
pub use session::{RunReport, Session, SessionMeta, VerifyReport};
pub use watch::CaptureMode;
