//! `ward-shell-core` — the Ward Shell's view model, without a toolkit.
//!
//! Everything the shell shows (ADR-0007, `docs/design-language.md`) is derived
//! here from two inputs and nothing else: a session's immutable facts
//! ([`SessionDescription`]) and the records of its event stream
//! ([`EventRecord`](ward_events::EventRecord)). The trust bar ([`trust`]), the
//! observer feed ([`feed`]), the command centre ([`launcher`]) and the semantic
//! settings ([`settings`]) are plain data with a colour role ([`Tone`]) per
//! element; a renderer (the `ward watch` TUI today, the layer-shell surfaces
//! after E-10) maps those roles to its own colour space and draws.
//!
//! The crate has no graphics dependency and never will: it is the part of the
//! shell that is tested without a display. The TUI in `ward-cli` is its first
//! consumer, so there is one implementation of the counters, the follow/scroll
//! state and the trust bar for every observer.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

pub mod feed;
pub mod launcher;
pub mod panel;
pub mod settings;
pub mod trust;
pub mod waybar;

pub use feed::{
    Counters, Model, SessionState, TamperWard, Verdict, Verification, Worktree, counters_text,
};
pub use launcher::{Command, Entry, Launcher, LineContext, Section, SessionCard, quote};
pub use panel::{Group, duration_text, panel_text, session_panel, verify_panel};
pub use settings::{Row, Settings, rows_text};
pub use trust::{
    Header, Segment, SegmentName, TrustBar, VerifyState, agent_glyph, agent_tone, agent_word,
    short_hex, short_id, tone_name, trust_bar_segments, trust_bar_text, trust_tone,
};
pub use ward_daemon::describe::SessionDescription;
pub use ward_daemon::render::Tone;
pub use waybar::Module;
