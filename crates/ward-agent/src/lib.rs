//! `ward-agent` — the in-sandbox PID 1 shim (architecture §3.3 and §6, ADR-0003).
//!
//! Before any untrusted code runs, the shim applies the *inner* hardening the
//! OCI runtime cannot: a [`landlock`] ruleset (rw under `/work`, `/env`, `/tmp`
//! and `$HOME`; read+exec elsewhere), the [`seccomp`] filter derived from
//! [`ward_sandbox::seccomp::Profile::baseline`], `PR_SET_NO_NEW_PRIVS` and an
//! empty capability set ([`privs`]). It then starts any egress [`relay`]s
//! (ADR-0014: loopback ports forwarded to the proxy's bind-mounted Unix
//! socket), execs the agent and performs PID 1 duties ([`supervise`]): reaping
//! orphans, forwarding termination signals and relaying the agent's exit status.
//!
//! Invoked as `ward-agent hook`, the binary is instead the Claude Code hook
//! client ([`hook`]): it forwards the hook payload to the daemon's socket and
//! prints the decision.
//!
//! Every step is irreversible for the process tree and fails closed: the only
//! opt-out is `--allow-no-landlock` for kernels without Landlock at all. The
//! crate uses only the safe APIs of `landlock`, `seccompiler`, `nix` and `caps`.
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

pub mod cli;
pub mod error;
pub mod hook;
pub mod landlock;
pub mod privs;
pub mod relay;
pub mod seccomp;
pub mod supervise;

pub use cli::Args;
pub use error::{AgentError, Result};
pub use landlock::PathSets;
pub use relay::Relay;
