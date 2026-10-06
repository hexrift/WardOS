//! The session broker's credentials (#267, ADR-0032): the provider interface,
//! its binding rules and the Vault/OpenBao backend are `ward-credentials`'s,
//! shared with `ward-node`, and re-exported here unchanged; this module adds
//! what only the session broker has.
//!
//! * [`local::LocalVault`], the host vault the model-API and GitHub gateways
//!   have always read (`$WARD_STATE_DIR/vault/<NAME>`, or the host variable):
//!   a static secret with a client-side lease, nothing to revoke at the source.
//! * [`config`], the host's `credentials.toml` and the system-layer policy it
//!   contributes; [`grant`], the launch's provider-backed grants; [`keeper`],
//!   the launch's custody of its leases.

pub mod config;
pub mod grant;
pub mod keeper;
pub mod local;

pub use ward_credentials::*;
