//! Local node mode: one installation's per-session state carried into a `ward-node` of
//! its own (#278, ADR-0040).
//!
//! A migrated installation has a node home, `<state>/node/` (mode 0700), which the
//! local node owns and nothing else writes:
//!
//! * `migration.json` — the [`MigrationRecord`], and the mode marker: while it exists the
//!   installation is in local node mode, and only [`migrate`] and [`migrate::rollback`]
//!   create or remove it, each by one rename;
//! * `issuer.seed` — the local issuer's Ed25519 seed, mode 0600, which `ward run
//!   --via-node` signs with;
//! * `trusted-issuers` — the node's trust store, binding that key to the local principal;
//!   a control plane's issuer is added beside it, never in its place;
//! * `state/` and `tasks/` — the node's `--state-dir` (with the snapshots the migration
//!   imported in `state/cas`) and `--task-root`;
//! * `node.sock` — the node's socket while `ward node serve` runs it.
//!
//! The session tree beside it is never written by a migration: evidence logs, the session
//! CAS, the vault and every policy file stay where they are, recorded by digest in the
//! record so `ward node status` can show they are unchanged.

pub(crate) mod compile;
pub(crate) mod migrate;
pub(crate) mod run;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ward_events::{NodeId, PrincipalId};

/// The node home's directory under the session state root.
pub(crate) const HOME_DIR: &str = "node";

/// The record format this `ward` writes and reads.
pub(crate) const RECORD_FORMAT: u32 = 1;

/// The paths of one node home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NodeHome {
    dir: PathBuf,
}

impl NodeHome {
    /// The node home of the installation whose session state root is `state`.
    pub(crate) fn under(state: &Path) -> Self {
        Self::at(state.join(HOME_DIR))
    }

    /// A node home rooted at `dir`.
    pub(crate) fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn record(&self) -> PathBuf {
        self.dir.join("migration.json")
    }

    pub(crate) fn seed(&self) -> PathBuf {
        self.dir.join("issuer.seed")
    }

    pub(crate) fn trust_store(&self) -> PathBuf {
        self.dir.join("trusted-issuers")
    }

    pub(crate) fn state_dir(&self) -> PathBuf {
        self.dir.join("state")
    }

    pub(crate) fn snapshots(&self) -> PathBuf {
        self.state_dir().join("cas")
    }

    pub(crate) fn task_root(&self) -> PathBuf {
        self.dir.join("tasks")
    }

    pub(crate) fn socket(&self) -> PathBuf {
        self.dir.join("node.sock")
    }
}

/// A sealed session log a migration left in place, as it was when it was carried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarriedLog {
    /// The log, relative to the session state root.
    pub path: PathBuf,
    /// Its length in bytes.
    pub bytes: u64,
    /// The BLAKE3 of its bytes, lowercase hex.
    pub blake3: String,
    /// The chain head its sealed `HEAD` names, lowercase hex.
    pub head: String,
    /// Records it holds.
    pub records: u64,
}

/// A policy layer a migration referenced and did not rewrite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReferencedPolicy {
    /// The file.
    pub path: PathBuf,
    /// The BLAKE3 of its bytes, lowercase hex; `None` when it did not exist.
    pub blake3: Option<String>,
}

/// What a migration carried, and the marker of local node mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigrationRecord {
    /// [`RECORD_FORMAT`].
    pub format: u32,
    /// The local node's identity, its `--node-id`.
    pub node: NodeId,
    /// The local issuing principal the local issuer key is bound to.
    pub issuer: PrincipalId,
    /// The local issuer key's id, lowercase hex.
    pub issuer_key_id: String,
    /// When the migration was committed, in Unix milliseconds.
    pub migrated_at_unix_ms: u64,
    /// The session state root it migrated.
    pub source: PathBuf,
    /// Snapshots imported into the node's store, as 64 lowercase hex digits.
    pub snapshots: Vec<String>,
    /// Sealed session logs left in place.
    pub evidence: Vec<CarriedLog>,
    /// Policy layers referenced.
    pub policy: Vec<ReferencedPolicy>,
}

/// Which runtime an installation is in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Per-session `wardd` only: no migration was committed.
    PerSession,
    /// A migration was committed; the record says what it carried.
    LocalNode(Box<MigrationRecord>),
}

/// The mode of the installation at `state`. A marker that exists but cannot be read is an
/// error, never per-session mode.
pub(crate) fn mode(state: &Path) -> ward_daemon::Result<Mode> {
    let path = NodeHome::under(state).record();
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Mode::PerSession),
        Err(source) => return Err(ward_daemon::Error::Io { path, source }),
    };
    let record: MigrationRecord = serde_json::from_slice(&bytes)
        .map_err(|e| ward_daemon::Error::Project(format!("{}: {e}", path.display())))?;
    if record.format != RECORD_FORMAT {
        return Err(ward_daemon::Error::Project(format!(
            "{}: record format {} is not {RECORD_FORMAT}",
            path.display(),
            record.format
        )));
    }
    Ok(Mode::LocalNode(Box::new(record)))
}

/// The `ward doctor` row naming the installation's mode.
pub(crate) fn doctor_check(state: &Path) -> ward_daemon::doctor::Check {
    use ward_daemon::doctor::{Check, Status};
    match mode(state) {
        Ok(Mode::PerSession) => Check::new(
            "node mode",
            Status::Ok,
            "per-session · `ward node migrate --dry-run` shows what a local node would carry",
        ),
        Ok(Mode::LocalNode(record)) => Check::new(
            "node mode",
            Status::Ok,
            format!(
                "local-node · {} · {} · `ward node serve`, then `ward run --via-node`",
                record.node,
                NodeHome::under(state).dir().display()
            ),
        ),
        Err(e) => Check::new(
            "node mode",
            Status::Fail,
            format!("{e}; `ward node migrate --rollback` returns to per-session mode"),
        ),
    }
}

/// The lowercase hex BLAKE3 of `bytes`.
pub(crate) fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn record() -> MigrationRecord {
        MigrationRecord {
            format: RECORD_FORMAT,
            node: NodeId::from_u128(4),
            issuer: PrincipalId::from_u128(2),
            issuer_key_id: "ab".repeat(32),
            migrated_at_unix_ms: 1,
            source: PathBuf::from("/state"),
            snapshots: vec!["cd".repeat(32)],
            evidence: vec![CarriedLog {
                path: PathBuf::from("sessions/sess_a/events.log"),
                bytes: 10,
                blake3: "ef".repeat(32),
                head: "01".repeat(32),
                records: 3,
            }],
            policy: vec![ReferencedPolicy {
                path: PathBuf::from("/p/.ward/policy.yaml"),
                blake3: None,
            }],
        }
    }

    #[test]
    fn the_node_home_lives_beside_the_session_tree_under_the_state_root() {
        let home = NodeHome::under(Path::new("/s"));
        assert_eq!(home.dir(), Path::new("/s/node"));
        assert_eq!(home.record(), Path::new("/s/node/migration.json"));
        assert_eq!(home.seed(), Path::new("/s/node/issuer.seed"));
        assert_eq!(home.trust_store(), Path::new("/s/node/trusted-issuers"));
        assert_eq!(home.state_dir(), Path::new("/s/node/state"));
        assert_eq!(home.snapshots(), Path::new("/s/node/state/cas"));
        assert_eq!(home.task_root(), Path::new("/s/node/tasks"));
        assert_eq!(home.socket(), Path::new("/s/node/node.sock"));
    }

    #[test]
    fn the_mode_is_per_session_until_a_record_exists_and_local_node_after() {
        let state = tempfile::tempdir().unwrap();
        assert_eq!(mode(state.path()).unwrap(), Mode::PerSession);
        let home = NodeHome::under(state.path());
        std::fs::create_dir(home.dir()).unwrap();
        assert_eq!(mode(state.path()).unwrap(), Mode::PerSession);
        std::fs::write(home.record(), serde_json::to_vec(&record()).unwrap()).unwrap();
        assert_eq!(
            mode(state.path()).unwrap(),
            Mode::LocalNode(Box::new(record()))
        );
    }

    #[test]
    fn a_damaged_or_foreign_record_is_an_error_never_per_session_mode() {
        let state = tempfile::tempdir().unwrap();
        let home = NodeHome::under(state.path());
        std::fs::create_dir(home.dir()).unwrap();
        std::fs::write(home.record(), b"{not json").unwrap();
        assert!(mode(state.path()).is_err());
        let mut future = record();
        future.format = 2;
        std::fs::write(home.record(), serde_json::to_vec(&future).unwrap()).unwrap();
        assert!(
            mode(state.path())
                .unwrap_err()
                .to_string()
                .contains("format 2")
        );
        let check = doctor_check(state.path());
        assert_eq!(check.status, ward_daemon::doctor::Status::Fail);
        assert!(check.detail.contains("--rollback"));
    }

    #[test]
    fn the_doctor_row_names_the_mode() {
        let state = tempfile::tempdir().unwrap();
        let check = doctor_check(state.path());
        assert_eq!(check.name, "node mode");
        assert!(check.detail.starts_with("per-session"), "{}", check.detail);
        let home = NodeHome::under(state.path());
        std::fs::create_dir(home.dir()).unwrap();
        std::fs::write(home.record(), serde_json::to_vec(&record()).unwrap()).unwrap();
        let check = doctor_check(state.path());
        assert_eq!(check.status, ward_daemon::doctor::Status::Ok);
        assert!(check.detail.starts_with("local-node"), "{}", check.detail);
        assert!(check.detail.contains(&NodeId::from_u128(4).to_string()));
    }
}
