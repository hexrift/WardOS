//! Thin, typed driver over an OCI runtime (`crun`).
//!
//! Only lifecycle is exposed; policy and spec construction live elsewhere. Full
//! isolation cannot be exercised without an unprivileged host, so this layer is
//! deliberately minimal.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::error::{Result, SandboxError};

/// Lifecycle operations of an OCI runtime for a single container id.
pub trait Runtime {
    /// Create the container from the bundle at `bundle` without starting it.
    ///
    /// # Errors
    /// Fails if the runtime cannot be spawned or exits non-zero.
    fn create(&self, id: &str, bundle: &Path) -> Result<()>;

    /// Start a previously created container.
    ///
    /// # Errors
    /// Fails if the runtime cannot be spawned or exits non-zero.
    fn start(&self, id: &str) -> Result<()>;

    /// Send `signal` (e.g. `"SIGKILL"`) to the container's init process.
    ///
    /// # Errors
    /// Fails if the runtime cannot be spawned or exits non-zero.
    fn kill(&self, id: &str, signal: &str) -> Result<()>;

    /// Delete container resources; `force` removes a still-running container.
    ///
    /// # Errors
    /// Fails if the runtime cannot be spawned or exits non-zero.
    fn delete(&self, id: &str, force: bool) -> Result<()>;

    /// Query the container's current state.
    ///
    /// # Errors
    /// Fails if the runtime cannot be spawned, exits non-zero, or emits
    /// unparsable JSON.
    fn state(&self, id: &str) -> Result<ContainerState>;
}

/// Subset of the OCI `state` output `WardOS` consumes.
#[derive(Debug, Clone, Deserialize)]
pub struct ContainerState {
    /// Container id.
    pub id: String,
    /// Lifecycle status (`creating`, `created`, `running`, `stopped`).
    pub status: String,
    /// Init process pid, present once created.
    #[serde(default)]
    pub pid: Option<i32>,
    /// Bundle directory the container was created from.
    #[serde(default)]
    pub bundle: Option<String>,
}

/// [`Runtime`] backed by the `crun` binary.
#[derive(Debug, Clone)]
pub struct CrunRuntime {
    binary: PathBuf,
}

impl Default for CrunRuntime {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("crun"),
        }
    }
}

impl CrunRuntime {
    /// Driver using an explicit `crun` binary path.
    #[must_use]
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    /// The configured binary path.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Whether the runtime binary responds to `--version`.
    #[must_use]
    pub fn is_available(&self) -> bool {
        Command::new(&self.binary)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn run(&self, subcommand: &'static str, id: &str, args: &[&str]) -> Result<Vec<u8>> {
        let output = Command::new(&self.binary)
            .arg(subcommand)
            .args(args)
            .output()
            .map_err(|source| SandboxError::Io {
                path: self.binary.clone(),
                source,
            })?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(SandboxError::Crun {
                subcommand,
                id: id.to_string(),
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
    }
}

impl Runtime for CrunRuntime {
    fn create(&self, id: &str, bundle: &Path) -> Result<()> {
        self.run(
            "create",
            id,
            &["--bundle", &bundle.display().to_string(), id],
        )?;
        Ok(())
    }

    fn start(&self, id: &str) -> Result<()> {
        self.run("start", id, &[id])?;
        Ok(())
    }

    fn kill(&self, id: &str, signal: &str) -> Result<()> {
        self.run("kill", id, &[id, signal])?;
        Ok(())
    }

    fn delete(&self, id: &str, force: bool) -> Result<()> {
        if force {
            self.run("delete", id, &["--force", id])?;
        } else {
            self.run("delete", id, &[id])?;
        }
        Ok(())
    }

    fn state(&self, id: &str) -> Result<ContainerState> {
        let stdout = self.run("state", id, &[id])?;
        serde_json::from_slice(&stdout).map_err(SandboxError::Serialize)
    }
}
