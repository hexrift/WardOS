//! Reading the three policy layers from disk.
//!
//! Pure functions over paths: no privileged operation, no environment lookup. Files are
//! capped at [`MAX_POLICY_FILE_BYTES`], must be regular files (symbolic links are
//! refused), and the system directory is read in sorted file-name order.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::defaults::default_policy;
use crate::error::LoadError;
use crate::schema::Policy;

/// Maximum size of a single policy file (256 KiB).
pub const MAX_POLICY_FILE_BYTES: u64 = 256 * 1024;

/// The three policy layers as loaded from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layers {
    /// Built-in defaults overlaid with the files of the system directory.
    pub system: Policy,
    /// The user's policy, or an empty (inheriting) policy if the file is absent.
    pub user: Policy,
    /// The project's policy, or an empty (inheriting) policy if the file is absent.
    pub project: Policy,
    /// Which files contributed.
    pub sources: LayerSources,
}

/// The files that contributed to a [`Layers`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayerSources {
    /// System directory files, in the order they were applied.
    pub system_files: Vec<PathBuf>,
    /// The user file, if it existed.
    pub user_file: Option<PathBuf>,
    /// The project file, if it existed.
    pub project_file: Option<PathBuf>,
}

/// Reads a policy file if it exists.
///
/// Returns `Ok(None)` when the path does not exist. Refuses symbolic links and
/// non-regular files, and rejects files larger than [`MAX_POLICY_FILE_BYTES`] without
/// reading past the cap.
///
/// # Errors
/// See [`LoadError`].
pub fn read_policy_file(path: &Path) -> Result<Option<String>, LoadError> {
    let io = |source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    };
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    };
    if meta.file_type().is_symlink() {
        return Err(LoadError::Symlink {
            path: path.to_path_buf(),
        });
    }
    if !meta.is_file() {
        return Err(LoadError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    let file = File::open(path).map_err(io)?;
    // Re-check on the open handle so a swap between stat and open cannot hand us a
    // device or FIFO.
    if !file.metadata().map_err(io)?.is_file() {
        return Err(LoadError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_POLICY_FILE_BYTES {
        return Err(LoadError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_POLICY_FILE_BYTES,
        });
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|e| io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

/// Reads and parses one optional policy file.
///
/// # Errors
/// See [`LoadError`].
pub fn load_policy_file(path: &Path) -> Result<Option<Policy>, LoadError> {
    read_policy_file(path)?
        .map(|text| {
            Policy::from_yaml(&text).map_err(|source| LoadError::Policy {
                path: path.to_path_buf(),
                source,
            })
        })
        .transpose()
}

fn is_policy_file_name(name: &str) -> bool {
    !name.starts_with('.')
        && Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
}

/// Lists the policy files of a system directory in sorted file-name order.
///
/// A missing directory yields an empty list. Hidden files and files without a
/// `.yaml`/`.yml` suffix are ignored.
///
/// # Errors
/// See [`LoadError`].
pub fn list_system_files(system_dir: &Path) -> Result<Vec<PathBuf>, LoadError> {
    let entries = match fs::read_dir(system_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(LoadError::Io {
                path: system_dir.to_path_buf(),
                source,
            });
        }
    };
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| LoadError::Io {
            path: system_dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(LoadError::NonUtf8FileName { path });
        };
        if is_policy_file_name(&name) {
            files.push((name, path));
        }
    }
    files.sort();
    Ok(files.into_iter().map(|(_, p)| p).collect())
}

/// Loads the three layers.
///
/// * `system_dir` (normally `/etc/ward/policy.d`): the built-in default policy is
///   overlaid with every `*.yaml`/`*.yml` file in sorted order (later wins per field,
///   see [`Policy::overlay`]). A missing directory yields the built-in defaults.
/// * `user_file` (normally `~/.config/ward/policy.yaml`) and `project_file` (normally
///   `<project>/.ward/policy.yaml`): an absent path or file yields an empty policy,
///   which inherits everything from the layer above.
///
/// # Errors
/// See [`LoadError`]. Any unreadable, oversized, non-regular or invalid file is an
/// error; nothing is silently skipped.
pub fn load_layers(
    system_dir: &Path,
    user_file: Option<&Path>,
    project_file: Option<&Path>,
) -> Result<Layers, LoadError> {
    let mut system = default_policy().map_err(|source| LoadError::Policy {
        path: PathBuf::from("<built-in>"),
        source,
    })?;
    let mut sources = LayerSources::default();
    for path in list_system_files(system_dir)? {
        if let Some(policy) = load_policy_file(&path)? {
            system.overlay(&policy);
            sources.system_files.push(path);
        }
    }
    let load_optional = |path: Option<&Path>| -> Result<(Policy, Option<PathBuf>), LoadError> {
        match path {
            Some(p) => match load_policy_file(p)? {
                Some(policy) => Ok((policy, Some(p.to_path_buf()))),
                None => Ok((Policy::default(), None)),
            },
            None => Ok((Policy::default(), None)),
        }
    };
    let (user, user_file) = load_optional(user_file)?;
    let (project, project_file) = load_optional(project_file)?;
    sources.user_file = user_file;
    sources.project_file = project_file;
    Ok(Layers {
        system,
        user,
        project,
        sources,
    })
}
