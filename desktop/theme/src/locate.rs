//! Where theme files live and how an id becomes a path. Shipped themes are
//! `<dir>/<id>.toml`; installed ones are a clone at `<dir>/<name>/` holding
//! `<name>.toml` or `theme.toml`. Either way the theme's backgrounds are in
//! `<dir>/<id>/backgrounds/`, so a shipped theme can carry backgrounds too.

use std::path::{Path, PathBuf};

use crate::Error;

/// A theme file and the directory its backgrounds would be in (which need
/// not exist).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located {
    /// The TOML file.
    pub path: PathBuf,
    /// `<theme dir>/<id>/backgrounds`.
    pub backgrounds: PathBuf,
}

/// The directories searched for a theme id, user first:
/// `$WARDOS_THEMES` (a colon-separated list), `$XDG_DATA_HOME/wardos/themes`
/// (or `~/.local/share/wardos/themes`), `/usr/share/wardos/themes`, and
/// `$WARDOS_ROOT/themes` for a checkout.
#[must_use]
pub fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(list) = std::env::var("WARDOS_THEMES") {
        dirs.extend(list.split(':').filter(|d| !d.is_empty()).map(PathBuf::from));
    }
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    if let Some(data) = data_home {
        dirs.push(data.join("wardos/themes"));
    }
    dirs.push(PathBuf::from("/usr/share/wardos/themes"));
    if let Some(root) = std::env::var_os("WARDOS_ROOT") {
        dirs.push(PathBuf::from(root).join("themes"));
    }
    dirs
}

/// Resolves an id (searched in `dirs`, first hit wins) or a path (anything
/// containing a `/` or ending in `.toml`, taken as given).
pub fn locate(spec: &str, dirs: &[PathBuf]) -> Result<Located, Error> {
    let is_toml = Path::new(spec)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
    if spec.contains('/') || is_toml {
        let path = PathBuf::from(spec);
        if !path.is_file() {
            return Err(Error::NotFound(spec.to_string()));
        }
        return Ok(Located {
            backgrounds: backgrounds_of(&path),
            path,
        });
    }
    for dir in dirs {
        for candidate in [
            dir.join(format!("{spec}.toml")),
            dir.join(spec).join(format!("{spec}.toml")),
            dir.join(spec).join("theme.toml"),
        ] {
            if candidate.is_file() {
                return Ok(Located {
                    backgrounds: dir.join(spec).join("backgrounds"),
                    path: candidate,
                });
            }
        }
    }
    Err(Error::NotFound(spec.to_string()))
}

/// The backgrounds directory beside a theme file: `<stem>/backgrounds` next
/// to `<stem>.toml`, or `backgrounds` next to a `theme.toml`.
fn backgrounds_of(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    match path.file_stem().and_then(|s| s.to_str()) {
        Some("theme") | None => parent.join("backgrounds"),
        Some(stem) => parent.join(stem).join("backgrounds"),
    }
}
