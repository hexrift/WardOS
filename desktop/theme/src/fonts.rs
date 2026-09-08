//! The two families the components are told to use. The theme lists
//! candidates; `wardos-font set` writes `~/.config/wardos/fonts.conf`
//! (`sans=`/`mono=`) and `WARDOS_FONT_SANS`/`WARDOS_FONT_MONO` win over that,
//! so one user choice reaches every component through the render.

use std::path::Path;

use crate::Theme;

/// The sans and mono family names written into every fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fonts {
    /// System UI (`Inter`).
    pub sans: String,
    /// Technical state, terminals, editors (`JetBrains Mono`).
    pub mono: String,
}

impl Fonts {
    /// The theme's first candidate of each class.
    #[must_use]
    pub fn from_theme(theme: &Theme) -> Self {
        Self {
            sans: theme.typography.sans[0].clone(),
            mono: theme.typography.mono[0].clone(),
        }
    }

    /// The theme's candidates, each replaced by an override when there is one.
    #[must_use]
    pub fn resolve(theme: &Theme, overrides: &Overrides) -> Self {
        let base = Self::from_theme(theme);
        Self {
            sans: overrides.sans.clone().unwrap_or(base.sans),
            mono: overrides.mono.clone().unwrap_or(base.mono),
        }
    }
}

/// A user's font choice: either family may be unset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Overrides {
    /// `sans=` / `WARDOS_FONT_SANS`.
    pub sans: Option<String>,
    /// `mono=` / `WARDOS_FONT_MONO`.
    pub mono: Option<String>,
}

impl Overrides {
    /// `WARDOS_FONT_SANS` and `WARDOS_FONT_MONO`; empty values count as unset.
    #[must_use]
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        Self {
            sans: var("WARDOS_FONT_SANS"),
            mono: var("WARDOS_FONT_MONO"),
        }
    }

    /// `sans=<family>` and `mono=<family>` lines of a `fonts.conf`; blank
    /// lines and `#` comments are skipped. A missing or unreadable file
    /// overrides nothing: the theme's own fonts are always a valid answer.
    #[must_use]
    pub fn from_file(path: &Path) -> Self {
        let mut out = Self::default();
        let Ok(text) = std::fs::read_to_string(path) else {
            return out;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let value = value.trim();
                if value.is_empty() {
                    continue;
                }
                match key.trim() {
                    "sans" => out.sans = Some(value.to_string()),
                    "mono" => out.mono = Some(value.to_string()),
                    _ => {}
                }
            }
        }
        out
    }

    /// These overrides, with `other` filling whatever they leave unset.
    #[must_use]
    pub fn over(self, other: Self) -> Self {
        Self {
            sans: self.sans.or(other.sans),
            mono: self.mono.or(other.mono),
        }
    }
}
