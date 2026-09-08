//! `wardos-theme` — renders one theme file (`desktop/themes/<id>.toml`, the
//! nine tokens of `docs/design-language.md` §3 plus tones, geometry, motion
//! and typography) into every desktop component's format, so a token change
//! is one edit (ADR-0016, `docs/desktop.md` §Themes).
//!
//! The binary `wardos-theme-render <id-or-path> --out <dir>` is what
//! `wardos-theme set` runs; this library is its whole implementation, so the
//! renderers are tested without a display: [`Theme::parse`] reads the file,
//! [`locate`] turns an id into a path, [`Fonts`] settles the two families,
//! [`render`] produces the fragments the component configs `include`, and
//! [`Wallpaper`] draws `background.png` from the tokens.

#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]

mod color;
mod fonts;
mod locate;
mod render;
mod theme;
mod wallpaper;

pub use color::Color;
pub use fonts::{Fonts, Overrides};
pub use locate::{Located, locate, search_dirs};
pub use render::{Files, WALLPAPER, render, render_into};
pub use theme::{
    Geometry, Meta, Motion, Palette, Terminal, Theme, Token, Tones, Typography, Variant,
};
pub use wallpaper::{HEIGHT, Rect, WIDTH, Wallpaper};

/// What can go wrong between a theme id and a rendered directory.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file is not the theme model.
    #[error("theme file: {0}")]
    Parse(#[from] toml::de::Error),
    /// The theme could not be written back as TOML.
    #[error("theme serialise: {0}")]
    Serialise(#[from] toml::ser::Error),
    /// A colour is not `#RRGGBB`.
    #[error("colour {0:?} is not #RRGGBB")]
    Color(String),
    /// A tone names a token the palette does not have.
    #[error("tone {0:?} names no palette token")]
    Tone(String),
    /// A font list is empty.
    #[error("typography.sans and typography.mono need at least one family")]
    Fonts,
    /// No theme file for the id or path.
    #[error("no theme {0:?} in the theme directories")]
    NotFound(String),
    /// Reading or writing.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}
