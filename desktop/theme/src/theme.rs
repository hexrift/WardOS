//! The theme file model: the tables of `desktop/themes/README.md`, one struct
//! each, parsed with serde so a missing token or a malformed colour is a
//! parse error rather than a wrong colour on screen.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Color, Error};

/// Dark or light: decides the GTK colour scheme, Neovim's `background` and
/// the direction of the terminal's bright cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Variant {
    /// Dark ground, light text.
    Dark,
    /// Light ground, dark text.
    Light,
}

impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Dark => "dark",
            Self::Light => "light",
        })
    }
}

/// `[meta]`: the theme's name, id and where its values come from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Shown in menus and notifications (`Ward Dark`).
    pub name: String,
    /// The file stem (`ward-dark`); what `wardos-theme set` takes.
    pub id: String,
    /// Dark or light.
    pub variant: Variant,
    /// `standard`, `low` or `AAA`.
    pub contrast: String,
    /// The design-language section, or the derivation, the values come from.
    pub source: String,
    /// For palette themes: the public name of the palette they map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// One of the nine tokens: its value, what it is for, where it comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    /// The colour.
    pub value: Color,
    /// The role, in the design language's words.
    pub role: String,
    /// The section fixing the value, `derived: <rule>`, or `palette`.
    pub source: String,
}

/// `[palette]`: the nine tokens of `docs/design-language.md` §3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Palette {
    /// Host layer.
    pub ground: Token,
    /// Surfaces.
    pub panel: Token,
    /// Thin, 1 px.
    pub separator: Token,
    /// Primary text.
    pub text: Token,
    /// Secondary text.
    pub text_muted: Token,
    /// The one hue: active agent, focus, selection.
    pub accent: Token,
    /// `✓ VERIFIED`, pass.
    pub verified: Token,
    /// Limited network, `ask` pending.
    pub restricted: Token,
    /// Denied, failed; used sparingly, never animated.
    pub denied: Token,
}

impl Palette {
    /// The tokens in the order of §3's table, with their names.
    #[must_use]
    pub fn tokens(&self) -> [(&'static str, &Token); 9] {
        [
            ("ground", &self.ground),
            ("panel", &self.panel),
            ("separator", &self.separator),
            ("text", &self.text),
            ("text_muted", &self.text_muted),
            ("accent", &self.accent),
            ("verified", &self.verified),
            ("restricted", &self.restricted),
            ("denied", &self.denied),
        ]
    }

    fn has(&self, name: &str) -> bool {
        self.tokens().iter().any(|(n, _)| *n == name)
    }
}

/// `[tones]`: which token each colour role of the shell maps to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tones {
    /// Secondary.
    pub dim: String,
    /// Primary text.
    pub ink: String,
    /// Focus, selection, the active agent.
    pub accent: String,
    /// Pass.
    pub ok: String,
    /// Pending, restricted.
    pub warn: String,
    /// Denied, failed.
    pub deny: String,
}

/// `[terminal]`: the xterm-256 cell for each role, for `ward watch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terminal {
    /// Secondary.
    pub dim: u8,
    /// Primary text.
    pub ink: u8,
    /// Focus, selection.
    pub accent: u8,
    /// Pass.
    pub ok: u8,
    /// Pending, restricted.
    pub warn: u8,
    /// Denied, failed.
    pub deny: u8,
}

/// `[geometry]`: §5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Geometry {
    /// Corner radius, 4–8 px.
    pub radius_px: u32,
    /// Separator thickness.
    pub separator_px: u32,
    /// The layout grid.
    pub grid_px: u32,
    /// Shadow levels: one for the command centre and approvals, or none.
    pub shadow_levels: u32,
}

/// `[motion]`: §12.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Motion {
    /// Transition length, 100–150 ms.
    pub transition_ms: u32,
    /// `linear` or `ease-out`.
    pub easing: String,
    /// The five transitions that animate.
    pub animated: Vec<String>,
}

/// `[typography]`: §4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Typography {
    /// Sans candidates, best first, ending in a generic family.
    pub sans: Vec<String>,
    /// Mono candidates, best first, ending in a generic family.
    pub mono: Vec<String>,
    /// Tabular numerals for durations and counts.
    pub tabular_numerals: bool,
}

/// One theme file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Theme {
    /// `[meta]`.
    pub meta: Meta,
    /// `[palette]`.
    pub palette: Palette,
    /// `[tones]`.
    pub tones: Tones,
    /// `[terminal]`.
    pub terminal: Terminal,
    /// `[geometry]`.
    pub geometry: Geometry,
    /// `[motion]`.
    pub motion: Motion,
    /// `[typography]`.
    pub typography: Typography,
}

impl Theme {
    /// Parses a theme file and checks what serde cannot: every tone names a
    /// token, and the font lists are not empty.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let theme: Self = toml::from_str(text)?;
        let t = &theme.tones;
        for tone in [&t.dim, &t.ink, &t.accent, &t.ok, &t.warn, &t.deny] {
            if !theme.palette.has(tone) {
                return Err(Error::Tone(tone.clone()));
            }
        }
        if theme.typography.sans.is_empty() || theme.typography.mono.is_empty() {
            return Err(Error::Fonts);
        }
        Ok(theme)
    }

    /// The theme as TOML again, for `theme.toml` in the rendered directory.
    pub fn to_toml(&self) -> Result<String, Error> {
        Ok(toml::to_string(self)?)
    }
}
