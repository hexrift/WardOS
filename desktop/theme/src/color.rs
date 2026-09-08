//! One sRGB colour and the few derivations the renderers need: hex forms, a
//! hue turn and a lightness step for the terminal cells, and the nearest
//! xterm-256 cell for the palette themes' `[terminal]` table.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

/// An opaque sRGB colour, written `#RRGGBB` in the theme files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color {
    /// Red, 0–255.
    pub r: u8,
    /// Green, 0–255.
    pub g: u8,
    /// Blue, 0–255.
    pub b: u8,
}

impl Color {
    /// Parses `#RRGGBB` (either case). Anything else, including the short
    /// `#RGB` form and alpha, is refused: a theme file names every colour
    /// in full so it can be read without a tool.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let bad = || Error::Color(text.to_string());
        let hex = text.strip_prefix('#').ok_or_else(bad)?;
        if hex.len() != 6 || !hex.is_ascii() {
            return Err(bad());
        }
        let channel = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| bad());
        Ok(Self {
            r: channel(0)?,
            g: channel(2)?,
            b: channel(4)?,
        })
    }

    /// `#RRGGBB`, upper case, as the theme files write it.
    #[must_use]
    pub fn hex(self) -> String {
        format!("#{}", self.bare())
    }

    /// `RRGGBB`, upper case, for Hyprland's `rgb(...)`.
    #[must_use]
    pub fn bare(self) -> String {
        format!("{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }

    /// `rrggbb`, lower case, for foot and fuzzel.
    #[must_use]
    pub fn lower(self) -> String {
        self.bare().to_lowercase()
    }

    /// WCAG relative luminance, 0 (black) to 1 (white).
    #[must_use]
    pub fn luminance(self) -> f64 {
        let lin = |c: u8| {
            let c = f64::from(c) / 255.0;
            if c <= 0.039_28 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(self.r) + 0.7152 * lin(self.g) + 0.0722 * lin(self.b)
    }

    /// The same colour with its hue turned `degrees` around the HSL circle
    /// (positive toward red from blue), saturation and lightness kept.
    #[must_use]
    pub fn rotate_hue(self, degrees: f64) -> Self {
        let (h, s, l) = self.hsl();
        Self::from_hsl((h + degrees).rem_euclid(360.0), s, l)
    }

    /// The same colour with its HSL lightness moved by `delta` (−1..1),
    /// clamped; negative darkens.
    #[must_use]
    pub fn lighten(self, delta: f64) -> Self {
        let (h, s, l) = self.hsl();
        Self::from_hsl(h, s, (l + delta).clamp(0.0, 1.0))
    }

    /// The xterm-256 cell nearest to this colour by RGB distance, from the
    /// 6×6×6 cube and the grey ramp (cells 16–255). The sixteen system cells
    /// are skipped: every terminal paints them differently.
    #[must_use]
    pub fn nearest_xterm256(self) -> u8 {
        const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
        let distance = |(r, g, b): (u8, u8, u8)| {
            let d = |a: u8, b: u8| (i32::from(a) - i32::from(b)).pow(2);
            d(r, self.r) + d(g, self.g) + d(b, self.b)
        };
        let cube = (0u8..216).map(|i| {
            let cell = (
                LEVELS[usize::from(i / 36)],
                LEVELS[usize::from(i / 6 % 6)],
                LEVELS[usize::from(i % 6)],
            );
            (16 + i, distance(cell))
        });
        let greys = (0u8..24).map(|i| {
            let v = 8 + 10 * i;
            (232 + i, distance((v, v, v)))
        });
        cube.chain(greys)
            .min_by_key(|(_, d)| *d)
            .map_or(16, |(cell, _)| cell)
    }

    // The textbook names, kept so the formulas read as the reference does.
    #[allow(clippy::many_single_char_names)]
    fn hsl(self) -> (f64, f64, f64) {
        let r = f64::from(self.r) / 255.0;
        let g = f64::from(self.g) / 255.0;
        let b = f64::from(self.b) / 255.0;
        let max = r.max(g).max(b);
        let min = r.min(g).min(b);
        let l = f64::midpoint(max, min);
        let delta = max - min;
        if delta.abs() < f64::EPSILON {
            return (0.0, 0.0, l);
        }
        let s = delta / (1.0 - (2.0 * l - 1.0).abs());
        let h = if (max - r).abs() < f64::EPSILON {
            60.0 * (((g - b) / delta).rem_euclid(6.0))
        } else if (max - g).abs() < f64::EPSILON {
            60.0 * ((b - r) / delta + 2.0)
        } else {
            60.0 * ((r - g) / delta + 4.0)
        };
        (h, s, l)
    }

    #[allow(clippy::many_single_char_names)]
    fn from_hsl(h: f64, s: f64, l: f64) -> Self {
        let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
        let x = c * (1.0 - ((h / 60.0).rem_euclid(2.0) - 1.0).abs());
        let m = l - c / 2.0;
        let (r, g, b) = match h {
            h if h < 60.0 => (c, x, 0.0),
            h if h < 120.0 => (x, c, 0.0),
            h if h < 180.0 => (0.0, c, x),
            h if h < 240.0 => (0.0, x, c),
            h if h < 300.0 => (x, 0.0, c),
            _ => (c, 0.0, x),
        };
        // Rounded and clamped to a channel; the float never leaves 0..=255.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let channel = |v: f64| ((v + m) * 255.0).round().clamp(0.0, 255.0) as u8;
        Self {
            r: channel(r),
            g: channel(g),
            b: channel(b),
        }
    }
}

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for Color {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Color {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parses_full_hex_only() {
        assert_eq!(
            Color::parse("#7fa1c3").unwrap(),
            Color {
                r: 127,
                g: 161,
                b: 195
            }
        );
        assert_eq!(Color::parse("#7FA1C3").unwrap().hex(), "#7FA1C3");
        for bad in ["7FA1C3", "#7FA1C", "#7FA1C3FF", "#GGGGGG", "#abc"] {
            assert!(Color::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hsl_round_trips_and_turns() {
        let accent = Color::parse("#7FA1C3").unwrap();
        assert_eq!(accent.rotate_hue(0.0), accent);
        assert_eq!(accent.rotate_hue(360.0), accent);
        let magenta = accent.rotate_hue(90.0);
        assert!(magenta.r > magenta.g, "{magenta}");
        assert!(accent.lighten(0.08).luminance() > accent.luminance());
        assert!(accent.lighten(-0.08).luminance() < accent.luminance());
        assert_eq!(
            Color::parse("#FFFFFF").unwrap().lighten(0.5).hex(),
            "#FFFFFF"
        );
        assert_eq!(
            Color::parse("#808080").unwrap().rotate_hue(120.0).hex(),
            "#808080"
        );
    }

    #[test]
    fn nearest_cells_land_on_the_cube_and_the_ramp() {
        assert_eq!(Color::parse("#000000").unwrap().nearest_xterm256(), 16);
        assert_eq!(Color::parse("#FFFFFF").unwrap().nearest_xterm256(), 231);
        assert_eq!(Color::parse("#8A8D91").unwrap().nearest_xterm256(), 245);
        assert_eq!(Color::parse("#C9A24A").unwrap().nearest_xterm256(), 179);
    }
}
