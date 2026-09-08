//! The wallpaper drawn from the tokens (`docs/design-language.md` §3, §5 and
//! "As built: wallpapers, lock screen, bar"): the ground colour, one thin
//! rule in the separator tone, and the WARD mark set small in the lower left
//! in `text_muted`. No gradient, no photo, no anti-aliasing: every element is
//! a rectangle on the 8 px grid, so the same composition holds for every
//! theme (only the three tones change), the PNG is a few kilobytes (two-bit
//! indexed, three entries) and the render a few milliseconds. The lock
//! screen shows the same file under a veil of the panel colour.

use std::io;

use crate::{Color, Theme};

/// Width in pixels: a 16:10 canvas that swaybg (`-m fill`) and hyprlock
/// scale to the output; the mark stays legible on every common size.
pub const WIDTH: u32 = 1920;
/// Height in pixels.
pub const HEIGHT: u32 = 1200;
/// The layout grid of §5.
const GRID: u32 = 8;

/// A glyph cell. The letters are 5×7 cells of 2 px, so `WARD` is 14 px
/// tall, the bar's text size: small, as §6 wants the host mark.
const CELL: u32 = 2;
const GLYPH_W: u32 = 5;
const GLYPH_H: u32 = 7;
/// One cell between letters.
const GAP: u32 = CELL;

/// The rule: one pixel high, eight grid cells in from either edge.
const RULE_Y: u32 = HEIGHT - 11 * GRID;
const RULE_X: u32 = 8 * GRID;
/// The mark's top-left corner, two grid cells under the rule.
const MARK_X: u32 = 8 * GRID;
const MARK_Y: u32 = HEIGHT - 9 * GRID;

// The mark sits under the rule and inside the canvas.
const _: () = assert!(MARK_Y > RULE_Y && MARK_Y + GLYPH_H * CELL < HEIGHT);

/// `W A R D` as 5×7 bitmaps; `X` is a filled cell.
const GLYPHS: [[&str; 7]; 4] = [
    [
        "X...X", "X...X", "X...X", "X.X.X", "X.X.X", "X.X.X", ".X.X.",
    ],
    [
        ".XXX.", "X...X", "X...X", "XXXXX", "X...X", "X...X", "X...X",
    ],
    [
        "XXXX.", "X...X", "X...X", "XXXX.", "X.X..", "X..X.", "X...X",
    ],
    [
        "XXXX.", "X...X", "X...X", "X...X", "X...X", "X...X", "XXXX.",
    ],
];

/// The three tones the wallpaper is drawn in, in palette order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Tone {
    Ground = 0,
    Separator = 1,
    TextMuted = 2,
}

/// A rectangle in pixels: `x`, `y`, `width`, `height`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    /// Left edge.
    pub x: u32,
    /// Top edge.
    pub y: u32,
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
}

/// One rendered wallpaper: a palette of three tones and one index per pixel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wallpaper {
    tones: [Color; 3],
    indices: Vec<u8>,
}

impl Wallpaper {
    /// The rule's rectangle.
    pub const RULE: Rect = Rect {
        x: RULE_X,
        y: RULE_Y,
        width: WIDTH - 2 * RULE_X,
        height: 1,
    };

    /// The mark's bounding rectangle: four glyphs and three gaps.
    pub const MARK: Rect = Rect {
        x: MARK_X,
        y: MARK_Y,
        width: 4 * GLYPH_W * CELL + 3 * GAP,
        height: GLYPH_H * CELL,
    };

    /// Draws the composition in the theme's ground, separator and
    /// `text_muted` tones.
    #[must_use]
    pub fn draw(theme: &Theme) -> Self {
        let p = &theme.palette;
        let mut w = Self {
            tones: [p.ground.value, p.separator.value, p.text_muted.value],
            indices: vec![Tone::Ground as u8; (WIDTH * HEIGHT) as usize],
        };
        w.fill(Self::RULE, Tone::Separator);
        for (i, glyph) in GLYPHS.iter().enumerate() {
            // Four letters: the offset stays far inside u32.
            #[allow(clippy::cast_possible_truncation)]
            let left = MARK_X + (i as u32) * (GLYPH_W * CELL + GAP);
            for (row, line) in glyph.iter().enumerate() {
                for (col, cell) in line.bytes().enumerate() {
                    if cell == b'X' {
                        #[allow(clippy::cast_possible_truncation)]
                        let rect = Rect {
                            x: left + (col as u32) * CELL,
                            y: MARK_Y + (row as u32) * CELL,
                            width: CELL,
                            height: CELL,
                        };
                        w.fill(rect, Tone::TextMuted);
                    }
                }
            }
        }
        w
    }

    fn fill(&mut self, r: Rect, tone: Tone) {
        for y in r.y..(r.y + r.height).min(HEIGHT) {
            let row = (y * WIDTH) as usize;
            let (from, to) = (
                row + r.x as usize,
                row + (r.x + r.width).min(WIDTH) as usize,
            );
            self.indices[from..to].fill(tone as u8);
        }
    }

    /// The colour at a pixel, or `None` outside the canvas.
    #[must_use]
    pub fn color_at(&self, x: u32, y: u32) -> Option<Color> {
        if x >= WIDTH || y >= HEIGHT {
            return None;
        }
        let index = self.indices[(y * WIDTH + x) as usize];
        self.tones.get(usize::from(index)).copied()
    }

    /// The wallpaper as a PNG: two bits per pixel over a three-entry palette,
    /// which deflates a screen of ground to a few kilobytes.
    pub fn png(&self) -> io::Result<Vec<u8>> {
        let palette: Vec<u8> = self.tones.iter().flat_map(|c| [c.r, c.g, c.b]).collect();
        let mut packed = Vec::with_capacity((WIDTH.div_ceil(4) * HEIGHT) as usize);
        for row in self.indices.chunks(WIDTH as usize) {
            for four in row.chunks(4) {
                let mut byte = 0u8;
                for (i, index) in four.iter().enumerate() {
                    byte |= index << (6 - 2 * i);
                }
                packed.push(byte);
            }
        }
        let mut out = Vec::new();
        let mut encoder = png::Encoder::new(&mut out, WIDTH, HEIGHT);
        encoder.set_color(png::ColorType::Indexed);
        encoder.set_depth(png::BitDepth::Two);
        encoder.set_palette(palette);
        encoder.set_compression(png::Compression::Fast);
        let mut writer = encoder.write_header().map_err(io::Error::other)?;
        writer.write_image_data(&packed).map_err(io::Error::other)?;
        writer.finish().map_err(io::Error::other)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn theme() -> Theme {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../themes/ward-dark.toml"
        ))
        .unwrap();
        Theme::parse(&text).unwrap()
    }

    #[test]
    fn the_rule_and_the_mark_sit_on_the_grid() {
        assert_eq!(Wallpaper::RULE.y % GRID, 0);
        assert_eq!(Wallpaper::RULE.x % GRID, 0);
        assert_eq!(Wallpaper::MARK.x % GRID, 0);
        assert_eq!(Wallpaper::MARK.y % GRID, 0);
        for glyph in GLYPHS {
            for line in glyph {
                assert_eq!(line.len(), GLYPH_W as usize);
            }
        }
    }

    #[test]
    fn the_three_tones_land_where_the_composition_says() {
        let theme = theme();
        let w = Wallpaper::draw(&theme);
        let p = &theme.palette;
        assert_eq!(w.color_at(0, 0), Some(p.ground.value));
        assert_eq!(w.color_at(WIDTH - 1, HEIGHT - 1), Some(p.ground.value));
        assert_eq!(w.color_at(WIDTH / 2, HEIGHT / 2), Some(p.ground.value));
        let rule = Wallpaper::RULE;
        assert_eq!(w.color_at(rule.x, rule.y), Some(p.separator.value));
        assert_eq!(
            w.color_at(rule.x + rule.width - 1, rule.y),
            Some(p.separator.value)
        );
        assert_eq!(w.color_at(rule.x - 1, rule.y), Some(p.ground.value));
        assert_eq!(w.color_at(rule.x, rule.y + 1), Some(p.ground.value));
        // W's top-left cell is filled; the cell to its right is not.
        let m = Wallpaper::MARK;
        assert_eq!(w.color_at(m.x, m.y), Some(p.text_muted.value));
        assert_eq!(w.color_at(m.x + CELL, m.y), Some(p.ground.value));
        // D's last column, fourth row (`X...X`) is filled.
        let d_right = m.x + m.width - 1;
        assert_eq!(
            w.color_at(d_right, m.y + 3 * CELL),
            Some(p.text_muted.value)
        );
        assert_eq!(w.color_at(WIDTH, 0), None);
    }

    #[test]
    fn the_png_is_small_and_decodes_to_the_same_pixels() {
        let theme = theme();
        let w = Wallpaper::draw(&theme);
        let bytes = w.png().unwrap();
        assert!(bytes.len() < 200 * 1024, "{} bytes", bytes.len());
        let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes.as_slice()));
        decoder.set_transformations(png::Transformations::EXPAND);
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!((info.width, info.height), (WIDTH, HEIGHT));
        assert_eq!(info.color_type, png::ColorType::Rgb);
        let at = |x: u32, y: u32| {
            let i = ((y * WIDTH + x) * 3) as usize;
            Color {
                r: buf[i],
                g: buf[i + 1],
                b: buf[i + 2],
            }
        };
        let m = Wallpaper::MARK;
        assert_eq!(at(0, 0), theme.palette.ground.value);
        assert_eq!(at(m.x, m.y), theme.palette.text_muted.value);
        assert_eq!(
            at(Wallpaper::RULE.x, Wallpaper::RULE.y),
            theme.palette.separator.value
        );
    }
}
