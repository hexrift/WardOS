//! Every shipped theme renders into every component's format, the two
//! fragments the compositor and the default terminal read are pinned to the
//! byte for Ward Dark, and the wallpaper drawn from the tokens is a small PNG
//! with the ground in its corners and the mark in `text_muted`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use wardos_theme::{
    Color, Fonts, HEIGHT, Overrides, Theme, Variant, WALLPAPER, WIDTH, Wallpaper, locate, render,
    render_into,
};

/// Where `wardos-theme` renders to; the fragments name the wallpaper there.
const OUT: &str = "/home/wardos/.config/wardos/theme/current";

fn out() -> &'static Path {
    Path::new(OUT)
}

const TOKENS: [&str; 9] = [
    "ground",
    "panel",
    "separator",
    "text",
    "text_muted",
    "accent",
    "verified",
    "restricted",
    "denied",
];

const FILES: [&str; 15] = [
    "hyprland.conf",
    "waybar.css",
    "mako.conf",
    "fuzzel.ini",
    "foot.ini",
    "alacritty.toml",
    "btop.theme",
    "hyprlock.conf",
    "swayosd.css",
    "nvim.lua",
    "chromium.json",
    "gtk.css",
    "colors.env",
    "background",
    "theme.toml",
];

fn themes_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../themes")
}

fn load(id: &str) -> Theme {
    let path = themes_dir().join(format!("{id}.toml"));
    Theme::parse(&fs::read_to_string(&path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn shipped() -> Vec<(String, Theme)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(themes_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "toml") {
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            out.push((stem.clone(), load(&stem)));
        }
    }
    assert!(
        out.len() >= 14,
        "expected the four official and ten palette themes"
    );
    out
}

#[test]
fn every_theme_parses_and_its_id_is_its_file_name() {
    for (stem, theme) in shipped() {
        assert_eq!(theme.meta.id, stem);
        assert!(!theme.meta.name.is_empty());
    }
}

#[test]
fn every_theme_carries_the_nine_tokens_as_rrggbb() {
    for (stem, theme) in shipped() {
        let names: BTreeSet<&str> = theme.palette.tokens().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, TOKENS.into_iter().collect::<BTreeSet<_>>(), "{stem}");
        for (name, token) in theme.palette.tokens() {
            let hex = token.value.hex();
            assert_eq!(hex.len(), 7, "{stem}.{name} = {hex}");
            assert!(hex.starts_with('#'));
            assert!(
                hex[1..].chars().all(|c| c.is_ascii_hexdigit()),
                "{stem}.{name} = {hex}"
            );
            assert!(!token.role.is_empty(), "{stem}.{name} has no role");
            assert!(!token.source.is_empty(), "{stem}.{name} has no source");
        }
        assert!(
            (4..=8).contains(&theme.geometry.radius_px),
            "{stem}: radius {} outside §5's 4–8 px",
            theme.geometry.radius_px
        );
    }
}

#[test]
fn palette_themes_say_so_on_every_token() {
    let mut palettes = 0;
    for (stem, theme) in shipped() {
        if stem.starts_with("ward-") {
            assert!(
                theme.meta.origin.is_none(),
                "{stem} is official, not a palette"
            );
            continue;
        }
        palettes += 1;
        assert!(theme.meta.origin.is_some(), "{stem} needs meta.origin");
        for (name, token) in theme.palette.tokens() {
            assert_eq!(token.source, "palette", "{stem}.{name}");
        }
        // Palettes keep Ward Dark's tones, geometry and motion; their terminal
        // cells are the nearest xterm-256 index to each token.
        assert_eq!(theme.geometry.radius_px, 6, "{stem}");
        assert_eq!(theme.motion.transition_ms, 120, "{stem}");
        let cells = [
            (theme.terminal.dim, &theme.palette.text_muted),
            (theme.terminal.ink, &theme.palette.text),
            (theme.terminal.accent, &theme.palette.accent),
            (theme.terminal.ok, &theme.palette.verified),
            (theme.terminal.warn, &theme.palette.restricted),
            (theme.terminal.deny, &theme.palette.denied),
        ];
        for (cell, token) in cells {
            assert_eq!(
                cell,
                token.value.nearest_xterm256(),
                "{stem}: {}",
                token.value.hex()
            );
        }
    }
    assert_eq!(palettes, 10);
}

#[test]
fn the_official_cells_are_the_design_languages_own() {
    // Ward Dark's cells were chosen by eye and are fixed by the design
    // language ("As built: ward watch"); the nearest-cell helper is for the
    // palette themes and is not applied to them.
    let dark = load("ward-dark");
    let t = dark.terminal;
    assert_eq!(
        [t.dim, t.ink, t.accent, t.ok, t.warn, t.deny],
        [245, 252, 110, 108, 179, 167]
    );
}

#[test]
fn every_theme_renders_every_file_with_its_tokens_in_place() {
    for (stem, theme) in shipped() {
        let files = render(&theme, None, &Fonts::from_theme(&theme), out());
        let names: BTreeSet<&str> = files.keys().copied().collect();
        assert_eq!(names, FILES.into_iter().collect::<BTreeSet<_>>(), "{stem}");
        let p = &theme.palette;
        let hypr = &files["hyprland.conf"];
        assert!(hypr.contains(&format!(
            "col.active_border = rgb({})",
            p.accent.value.bare()
        )));
        assert!(hypr.contains(&format!("rounding = {}", theme.geometry.radius_px)));
        let waybar = &files["waybar.css"];
        assert!(waybar.contains(&format!("@define-color denied {};", p.denied.value.hex())));
        assert!(waybar.contains(&format!(
            "@define-color text_muted {};",
            p.text_muted.value.hex()
        )));
        assert!(waybar.contains(&format!(
            "font-family: \"{}\", sans-serif;",
            theme.typography.sans[0]
        )));
        let mako = &files["mako.conf"];
        assert!(mako.contains(&format!("background-color={}", p.panel.value.hex())));
        assert!(mako.contains("[urgency=critical]"));
        let fuzzel = &files["fuzzel.ini"];
        assert!(fuzzel.contains(&format!(
            "background={}ff",
            p.panel.value.bare().to_lowercase()
        )));
        assert!(fuzzel.contains(&format!("radius={}", theme.geometry.radius_px)));
        let foot = &files["foot.ini"];
        assert!(foot.contains(&format!("font={}:size=11", theme.typography.mono[0])));
        assert!(foot.contains(&format!(
            "regular1={}",
            p.denied.value.bare().to_lowercase()
        )));
        let ala = &files["alacritty.toml"];
        assert!(ala.contains("[colors.primary]"));
        assert!(ala.contains(&format!("green = \"{}\"", p.verified.value.hex())));
        let btop = &files["btop.theme"];
        assert!(btop.contains(&format!("theme[main_bg]=\"{}\"", p.ground.value.hex())));
        assert!(btop.contains(&format!("theme[temp_end]=\"{}\"", p.denied.value.hex())));
        let lock = &files["hyprlock.conf"];
        assert!(lock.contains(&format!("$accent     = rgb({})", p.accent.value.bare())));
        assert!(lock.contains(&format!("$text_muted = rgb({})", p.text_muted.value.bare())));
        assert!(lock.contains(&format!("$font       = {}", theme.typography.sans[0])));
        assert!(lock.contains(&format!("$radius     = {}", theme.geometry.radius_px)));
        assert!(lock.contains(&format!("$veil       = rgba({}B3)", p.panel.value.bare())));
        assert!(lock.contains(&format!("$wallpaper  = {OUT}/{WALLPAPER}\n")));
        assert!(
            !lock.contains("input-field"),
            "{stem}: hyprlock draws its own blocks"
        );
        let osd = &files["swayosd.css"];
        assert!(osd.contains(&format!("border-radius: {}px;", theme.geometry.radius_px)));
        let nvim = &files["nvim.lua"];
        assert!(
            nvim.contains("\nreturn {\n"),
            "{stem}: init.lua dofile's a table"
        );
        assert!(nvim.contains(&format!("vim.o.background = \"{}\"", theme.meta.variant)));
        assert!(nvim.contains(&format!(
            "DiagnosticError = {{ fg = \"{}\" }}",
            p.denied.value.hex()
        )));
        let chromium = &files["chromium.json"];
        assert_eq!(
            chromium.trim(),
            format!(
                "{{\"theme_color\": \"{}\", \"variant\": \"{}\"}}",
                p.panel.value.hex(),
                theme.meta.variant
            )
        );
        let gtk = &files["gtk.css"];
        assert!(gtk.contains(&format!("@define-color ground {};\n", p.ground.value.hex())));
        assert!(gtk.contains(&format!(
            "@define-color accent_bg_color {};",
            p.accent.value.hex()
        )));
        let env = &files["colors.env"];
        for (name, token) in p.tokens() {
            let line = format!("WARDOS_{}=\"{}\"", name.to_uppercase(), token.value.hex());
            assert!(env.contains(&line), "{stem}: {line}");
        }
        assert!(env.contains(&format!("WARDOS_THEME_ID=\"{}\"", theme.meta.id)));
        assert!(env.contains(&format!("WARDOS_VARIANT=\"{}\"", theme.meta.variant)));
        assert!(env.contains(&format!(
            "WARDOS_FONT_MONO=\"{}\"",
            theme.typography.mono[0]
        )));
        assert_eq!(files["background"].trim(), format!("{OUT}/{WALLPAPER}"));
        assert!(files["theme.toml"].contains(&format!("id = \"{}\"", theme.meta.id)));
    }
}

/// Decodes a PNG to 8-bit RGB: `(width, height, pixels)`.
fn decode(bytes: &[u8]) -> (u32, u32, Vec<u8>) {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::EXPAND);
    let mut reader = decoder.read_info().unwrap();
    let mut buf = vec![0; reader.output_buffer_size().unwrap()];
    let info = reader.next_frame(&mut buf).unwrap();
    assert_eq!(info.color_type, png::ColorType::Rgb);
    buf.truncate(info.buffer_size());
    (info.width, info.height, buf)
}

fn pixel(image: &(u32, u32, Vec<u8>), x: u32, y: u32) -> Color {
    let i = ((y * image.0 + x) * 3) as usize;
    Color {
        r: image.2[i],
        g: image.2[i + 1],
        b: image.2[i + 2],
    }
}

#[test]
fn every_theme_draws_a_small_wallpaper_with_the_ground_in_the_corners_and_the_mark_in_text_muted() {
    for (stem, theme) in shipped() {
        let started = Instant::now();
        let png = Wallpaper::draw(&theme).png().unwrap();
        let took = started.elapsed();
        // The budget is 200 ms; an unoptimised test build gets five times that.
        let budget = if cfg!(debug_assertions) { 1000 } else { 200 };
        assert!(took.as_millis() < budget, "{stem}: {took:?}");
        assert!(png.len() < 200 * 1024, "{stem}: {} bytes", png.len());
        let image = decode(&png);
        assert_eq!((image.0, image.1), (WIDTH, HEIGHT), "{stem}");
        assert_eq!((image.0, image.1), (1920, 1200));
        let p = &theme.palette;
        for (x, y) in [
            (0, 0),
            (WIDTH - 1, 0),
            (0, HEIGHT - 1),
            (WIDTH - 1, HEIGHT - 1),
        ] {
            assert_eq!(pixel(&image, x, y), p.ground.value, "{stem} corner {x},{y}");
        }
        let mark = Wallpaper::MARK;
        assert_eq!(pixel(&image, mark.x, mark.y), p.text_muted.value, "{stem}");
        let rule = Wallpaper::RULE;
        assert_eq!(pixel(&image, rule.x, rule.y), p.separator.value, "{stem}");
        // Three tones and nothing else: no gradient, no anti-aliasing.
        let tones: BTreeSet<[u8; 3]> = image.2.chunks(3).map(|c| [c[0], c[1], c[2]]).collect();
        let want: BTreeSet<[u8; 3]> = [p.ground.value, p.separator.value, p.text_muted.value]
            .into_iter()
            .map(|c| [c.r, c.g, c.b])
            .collect();
        assert!(tones.is_subset(&want), "{stem}: {tones:?}");
    }
}

#[test]
fn ward_dark_hyprland_fragment_is_pinned() {
    let theme = load("ward-dark");
    let files = render(&theme, None, &Fonts::from_theme(&theme), out());
    assert_eq!(
        files["hyprland.conf"],
        "\
# Rendered by wardos-theme-render from ward-dark (Ward Dark); do not edit.
general {
    col.active_border = rgb(7FA1C3)
    col.inactive_border = rgb(24272B)
}
decoration {
    rounding = 6
}
misc {
    background_color = rgb(0E0F11)
}
"
    );
}

#[test]
fn ward_dark_foot_fragment_is_pinned() {
    let theme = load("ward-dark");
    let files = render(&theme, None, &Fonts::from_theme(&theme), out());
    assert_eq!(
        files["foot.ini"],
        "\
# Rendered by wardos-theme-render from ward-dark (Ward Dark); do not edit.
# The sixteen cells come from the nine tokens: black is ground/separator,
# red denied, green verified, yellow restricted, blue accent, magenta the
# accent's hue turned 90° toward red, cyan the accent's hue turned 30° toward
# green, white text_muted/text; each bright cell is its regular cell lightened
# (darkened on a light theme) by 8 %.
[main]
font=JetBrains Mono:size=11

[colors-dark]
foreground=d9d9d6
background=0e0f11
selection-foreground=0e0f11
selection-background=7fa1c3
regular0=0e0f11
regular1=c25a5a
regular2=6fae8a
regular3=c9a24a
regular4=7fa1c3
regular5=c37fc3
regular6=7fc3c3
regular7=8a8d91
bright0=24272b
bright1=cd7878
bright2=89bd9f
bright3=d2b269
bright4=9bb5d0
bright5=d09bd0
bright6=9bd0d0
bright7=d9d9d6

[colors-light]
foreground=d9d9d6
background=0e0f11
selection-foreground=0e0f11
selection-background=7fa1c3
regular0=0e0f11
regular1=c25a5a
regular2=6fae8a
regular3=c9a24a
regular4=7fa1c3
regular5=c37fc3
regular6=7fc3c3
regular7=8a8d91
bright0=24272b
bright1=cd7878
bright2=89bd9f
bright3=d2b269
bright4=9bb5d0
bright5=d09bd0
bright6=9bd0d0
bright7=d9d9d6
"
    );
}

#[test]
fn light_variants_flip_the_terminal_brightness_and_the_colour_scheme() {
    let theme = load("ward-light");
    assert_eq!(theme.meta.variant, Variant::Light);
    let files = render(&theme, None, &Fonts::from_theme(&theme), out());
    assert!(files["nvim.lua"].contains("vim.o.background = \"light\""));
    assert!(files["colors.env"].contains("WARDOS_VARIANT=\"light\""));
    // Bright red is darker than red on a light ground.
    let foot = &files["foot.ini"];
    let cell = |k: &str| {
        let line = foot.lines().find(|l| l.starts_with(k)).unwrap();
        Color::parse(&format!("#{}", &line[k.len()..])).unwrap()
    };
    assert!(cell("bright1=").luminance() < cell("regular1=").luminance());
}

#[test]
fn fonts_come_from_the_theme_unless_overridden() {
    let theme = load("ward-dark");
    let fonts = Fonts::from_theme(&theme);
    assert_eq!(fonts.sans, "Inter");
    assert_eq!(fonts.mono, "JetBrains Mono");

    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("fonts.conf");
    fs::write(
        &conf,
        "# chosen with wardos-font\nsans=Geist\nmono = Commit Mono\n",
    )
    .unwrap();
    let file = Overrides::from_file(&conf);
    let fonts = Fonts::resolve(&theme, &file);
    assert_eq!(fonts.sans, "Geist");
    assert_eq!(fonts.mono, "Commit Mono");

    let env = Overrides {
        sans: None,
        mono: Some("Iosevka".into()),
    }
    .over(file);
    let fonts = Fonts::resolve(&theme, &env);
    assert_eq!(fonts.sans, "Geist");
    assert_eq!(fonts.mono, "Iosevka");

    let files = render(&theme, None, &fonts, out());
    assert!(files["foot.ini"].contains("font=Iosevka:size=11"));
    assert!(files["waybar.css"].contains("font-family: \"Geist\", sans-serif;"));
    assert!(files["colors.env"].contains("WARDOS_FONT_SANS=\"Geist\""));

    // A missing file overrides nothing.
    let none = Overrides::from_file(&dir.path().join("absent"));
    assert_eq!(Fonts::resolve(&theme, &none).sans, "Inter");
}

#[test]
fn background_is_the_first_file_of_the_backgrounds_dir_or_the_rendered_wallpaper() {
    let theme = load("ward-dark");
    let dir = tempfile::tempdir().unwrap();
    let bg = dir.path().join("backgrounds");
    fs::create_dir(&bg).unwrap();
    fs::write(bg.join("b-second.png"), "").unwrap();
    fs::write(bg.join("a-first.jpg"), "").unwrap();
    let files = render(&theme, Some(&bg), &Fonts::from_theme(&theme), out());
    assert_eq!(
        files["background"].trim(),
        bg.join("a-first.jpg").to_string_lossy()
    );
    // The lock screen shows the same file.
    assert!(files["hyprlock.conf"].contains(&format!(
        "$wallpaper  = {}\n",
        bg.join("a-first.jpg").to_string_lossy()
    )));

    let empty = dir.path().join("none");
    let files = render(&theme, Some(&empty), &Fonts::from_theme(&theme), out());
    assert_eq!(files["background"].trim(), format!("{OUT}/{WALLPAPER}"));

    // A relative output directory still yields an absolute path.
    let files = render(
        &theme,
        None,
        &Fonts::from_theme(&theme),
        Path::new("current"),
    );
    let named = PathBuf::from(files["background"].trim());
    assert!(named.is_absolute(), "{}", named.display());
    assert!(named.ends_with(format!("current/{WALLPAPER}")));
}

#[test]
fn render_into_writes_every_file_and_the_wallpaper() {
    let theme = load("nord");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("current");
    render_into(&theme, None, &Fonts::from_theme(&theme), &out).unwrap();
    for f in FILES {
        assert!(out.join(f).is_file(), "{f}");
    }
    let png = fs::read(out.join(WALLPAPER)).unwrap();
    let image = decode(&png);
    assert_eq!((image.0, image.1), (WIDTH, HEIGHT));
    assert_eq!(pixel(&image, 0, 0), theme.palette.ground.value);
    // The fragments name the file that was written.
    let named = out.join(WALLPAPER).to_string_lossy().into_owned();
    assert_eq!(
        fs::read_to_string(out.join("background")).unwrap().trim(),
        named
    );
    assert!(
        fs::read_to_string(out.join("hyprlock.conf"))
            .unwrap()
            .contains(&format!("$wallpaper  = {named}\n"))
    );
}

#[test]
fn locate_finds_ids_in_the_search_dirs_and_paths_as_given() {
    let dir = tempfile::tempdir().unwrap();
    let user = dir.path().join("user");
    fs::create_dir_all(user.join("mine")).unwrap();
    fs::write(user.join("mine/theme.toml"), "").unwrap();
    fs::create_dir_all(user.join("other")).unwrap();
    fs::write(user.join("other/other.toml"), "").unwrap();
    let dirs = [user.clone(), themes_dir()];

    let found = locate("ward-dark", &dirs).unwrap();
    assert_eq!(found.path, themes_dir().join("ward-dark.toml"));
    assert_eq!(
        found.backgrounds,
        themes_dir().join("ward-dark/backgrounds")
    );

    let found = locate("mine", &dirs).unwrap();
    assert_eq!(found.path, user.join("mine/theme.toml"));
    assert_eq!(found.backgrounds, user.join("mine/backgrounds"));

    let found = locate("other", &dirs).unwrap();
    assert_eq!(found.path, user.join("other/other.toml"));

    let explicit = themes_dir().join("nord.toml");
    let found = locate(explicit.to_str().unwrap(), &dirs).unwrap();
    assert_eq!(found.path, explicit);
    assert_eq!(found.backgrounds, themes_dir().join("nord/backgrounds"));

    assert!(locate("no-such-theme", &dirs).is_err());
}

#[test]
fn a_theme_with_a_missing_token_or_a_bad_colour_is_refused() {
    let text = fs::read_to_string(themes_dir().join("ward-dark.toml")).unwrap();
    let missing = text.replace("denied = {", "# denied = {");
    assert!(Theme::parse(&missing).is_err());
    let bad = text.replace("#C25A5A", "#C25A5");
    assert!(Theme::parse(&bad).is_err());
    let bad_tone = text.replace("deny = \"denied\"", "deny = \"crimson\"");
    assert!(Theme::parse(&bad_tone).is_err());
}
