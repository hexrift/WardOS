//! One function per component: the nine tokens, the geometry and the two
//! fonts written in the component's own syntax. Every fragment starts with a
//! "do not edit" line naming the theme, because the component configs
//! `include` these files and a hand edit is lost at the next render.
//!
//! What the fragments carry is bounded by what each component can express
//! (ADR-0016): Waybar and swayosd take CSS, fuzzel and foot INI, Hyprland and
//! hyprlock their own conf, btop `theme[key]="#hex"`, Neovim Lua. The rules
//! of `docs/design-language.md` §3 hold in each: no gradients, no glow, a
//! state colour on a marker or a border, never on a whole surface.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;

use crate::{Color, Fonts, Theme, Variant};

/// Font size for terminals and menus, in points.
const SIZE: u32 = 11;

/// The lightness step between a regular terminal cell and its bright twin.
const BRIGHT_STEP: f64 = 0.08;

/// The rendered fragments, keyed by file name.
pub type Files = BTreeMap<&'static str, String>;

/// Renders every fragment. `backgrounds` is the theme's backgrounds
/// directory (need not exist); its first file, by name, becomes
/// `background`, else the ground colour does.
#[must_use]
pub fn render(theme: &Theme, backgrounds: Option<&Path>, fonts: &Fonts) -> Files {
    let background = background_line(theme, backgrounds);
    let mut files = Files::new();
    files.insert("hyprland.conf", hyprland(theme));
    files.insert("waybar.css", waybar(theme, fonts));
    files.insert("mako.conf", mako(theme, fonts));
    files.insert("fuzzel.ini", fuzzel(theme, fonts));
    files.insert("foot.ini", foot(theme, fonts));
    files.insert("alacritty.toml", alacritty(theme, fonts));
    files.insert("btop.theme", btop(theme));
    files.insert("hyprlock.conf", hyprlock(theme, fonts));
    files.insert("swayosd.css", swayosd(theme, fonts));
    files.insert("nvim.lua", nvim(theme));
    files.insert("chromium.json", chromium(theme));
    files.insert("gtk.css", gtk(theme));
    files.insert("colors.env", colors_env(theme, fonts));
    files.insert("background", format!("{background}\n"));
    // A theme that fails to re-serialise is a bug in this crate, not in the
    // theme; the copy is a convenience for the shell, so the render goes on.
    files.insert("theme.toml", theme.to_toml().unwrap_or_default());
    files
}

/// Renders into `out` (created if needed), one file per fragment.
pub fn render_into(
    theme: &Theme,
    backgrounds: Option<&Path>,
    fonts: &Fonts,
    out: &Path,
) -> io::Result<()> {
    fs::create_dir_all(out)?;
    for (name, content) in render(theme, backgrounds, fonts) {
        fs::write(out.join(name), content)?;
    }
    Ok(())
}

fn header(theme: &Theme, open: &str, close: &str) -> String {
    format!(
        "{open} Rendered by wardos-theme-render from {} ({}); do not edit.{close}\n",
        theme.meta.id, theme.meta.name
    )
}

fn background_line(theme: &Theme, backgrounds: Option<&Path>) -> String {
    let first = backgrounds
        .and_then(|dir| fs::read_dir(dir).ok())
        .map(|entries| {
            let mut files: Vec<_> = entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            files.sort();
            files
        })
        .and_then(|files| files.into_iter().next());
    match first {
        Some(path) => path.to_string_lossy().into_owned(),
        None => format!("solid:{}", theme.palette.ground.value.hex()),
    }
}

fn hyprland(theme: &Theme) -> String {
    let p = &theme.palette;
    format!(
        "{}general {{\n    col.active_border = rgb({})\n    col.inactive_border = rgb({})\n}}\n\
         decoration {{\n    rounding = {}\n}}\nmisc {{\n    background_color = rgb({})\n}}\n",
        header(theme, "#", ""),
        p.accent.value.bare(),
        p.separator.value.bare(),
        theme.geometry.radius_px,
        p.ground.value.bare()
    )
}

/// The nine tokens as GTK CSS colours under their own names (`@ground` …
/// `@denied`), what the shipped Waybar, GTK and swayosd styles refer to.
fn define_colors(theme: &Theme) -> String {
    let mut out = String::new();
    for (name, token) in theme.palette.tokens() {
        let _ = writeln!(out, "@define-color {name} {};", token.value);
    }
    out
}

fn waybar(theme: &Theme, fonts: &Fonts) -> String {
    format!(
        "{}{}* {{\n    font-family: \"{}\", sans-serif;\n}}\n.mono {{\n    font-family: \"{}\", monospace;\n}}\n",
        header(theme, "/*", " */"),
        define_colors(theme),
        fonts.sans,
        fonts.mono
    )
}

fn mako(theme: &Theme, fonts: &Fonts) -> String {
    let p = &theme.palette;
    let g = &theme.geometry;
    format!(
        "{}font={} {SIZE}\nbackground-color={}\ntext-color={}\nborder-color={}\nborder-size={}\n\
         border-radius={}\nprogress-color=over {}\n\n[urgency=low]\ntext-color={}\n\n\
         [urgency=high]\nborder-color={}\n\n[urgency=critical]\nborder-color={}\n",
        header(theme, "#", ""),
        fonts.sans,
        p.panel.value,
        p.text.value,
        p.separator.value,
        g.separator_px,
        g.radius_px,
        p.accent.value,
        p.text_muted.value,
        p.restricted.value,
        p.denied.value
    )
}

fn fuzzel(theme: &Theme, fonts: &Fonts) -> String {
    let p = &theme.palette;
    let c = |color: Color| format!("{}ff", color.lower());
    format!(
        "{}[main]\nfont={}:size={SIZE}\n\n[colors]\nbackground={}\ntext={}\nprompt={}\n\
         placeholder={}\ninput={}\nmatch={}\nselection={}\nselection-text={}\n\
         selection-match={}\nborder={}\n\n[border]\nwidth={}\nradius={}\n",
        header(theme, "#", ""),
        fonts.sans,
        c(p.panel.value),
        c(p.text.value),
        c(p.text_muted.value),
        c(p.text_muted.value),
        c(p.text.value),
        c(p.accent.value),
        c(p.accent.value),
        c(p.ground.value),
        c(p.text.value),
        c(p.accent.value),
        theme.geometry.separator_px,
        theme.geometry.radius_px
    )
}

/// The sixteen ANSI cells, regular then bright, from the nine tokens.
fn ansi(theme: &Theme) -> [[Color; 8]; 2] {
    let p = &theme.palette;
    let accent = p.accent.value;
    let regular = [
        p.ground.value,
        p.denied.value,
        p.verified.value,
        p.restricted.value,
        accent,
        accent.rotate_hue(90.0),
        accent.rotate_hue(-30.0),
        p.text_muted.value,
    ];
    let step = match theme.meta.variant {
        Variant::Dark => BRIGHT_STEP,
        Variant::Light => -BRIGHT_STEP,
    };
    let mut bright = regular.map(|c| c.lighten(step));
    bright[0] = p.separator.value;
    bright[7] = p.text.value;
    [regular, bright]
}

const ANSI_NOTE: &str = "\
# The sixteen cells come from the nine tokens: black is ground/separator,
# red denied, green verified, yellow restricted, blue accent, magenta the
# accent's hue turned 90° toward red, cyan the accent's hue turned 30° toward
# green, white text_muted/text; each bright cell is its regular cell lightened
# (darkened on a light theme) by 8 %.
";

fn foot(theme: &Theme, fonts: &Fonts) -> String {
    let p = &theme.palette;
    let [regular, bright] = ansi(theme);
    let mut out = format!(
        "{}{ANSI_NOTE}[main]\nfont={}:size={SIZE}\n",
        header(theme, "#", ""),
        fonts.mono,
    );
    // foot 1.25 deprecated [colors] for [colors-dark] and [colors-light], picked by the
    // desktop's colour-scheme preference; the theme is the theme whichever is asked
    // for, so both sections carry it.
    for section in ["colors-dark", "colors-light"] {
        let _ = write!(
            out,
            "\n[{section}]\nforeground={}\nbackground={}\nselection-foreground={}\n\
             selection-background={}\n",
            p.text.value.lower(),
            p.ground.value.lower(),
            p.ground.value.lower(),
            p.accent.value.lower(),
        );
        for (i, c) in regular.iter().enumerate() {
            let _ = writeln!(out, "regular{i}={}", c.lower());
        }
        for (i, c) in bright.iter().enumerate() {
            let _ = writeln!(out, "bright{i}={}", c.lower());
        }
    }
    out
}

const ANSI_NAMES: [&str; 8] = [
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
];

fn alacritty(theme: &Theme, fonts: &Fonts) -> String {
    let p = &theme.palette;
    let [regular, bright] = ansi(theme);
    let mut out = format!(
        "{}{ANSI_NOTE}[font]\nnormal.family = \"{}\"\nsize = {SIZE}.0\n\n[colors.primary]\n\
         foreground = \"{}\"\nbackground = \"{}\"\n\n[colors.selection]\ntext = \"{}\"\n\
         background = \"{}\"\n",
        header(theme, "#", ""),
        fonts.mono,
        p.text.value,
        p.ground.value,
        p.ground.value,
        p.accent.value,
    );
    for (table, cells) in [("normal", regular), ("bright", bright)] {
        let _ = write!(out, "\n[colors.{table}]\n");
        for (name, c) in ANSI_NAMES.iter().zip(cells) {
            let _ = writeln!(out, "{name} = \"{c}\"");
        }
    }
    out
}

fn btop(theme: &Theme) -> String {
    let p = &theme.palette;
    let mut out = header(theme, "#", "");
    out.push_str(
        "# btop draws its graphs as gradients of its own; the shell has none (§3).\n\
         # Temperature runs verified → restricted → denied because it is a state;\n\
         # every other graph is the flat accent.\n",
    );
    let flat = [
        ("main_bg", p.ground.value),
        ("main_fg", p.text.value),
        ("title", p.text.value),
        ("hi_fg", p.accent.value),
        ("selected_bg", p.accent.value),
        ("selected_fg", p.ground.value),
        ("inactive_fg", p.text_muted.value),
        ("graph_text", p.text_muted.value),
        ("meter_bg", p.separator.value),
        ("proc_misc", p.accent.value),
        ("cpu_box", p.separator.value),
        ("mem_box", p.separator.value),
        ("net_box", p.separator.value),
        ("proc_box", p.separator.value),
        ("div_line", p.separator.value),
    ];
    for (key, c) in flat {
        let _ = writeln!(out, "theme[{key}]=\"{c}\"");
    }
    let gradients = [
        (
            "temp",
            [p.verified.value, p.restricted.value, p.denied.value],
        ),
        ("cpu", [p.accent.value; 3]),
        ("free", [p.accent.value; 3]),
        ("cached", [p.accent.value; 3]),
        ("available", [p.accent.value; 3]),
        ("used", [p.accent.value; 3]),
        ("download", [p.accent.value; 3]),
        ("upload", [p.accent.value; 3]),
        ("process", [p.accent.value; 3]),
    ];
    for (key, [start, mid, end]) in gradients {
        let _ = writeln!(out, "theme[{key}_start]=\"{start}\"");
        let _ = writeln!(out, "theme[{key}_mid]=\"{mid}\"");
        let _ = writeln!(out, "theme[{key}_end]=\"{end}\"");
    }
    out
}

/// Variables only: the shipped `hyprlock.conf` sources this fragment and draws
/// its own `background`, `input-field` and `label` blocks from `$ground` …
/// `$denied` and `$font`, so a block here would be drawn twice.
fn hyprlock(theme: &Theme, fonts: &Fonts) -> String {
    let mut out = header(theme, "#", "");
    for (name, token) in theme.palette.tokens() {
        let _ = writeln!(out, "${name:<10} = rgb({})", token.value.bare());
    }
    let _ = writeln!(out, "$font       = {}", fonts.sans);
    let _ = writeln!(out, "$radius     = {}", theme.geometry.radius_px);
    out
}

fn swayosd(theme: &Theme, fonts: &Fonts) -> String {
    let g = &theme.geometry;
    format!(
        "{}{}window#osd {{\n    background-color: @panel;\n    border: {}px solid @separator;\n    \
         border-radius: {}px;\n    color: @text;\n    font-family: \"{}\", sans-serif;\n}}\n\
         image, label {{\n    color: @text;\n}}\nprogressbar {{\n    border-radius: {}px;\n}}\n\
         trough {{\n    background-color: @separator;\n}}\nprogress {{\n    background-color: @accent;\n}}\n",
        header(theme, "/*", " */"),
        define_colors(theme),
        g.separator_px,
        g.radius_px,
        fonts.sans,
        g.radius_px
    )
}

fn nvim(theme: &Theme) -> String {
    let p = &theme.palette;
    let [_, bright] = ansi(theme);
    let (magenta, cyan) = (bright[5], bright[6]);
    // The shipped init.lua `dofile`s this and hands every entry of the returned
    // table to nvim_set_hl, so the table holds highlight groups and nothing else;
    // the variant is set as a statement before the return.
    let mut out = format!(
        "{}-- A table of highlight groups for nvim_set_hl; dofile'd by the WardOS init.lua\n\
         -- at start and on SIGUSR1.\nvim.o.background = \"{}\"\n\nreturn {{\n",
        header(theme, "--", ""),
        theme.meta.variant
    );
    let fg_bg =
        |g: &str, fg: Color, bg: Color| format!("  {g} = {{ fg = \"{fg}\", bg = \"{bg}\" }},\n");
    let fg = |g: &str, c: Color| format!("  {g} = {{ fg = \"{c}\" }},\n");
    let bg = |g: &str, c: Color| format!("  {g} = {{ bg = \"{c}\" }},\n");
    let groups = [
        fg_bg("Normal", p.text.value, p.ground.value),
        fg_bg("NormalFloat", p.text.value, p.panel.value),
        fg("FloatBorder", p.separator.value),
        format!(
            "  Comment = {{ fg = \"{}\", italic = true }},\n",
            p.text_muted.value
        ),
        fg("Constant", p.restricted.value),
        fg("String", p.verified.value),
        fg("Identifier", p.text.value),
        fg("Function", p.accent.value),
        fg("Statement", p.accent.value),
        fg("Keyword", magenta),
        fg("Type", cyan),
        fg("Special", p.accent.value),
        fg("Error", p.denied.value),
        format!(
            "  Todo = {{ fg = \"{}\", bold = true }},\n",
            p.restricted.value
        ),
        fg("LineNr", p.text_muted.value),
        fg("CursorLineNr", p.text.value),
        bg("CursorLine", p.panel.value),
        bg("Visual", p.separator.value),
        fg_bg("Search", p.ground.value, p.restricted.value),
        fg_bg("IncSearch", p.ground.value, p.accent.value),
        fg_bg("Pmenu", p.text.value, p.panel.value),
        fg_bg("PmenuSel", p.ground.value, p.accent.value),
        fg_bg("StatusLine", p.text.value, p.panel.value),
        fg_bg("StatusLineNC", p.text_muted.value, p.panel.value),
        fg("VertSplit", p.separator.value),
        fg("WinSeparator", p.separator.value),
        fg("NonText", p.separator.value),
        fg("DiagnosticError", p.denied.value),
        fg("DiagnosticWarn", p.restricted.value),
        fg("DiagnosticInfo", p.accent.value),
        fg("DiagnosticHint", p.text_muted.value),
        fg("DiffAdd", p.verified.value),
        fg("DiffChange", p.restricted.value),
        fg("DiffDelete", p.denied.value),
        fg("GitSignsAdd", p.verified.value),
        fg("GitSignsChange", p.restricted.value),
        fg("GitSignsDelete", p.denied.value),
    ];
    for g in groups {
        out.push_str(&g);
    }
    out.push_str("}\n");
    out
}

fn chromium(theme: &Theme) -> String {
    format!(
        "{{\"theme_color\": \"{}\", \"variant\": \"{}\"}}\n",
        theme.palette.panel.value, theme.meta.variant
    )
}

fn gtk(theme: &Theme) -> String {
    let p = &theme.palette;
    // The nine tokens by name, then the libadwaita names they map onto.
    let mut out = header(theme, "/*", " */");
    out.push_str(&define_colors(theme));
    let pairs = [
        ("accent_color", p.accent.value),
        ("accent_bg_color", p.accent.value),
        ("accent_fg_color", p.ground.value),
        ("window_bg_color", p.ground.value),
        ("window_fg_color", p.text.value),
        ("view_bg_color", p.panel.value),
        ("view_fg_color", p.text.value),
        ("headerbar_bg_color", p.panel.value),
        ("headerbar_fg_color", p.text.value),
        ("headerbar_border_color", p.separator.value),
        ("headerbar_backdrop_color", p.ground.value),
        ("headerbar_shade_color", p.separator.value),
        ("card_bg_color", p.panel.value),
        ("card_fg_color", p.text.value),
        ("dialog_bg_color", p.panel.value),
        ("dialog_fg_color", p.text.value),
        ("popover_bg_color", p.panel.value),
        ("popover_fg_color", p.text.value),
        ("sidebar_bg_color", p.panel.value),
        ("sidebar_fg_color", p.text.value),
        ("sidebar_backdrop_color", p.ground.value),
        ("sidebar_border_color", p.separator.value),
        ("borders", p.separator.value),
        ("success_color", p.verified.value),
        ("success_bg_color", p.verified.value),
        ("success_fg_color", p.ground.value),
        ("warning_color", p.restricted.value),
        ("warning_bg_color", p.restricted.value),
        ("warning_fg_color", p.ground.value),
        ("error_color", p.denied.value),
        ("error_bg_color", p.denied.value),
        ("error_fg_color", p.ground.value),
        ("destructive_color", p.denied.value),
        ("destructive_bg_color", p.denied.value),
        ("destructive_fg_color", p.ground.value),
    ];
    for (name, c) in pairs {
        let _ = writeln!(out, "@define-color {name} {c};");
    }
    out
}

fn colors_env(theme: &Theme, fonts: &Fonts) -> String {
    let mut out = header(theme, "#", "");
    out.push_str("# Every value is double-quoted so the file sources in bash as it is.\n");
    let q = |k: &str, v: &str| format!("{k}=\"{v}\"\n");
    out.push_str(&q("WARDOS_THEME_ID", &theme.meta.id));
    out.push_str(&q("WARDOS_THEME_NAME", &theme.meta.name));
    out.push_str(&q("WARDOS_VARIANT", &theme.meta.variant.to_string()));
    for (name, token) in theme.palette.tokens() {
        out.push_str(&q(
            &format!("WARDOS_{}", name.to_uppercase()),
            &token.value.hex(),
        ));
    }
    out.push_str(&q("WARDOS_FONT_SANS", &fonts.sans));
    out.push_str(&q("WARDOS_FONT_MONO", &fonts.mono));
    out.push_str(&q(
        "WARDOS_RADIUS_PX",
        &theme.geometry.radius_px.to_string(),
    ));
    out
}
