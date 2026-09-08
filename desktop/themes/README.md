# Ward themes

The four official variants of [`docs/design-language.md`](../../docs/design-language.md) §3,
one TOML file each: **Ward Dark** (default), **Ward Light**, **Ward Graphite** (lower
contrast dark) and **Ward High Contrast** (WCAG AAA). They are the identity. Beside them,
per [ADR-0016](../../docs/decisions/ADR-0016-desktop-feature-set.md), ten *palette themes*
map well-known palettes onto the same nine tokens and follow the same rules: Tokyo Night,
Catppuccin Mocha and Latte, Nord, Gruvbox Dark, Everforest Dark, Kanagawa Wave, Rosé Pine,
Matte Black and Flexoki Dark.

Each file has the same tables:

| Table | What it holds |
| --- | --- |
| `meta` | Name, id, dark/light, contrast target, where the values come from; palette themes add `origin`, the palette's public name |
| `palette` | The nine tokens of §3, each with `value`, `role` and `source` |
| `tones` | Which token each colour role of the shell (`Tone` in `ward-shell-core`) maps to |
| `terminal` | The xterm-256 cell for each role, for `ward watch` |
| `geometry` | Radius, separator, grid, shadow levels (§5) |
| `motion` | Transition length, easing, the five transitions that animate (§12) |
| `typography` | The candidate sans and mono classes, decided in Phase 5 (§4) |

`source` is either the design-language section that fixes the value, `derived` with the
rule used, or `palette` for a value taken from a public palette. Ward Dark and the
neutral half of Ward Light are the design's own values; Ward Light's state colours are
"same, darker" and are derived; Ward Graphite and Ward High Contrast are named by the
design without values, so every token there is derived and marked so. The four state
colours are identical in Ward Dark and Ward Graphite on purpose: `✓ VERIFIED` is always
rendered the same way (§11).

## Palette themes

A palette theme takes ground from the palette's darkest background, panel from its
surface, separator from the next step up, text and text muted from its foreground pair,
accent from its blue or lavender (the one hue), verified from its green, restricted from
its yellow or amber, denied from its red; the header comment of each file names the
palette's own colour names used. Every token says `source = "palette"`. Tones, geometry,
motion and typography are Ward Dark's (Ward Light's for a light palette), unchanged, so
a palette changes colours and nothing else. The `[terminal]` cells are the nearest
xterm-256 cell to each token by RGB distance (`Color::nearest_xterm256` in
`desktop/theme`, checked by its tests); the official themes keep the cells the design
language fixed by eye. Matte Black is WardOS's own rendition of that near-monochrome
look, not a copy of anyone's values, and its header says so.

Rules the files encode, from §3: no gradients; no glow; state colour on the glyph or a
2 px marker, not on whole panels; never more than one red element visible at a time by
default.

## Rendering

`wardos-theme-render <id> --out <dir>` (crate `desktop/theme`, run by
`wardos-theme set`) turns one file into every component's fragment; the component
configs `include` those fragments and never carry a colour of their own. Choices the
renderer makes, so a theme author knows what a token reaches:

- The terminal palette (foot, alacritty, btop's flat graphs, Neovim's keywords and
  types) is sixteen cells from the nine tokens: black is ground/separator, red denied,
  green verified, yellow restricted, blue accent, magenta the accent's hue turned 90°
  toward red, cyan the accent's hue turned 30° toward green, white text muted/text; each
  bright cell is its regular cell lightened by 8 % (darkened on a light theme).
- Selection is the accent with ground-coloured text (fuzzel, foot, alacritty, btop,
  Neovim's `PmenuSel`): the accent *is* focus and selection (§3).
- A state colour reaches a component only as a marker: mako's border for `high`
  (restricted) and `critical` (denied), hyprlock's `$restricted`/`$denied` (its shipped
  config draws caps-lock and failure with them; the fragment is variables only, the
  blocks are the config's), libadwaita's `success`/`warning`/`error` names, Neovim's
  diagnostics and diff signs.
- Waybar, GTK and swayosd get the nine tokens as `@define-color` under their own names
  (`@ground` … `@denied`); GTK also gets the libadwaita names mapped onto them. btop's
  temperature graph runs verified → restricted → denied because temperature is a state;
  its other graphs are the flat accent (btop draws gradients of its own; the shell has
  none).
- `colors.env` carries every token as `WARDOS_<TOKEN>="#RRGGBB"` plus the id, name,
  variant, fonts and radius, double-quoted so scripts `source` it.
- `background.png` is a wallpaper drawn from the tokens for every theme (1920×1200:
  the ground, one 1 px rule in the separator tone, the WARD mark small in the lower
  left in text muted; a two-bit indexed PNG of a few kilobytes, no gradient, no
  photo). `background` names the file swaybg and hyprlock show: the first file, by
  name, of `<themes dir>/<id>/backgrounds/` when the theme ships one, else that
  `background.png`; `wardos-theme bg next` cycles the directory. The hyprlock
  fragment carries the same path as `$wallpaper` and the panel colour at 70 % as
  `$veil`, the lock screen's dimming layer.
- A theme's `backgrounds/` directory is optional and holds image files only (PNG or
  JPEG, any size; sorted by name, the first is the default). It sits beside the
  theme file as `<id>/backgrounds/` for a shipped theme and as `backgrounds/` inside
  an installed clone. A theme without one still has a wallpaper: the rendered one.
- Fonts are the theme's first candidates unless `~/.config/wardos/fonts.conf`
  (`sans=`, `mono=`, written by `wardos-font set`) or `WARDOS_FONT_SANS`/`WARDOS_FONT_MONO`
  override them.

Themes from `wardos-theme install <git-url>` are clones under
`~/.local/share/wardos/themes/<name>/` holding `<name>.toml` or `theme.toml` and an
optional `backgrounds/`; they are data, never code. `desktop/hyprland/hyprland.conf`
still carries the two Ward Dark literals the compositor needs before the first render.
