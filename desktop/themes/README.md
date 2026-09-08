# Ward themes

The four official variants of [`docs/design-language.md`](../../docs/design-language.md) §3,
one TOML file each: **Ward Dark** (default), **Ward Light**, **Ward Graphite** (lower
contrast dark) and **Ward High Contrast** (WCAG AAA). No theme packs in 0.1.

Each file has the same tables:

| Table | What it holds |
| --- | --- |
| `meta` | Name, id, dark/light, contrast target, where the values come from |
| `palette` | The nine tokens of §3, each with `value`, `role` and `source` |
| `tones` | Which token each colour role of the shell (`Tone` in `ward-shell-core`) maps to |
| `terminal` | The xterm-256 cell for each role, for `ward watch` |
| `geometry` | Radius, separator, grid, shadow levels (§5) |
| `motion` | Transition length, easing, the five transitions that animate (§12) |
| `typography` | The candidate sans and mono classes, decided in Phase 5 (§4) |

`source` is either the design-language section that fixes the value, or
`derived` with the rule used. Ward Dark and the neutral half of Ward Light are the
design's own values; Ward Light's state colours are "same, darker" and are derived;
Ward Graphite and Ward High Contrast are named by the design without values, so
every token there is derived and marked so. The four state colours are identical in
Ward Dark and Ward Graphite on purpose: `✓ VERIFIED` is always rendered the same way
(§11).

Rules the files encode, from §3: no gradients; no glow; state colour on the glyph or
a 2 px marker, not on whole panels; never more than one red element visible at a time
by default.

The shell reads a theme by id (`ward-dark`); `desktop/hyprland/hyprland.conf` carries
the two Ward Dark values the compositor needs (ground, accent border) as literals.
