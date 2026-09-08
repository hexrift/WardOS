# WardOS Design Language

Status: Phase 0. Decision record: [ADR-0007](decisions/ADR-0007-desktop-and-shell.md).

## 1. Identity

WardOS is **not** a themed Hyprland configuration with a security icon. Its identity comes
from the desktop *understanding* agents, trust, isolation and verification, and expressing
them through layout and information hierarchy rather than through wallpapers or colour.

Five words: **Calm. Precise. Dense. Observable. Trustworthy.**

Reference mood: precision workstation, aircraft instrumentation, Braun, high-end
developer tooling. Explicitly **not**: neon green, terminal rain, shields, glowing red
alerts, robot avatars, "hacker distro" styling. Those age badly and undermine seriousness.

Identity statement:

> The operating system where autonomous agents are visible, constrained, and verifiable.

## 2. Three visual layers

```text
HOST        stable, calm, trusted          — nearly static; neutral; never shouts
WORKSPACE   project, editor, terminal      — the user's tools; conventional; dense
AGENT       dynamic, observable, constrained — the only thing that visibly "moves"
```

Everything in the shell belongs to exactly one layer. The host layer looks the same
whether or not an agent is running. The agent layer is where activity, state and
verification live.

## 3. Colour: colour means something

Restrained neutral base with **one** accent. State colours are used deliberately and
rarely so that security state stays visible.

| Role | Ward Dark | Ward Light | Meaning |
| --- | --- | --- | --- |
| Ground | near-black (`#0E0F11`) | off-white (`#F4F4F2`) | Host layer |
| Panel | graphite (`#16181B`) | light grey (`#EAEAE7`) | Surfaces |
| Separator | `#24272B` | `#D6D6D2` | Thin, 1 px |
| Text | `#D9D9D6` | `#1A1B1E` | Primary |
| Text muted | `#8A8D91` | `#6B6E73` | Secondary |
| Accent | one hue, restrained blue-grey (`#7FA1C3`) | same, darker | *Active agent*, focus, selection |
| Verified | muted green (`#6FAE8A`) | same, darker | `✓ VERIFIED`, pass |
| Restricted | amber (`#C9A24A`) | same, darker | limited network, `ask` pending |
| Denied / failed | red (`#C25A5A`) | same, darker | used sparingly, never animated |

Rules: no gradients; no glow; state colour on the glyph or a 2 px marker, not on whole
panels; never more than one red element visible at a time by default.

Official variants (few, polished): **Ward Dark**, **Ward Light**, **Ward Graphite**
(lower contrast dark), **Ward High Contrast** (WCAG AAA). No theme packs in 0.1.

## 4. Typography

Two families. A clean grotesk sans for system UI; a monospace for technical state.

```text
WARDOS                     sans
payments-api               sans
CLAUDE · LIVE              sans

cargo test                 mono
src/auth.rs                mono
exit 0                     mono
```

Never everything in monospace. Tabular numerals for durations and counts. Font choice is
decided by rendering tests in Phase 5 (candidates: Inter/Geist-class sans; JetBrains
Mono/Commit Mono-class mono), with fallbacks that ship in the image.

## 5. Surfaces and geometry

```text
radius       4–8 px
separators   1 px, low contrast
shadows      almost none (one level, for the command centre and approvals only)
density      engineer-dense, never cluttered; 8 px grid
```

## 6. The top bar: trust state, not system trivia

```text
WARD │ payments-api │ CLAUDE ● LIVE │ NET LIMITED │ TW ✓ │ 23:41
```

Left to right: host mark, current project, agent state, network state, TamperWard state,
clock. System stats (CPU, RAM, battery, Wi-Fi) exist but are demoted to a secondary group
at the far right in muted text, or to the session panel.

Clicking `CLAUDE ● LIVE` opens the session panel:

```text
Session
────────────────────────
Agent          Claude
Duration       12m 43s
Repo write     allowed
Network        restricted
Secrets        none

TamperWard
Policy         locked
Verifier       isolated
Last verify    pass
```

## 7. Agents as operators, not cartoons

```text
● CLAUDE       working
◌ CODEX        idle
▲ CLAUDE       approval required
■ CLAUDE       blocked
◐ CLAUDE       verifying
✓ CLAUDE       complete
```

States: `idle · working · waiting · blocked · verifying · finished`. Each agent may have a
small geometric glyph and a subtle accent; no avatars.

## 8. Default workspace

```text
┌─────────────────────────────────────────────────────────────┐
│ WARD   payments-api      CLAUDE ●       VERIFY ✓            │
├────────────────────────────────┬────────────────────────────┤
│                                │                            │
│            EDITOR              │       AGENT ACTIVITY       │
│                                │                            │
│                                │  READ  src/auth.rs         │
│                                │  EDIT  src/token.rs        │
│                                │  RUN   cargo test          │
│                                │  DENY  policy.toml         │
│                                │                            │
├────────────────────────────────┴────────────────────────────┤
│                       TERMINAL                              │
└─────────────────────────────────────────────────────────────┘
```

The agent activity panel is the observer in Live mode. Its rows use a fixed verb column
(`READ EDIT RUN DENY NET ASK VERIFY`) in sans and the subject in mono.

## 9. Denials: authoritative, not dramatic

```text
ACCESS DENIED

tests/security/auth.rs

Protected by TamperWard policy:
security-tests

No changes were applied.
```

Short, calm, unambiguous. The message communicates "the system handled it", never
"something catastrophic almost happened". No exclamation marks, no sirens, no emoji.
Hard denials show no override control.

## 10. Approvals

```text
Claude requests

api.github.com

Reason      Read GitHub issue #381
Scope       Network only
Duration    Current session

[Allow once]   [Allow session]   [Deny]
```

Rendered by the shell as a layer-shell surface with a single shadow level; keyboard-first
(`y` / `s` / `n`). Timeout is shown as a thin progress line, not a countdown number.

## 11. Verification: a distinct phase with its own language

```text
Agent finished
      ↓
───────────────
VERIFYING
───────────────

Entry state       locked
Candidate         captured
Trusted verifier  running

tests     184/184
policy    pass
integrity pass

✓ VERIFIED
```

`✓ VERIFIED` should become recognisable as a WardOS/TamperWard state. It is always
rendered the same way, in the same place, in the verified colour.

## 12. Motion

Transitions of 100–150 ms, linear or gentle ease-out, no springs, no bounces. Only these
transitions animate: agent starts, workspace changes, verification begins, approval
appears, agent finishes. Everything else is instant. Responsive before beautiful, and
beautiful because it is responsive.

## 13. Command centre (launcher)

```text
WARD

Search anything…

PROJECTS
tamperward
payments-api
infra

AGENTS
Start Claude
Start Codex
Resume session

SECURITY
Verify current project
Review permissions
Replay last session

SYSTEM
Terminal
Browser
Settings
```

Opened with `Super + Space`. It is a command surface over `wardd` (projects, sessions,
verification, permissions) as well as an application launcher. Latency budget: visible
< 16 ms.

## 14. Settings are semantic

```text
Agent Access

Repository             Read & Write
Internet               Restricted
Private network        Denied
Host files             Denied
SSH credentials        Ask
Cloud credentials      Denied
```

Namespaces, seccomp, cgroups and mounts are never shown. An "Advanced" view can show the
effective manifest hash and the policy layer that produced each line.

## 15. What WardOS deliberately does not copy

From any existing distribution, Omarchy included: exact bar layout, menu structure,
typography choices, theme set, launcher layout, keybinding cheat-sheet presentation,
branding mood. Good *principles* (speed, polish, keyboard-first, strong defaults) are
adopted; the visual language, interaction model and product identity are WardOS's own.

## As built: `ward watch` (Phase 3)

The first observer is a terminal UI (`ward watch`, ADR-0012), so it follows §3, §6
and §8 within what a terminal can do. Colour: the six roles (dim, ink, accent,
verified, restricted, denied) are the xterm-256 indices line mode already prints
(245, 252, 110, 108, 179, 167), the nearest cells to the Ward Dark palette; a real
theme comes with the shell. The trust bar is one row, `WARD │ session │ project │
NET mode │ CRED n granted │ OBS mode │ LIVE`, with a 1-cell separator below (§5), and
the state colour sits on the leading marker (`●` live, `■` sealed) and the state
words, never on the whole bar (§3). It carries the observer's facts rather than §6's
exact groups: no agent glyph yet (the agent's state is not in the stream today) and no
clock or TamperWard state, because the session daemon does not know them; they arrive
with the shell. Typography: §4 wants the verb column in sans and the subject in mono;
a terminal has one face, so the verb column is distinguished by its fixed width and
colour instead. Motion: none; the view redraws on a 50 ms tick, well inside §12's
budget, and nothing animates, not even the seal. The status line's counters are
§8-of-`event-model.md`'s footer, not a §6 element.

## As built: shell scaffold (Phase 5 start)

The shell's view model exists before its toolkit. `crates/ward-shell-core` derives every
surface named here from two inputs only, the session's `SessionDescription` and its
`EventRecord`s, with a colour role (`Tone`: dim, ink, accent, verified, restricted,
denied) on each element and no graphics dependency: the trust bar (§6) as segments
`session · project · agent · network · credentials · observer · TamperWard · verified ·
daemon`, where the agent (`CLAUDE ● working`, §7 glyphs and words), `TW ✓`/`TW ■` and
`VERIFYING`/`VERIFY ✓`/`VERIFY ✗` appear only once the stream has said so, and a sealed
log dims the state marker, the network word, the daemon word and the agent but never a
verdict; the session panel (§6) as `Session` and `TamperWard` rows; the observer feed
(§8), which is the `ward watch` TUI's `Model` moved here so the TUI and the shell share
one implementation of the counters and the follow/scroll state (the TUI's bar is the
same `TrustBar` with the three stream-derived segments omitted, unchanged to the byte);
the command centre (§13) with its four sections, session rows carrying §7 states, and
filtering by typed text; and the semantic settings (§14) as read-only rows (`Repository
Read & Write`, `Internet Restricted`, `Private network Denied` derived from the
manifest's own invariant, one row per credential rule, `Containers`, `Observer`, and an
`Advanced` group with the manifest hash). `desktop/shell` is the `ward-shell` binary:
a client of the session daemon like `ward watch`, it asks for the description, catches
up with the stream, and prints the surface asked for (`bar`, `session`, `launcher`,
`observer`, `settings`) or `no session`; its `gui` feature is where the layer-shell
toolkit lands after E-10 and today adds nothing but a notice. `desktop/hyprland` carries
the bindings of `architecture.md` §11 plus `Super + S` (session panel), `Super + O`
(observer toggle) and `Super + Shift + S` (permissions), the §5 geometry, and §12's
motion rule as configuration: every compositor animation off except the workspace
change (120 ms, ease-out) and a layer's appearance (approvals, 100 ms fade).
`desktop/themes` holds the four official variants as TOML with every token of §3
named and its source recorded; where this document names a variant without values
(Graphite, High Contrast, Light's state colours) the value is derived and marked so.
Not yet built: the approval surface (§10), the verification display (§11), fonts (§4),
and any pixel.
