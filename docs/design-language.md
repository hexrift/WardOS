# WardOS Design Language

Status: living document; the project's phase is in docs/status.toml and the README.
Decision record: [ADR-0007](decisions/ADR-0007-desktop-and-shell.md).

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

An approval separates what the agent claims from what Ward will allow (ADR-0019,
decision 2). Three blocks, in this order, and nothing the agent wrote ever looks like
something Ward derived:

```text
Claude requests

DESTINATION
api.github.com

REQUESTED BY AGENT
WebFetch https://api.github.com/repos/hexrift/WardOS/issues/381

WARD WILL ALLOW
Network      reachable · restricted (dev)
Method       GET
Credential   GitHub · contents:read, issues:read
Repository   hexrift/WardOS
Lifetime     once (y) · session (s)

Allow once  y      Allow session  s      Deny  n
```

*Destination* is the target as the daemon sanitised it: the host of a URL, the path as
the sandbox sees it, the program of a command; in the mono face (§4). *Requested by
agent* is the agent's request verbatim, labelled as the agent's words and never more
prominent than the block under it; its markup is escaped, so it cannot dress itself up
as a row. *Ward will allow* is what the policy and the credential rules grant if the
user says yes, derived by the daemon from the session's manifest and never from the
agent's text: the proxy's own verdict on the destination (`reachable · restricted
(dev)`, `refused · host is not on the session allowlist`), the method (`GET`, `read`,
`write`, `exec`; a write to a TamperWard-protected path or a read-only worktree says
`refused` here, whatever the answer), the credential the proxy injects with its scope
(or `none`, or the rule and why nothing is granted: `not granted (--grant github)`),
the repository the rule scopes it to, and the lifetime, which the answer chooses. The
three actions carry their keys. Rendered by the shell as a layer-shell surface with a
single shadow level; keyboard-first (`y` / `s` / `n`). Timeout is shown as a thin
progress line, not a countdown number.

Authority that outlives an answer stays visible while it exists (decision 4): an
`allow-session` and a `--grant` credential put `GRANTS n` on the bar and turn the
network segment into `NET restricted · github+` until the session ends; the panel
behind both lists the current agent authority — filesystem, network, every temporary
grant with its scope and lifetime, and the standing denials (host files, private
network, cloud and publish credentials).

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
rendered the same way, in the same place, in the verified colour, and it is bound to
the snapshot it judged (ADR-0019): the bar's `VERIFY` segment has five states and shows
exactly one, decided by content, not by time or heuristics. The shell digests the
worktree with the snapshot crate's incremental hash cache and compares the id with the
candidate the last `VerificationPassed` record names; green disappears the moment the
tree differs from that candidate.

| State | Segment | Colour | Meaning |
| --- | --- | --- | --- |
| never | `VERIFY —` | muted | nothing has been verified in this session |
| verifying | `VERIFY ◐ 7c01a2b3` | accent | the trusted verifier is running on candidate `7c01…` |
| verified | `VERIFY ✓ 7c01a2b3` | verified green | candidate `7c01…` passed, and the worktree is `7c01…` byte for byte |
| stale | `VERIFY ~ STALE` | restricted amber | `7c01…` passed, but the worktree has changed since; the verdict is history |
| failed | `VERIFY ✗` | denied red | the candidate failed |

A failed verdict stays red whatever the tree does next: only a new run changes it. A
sealed log keeps its verdict; the tree can still make it stale. Clicking the segment
opens the verify panel: the verified candidate, when it was verified, the worktree's
digest now, how many manifest entries differ, TamperWard's evidence, the test counts,
and integrity (how many protected files the verifier had to restore from the entry
snapshot because the worktree's copy differed).

```text
Verify
────────────────────────
Verified candidate   7c01a2b3
Verified time        at 12:04 · 3m 12s ago
Current digest       9d3e5f10
Changes              2 entries
TamperWard           clean
Tests                184/184
Integrity            pass
```

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
daemon`, where the agent (`CLAUDE ● working`, §7 glyphs and words) and `TW ✓`/`TW ■`
appear only once the stream has said so, the verify segment is the five-state machine of
§11 (`VERIFY —` from the first frame, `◐`, `✓`, `~ STALE`, `✗`; `VerifyState` in
`trust.rs`, fed by the stream's verdict and the worktree digest the shell observes
through `Model::observe_worktree`), and a sealed log dims the state marker, the network
word, the daemon word and the agent but never a verdict; the session panel (§6) as
`Session` and `TamperWard` rows and the verify panel (§11) as `Verify` rows; the observer feed
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
`observer`, `settings`) or, with no session, one calm line saying what to do next
(`Super + Space → Start Claude`, or `ward init` then `ward claude`); its `gui` feature is where the layer-shell
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

## As built: Waybar rendering and approvals (ADR-0016)

Until E-10, Waybar draws the trust bar (§6) from `ward-shell bar --waybar`: one
custom module per segment (`project`, `agent`, `network`, `grants`, `tamperward`,
`verify`; the `WARD` mark is static), each fed by `--segment <name> --follow` so a change in the
session's stream is a new JSON line and nothing polls. The shell decides the words
and the colour roles; Waybar's stylesheet only maps the classes the JSON carries: the
six roles of §3 by their names (`dim`, `ink`, `accent`, `verified`, `restricted`,
`denied`), on the agent module the §7 state word (`working`, `waiting`,
`blocked`, `verifying`, `finished`, `idle`) and on the verify module the §11 state
word (`never`, `verifying`, `stale`, `failed`), so state colour sits on the segment's
text and nowhere else. A segment the stream has not established is the empty module,
which Waybar hides, so the bar grows as the session says more (§2: the host layer
looks the same with or without an agent) and the mark alone is a bar with no session
(`WARD`, dim); the verify module is the exception, since `VERIFY —` is a state. The
session panel (§6) is the whole-bar module's tooltip and opens on click in a terminal;
the verify panel (§11) is the verify module's tooltip and opens on its click
(`ward-shell verify-panel`). The command centre (§13) is fuzzel in dmenu mode over
`ward-shell launcher --lines`: the four sections in order, the label with its state
detail, and the command the shell chose (`ward claude` in a terminal in the worktree,
`ward verify` in one that stays open); fuzzel matches what the user types, the shell
never sees it. Approvals (§10) are real: an `ask` is held by the session daemon
(`agent-integration.md` §4.1), which derives the `WARD WILL ALLOW` block from the
manifest, the credential rules, the credentials it has granted and the protected
paths, and mako shows it as a notification in the `ward-approval` category:
`<Agent> requests`, then the three blocks as §10 draws them (`DESTINATION` in `<tt>`,
`REQUESTED BY AGENT` with the agent's words escaped, `WARD WILL ALLOW` with its five
rows), then the three actions with their keys, answered from the keyboard (`y` / `s`
/ `n`) through `wardos-approve`; the timeout is the daemon's (60 s, deny), and the
notification shows it as mako's progress line, not a number. The `Lifetime` row reads
`once (y) · session (s)` while the question is open, since the answer chooses it; the
daemon fills it in the grant. Temporary authority stays visible (§10, last
paragraph): the `network` module reads `NET restricted · github+` and a `grants`
module `GRANTS n` while an `allow-session` or a `--grant` credential is live, both
open the authority panel (`ward-shell authority-panel`) on click, and `ward session
grants` is the same list in a terminal. Not yet built: a layer-shell surface of the
shell's own for any of this, the verification display (§11), fonts (§4).

## As built: wallpapers, lock screen, bar

The wallpaper is drawn from the tokens, not chosen: `wardos-theme-render` writes a
`background.png` for every theme, 1920×1200, in three tones and nothing else, the
ground with one 1 px rule in the separator tone (64 px in from either edge, 88 px
from the bottom) and the WARD mark set small in the lower left in `text_muted`
(14 px tall: 5×7 bitmap glyphs of 2 px cells, rectangles on the 8 px grid, no
anti-aliasing). No gradient, no photo, no second composition: the same drawing
holds under every palette, so the host layer looks the same whichever theme is on
(§2), and a theme that ships its own `backgrounds/` wins over it. The file is a
two-bit indexed PNG of about 6 KB and takes milliseconds to render. The lock screen
shows the same file under a veil of the panel colour at 70 % (the ground alone
before the first render), the clock in the sans face at 96 px in the light weight,
the date under it in `text_muted`, one 320×40 input on the grid whose 1 px border
is the accent because it is the focused element (§3), the denied colour on that
border after a failure without animation, and `WARD` at 12 px at 64, 64 in the lower
left; no blur, nothing moves (§12). The bar is 32 px: every module a cell padded 8 px
either side of its text with a 1 px separator, words and never icon-font glyphs in
the system group (`VOL 40`, `WIFI 80`, `ETH`, `OFFLINE`, `BT`, `BAT 90`, `AC 90`,
`CPU 12`, `MEM 40`), state colour on the trust segments' text only and otherwise on
a 2 px marker at the foot of a cell (the active workspace's accent, a battery at
warning or critical in restricted or denied, the number staying muted), tooltips as
panels with 8 px of padding and the theme's radius. The command centre is fuzzel
with `WARD` as its prompt, 28 rows of 24 px under it in a 640×720 surface, matches
in the accent; the approval notification is a mako style for the `ward-approval`
category, the §10 layout as far as a notification allows: the title, the body (the
target on its own line, expected in the mono face through `<tt>` from
`wardos-approve`, then the `Reason` and `Scope` rows) and the three actions with
their keys as one dimmed row, because mako draws no buttons and `y` / `s` / `n`
answer. Motion in the compositor is unchanged: the 120 ms workspace slide and the
100 ms layer fade, gaps 4 and 8, 1 px borders, 6 px radius. Not yet built: the one
shadow level (§5) for the command centre and approvals, which neither fuzzel nor
mako draws.
