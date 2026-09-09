# WardOS experience & positioning — design brief (draft)

Status: **draft for review.** Turns the E-09 hardware data ([#99](https://github.com/hexrift/WardOS/issues/99))
and the first-boot UX feedback into a positioning decision and a prioritised set of design
changes. Not yet an ADR — the decisions here graduate into ADRs and issues once agreed.
Anchors: README (positioning), [`docs/desktop.md`](../desktop.md) (the desktop contract),
[`design-language.md`](../design-language.md) (identity), [ADR-0019](../decisions/ADR-0019-legibility-over-decoration.md)
(legibility over decoration).

---

## 1. What is WardOS for, and who is it for?

**One line:** WardOS is the workstation a software engineer uses *when they work with
autonomous coding agents* — the OS itself is the guardrail, so agents can run freely
without being trusted with the host, the credentials, the policy, or the verifier.

The differentiator is not the desktop; it is that **the machine keeps the agent inside a
boundary it cannot see past** (sandbox, egress allowlist, host-side credential broker,
disposable verifier, TamperWard). Everything a developer distribution normally sells —
looks, speed, batteries-included — WardOS still owes, but its reason to exist is agent
safety made effortless.

### Primary user
A developer who already runs Claude Code / Codex / similar every day and is uneasy about
what an autonomous agent can reach: their SSH keys, their cloud tokens, their whole home
directory, the open internet. They want to *let the agent work* — not approve every
keystroke — and trust the environment to contain it. Secondary: security-conscious teams
who want a standard, auditable agent workstation they can hand to engineers.

### Explicitly not (for now)
A general-purpose daily driver for non-developers; a server OS; a hardened appliance with
no local user. Those are distractions from the agent-workstation thesis.

### Non-negotiable constraints: minimal footprint & fast

Minimal and fast are not "nice to have" — they are hard constraints that override
convenience. A smaller image pulls faster, reads faster off a stick, updates faster over
`bootc`, and boots faster; a leaner running system has fewer services to start, fewer
things to break, and more headroom for the agent's own work. Concretely:

- **Footprint budget.** Target a compressed image well under 2 GB and a booted root under
  ~6 GB. Every package earns its place (`image/packages.txt` already carries a "why" per
  line); the default answer to "should we add this?" is *no* unless it serves the thesis
  or a common laptop's hardware. Applications come from Flathub at first boot, not the
  image.
- **No monolithic dependencies when a targeted one exists** — the `linux-firmware`
  decision below is the first example.
- **Fast is measured, not felt.** Boot budget in §4.1; runtime responsiveness (GPU accel,
  trimmed effects) in §4.4. Regressions in image size or boot time are treated as bugs.

Where minimal and reliable genuinely conflict (drivers on unknown hardware), we resolve it
with *two image variants*, not one bloated image — see §2 and §4.2.

---

## 2. How is it used? (deployment model)

WardOS already has more than one front door. The design mistake would be optimising all of
them equally. Pick a flagship, make the others honest on-ramps to it.

| Tier | What | Who it's for | Commitment | We optimise… |
|------|------|--------------|------------|--------------|
| **Try** | Live USB (raw whole-disk image, non-destructive) | Anyone evaluating; the current E-09 path | None — boots off the stick | that it *boots and shows the thesis* on real hardware, quickly |
| **Adopt** (flagship) | Installed to disk, or a VM | The primary user, daily | A machine or a VM | the *whole experience*: boot, drivers, onboarding, discoverability, delight |
| **Layer** | `ward` binaries on an existing Linux (no desktop) | Developers who won't switch OS | Minimal | that the toolchain is correct and self-contained |

**Recommendation.** Treat **Adopt (installed / VM) as the flagship** and design the felt
experience for it. The live USB is an *evaluation* mode, not the product — so we stop
letting USB-only limitations (slow reads, no persistence) shape decisions that a real
install doesn't suffer, while still making the USB boot fast enough to sell the idea. The
`ward` layer stays a first-class way in for the unconvinced, but it is a subset, not the
headline.

Consequence: two of the E-09 complaints ("slow boot", "laggy") are partly USB-medium
artefacts. We fix what is genuinely ours (a 60 s network stall, software rendering) and
stop treating USB read speed as a bug in WardOS.

**Open decision for the owner:** is the flagship a machine you *dedicate* to agents (spare
laptop / VM, isolation is the point) or your *daily driver* (WardOS is your main OS)? It
changes defaults below (login, power, updates). This brief assumes **daily driver, single
primary user** and notes where the dedicated-box answer differs.

---

## 3. The data (E-09, ThinkPad T480s, first hardware boot)

From [#99](https://github.com/hexrift/WardOS/issues/99), grouped by what they teach:

- **The base wasn't solid.** No Wi-Fi device (missing firmware), ~60 s boot stall on a
  network that wasn't there, console flooded with errors, `ward doctor` able to hang boot,
  Flathub failing red offline, a foot config error at startup. → *reliability first.*
  (All fixed in #98; awaiting a re-flash to confirm on hardware.)
- **The system didn't explain itself.** Clicking `agent` lands on an empty workspace;
  nothing says what it's for or what to press. Couldn't find how to log out. Expected a
  login screen, got autologin. "The UI isn't intuitive." → *onboarding + discoverability.*
- **It didn't feel fast or finished.** Perceived lag (likely software rendering + USB
  reads); stray floating windows; cosmetic startup nags. → *delight, after the base.*

Order stands (owner's call): **reliability → onboarding → discoverability → delight.**

---

## 4. Design changes

Each change lists: **why** (the data), **what** (the change), **where** (the file/area),
and **P** (priority: P0 now, P1 next, P2 later). Anything already shipped is marked ✓.

### 4.1 Boot time

Goal: **desktop visible ≤ 20 s from power on** on an installed SSD machine; **≤ 10 s**
userspace (firmware/USB read time is the medium's, not ours). Prove it with
`systemd-analyze` on hardware, not by feel.

- ✓ **Kill the no-network stall.** Masked `NetworkManager-wait-online` (#98) — was ~60 s
  with no Wi-Fi. **P0.**
- **Measure before tuning.** Add boot timing to `ward doctor` and print
  `systemd-analyze blame`/`critical-chain` in the first-boot report so every boot is
  self-diagnosing. **P0.** *(needs the E-09 numbers to target the real offenders.)*
- **Move first-boot work off the critical path.** `wardos-firstboot` (ward doctor) and
  `wardos-flathub` should run *after* the desktop is up (a `wardos-firstboot.timer` at
  `OnBootSec`, or ordered `After=graphical.target`), so the user sees the desktop first
  and setup finishes behind it. **P1.** (`image/rootfs/.../*.service`)
- **`hostonly` initramfs for installed systems.** A generic initramfs loads every driver;
  a host-only one (set at install / first `bootc` deploy) is smaller and faster. Keep the
  generic one for the live USB (unknown hardware). **P1.** (`image/Containerfile`, dracut conf)
- **Trim the plymouth→greeter→session handoff.** Confirm the splash never *blocks* on a
  slow unit and that autologin starts the compositor the instant `graphical.target` is
  reached. **P1.** (`image/`, `desktop/systemd/` autologin drop-in)
- **Two image variants, minimal by default.** The **flagship** image ships a *curated
  firmware subset* (§4.2) and no full `linux-firmware`; a **`live`/`try`** image (and
  optionally a laptop-broad build) keeps full firmware for booting unknown hardware off a
  stick. A VM install needs no firmware at all. This is how we keep the default minimal
  without stranding an evaluator's Wi-Fi. **P1.** (`image/Containerfile`, a build arg)

### 4.2 Drivers & hardware

Goal: **on mainstream laptop hardware, everything works on first boot** — Wi-Fi,
Bluetooth, GPU acceleration, audio, touchpad gestures, backlight/keys, suspend, fingerprint.

- ✓ **Firmware exists at all** — added `linux-firmware` (#98) so the T480s had Wi-Fi;
  QEMU never needed it, hardware does. But the full package is ~400 MB and violates the
  footprint constraint. **P0 done; superseded by the next item.**
- **Replace the monolith with a curated firmware subset (minimal).** Fedora splits
  firmware into per-vendor subpackages; the flagship image should install only what common
  laptops need — e.g. Intel Wi-Fi (`iwlwifi-mvm-firmware`), Intel/AMD GPU
  (`intel-gpu-firmware`, `amd-gpu-firmware`), common Wi-Fi/BT (`realtek-firmware`,
  `mediatek-firmware`/`mt7xxx-firmware`, `atheros-firmware`, `brcmfmac-firmware`) — cutting
  hundreds of MB while keeping mainstream hardware working. Exact set proven by
  `check-packages` on Fedora 44 and by a re-flash on the T480s **before** dropping the
  monolith, so we never regress the Wi-Fi we just fixed. Unknown hardware is served by the
  full-firmware `live` variant (§4.1), not by bloating the default. **P1.**
  (`image/packages.txt`, `image/Containerfile` build arg)
- **GPU acceleration must be real, not llvmpipe.** The perceived lag is very likely
  software rendering. Verify with `hyprctl systeminfo`; ensure the userspace stack is
  present per vendor: Intel (`intel-media-driver` for VAAPI), AMD (`mesa-va-drivers`),
  and a documented path for NVIDIA. Add a `ward doctor` probe that flags "no hardware
  renderer" loudly. **P0.** (`image/packages.txt`, `crates/ward-daemon/src/doctor.rs`)
- **Suspend/resume, lid, backlight, function keys, touchpad** — enumerate on the T480s and
  add a hardware checklist to the E-09 record; fix the gaps (most are firmware + the
  right daemons, several already shipped: `power-profiles-daemon`, `brightnessctl`,
  `upower`, libinput via Hyprland). **P1.**
- **Fingerprint / FIDO2 login** packages ship (`fprintd`, `pam-u2f`); wire them into the
  greeter decision (§4.3) so they're actually reachable. **P2.**

### 4.3 UX / UI intuitiveness

This is the heart of "the UI isn't intuitive." Principle from ADR-0019: **the system must
explain itself where the user is looking; nothing important should require prior
knowledge of a keybinding.**

- **Every empty space teaches.** When a WardOS workspace (`code`/`agent`/`web`) is empty,
  draw a centred hint card: what this workspace is for and the *one* thing to press
  (e.g. on `agent`: "Start a sandboxed agent → press **Super + Space**, or type
  `ward claude` in a terminal (**Super + Return**)"). This is the single highest-leverage
  fix from the screenshot. **P1.** (a small layer-shell/`swaybg`-style overlay, or a
  first-window placeholder per workspace)
- **The agent workspace opens *doing something*.** On first entry with nothing running,
  offer "Start Claude / Start Codex" front and centre rather than a blank room. **P1.**
- **A visible entry point.** Not everyone will guess `Super + Space`. Add a persistent,
  clickable affordance on the trust bar — a "◆ Ward" / launcher button that opens the
  command centre — and a help overlay on `Super + /` (and a `?` on the bar). Tooltips on
  every bar module (ADR-0019 legibility). **P1.** (`desktop/config/waybar/`, `desktop/bin/wardos-menu`)
- **Onboarding that *feels* like a first run.** The pieces exist (`wardos-first-run` →
  `wardos-welcome`: theme → key → project → agent) but arrive as separate fuzzel menus and
  can be missed. Make it one coherent, unskippable-until-done, graphical walkthrough that:
  (1) never drops the user into a raw TUI; (2) covers **Wi-Fi first** (you can't sign into
  an agent offline); (3) sets the **login preference** (§ below); (4) ends by *starting the
  first agent* so the payoff is immediate. Keep it keyboard-navigable but pointer-friendly.
  **P1.** (`desktop/bin/wardos-welcome`, `wardos-first-run`)
- **Log out / shut down must be obvious.** Power actions exist (`wardos-power`,
  `Super + Shift + Escape`) but the user couldn't find them. Add a visible power/session
  control on the bar (click → the same menu) and show it in the keys overlay. **P1.**
  (`desktop/config/waybar/`, `desktop/bin/wardos-power`)
- **Fix the mixed metaphor in the bar.** `code`/`agent`/`web` read as clickable apps but
  are empty workspaces. Decide: either clicking one *launches its default* (agent →
  Start Claude, web → browser, code → terminal+editor) or restyle them unmistakably as
  workspace pills. Recommend **make them act** — click does the obvious thing. **P1.**
- **Stray floating windows.** `pavucontrol` and friends stranded on the wrong workspace →
  review `windows.conf` rules so tool dialogs float centred on the *current* workspace and
  don't persist across switches. **P2.** (`desktop/hyprland/windows.conf`)

**Login vs autologin (needs the owner's decision).**
- *Daily driver:* offer a **greeter** (username/password, with fingerprint/FIDO2 optional)
  — it matches expectation and is the honest posture for a machine with real credentials.
  Autologin becomes an opt-in for a dedicated single-user box.
- *Dedicated agent box:* keep **autologin** (fast, kiosk-like), physical security assumed.
- Proposal: ship a greeter (e.g. a minimal `greetd`/`tuigreet`, themed) and let the
  first-run walkthrough set the preference; default to greeter for the flagship. **P1.**

### 4.4 Delight

Only after the base is solid. Delight is *coherence + speed + the wow of watching an agent
work safely* — not decoration (ADR-0019).

- **Smoothness over effects.** With real GPU accel (§4.2), keep tasteful Hyprland
  animations; if a machine is on software rendering, auto-reduce effects rather than lag.
  A `wardos-toggle performance` and an automatic fallback. **P2.**
- **The hero moment.** The delightful thing unique to WardOS is *seeing the agent work
  inside the boundary*: the trust bar going green→amber, the observer, an approval answered
  from a notification. The onboarding should end on this, and the README GIF already tells
  this story — make the live experience match it. **P1.**
- **Coherent, quiet defaults.** One splash → desktop with no console spam (✓ #98), a single
  theme that looks intentional (Ward Dark ✓), notifications that inform without nagging
  (drop the cosmetic startup nags, #99). **P1–P2.**
- **Respect the user's time.** Fast boot, no modal walls, sensible keybindings shown once
  and recallable (`Super + K` ✓, plus the `Super + /` overlay above). **P1.**

---

## 5. How we'll know it worked (success signals)

- **Footprint:** flagship compressed image < 2 GB, booted root < ~6 GB; `check-packages`
  clean; every package still justified by a one-line "why". Image size tracked per build
  and a growth treated as a regression.
- **Boot:** `systemd-analyze` userspace ≤ 10 s on an SSD install; no unit > 5 s on the
  critical chain; desktop visible ≤ 20 s from power.
- **Drivers:** on the T480s (and one AMD + one NVIDIA reference machine), Wi-Fi,
  Bluetooth, GPU accel (`hyprctl systeminfo` shows a real renderer), audio, suspend,
  backlight all work first boot, recorded in the E-09 checklist.
- **Intuitiveness:** a new user who has never seen WardOS can, without docs, get online,
  sign into an agent, and start it — because the screen told them how at each step.
- **Delight:** the first session ends with the user having watched an agent run inside the
  trust boundary, and nothing on screen looked broken or unexplained.

---

## 6. Decisions needed from the owner

1. **Flagship deployment:** daily driver vs dedicated agent box (sets login/power/update
   defaults). *This brief assumes daily driver.*
2. **Login:** greeter (recommended for daily driver) vs keep autologin.
3. **Bar metaphor:** make `code`/`agent`/`web` clickable-actions (recommended) vs restyle
   as passive workspace pills.
4. **Scope of this pass:** confirm the P0/P1 set for the next PRs, or re-rank.

---

## 7. Sequenced backlog (once decisions land)

1. **P0 (reliability, mostly done):** confirm #98 on hardware; add boot-timing + GPU-renderer
   probes to `ward doctor`; ensure real GPU acceleration.
2. **P1 (minimal & fast):** curated firmware subset + full-firmware `live` variant; package
   audit against the footprint budget; move first-boot work off the critical path;
   hostonly initramfs for installs. Track image size per build.
3. **P1 (onboarding):** one coherent graphical first-run (Wi-Fi → login pref → key →
   project → start agent); greeter; ending on the agent running.
4. **P1 (discoverability):** empty-workspace hint cards; bar launcher + power control +
   tooltips; `Super + /` help; make the workspace labels act.
5. **P2 (delight + polish):** performance auto-fallback; window-rule cleanup; slim VM image;
   fingerprint/FIDO2 login; drop cosmetic nags.

Each becomes an ADR (for the decisions) and issues (for the work), tracked against
[#99](https://github.com/hexrift/WardOS/issues/99).
