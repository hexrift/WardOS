#!/usr/bin/env bash
# The component configurations (docs/desktop.md §Layout `config/`, §Keys, the Hyprland
# tree, the units). Static checks, no component is started:
#   - every *.jsonc under desktop/config parses as strict JSON (waybar and fastfetch
#     accept comments, but strict JSON keeps the files machine-checkable);
#   - every Hyprland bind line parses, its dispatcher is known, and an exec target's
#     first word is a $variable defined in the tree, a wardos-* command named in
#     docs/desktop.md, or a program in the allowlist below;
#   - every key of docs/desktop.md §Keys has a bind, and no two binds share MODS+KEY;
#   - every `source =` names a file in the tree (the theme fragment excepted);
#   - every desktop/config/<dir> is named in docs/desktop.md §Layout;
#   - bash configs pass `bash -n`, the profile.d script passes shellcheck;
#   - systemd units carry the keys they need (`systemd-analyze verify` needs a running
#     manager and a bus, so the check is structural);
#   - the waybar bar lists the seven trust segments of design-language §6 in order,
#     including the daemon connection-state segment (#138 item 5), and its stylesheet
#     knows every state class the ward-shell JSON supplies.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

root=$WARDOS_ROOT
docs=$root/../docs/desktop.md

# Programs a bind or exec-once may start directly. Everything else goes through a
# wardos-* command so it has a menu entry and a test (docs/desktop.md §Commands).
exec_allowlist="waybar mako hypridle systemctl wl-paste swayosd-client playerctl cliphist pkill ward hyprctl loginctl wl-copy"

# --- JSON ---------------------------------------------------------------------
while IFS= read -r f; do
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$f" || fail "$f is not strict JSON"
done < <(find "$root/config" -name '*.jsonc' -o -name '*.json' | sort)

# --- Hyprland: binds, keys, sources -------------------------------------------
python3 - "$root/hyprland" "$docs" "$exec_allowlist" <<'PY' || fail "hyprland checks failed"
import re, sys, pathlib
tree, docs, allow = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]).read_text(), set(sys.argv[3].split())
confs = sorted(tree.glob("*.conf"))
text = "\n".join(p.read_text() for p in confs)
variables = set(re.findall(r"^\$(\w+)\s*=", text, re.M))
commands = set(re.findall(r"`(wardos-[a-z0-9-]+)", docs))
dispatchers = {"exec", "workspace", "movetoworkspace", "killactive", "fullscreen", "togglefloating",
               "pseudo", "togglesplit", "layoutmsg", "movefocus", "movewindow", "resizeactive", "resizewindow",
               "exit", "togglespecialworkspace", "movetoworkspacesilent", "centerwindow", "pin",
               "swapwindow", "cyclenext", "focusmonitor", "movecurrentworkspacetomonitor"}
errors = []

def norm_mods(s):
    mods = set()
    for m in s.replace("$mod", "SUPER").split():
        mods.add({"SUPER": "super", "ALT": "alt", "CTRL": "ctrl", "CONTROL": "ctrl", "SHIFT": "shift"}.get(m.upper(), m.lower()))
    return frozenset(mods)

def check_first_word(cmd, where):
    first = cmd.strip().split()[0]
    if first.startswith("$"):
        if first[1:] not in variables:
            errors.append(f"{where}: undefined variable {first}")
    elif first.startswith("wardos-"):
        if first not in commands:
            errors.append(f"{where}: {first} is not a command in docs/desktop.md")
    elif first not in allow:
        errors.append(f"{where}: {first} is not a wardos-* command, a $variable or allowlisted")

seen = {}
bind_re = re.compile(r"^(bind[a-z]*)\s*=\s*([^,]*),\s*([^,]+),\s*([a-z]+)\s*(?:,\s*(.*))?$")
for path in confs:
    for n, line in enumerate(path.read_text().splitlines(), 1):
        where = f"{path.name}:{n}"
        s = line.strip()
        if s.startswith("bind"):
            m = bind_re.match(s)
            if not m:
                errors.append(f"{where}: unparsable bind: {s}"); continue
            flags, mods, key, dispatcher, args = m.groups()
            if dispatcher not in dispatchers:
                errors.append(f"{where}: unknown dispatcher {dispatcher}"); continue
            if dispatcher == "exec":
                if not args: errors.append(f"{where}: exec without a command"); continue
                check_first_word(args, where)
            combo = (norm_mods(mods), key.strip().lower())
            if combo in seen:
                errors.append(f"{where}: {mods.strip()} + {key.strip()} already bound at {seen[combo]}")
            seen[combo] = where
        elif s.startswith("exec"):
            check_first_word(s.split("=", 1)[1], where)
        elif s.startswith("source"):
            target = s.split("=", 1)[1].strip()
            if "wardos/theme/current" in target: continue
            rel = target.replace("~/.config/hypr/", "").replace("./", "")
            if not (tree / rel).exists():
                errors.append(f"{where}: sourced file {target} is not in the tree")

# Every key of docs/desktop.md §Keys: backticked spans of the first column. A span
# without `+` inherits the modifiers of the span before it (`Super + Ctrl + N` / `I`).
keys = docs.split("## Keys", 1)[1].split("\n## ", 1)[0]
keynames = {"/": "slash", "[": "bracketleft", "]": "bracketright", "return": "return", "scroll": "scroll"}
wanted, mods = [], frozenset()
for row in keys.splitlines():
    if not row.startswith("| `"): continue
    for span in re.findall(r"`([^`]+)`", row.split("|")[1]):
        if span.startswith("XF86"):
            wanted += [(frozenset(), k) for k in ("xf86audioraisevolume", "xf86audiolowervolume", "xf86audiomute",
                       "xf86audiomicmute", "xf86monbrightnessup", "xf86monbrightnessdown",
                       "xf86audioplay", "xf86audionext", "xf86audioprev")]
            continue
        parts = [p.strip() for p in span.split("+")]
        if len(parts) > 1:
            mods = norm_mods(" ".join(parts[:-1]))
        key = parts[-1].lower()
        key = keynames.get(key, key)
        if key == "scroll":
            wanted += [(mods, "mouse_down"), (mods, "mouse_up")]
        elif key == "arrows":
            wanted += [(mods, k) for k in ("left", "down", "up", "right")]
        else:
            wanted.append((mods, key))
for combo in wanted:
    if combo not in seen:
        errors.append(f"docs/desktop.md §Keys: no bind for {'+'.join(sorted(combo[0])) or 'none'} + {combo[1]}")

# Every bind that runs something has a description line above it for wardos-keys.
for path in confs:
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        if line.startswith("bind") and (i == 0 or not lines[i - 1].startswith("#")):
            errors.append(f"{path.name}:{i + 1}: bind without a '# description' line above it")

print("\n".join(errors), file=sys.stderr)
sys.exit(1 if errors else 0)
PY

# hyprland.conf sources every sibling and the theme fragment last.
for f in envs monitors input looknfeel windows autostart bindings; do
  grep -q "^source = ./$f.conf" "$root/hyprland/hyprland.conf" || fail "hyprland.conf does not source $f.conf"
done
[[ $(grep '^source' "$root/hyprland/hyprland.conf" | tail -1) == *wardos/theme/current/hyprland.conf* ]] \
  || fail "the theme fragment must be sourced last"
grep -q 'rgb(' "$root/hyprland/looknfeel.conf" && fail "looknfeel.conf carries colour literals; they come from the theme"

# --- config directories are documented ----------------------------------------
layout=$(sed -n '/^## Layout/,/^## /p' "$docs")
for d in "$root"/config/*/; do
  name=$(basename "$d")
  grep -qw "$name" <<<"$layout" || fail "desktop/config/$name is not named in docs/desktop.md §Layout"
done

# --- every component includes its theme fragment ------------------------------
assert_fragment() { grep -q "$2" "$root/config/$1" || fail "config/$1 does not include its theme fragment ($2)"; }
assert_fragment waybar/style.css '@import "../wardos/theme/current/waybar.css"'
assert_fragment mako/config 'include=~/.config/wardos/theme/current/mako.conf'
# mako takes include= only in the global section: after a [criteria] it is "Failed to
# parse option" and mako refuses the whole config (no notification daemon at login).
include_at=$(grep -n '^include=' "$root/config/mako/config" | head -n 1 | cut -d: -f1)
section_at=$(grep -n '^\[' "$root/config/mako/config" | head -n 1 | cut -d: -f1)
[[ -n $include_at && -n $section_at && $include_at -lt $section_at ]] ||
  fail "config/mako/config: include= (line ${include_at:-none}) must come before the first [criteria] (line ${section_at:-none})"
assert_fragment fuzzel/fuzzel.ini 'include=~/.config/wardos/theme/current/fuzzel.ini'
assert_fragment foot/foot.ini 'include=~/.config/wardos/theme/current/foot.ini'
assert_fragment alacritty/alacritty.toml 'import = \["~/.config/wardos/theme/current/alacritty.toml"\]'
assert_fragment btop/btop.conf 'color_theme = "wardos"'
assert_fragment hyprlock/hyprlock.conf 'source = ~/.config/wardos/theme/current/hyprlock.conf'
assert_fragment nvim/init.lua 'wardos/theme/current/nvim.lua'
assert_fragment gtk/gtk.css '@import url("../wardos/theme/current/gtk.css")'
grep -q 'wardos/theme/current/swayosd.css' "$root/systemd/user/swayosd.service" || fail "swayosd.service does not use the theme style"

# --- waybar: the trust bar ----------------------------------------------------
python3 - "$root/config/waybar/config.jsonc" <<'PY' || fail "waybar config is not the trust bar"
import json, sys
c = json.load(open(sys.argv[1]))
want = ["custom/ward-mark", "custom/ward-project", "custom/ward-agent", "custom/ward-network", "custom/ward-grants", "custom/ward-tamperward", "custom/ward-verify", "custom/ward-daemon"]
assert c["modules-left"] == want, c["modules-left"]
# Network keeps the read-only authority panel; grants opens the focused revoke picker (#317).
assert c["custom/ward-network"]["on-click"] == "foot --app-id ward-authority -e sh -c 'ward-shell authority-panel; read -r _'", c["custom/ward-network"]["on-click"]
assert c["custom/ward-grants"]["on-click"] == "wardos-grants", c["custom/ward-grants"]["on-click"]
assert c["modules-center"] == ["hyprland/workspaces"]
# #99: a power cell closes the right group, after the clock, so a working lock / suspend /
# shut down path is visible in the bar and not only behind Super + Shift + Escape. It opens
# wardos-power's own menu (its confirmations and actions unchanged) and its tooltip names
# the key and the menu path.
assert c["modules-right"][0] == "custom/ward-update" and c["modules-right"][-2:] == ["clock", "custom/ward-power"], c["modules-right"]
power = c["custom/ward-power"]
assert power["on-click"] == "wardos-power menu", power["on-click"]
assert power["format"] == "POWER", power["format"]
assert "Super + Shift + Escape" in power["tooltip-format"] and "SYSTEM" in power["tooltip-format"], power["tooltip-format"]
assert "exec" not in power, "the power cell is static text, no process behind it"
# #99: the workspace labels read as numbered workspaces (`1 code`, `2 agent`, `3 web`, a
# free one as its number alone), never as three app names to click: the number is the
# Super + 1/2/3 key, the word is the Hyprland defaultName of looknfeel.conf.
ws = c["hyprland/workspaces"]
assert ws["format"] == "{id} {icon}", ws["format"]
assert ws["format-icons"] == {"code": "code", "agent": "agent", "web": "web", "default": ""}, ws["format-icons"]
assert ws["persistent-workspaces"] == {"1": [], "2": [], "3": []}
for name in want[1:]:
    m = c[name]
    assert m["exec"] == f"ward-shell bar --waybar --segment {name.split('/ward-')[1]} --follow", m["exec"]
    assert m["return-type"] == "json" and m["restart-interval"] == 5
    # network opens the authority panel and grants opens wardos-grants (asserted above);
    # the verify segment opens its own panel; every other left segment opens the session panel.
    if name in ("custom/ward-network", "custom/ward-grants"):
        continue
    panel = "verify-panel" if name == "custom/ward-verify" else "session"
    assert m["on-click"] == f"foot --app-id ward-session -e sh -c 'ward-shell {panel}; read -r _'", m["on-click"]
assert c["custom/ward-update"]["interval"] >= 3600
for m in ("cpu", "memory", "battery", "network", "pulseaudio", "bluetooth"):
    assert c[m].get("interval", 5) >= 5, m
PY
for cls in working waiting blocked verifying finished verified restricted denied unknown; do
  grep -q "\.$cls\b" "$root/config/waybar/style.css" || fail "waybar/style.css has no .$cls rule"
done
# The power cell is a cell like the others (padded, in the muted system group) and, being
# the last one, the cell without a right border (#99).
python3 - "$root/config/waybar/style.css" <<'PY' || fail "waybar/style.css: the power cell is not a cell, or does not close the bar"
import re, sys
css = open(sys.argv[1]).read()
# The rule whose selector list names the power cell along with the clock: the cell geometry.
cells = [m for m in re.finditer(r"([^{}]*)\{([^}]*)\}", css) if "#custom-ward-power" in m.group(1) and "#clock" in m.group(1)]
assert cells, "the power cell is not in the cell list with the clock"
assert "padding: 0 8px" in cells[0].group(2) and "border-bottom: 2px solid transparent" in cells[0].group(2), cells[0].group(2)
# The rule for exactly that one selector (comments stripped), not a list it is part of.
plain = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
own = lambda sel: [m.group(2) for m in re.finditer(r"([^{}]*)\{([^}]*)\}", plain) if m.group(1).strip() == sel]
assert own("#custom-ward-power") and "border-right: none" in own("#custom-ward-power")[0], "the last cell has no right border"
assert own("#clock") and "border-right: none" not in own("#clock")[0], "the clock is no longer the last cell"
PY
grep -Eq 'gradient\(|box-shadow:[^;]*[0-9]' "$root/config/waybar/style.css" && fail "waybar/style.css: no gradients, no shadows (§3, §5)"
# The bar is 32 px tall, its cells are padded on the 8 px grid, the system group is
# words (no icon-font glyphs anywhere in a format), and battery state is a 2 px marker
# under the cell, never a colour on the text (§3, §5, §6).
python3 - "$root/config/waybar/config.jsonc" "$root/config/waybar/style.css" <<'PY' || fail "waybar polish (height, words, marker, grid)"
import json, re, sys
c = json.load(open(sys.argv[1])); css = open(sys.argv[2]).read()
assert c["height"] == 32, c["height"]
for name, m in c.items():
    if not isinstance(m, dict): continue
    for k, v in m.items():
        if k.startswith("format") and isinstance(v, str):
            assert all(ord(ch) < 0x2000 or ch in "·…" for ch in v), f"{name}.{k}: icon glyph in {v!r}"
rule = lambda sel: re.search(re.escape(sel) + r"\s*\{([^}]*)\}", css)
for sel in ("#battery.warning", "#battery.critical"):
    body = rule(sel).group(1)
    assert "border-bottom: 2px solid" in body, sel
    assert "color:" not in body.replace("border-bottom: 2px solid", ""), sel + " colours the text"
assert "padding: 0 8px" in rule("#clock").group(1) or "padding: 0 8px" in css, "cells are 8 px padded"
for m in re.finditer(r"padding:\s*([^;]+);", css):
    for px in re.findall(r"(\d+)px", m.group(1)):
        assert int(px) % 8 == 0, f"padding {m.group(1)} is off the 8 px grid"
assert "8px" in rule("tooltip label").group(1), "tooltip text sits on the grid"
PY

# --- mako: the approval layout of design-language §10 as a style ---------------
approval=$(sed -n '/^\[category=ward-approval\]/,/^\[/p' "$root/config/mako/config")
grep -q '^format=<b>%s</b>' <<<"$approval" || fail "mako ward-approval: the title is the summary, bold"
grep -q '%b' <<<"$approval" || fail "mako ward-approval: the body (target, Reason, Scope) is shown"
for action in 'Allow once' 'Allow session' 'Deny'; do
  grep -q "$action" <<<"$approval" || fail "mako ward-approval: the action '$action' is not in the layout"
done
grep -q '^anchor=center' <<<"$approval" || fail "mako ward-approval: centred"
grep -Eq '^padding=(8|16|24|32)(,(8|16|24|32))*$' <<<"$approval" || fail "mako ward-approval: padding on the 8 px grid"
grep -Eq '^(default-timeout=0|ignore-timeout=1)' <<<"$approval" || fail "mako ward-approval: waits for the answer"
grep -Eq '^(padding|margin)=' "$root/config/mako/config" | grep -Evq '^(padding|margin)=(0|8|16|24|32)(,(0|8|16|24|32))*$' && fail "mako: padding and margin on the 8 px grid"

# --- fuzzel: the command centre (§13) -------------------------------------------
fuzzel=$root/config/fuzzel/fuzzel.ini
grep -q '^prompt="WARD  "' "$fuzzel" || fail "fuzzel: the prompt is the WARD mark"
grep -q '^placeholder=Search anything' "$fuzzel" || fail "fuzzel: placeholder"
{ grep -q '^lines=28$' "$fuzzel" && grep -q '^line-height=24$' "$fuzzel"; } || fail "fuzzel: 28 lines of 24 px make the 720 px command centre"
grep -q '^width=42$' "$fuzzel" || fail "fuzzel: width 42 (about 640 px at 11 pt)"
for k in horizontal-pad vertical-pad inner-pad; do
  v=$(sed -n "s/^$k=//p" "$fuzzel")
  [[ -n $v && $((v % 8)) -eq 0 ]] || fail "fuzzel: $k=$v is off the 8 px grid"
done
grep -Eq '^(match|selection-match)=' "$fuzzel" && fail "fuzzel: match colours come from the theme fragment"

# --- hyprlock: the wallpaper under a veil, the clock, the mark -------------------
lock=$root/config/hyprlock/hyprlock.conf
for v in ground panel separator text text_muted accent verified restricted denied veil font radius wallpaper; do
  grep -q "^\\\$$v *= " "$lock" || fail "hyprlock: no fallback for \$$v before the first render"
done
grep -q '^\s*path = [$]wallpaper' "$lock" || fail "hyprlock: the background is the theme's wallpaper"
grep -q '^\s*color = [$]veil' "$lock" || fail "hyprlock: the wallpaper is veiled by the panel colour"
grep -q '^\s*color = [$]ground' "$lock" || fail "hyprlock: the ground shows when there is no wallpaper"
grep -q '^\s*outer_color = [$]accent' "$lock" || fail "hyprlock: the input's border is the accent (focus)"
grep -q '^\s*rounding = [$]radius' "$lock" || fail "hyprlock: the input's radius is the theme's"
grep -q 'WARD' "$lock" || fail "hyprlock: the WARD mark"
grep -q '^\s*blur_passes = 0' "$lock" || fail "hyprlock: no blur"
grep -E '^\s*(size|position) = ' "$lock" | tr -d ' ' | cut -d= -f2 | tr ',' '\n' | awk '$1 % 8 != 0 { exit 1 }' \
  || fail "hyprlock: sizes and positions on the 8 px grid"

# --- looknfeel: geometry (§5) and motion (§12) ------------------------------------
lnf=$root/hyprland/looknfeel.conf
for want in 'gaps_in = 4' 'gaps_out = 8' 'border_size = 1' 'rounding = 6' \
  'animation = workspaces, 1, 1.2, wardOut, slide' 'animation = layers, 1, 1.0, wardOut, fade' \
  'force_default_wallpaper = 0'; do
  grep -q "^\s*$want$" "$lnf" || fail "looknfeel.conf lacks '$want'"
done
# Hyprland's built-in wallpaper (a blue gradient) must be off, or it shows through before
# swaybg paints — the "doesn't look like what we agreed on" ground (E-09).
grep -E '^\s*animation = ' "$lnf" | grep -Ev '^\s*animation = (workspaces|layers), 1' | grep -Evq ', 0$' && fail "looknfeel.conf: only the workspace slide and the layer fade animate (§12)"
grep -Eq '^\s*(pseudotile|vfr|workspace_swipe)' "$lnf" && fail "looknfeel.conf: an option Hyprland 0.56 no longer has"

# --- window rules for the welcome terminal and the session panel ----------------
# Hyprland 0.56's legacy parser: `windowrule = match:class <regex>, <effect> <value>`;
# the v2 form is gone.
win=$root/hyprland/windows.conf
for want in 'match:class ^(wardos-welcome)$, float on' 'match:class ^(wardos-welcome)$, size 720 560' \
  'match:class ^(wardos-welcome)$, center on' 'match:class ^(ward-session)$, float on' \
  'match:class ^(ward-session)$, size 480 400'; do
  grep -qF "windowrule = $want" "$win" || fail "windows.conf lacks '$want'"
done
grep -Eq '^(windowrulev2|layerrule = [^m])' "$win" && fail "windows.conf: a rule in the form Hyprland 0.56 rejects"
# --- tool dialogs (#99): a tool opened from the bar or the menu (the audio mixer, the
# network and Bluetooth editors, the portal pickers, a wardos-* terminal that runs an
# install, an update, a setup step or About) is a floating, sized, centred window on the
# workspace it was asked for, never a tile that re-arranges the editor and never a window
# sent to another workspace. Every `float on` match therefore also places its window
# (`center on` or `move`), except a tile-only rule, and no dialog match carries a
# `workspace` effect.
for want in 'match:class ^(org.pulseaudio.pavucontrol|pavucontrol)$, size 800 560' \
  'match:class ^(nm-connection-editor|blueman-manager)$, size 800 560' \
  'match:class ^(nm-connection-editor|blueman-manager)$, center on' \
  'match:class ^(xdg-desktop-portal-gtk|xdg-desktop-portal-hyprland|hyprland-share-picker)$, size 800 560' \
  'match:class ^(wardos-(install|remove|update|setup|about|passwd))$, float on' \
  'match:class ^(wardos-(install|remove|update|setup|about|passwd))$, size 1000 700' \
  'match:class ^(wardos-(install|remove|update|setup|about|passwd))$, center on'; do
  grep -qF "windowrule = $want" "$win" || fail "windows.conf lacks '$want'"
done
python3 - "$win" <<'PY' || fail "windows.conf: a floating rule that does not place its window, or a dialog sent elsewhere"
import re, sys
rules = {}
for line in open(sys.argv[1]):
    m = re.match(r"windowrule = (match:\S+ \S+), (\S+)(?: (.*))?$", line.strip())
    if m:
        rules.setdefault(m.group(1), set()).add(m.group(2))
errors = []
for match, effects in rules.items():
    if "float" in effects and not ({"center", "move"} & effects):
        errors.append(f"{match}: floats but is not placed (center or move)")
    if "float" in effects and "workspace" in effects:
        errors.append(f"{match}: a floating dialog must open where it was asked for, not on another workspace")
    if "size" in effects and "float" not in effects:
        errors.append(f"{match}: sized but not floating")
print("\n".join(errors), file=sys.stderr)
sys.exit(1 if errors else 0)
PY

# --- emoji list: `<emoji> <name>` per line, a few hundred lines -----------------
[[ $(wc -l <"$root/config/fuzzel/emoji.txt") -ge 250 ]] || fail "emoji.txt is too short"
grep -Evq '^[^ ]+ [a-z0-9 ,-]+$' "$root/config/fuzzel/emoji.txt" && fail "emoji.txt: every line is '<emoji> <name>'"

# --- bash ---------------------------------------------------------------------
for f in bashrc aliases prompt envs profile.d-wardos.sh; do
  bash -n "$root/config/bash/$f" || fail "config/bash/$f: syntax"
done
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --severity=style --shell=bash "$root/config/bash/profile.d-wardos.sh" "$root/config/bash/bashrc" \
    "$root/config/bash/aliases" "$root/config/bash/prompt" "$root/config/bash/envs" || fail "shellcheck on config/bash"
fi
# The prompt renders without colors.env and with it.
mock git 'echo main'
out=$(bash -c "source '$root/config/bash/prompt'; wardos_prompt; printf '%s' \"\$PS1\"")
[[ $out == *' main'*'\n$ ' || $out == *' main'*'\n# ' ]] || fail "prompt without colors.env: $out"
[[ $out != *'38;2;'* ]] || fail "prompt without colors.env must not colour: $out"
mkdir -p "$XDG_CONFIG_HOME/wardos/theme/current"
printf 'WARDOS_ACCENT=#7FA1C3\nWARDOS_TEXT_MUTED=#8A8D91\n' >"$XDG_CONFIG_HOME/wardos/theme/current/colors.env"
out=$(bash -c "source '$root/config/bash/prompt'; wardos_prompt; printf '%s' \"\$PS1\"")
[[ $out == *'38;2;127;161;195'* ]] || fail "prompt does not use the accent from colors.env: $out"
# profile.d: no override marker -> sources the shipped bashrc; the marker stops it.
# (Starting the graphical session is greetd's job now, not this file's — see the greeter
# checks below and greeter.test.sh.)
out=$(bash -ic "WARDOS_CONFIG='$root/config'; source '$root/config/bash/profile.d-wardos.sh'; type wardos_prompt >/dev/null && echo loaded" 2>/dev/null)
[[ $out == loaded ]] || fail "profile.d did not load the shipped bashrc"
touch "$XDG_CONFIG_HOME/wardos/bash-override"
out=$(bash -ic "WARDOS_CONFIG='$root/config'; source '$root/config/bash/profile.d-wardos.sh'; type wardos_prompt >/dev/null 2>&1 && echo loaded || echo skipped" 2>/dev/null)
[[ $out == skipped ]] || fail "profile.d ignored the override marker"
rm "$XDG_CONFIG_HOME/wardos/bash-override"
# profile.d must NOT start a session any more: even on tty1 with no Wayland display,
# sourcing it touches neither uwsm nor Hyprland (greetd owns login).
mock uwsm
mock Hyprland
mock tty 'echo /dev/tty1'
: >"$MOCK_LOG"
bash -ic "unset WAYLAND_DISPLAY HYPRLAND_INSTANCE_SIGNATURE; WARDOS_CONFIG='$root/config'; source '$root/config/bash/profile.d-wardos.sh'" 2>/dev/null
assert_not_logged '^uwsm'
assert_not_logged '^Hyprland'

# --- systemd units ------------------------------------------------------------
unit_has() { grep -q "^$2" "$1" || fail "$(basename "$1") lacks $2"; }
for u in "$root"/systemd/user/*.service; do
  unit_has "$u" '\[Unit\]'; unit_has "$u" 'Description='; unit_has "$u" '\[Service\]'; unit_has "$u" 'ExecStart='
done
for t in "$root"/systemd/user/*.timer; do
  unit_has "$t" '\[Timer\]'; unit_has "$t" 'OnUnitActiveSec='; unit_has "$t" 'WantedBy=timers.target'
  assert_file "${t%.timer}.service"
done
unit_has "$root/systemd/user/wardos-approve.service" 'ExecStart=.*wardos-approve --watch'
unit_has "$root/systemd/user/wardos-approve.service" 'WantedBy=graphical-session.target'
unit_has "$root/systemd/user/swayosd.service" 'ExecStart=.*swayosd-server --style %h/.config/wardos/theme/current/swayosd.css'
unit_has "$root/systemd/user/wardos-battery-monitor.timer" 'OnUnitActiveSec=2min'
unit_has "$root/systemd/user/wardos-shell-worker.service" 'ExecStart=.*ward-shell worker'
unit_has "$root/systemd/user/wardos-shell-worker.service" 'WantedBy=graphical-session.target'
# The empty-workspace hint (#99) follows Hyprland's event socket for the whole session,
# like the approval listener; it is bound to the graphical session and restarted if it
# exits.
unit_has "$root/systemd/user/wardos-hint.service" 'ExecStart=.*wardos-hint --watch'
unit_has "$root/systemd/user/wardos-hint.service" 'PartOf=graphical-session.target'
unit_has "$root/systemd/user/wardos-hint.service" 'Restart=on-failure'
unit_has "$root/systemd/user/wardos-hint.service" 'WantedBy=graphical-session.target'

# --- autostart: the shared bar worker is actually started on the plain-Hyprland path ---
# (review finding 1 on #331): the systemd preset (image/install-desktop.sh) only reaches
# units under systemd --user's own graphical-session.target, i.e. the UWSM-driven path
# (`uwsm start hyprland.desktop`); a plain `Hyprland` session has no target pulling
# `[Install]`-enabled units in automatically, so every unit `waybar`/the bar depends on
# that isn't itself exec-once'd is instead started explicitly by this one
# `systemctl --user start` line, same as hyprpolkitagent/swayosd/wardos-approve/the
# battery timer already are. wardos-shell-worker.service must be named there too, and
# before the `exec-once = waybar` line, so a freshly-started session gives the worker as
# much of a head start on binding its socket as this file can give it (`relay_from_worker`'s
# own bounded connect-retry, `ward-shell` `worker::tests::a_cold_start_race_*`, is what
# actually closes the remaining race once Waybar's six segment processes exec).
autostart="$root/hyprland/autostart.conf"
start_line=$(grep '^exec-once = systemctl --user start ' "$autostart") \
  || fail "autostart.conf has no 'systemctl --user start' line"
grep -qw 'wardos-shell-worker.service' <<<"$start_line" \
  || fail "autostart.conf's systemctl start line does not start wardos-shell-worker.service: $start_line"
# The hint listener (#99) is started on the same line, for the same plain-Hyprland reason.
grep -qw 'wardos-hint.service' <<<"$start_line" \
  || fail "autostart.conf's systemctl start line does not start wardos-hint.service: $start_line"
start_line_no=$(grep -n '^exec-once = systemctl --user start ' "$autostart" | cut -d: -f1)
waybar_line_no=$(grep -n '^exec-once = waybar$' "$autostart" | cut -d: -f1)
[[ -n $waybar_line_no ]] || fail "autostart.conf has no 'exec-once = waybar' line"
(( start_line_no < waybar_line_no )) \
  || fail "autostart.conf must start wardos-shell-worker.service (and its siblings) before execing waybar"

# --- flatpaks: one id per line with a purpose ---------------------------------
grep -Ev '^#|^$' "$root/flatpaks.txt" | grep -Evq '^[a-z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_-]+)+ +# .+$' \
  && fail "flatpaks.txt: '<id>  # purpose' per line"
for id in org.signal.Signal com.spotify.Client com.onepassword.OnePassword; do
  grep -q "^$id " "$root/flatpaks.txt" || fail "flatpaks.txt lacks $id, which a key opens"
done
