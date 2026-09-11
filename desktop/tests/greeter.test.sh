#!/usr/bin/env bash
# WardOS login (greetd): the greeter config, its Ward Dark theme, and the post-auth
# session launcher (docs/desktop.md §Login, docs/design-language.md §2). All three ship
# under image/rootfs, so this test reads them from the checkout.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"

repo=$WARDOS_ROOT/..
greetd=$repo/image/rootfs/etc/greetd
launcher=$repo/image/rootfs/usr/libexec/wardos-session
sysusers=$repo/image/rootfs/usr/lib/sysusers.d/wardos-greeter.conf
assert_contains() { grep -Fq -- "$2" "$1" || fail "expected '$2' in $1:
$(cat "$1")"; }

# --- greetd config: greeter on VT 1, unprivileged, via the marker-gated selector --------
cfg=$greetd/config.toml
selector=$repo/desktop/bin/wardos-greetd-session
assert_file "$cfg"
assert_contains "$cfg" '[terminal]'
assert_contains "$cfg" 'vt = 1'
assert_contains "$cfg" '[default_session]'
assert_contains "$cfg" 'user = "greeter"'
# greetd runs the selector (ADR-0027), not a fixed command.
grep -Eq '^command = "wardos-greetd-session"' "$cfg" \
  || fail "greetd command must run the selector wardos-greetd-session:
$(grep '^command' "$cfg")"
# No [initial_session]: the user explicitly asked for a real login screen, not autologin.
! grep -q '\[initial_session\]' "$cfg" || fail "greetd must not auto-login (no [initial_session])"

# The selector: provisioned -> cage hosting gtkgreet (styled, handing off to wardos-session);
# unprovisioned -> the provisioning UI as a foot-hosted TUI under cage (xdg-shell; cage has no
# layer-shell, so the UI is NOT fuzzel).
assert_file "$selector"
grep -Eq 'cage -s -- gtkgreet .*-c /usr/libexec/wardos-session' "$selector" \
  || fail "the selector's greeter path must run gtkgreet in cage and hand off to wardos-session"
assert_contains "$selector" '-s /etc/greetd/wardos-greeter.css'
# The bootstrap path runs the provisioning UI inside foot under cage -s (VT recovery kept).
grep -Eq 'cage -s -- foot .* wardos-provision-ui' "$selector" \
  || fail "the selector's bootstrap path must host wardos-provision-ui in foot under cage -s"
# The provisioning UI must not be launched as a layer-shell client (fuzzel) under cage. Check
# executable lines only (a comment may still name fuzzel to explain why it is avoided).
if grep -vE '^[[:space:]]*#' "$selector" | grep -q 'fuzzel'; then
  fail "the bootstrap UI must not use fuzzel under cage (no layer-shell)"
fi
# cage has no wlr-layer-shell: the selector's gtkgreet must NOT run in layer-shell mode
# (`-l`), or it commits a 0x0 surface, cage disconnects it and greetd crash-loops the
# greeter — the E-09 flicker loop. cage fullscreens a plain gtkgreet window on its own.
# (The guard moved here from config.toml when greetd's command became the selector.)
grep -n 'gtkgreet' "$selector" | grep -Eq -- '(^| )-l( |$)' && fail "gtkgreet must not use -l under cage (cage has no layer-shell)"

# --- Ward Dark theme (docs/design-language.md §3): host-layer palette, continuous with
#     the Plymouth splash; the single accent is the violet focus ring; the mark is drawn.
css=$greetd/wardos-greeter.css
assert_file "$css"
assert_contains "$css" '#0E0F11'   # ground (same near-black as Plymouth)
assert_contains "$css" '#D9D9D6'   # primary text
assert_contains "$css" '#8E7CF0'   # accent: focus/selection
assert_contains "$css" '#C25A5A'   # denied red, for a failed login
assert_contains "$css" 'wardos-mark.svg'
assert_file "$greetd/wardos-mark.svg"
grep -q 'entry:focus' "$css" || fail "the focus state must be styled (the one accent)"

# --- the greeter user is created before greetd starts ---------------------------------
assert_file "$sysusers"
grep -Eq '^u greeter ' "$sysusers" || fail "sysusers must create the 'greeter' user"
grep -Eq '^m greeter video' "$sysusers" || fail "the greeter needs the 'video' group for DRM"
# ...and its home exists (cage needs a working dir + a writable shader cache, E-09).
tmpfiles=$repo/image/rootfs/usr/lib/tmpfiles.d/wardos-greeter.conf
assert_file "$tmpfiles"
grep -Eq '^d /var/lib/greeter ' "$tmpfiles" || fail "tmpfiles must create the greeter home /var/lib/greeter"

# --- the launcher: shape and shell hygiene --------------------------------------------
assert_file "$launcher"
[[ -x "$launcher" ]] || fail "wardos-session must be executable"
bash -n "$launcher" || fail "wardos-session: syntax"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --severity=style --shell=bash "$launcher" || fail "shellcheck on wardos-session"
fi

# --- the launcher stays in the foreground and starts the managed session first --------
# uwsm start blocks until the session ends (uwsm docs), so its exit is the session's end;
# greetd treats this command's exit as logout. A clean managed start reaches neither the
# bare-binary form nor Hyprland.
setup_env
# shellcheck disable=SC2016  # $2 is for the generated mock to expand at run time, not here
mock uwsm 'test "$2" = hyprland.desktop'   # `uwsm start hyprland.desktop` -> 0, else 1
mock Hyprland
bash "$launcher" >/dev/null 2>&1 || true
assert_logged '^uwsm start hyprland.desktop$'
assert_not_logged '^uwsm start hyprland$'
assert_not_logged '^Hyprland'

# --- fallback ladder: managed entry fails -> bare binary -> Hyprland directly ---------
setup_env
mock uwsm 'exit 1'
mock Hyprland
bash "$launcher" >/dev/null 2>&1 || true
assert_logged '^uwsm start hyprland.desktop$'
assert_logged '^uwsm start hyprland$'
assert_logged '^Hyprland'
