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

# --- greetd config: greeter on VT 1, unprivileged, graphical via cage + gtkgreet ------
cfg=$greetd/config.toml
assert_file "$cfg"
assert_contains "$cfg" '[terminal]'
assert_contains "$cfg" 'vt = 1'
assert_contains "$cfg" '[default_session]'
assert_contains "$cfg" 'user = "greeter"'
# The greeter is cage hosting gtkgreet, styled by the Ward Dark CSS, running our launcher.
grep -Eq '^command = "cage -s -- gtkgreet .*-c /usr/libexec/wardos-session"' "$cfg" \
  || fail "greetd command must run gtkgreet in cage and hand off to the WardOS session:
$(grep '^command' "$cfg")"
assert_contains "$cfg" '-s /etc/greetd/wardos-greeter.css'
# No [initial_session]: the user explicitly asked for a real login screen, not autologin.
! grep -q '\[initial_session\]' "$cfg" || fail "greetd must not auto-login (no [initial_session])"

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
