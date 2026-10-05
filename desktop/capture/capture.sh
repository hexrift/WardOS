#!/usr/bin/env bash
# The README capture (issue #84, docs/desktop.md "The README animation"): the shipped
# Hyprland on a virtual 1920x1080 output (the vkms kernel module's; a headless one as the
# fallback), software-rendered, with the shipped Waybar, mako, fuzzel and foot. Each scene of scenes.tsv is driven through `hyprctl dispatch`
# and wardos-menu-select (fuzzel --dmenu), shot with grim, and assemble.py turns the
# shots into the GIF. Nothing is drawn afterwards: every pixel is the compositor's.
#
#   desktop/capture/capture.sh OUT
#
# Runs as an unprivileged user (Hyprland refuses root) where image/install-desktop.sh
# has placed desktop/ and ward, wardd, ward-shell and wardos-theme-render are on PATH,
# with a KMS device in /dev/dri (CAPTURE_DRM_CARD, else the card sysfs attributes to the
# CAPTURE_DRM_DRIVER driver, default vkms, by driver name, device path or uevent) and a
# seat for it: seatd on ${SEATD_SOCK:-/run/seatd.sock} when LIBSEAT_BACKEND is seatd (CI:
# ci-run.sh, in a container given the runner's vkms card). aquamarine opens the device
# through the seat and allocates its buffers on it (AQ_DRM_DEVICES names it; a preset
# value is kept), so the DRM backend is wanted, not headless only. The user is first set
# up the way a first login leaves it (wardos-refresh --all, the Ward Dark render, the
# onboarding markers, a 1920x1080@60 line in ~/.config/hypr/monitors.conf, ~/ward-demo
# as a git repository), with Hyprland's debug log switched on in
# ~/.config/hypr/hyprland.conf, and must pass `Hyprland --verify-config`; then a session
# bus and Hyprland start (the system bus is the caller's: ci-run.sh runs one, so Waybar's
# bluetooth, network and battery modules find a bus with no services on it rather than
# none). Writes OUT/frames/NN-<scene>.png, OUT/wardos-desktop.gif,
# OUT/summary.md and OUT/logs/. A required scene that is not on screen in time fails the
# run with Hyprland's log, the DRM nodes and the EGL vendor; an optional one (the lock
# screen) is left out with a warning.
set -euo pipefail

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; }
case "${1:-}" in
  -h | --help) usage; exit 0 ;;
  "") usage >&2; exit 2 ;;
esac

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mkdir -p "$1"
out=$(cd "$1" && pwd)
frames=$out/frames
logs=$out/logs
output=""
headless=WARD-1
driver=${CAPTURE_DRM_DRIVER:-vkms}
limit=${WARDOS_CAPTURE_TIMEOUT:-60}
settle=1
project=$HOME/ward-demo
pids=()
hypr_pid=""

say() { printf 'capture: %s\n' "$*"; }
annotate() { if [[ ${GITHUB_ACTIONS:-} == true ]]; then printf '::%s::capture: %s\n' "$1" "$2"; fi; }
die() {
  echo "capture: $*" >&2
  annotate error "$*"
  exit 1
}

[[ $(id -u) -ne 0 ]] || die "run as an unprivileged user; Hyprland refuses root"
missing=()
for cmd in Hyprland hyprctl grim jq waybar mako fuzzel foot swaybg notify-send dbus-daemon \
  wl-paste cliphist pgrep pkill ps git python3 ward wardd ward-shell wardos-theme-render wardos-refresh \
  wardos-theme wardos-welcome wardos-launch wardos-menu wardos-power; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
[[ ${#missing[@]} -eq 0 ]] || die "not on PATH: ${missing[*]}"

# --- waiting ------------------------------------------------------------------------

# wait_for WHAT SECONDS CMD…: poll CMD until it succeeds; false after SECONDS, or as soon
# as Hyprland is gone, saying which.
wait_for() {
  local what=$1 secs=$2 start=$SECONDS end told
  shift 2
  end=$((SECONDS + secs))
  told=$SECONDS
  until "$@"; do
    if [[ -n $hypr_pid ]] && ! kill -0 "$hypr_pid" 2>/dev/null; then
      echo "capture: Hyprland exited while waiting for $what" >&2
      return 1
    fi
    if ((SECONDS >= end)); then
      echo "capture: timed out after ${secs}s waiting for $what; layers [$(layers_seen)], clients [$(clients_seen)]" >&2
      return 1
    fi
    if ((SECONDS - told >= 10)); then
      say "still waiting for $what ($((SECONDS - start))s): layers [$(layers_seen)], clients [$(clients_seen)]"
      told=$SECONDS
    fi
    sleep 0.2
  done
}

# hypr_json REQUEST JQ-ARGS…: hyprctl's JSON answer through jq, nothing when hyprctl
# fails or answers with an error line instead of JSON (the socket not up yet).
hypr_json() {
  local request=$1 answer
  shift
  answer=$(hyprctl "$request" -j 2>/dev/null) || return 1
  [[ $answer == [\[\{]* ]] || return 1
  jq "$@" <<<"$answer" 2>/dev/null
}
# layers_seen / clients_seen: every layer-shell namespace and every window class on
# screen now, for the waits' progress lines.
layers_seen() { hypr_json layers -r '[.. | objects | .namespace? // empty] | unique | join(" ")' 2>/dev/null || true; }
clients_seen() { hypr_json clients -r '[.[] | .class] | join(" ")' 2>/dev/null || true; }
# shellcheck disable=SC2016  # $ns is jq's
layer_up() { hypr_json layers -e --arg ns "$1" '[.. | objects | .namespace? // empty] | index($ns) != null' >/dev/null; }
layer_gone() { ! layer_up "$1"; }
# layer_addresses NS: the addresses of NS's layer surfaces, sorted. Logged around a
# theme switch for the record only: Waybar re-creates its surface on SIGUSR2, but the
# new surface may land at the address the old one had (run 9 of #84 waited 60 s for an
# address change that never came while the bar was already in Tokyo Night), so the
# addresses prove nothing and nothing waits on them.
# shellcheck disable=SC2016  # $ns is jq's
layer_addresses() { hypr_json layers -r --arg ns "$1" '[.. | objects | select(.namespace? == $ns) | .address] | sort | join(" ")' 2>/dev/null || true; }
# bar_ground_is COLOUR: the bar strip, shot now, is dominated by COLOUR -- the same
# check assemble.py makes on the Tokyo frame (expect[tokyo]), so the wait and the
# assertion cannot disagree. The probe shot goes to the logs, never among the frames.
bar_ground_is() {
  grim -o "$output" "$logs/bar-probe.png" 2>/dev/null || return 1
  python3 "$here/assemble.py" check "$logs/bar-probe.png" --region 0,0,1920,32 --dominant "$1" >/dev/null 2>&1
}
# pid_gone PID: the process is no longer there (swaybg is replaced, not reloaded).
pid_gone() { [[ -n $1 ]] && ! kill -0 "$1" 2>/dev/null; }
# dismiss: Hyprland's own notifications (the overlay toasts top-right: on 0.56, that
# hyprland-guiutils is not installed and that the .conf format goes in 0.57) are not the
# desktop and a user clicks them away; no shot has one.
dismiss() { hyprctl dismissnotify >/dev/null 2>&1 || true; }
# shellcheck disable=SC2016  # $c is jq's
clients() { hypr_json clients --arg c "$1" '[.[] | select(.class == $c and .mapped)] | length'; }
client_up() {
  local n
  n=$(clients "$1")
  ((${n:-0} >= ${2:-1}))
}
client_gone() {
  local n
  n=$(clients "$1")
  [[ -n $n ]] && ((n == 0))
}
running() { pgrep -u "$UID" -f -- "$1" >/dev/null; }
idle() { ! running "$1"; }
# running_for NAME SECONDS: a process called NAME has been up at least that long.
running_for() {
  local pid age
  pid=$(pgrep -n -u "$UID" -x "$1") || return 1
  age=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
  ((${age:-0} >= $2))
}
# monitor_up: an enabled 1920x1080 monitor (the vkms connector, or the headless one
# created as the fallback); its name becomes $output for grim and the summary.
monitor_up() {
  local name
  name=$(hypr_json monitors -r 'first(.[] | select(.width == 1920 and .height == 1080 and (.disabled | not)) | .name) // empty') || return 1
  [[ -n $name ]] || return 1
  output=$name
}
theme_is() { [[ $(cat "$HOME/.config/wardos/theme/current/id" 2>/dev/null) == "$1" ]]; }
# theme_token NAME: the current render's value of a WARDOS_* token (colors.env).
theme_token() { sed -n "s/^$1=\"\{0,1\}\([^\"]*\)\"\{0,1\}\$/\1/p" "$HOME/.config/wardos/theme/current/colors.env" 2>/dev/null | head -n 1; }
# wallpaper_sha: the rendered wallpaper's digest, to see it change under a theme switch.
wallpaper_sha() { sha256sum "$HOME/.config/wardos/theme/current/background.png" 2>/dev/null | cut -d' ' -f1; }
wallpaper_is_not() { [[ -n $(wallpaper_sha) && $(wallpaper_sha) != "$1" ]]; }
session_live() {
  local status
  status=$(ward status "$project" 2>/dev/null) || return 1
  [[ $status == *"session ACTIVE"* ]]
}

# bar_live: every `ward-shell bar --waybar … --follow` segment of the Waybar config has
# been running for two seconds. With no session each one exits at once and Waybar
# restarts it every five; with one it stays subscribed, so this is the bar gone live.
bar_live() {
  local want n=0 pid age
  want=$(jq '[.[] | objects | .exec? // empty | select(test("^ward-shell bar .*--follow"))] | length' \
    "$HOME/.config/waybar/config.jsonc")
  for pid in $(pgrep -u "$UID" -f -- '^ward-shell bar --waybar .*--follow'); do
    age=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
    if ((${age:-0} >= 2)); then n=$((n + 1)); fi
  done
  ((want > 0 && n >= want))
}

# hypr_ready: the instance this script started answers on its socket; exports its
# signature and Wayland display for hyprctl and grim.
hypr_ready() {
  local inst
  inst=$(hypr_json instances -r 'first(.[] | "\(.instance) \(.wl_socket)") // empty') || return 1
  [[ -n $inst ]] || return 1
  read -r HYPRLAND_INSTANCE_SIGNATURE WAYLAND_DISPLAY <<<"$inst"
  export HYPRLAND_INSTANCE_SIGNATURE WAYLAND_DISPLAY
  hyprctl version >/dev/null 2>&1
}

# --- driving ------------------------------------------------------------------------

# hypr_run CMD…: start CMD from the compositor, as a key binding would.
hypr_run() { hyprctl dispatch exec "$(printf '%q ' "$@")" >/dev/null; }

menu_open() {
  hypr_run "$@"
  wait_for "the menu of $*" "$limit" layer_up launcher
}

# menu_close: cancel the menu as Escape would (wardos-menu-select fails, the step
# skips) and wait for the command that opened it to finish.
menu_close() {
  pkill -u "$UID" -x fuzzel || true
  wait_for "the menu to close" 20 layer_gone launcher
  wait_for "the menu's command to finish" 20 idle 'wardos-(welcome|menu)'
}

# --- scenes (scenes.tsv) ------------------------------------------------------------

scene_desktop() {
  wait_for "the bar" "$limit" layer_up waybar
  wait_for "the wallpaper" "$limit" layer_up wallpaper
  wait_for "the login theme render" "$limit" idle 'wardos-(theme|first-run)'
  wait_for "the bar after the theme reload" "$limit" layer_up waybar
}

scene_theme() { menu_open wardos-welcome theme; }
leave_theme() { menu_close; }

scene_keys() { menu_open wardos-welcome keys; }
leave_keys() { menu_close; }

scene_project() { menu_open wardos-welcome project; }
leave_project() { menu_close; }

# What the project step runs for a chosen directory (wardos-welcome step_project).
scene_init() {
  hypr_run wardos-launch run wardos-init ward init "$project"
  wait_for "the ward init terminal" "$limit" client_up wardos-init
  wait_for "ward init's TamperWard file" "$limit" test -f "$project/.tamperward.yml"
  wait_for "ward init to finish" "$limit" idle '^ward init '
}
leave_init() {
  hyprctl dispatch closewindow class:wardos-init >/dev/null
  wait_for "the ward init terminal to close" 20 client_gone wardos-init
  # What step_project records after a successful init, so the agent step names it.
  mkdir -p "$HOME/.local/state/wardos"
  printf '%s\n' "$project" >"$HOME/.local/state/wardos/welcome-project"
}

scene_agent() { menu_open wardos-welcome agent; }
leave_agent() { menu_close; }

scene_up() {
  hypr_run wardos-launch run foot ward up "$project"
  wait_for "the ward up terminal" "$limit" client_up foot
  wait_for "the session" "$limit" session_live
  wait_for "ward up to finish" "$limit" idle '^ward up '
  wait_for "the live trust bar" "$limit" bar_live
}

scene_done() { menu_open wardos-welcome "done"; }
leave_done() {
  menu_close
  wait_for "the welcome toast" "$limit" layer_up notifications
}

# The command centre's own Resume session line, run as it is.
scene_observer() {
  local cmd
  cmd=$(ward-shell launcher --lines | awk -F'\t' '$1 == "AGENTS" && index($2, "Resume session") == 1 { print $3; exit }')
  [[ -n $cmd ]] || {
    echo "capture: the command centre lists no Resume session" >&2
    return 1
  }
  hyprctl dispatch exec "$cmd" >/dev/null
  wait_for "the observer terminal" "$limit" client_up foot 2
  wait_for "ward watch" "$limit" running '^ward watch'
  sleep 1
}

scene_menu() { menu_open wardos-menu; }
leave_menu() { menu_close; }

# The switch is done when every component has taken the render, not when the toast is
# up: the wallpaper is re-drawn (its digest changes; both are logged), swaybg is replaced
# after that (its pid goes), and the bar shows the new ground (bar_ground_is: a probe
# shot of its strip, checked the way the frame will be), then a second for the
# re-render. What the shot proves is the bar: its strip must be dominated by the new
# theme's ground (expect[tokyo], checked by assemble.py), since the two foot terminals
# of the up and observer scenes still cover most of the screen in Ward Dark, as open
# terminals do on any desktop (foot reads its colours once, at start, and wardos-theme
# signals nothing to it), and the wallpaper shows only in the gaps. Runs 7 and 8 were
# shot with the switch complete and failed a whole-frame check on exactly that; run 9
# waited on the bar's layer addresses changing, which they need not (layer_addresses).
scene_tokyo() {
  local swaybg_was bar_was sha_was
  swaybg_was=$(pgrep -n -u "$UID" -x swaybg || true)
  bar_was=$(layer_addresses waybar)
  sha_was=$(wallpaper_sha)
  hypr_run wardos-theme set tokyo-night
  wait_for "the Tokyo Night render" "$limit" theme_is tokyo-night
  wait_for "the wallpaper to be re-drawn" "$limit" wallpaper_is_not "$sha_was"
  say "wallpaper: $sha_was before, $(wallpaper_sha) after; ground $(theme_token WARDOS_GROUND)"
  wait_for "wardos-theme to finish" "$limit" idle wardos-theme
  wait_for "swaybg to be replaced" "$limit" pid_gone "$swaybg_was"
  wait_for "the wallpaper" "$limit" layer_up wallpaper
  wait_for "the bar to show the Tokyo Night ground" "$limit" bar_ground_is "$(theme_token WARDOS_GROUND)"
  say "bar surfaces: [$bar_was] before, [$(layer_addresses waybar)] after"
  wait_for "the theme toast" "$limit" layer_up notifications
  sleep 1
  wait_for "the live trust bar" "$limit" bar_live
}

scene_lock() {
  hypr_run wardos-power lock
  wait_for "hyprlock" 20 running_for hyprlock 3
}

# --- the session --------------------------------------------------------------------

# drm_of CARD: what sysfs says about /dev/dri/cardN: `<driver> (<device path>)`. The
# driver is the device's driver link, else DRIVER= in its uevent; a driver on the faux
# bus (vkms from Linux 6.16) reads `faux_driver`, so the device path is printed too.
drm_of() {
  local sys driver="" device=""
  sys="/sys/class/drm/$(basename "$1")"
  driver=$(basename "$(readlink -f "$sys/device/driver" 2>/dev/null)" 2>/dev/null) || driver=""
  [[ -n $driver && $driver != / && $driver != . ]] || driver=$(sed -n 's/^DRIVER=//p' "$sys/device/uevent" 2>/dev/null || true)
  device=$(readlink -f "$sys/device" 2>/dev/null) || device=""
  printf '%s (%s)\n' "${driver:-?}" "${device:-?}"
}

# drm_is CARD DRIVER: the card is DRIVER's by its driver name, its device path (the faux
# bus names the device /sys/devices/faux/vkms) or its uevent's DRIVER= or MODALIAS=.
drm_is() {
  local sys what
  sys="/sys/class/drm/$(basename "$1")"
  what=$(drm_of "$1")
  [[ $what == "$2 ("* || $what == *"/$2"* || $what == *"/$2/"* ]] && return 0
  grep -qE "^(DRIVER=$2|MODALIAS=.*$2)" "$sys/device/uevent" 2>/dev/null
}

# drm_card DRIVER: the /dev/dri/card* that is DRIVER's, so the runner's own display
# adapter is never taken.
drm_card() {
  local card
  for card in /dev/dri/card*; do
    [[ -e $card ]] || continue
    if drm_is "$card" "$1"; then
      printf '%s\n' "$card"
      return 0
    fi
  done
  return 1
}

# drm_cards: every card with its driver and device, for the start line and a failed pick.
drm_cards() {
  local card
  for card in /dev/dri/card*; do
    [[ -e $card ]] || continue
    printf '%s: %s; ' "$(basename "$card")" "$(drm_of "$card")"
  done
}

# The command the session entry starts (uwsm runs this entry on the image; there is no
# systemd user session here), else Hyprland itself, as wardos-session falls back to.
session_command() {
  local exec=""
  if [[ -f /usr/share/wayland-sessions/hyprland.desktop ]]; then
    exec=$(grep -m 1 '^Exec=' /usr/share/wayland-sessions/hyprland.desktop | cut -d= -f2-) || true
  fi
  case "${exec%% *}" in
    Hyprland | hyprland | start-hyprland | */Hyprland | */hyprland | */start-hyprland) printf '%s\n' "$exec" ;;
    *) printf 'Hyprland\n' ;;
  esac
}

# diagnose: what the renderer had to work with, for a failed run.
diagnose() {
  local report log hlog
  for log in "$logs"/*.log; do
    [[ -f $log && $log != "$logs/hyprland.log" ]] || continue
    echo "capture: ---- $(basename "$log") ($(wc -l <"$log") lines; last 40) ----"
    tail -n 40 "$log"
  done
  echo "capture: ---- hyprctl monitors / layers / clients ----"
  hypr_json monitors -c '.' || echo "  (no answer)"
  hypr_json layers -c '.' || echo "  (no answer)"
  hypr_json clients -c '[.[] | {class, title, mapped, workspace: .workspace.name, at, size}]' || echo "  (no answer)"
  echo "capture: ---- processes of $(id -un) ----"
  ps -o pid,ppid,stat,etime,cmd -u "$(id -un)" 2>&1 || true
  for hlog in "$XDG_RUNTIME_DIR"/hypr/*/hyprland.log; do
    [[ -f $hlog ]] || continue
    echo "capture: ---- Hyprland's log without TRACE ($hlog, last 200 of $(grep -cv '\[TRACE\]' "$hlog" || true) lines; the whole log is logs/hyprland.log) ----"
    grep -v '\[TRACE\]' "$hlog" | tail -n 200
    echo "capture: ---- Hyprland's log, last 40 TRACE lines ----"
    grep '\[TRACE\]' "$hlog" | tail -n 40
  done
  echo "capture: ---- Hyprland's stdout ($logs/hyprland.out, last 40 lines without TRACE) ----"
  grep -v '\[TRACE\]' "$logs/hyprland.out" 2>/dev/null | tail -n 40 || true
  echo "capture: ---- the DRM nodes (ls -l /dev/dri), as $(id -un) in groups $(id -Gn) ----"
  ls -l /dev/dri 2>&1 || true
  if command -v eglinfo >/dev/null 2>&1; then
    echo "capture: ---- EGL (eglinfo -B, GBM and surfaceless platforms, LIBGL_ALWAYS_SOFTWARE=${LIBGL_ALWAYS_SOFTWARE:-}) ----"
    timeout 30 eglinfo -B -p gbm 2>&1 || true
    timeout 30 eglinfo -B -p surfaceless 2>&1 || true
  else
    echo "capture: no eglinfo (egl-utils) to name the EGL vendor"
  fi
  if [[ -f $out/seatd.log ]]; then
    echo "capture: ---- seatd's log ($out/seatd.log) ----"
    tail -n 50 "$out/seatd.log"
  fi
  for report in "$HOME"/.cache/hyprland/hyprlandCrashReport*.txt; do
    [[ -f $report ]] || continue
    echo "capture: ---- Hyprland's crash report $report ----"
    cat "$report"
  done
}

cleanup() {
  local status=$? pid
  trap - EXIT
  if [[ -n ${HYPRLAND_INSTANCE_SIGNATURE:-} ]]; then
    hyprctl monitors -j >"$logs/monitors.json" 2>&1 || true
    hyprctl clients -j >"$logs/clients.json" 2>&1 || true
    hyprctl layers -j >"$logs/layers.json" 2>&1 || true
  fi
  cp "$XDG_RUNTIME_DIR"/hypr/*/hyprland.log "$logs/" 2>/dev/null || true
  cp "$HOME"/.cache/hyprland/hyprlandCrashReport*.txt "$logs/" 2>/dev/null || true
  if ((status != 0)); then
    echo "capture: failed; what the session looked like:" >&2
    diagnose 2>&1 | tee "$logs/diagnosis.txt" >&2
  fi
  ward stop "$project" >/dev/null 2>&1 || true
  if [[ -n ${HYPRLAND_INSTANCE_SIGNATURE:-} ]]; then hyprctl dispatch exit >/dev/null 2>&1 || true; fi
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  sleep 1
  for pid in "${pids[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
  rm -rf "$XDG_RUNTIME_DIR"
  exit "$status"
}

# A private runtime directory, short enough that Hyprland's socket path fits sun_path.
XDG_RUNTIME_DIR=$(mktemp -d /tmp/xdg.XXXXXX)
chmod 0700 "$XDG_RUNTIME_DIR"
export XDG_RUNTIME_DIR
trap cleanup EXIT
unset WAYLAND_DISPLAY DISPLAY HYPRLAND_INSTANCE_SIGNATURE
# Mesa's software rasteriser for EGL and, through kms_swrast on the card's dumb
# buffers, for the GBM buffers aquamarine allocates (vkms has no Mesa driver of its own);
# the seat aquamarine opens the card through; aquamarine's and Hyprland's trace logging,
# so a backend or renderer that fails says why. Not HYPRLAND_HEADLESS_ONLY: the DRM
# backend is the one with an allocator, and the headless output is only the fallback.
export LIBGL_ALWAYS_SOFTWARE=1 GBM_ALWAYS_SOFTWARE=1 AQ_TRACE=1 HYPRLAND_TRACE=1
export LIBSEAT_BACKEND=${LIBSEAT_BACKEND:-seatd}
# The card: the one the caller chose (CAPTURE_DRM_CARD, the workflow's: it saw which
# card modprobe added), else the one sysfs attributes to $driver.
if [[ -z ${AQ_DRM_DEVICES:-} ]]; then
  if [[ -n ${CAPTURE_DRM_CARD:-} ]]; then
    [[ -e $CAPTURE_DRM_CARD ]] || die "CAPTURE_DRM_CARD=$CAPTURE_DRM_CARD is not a device here (cards: $(drm_cards))"
    AQ_DRM_DEVICES=$CAPTURE_DRM_CARD
  else
    AQ_DRM_DEVICES=$(drm_card "$driver") || die "no /dev/dri/card* that is $driver's (cards: $(drm_cards)); the capture needs the vkms module loaded and /dev/dri passed in"
  fi
fi
export AQ_DRM_DEVICES
say "DRM device: $AQ_DRM_DEVICES, $(drm_of "$AQ_DRM_DEVICES"); cards: $(drm_cards)"
if [[ $LIBSEAT_BACKEND == seatd ]]; then
  wait_for "the seat (seatd on ${SEATD_SOCK:-/run/seatd.sock})" 20 test -S "${SEATD_SOCK:-/run/seatd.sock}" ||
    die "no seatd socket; aquamarine cannot open $AQ_DRM_DEVICES without a seat"
fi
rm -rf "$frames" "$logs"
mkdir -p "$frames" "$logs"
cd "$HOME"

say "setting up $(id -un) as a first login leaves it"
wardos-refresh --all >"$logs/refresh.log"
wardos-theme render ward-dark
# What a scene's shot must show, for assemble.py check, evaluated once the scene is on
# screen: the bar strip (Waybar, 32 px at the top, `window#waybar { background: @ground }`)
# dominated by the theme's ground as the current render has it, so the Tokyo Night shot
# is one of a bar that has taken the switch.
declare -A expect=()
# shellcheck disable=SC2016  # evaluated by the scene loop, after the scene
expect[tokyo]='--region 0,0,1920,32 --dominant "$(theme_token WARDOS_GROUND)"'
for marker in first-run-done calibrate-done welcome-done; do
  date -u +%Y-%m-%dT%H:%M:%SZ >"$HOME/.config/wardos/$marker"
done
# Every output at 1920x1080@60: vkms's Virtual-1, or the headless fallback. The later
# catch-all line replaces the shipped `preferred` one.
printf 'monitor = , 1920x1080@60, auto, 1\n' >>"$HOME/.config/hypr/monitors.conf"
# The clients start as on the image, from autostart.conf's exec-once lines (waybar, mako,
# the clipboard watchers, the theme re-apply that starts swaybg, wardos-first-run), each
# line's output going to logs/<command>.log instead of Hyprland's stdout, which the
# trace log would drown it in, followed by `exited <status>` when the command ends (128
# plus the signal for one that was killed: Waybar went away after its start-up in run 6
# with nothing in its log). The user's copy of the file is what Hyprland reads. Two
# lines are changed for the capture only: Waybar gets `-l debug`, and hypridle's line
# becomes a no-op (its idle timer would lock the screen mid-capture; the package is not
# installed here).
awk -v logs="$logs" '/^exec-once = / {
  cmd = substr($0, 13); split(cmd, w, " "); name = w[1]; sub(/.*\//, "", name)
  if (name == "hypridle") { print "exec-once = true # hypridle: left out of the capture"; next }
  if (cmd == "waybar") cmd = "waybar -l debug"
  print "exec-once = " cmd " >>" logs "/" name ".log 2>&1; echo \"exited $?\" >>" logs "/" name ".log"; next
} { print }' "$HOME/.config/hypr/autostart.conf" >"$HOME/.config/hypr/autostart.conf.capture" &&
  mv "$HOME/.config/hypr/autostart.conf.capture" "$HOME/.config/hypr/autostart.conf"
# Hyprland logs nothing to its file by default (debug:disable_logs); the capture's
# failure output needs the log, to the file and to stdout ($logs/hyprland.out).
printf '\n# desktop/capture/capture.sh: the debug log for the capture\ndebug {\n    disable_logs = false\n    enable_stdout_logs = true\n}\n' \
  >>"$HOME/.config/hypr/hyprland.conf"
# Where Hyprland writes a crash report; it does not create the parent itself.
mkdir -p "$HOME/.cache/hyprland"
if ! verified=$(Hyprland --verify-config -c "$HOME/.config/hypr/hyprland.conf" 2>&1); then
  printf '%s\n' "$verified" >&2
  die "Hyprland --verify-config refuses the session's configuration"
fi
rm -rf "$project"
cp -R "$root/examples/ward-demo" "$project"
git -C "$project" init -q -b main
git -C "$project" add -A
git -C "$project" -c user.name=ward-demo -c user.email=ward-demo@localhost commit -q -m "ward-demo"

dbus-daemon --session --address="unix:path=$XDG_RUNTIME_DIR/bus" --nofork --nopidfile >"$logs/dbus.log" 2>&1 &
pids+=("$!")
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
wait_for "the session bus" 20 test -S "$XDG_RUNTIME_DIR/bus" || die "the session bus did not start"

read -ra session < <(session_command)
say "starting ${session[*]} (AQ_DRM_DEVICES=$AQ_DRM_DEVICES, LIBSEAT_BACKEND=$LIBSEAT_BACKEND, software GL)"
"${session[@]}" >"$logs/hyprland.out" 2>&1 &
hypr_pid=$!
pids+=("$hypr_pid")
wait_for "Hyprland's socket" "$limit" hypr_ready || die "Hyprland did not come up"
say "$(hyprctl version | sed -n 1p), instance $HYPRLAND_INSTANCE_SIGNATURE on $WAYLAND_DISPLAY"
dismiss
# There is no systemd here, so the exec-once systemctl line only logs its failure and the
# units it would start do not run: the bar's segments subscribe to the daemon themselves,
# as they do whenever wardos-shell-worker.service is down (desktop/systemd/user), and no
# approval listener, polkit agent or on-screen display is needed for the scenes.
if ! wait_for "the $driver output at 1920x1080" 20 monitor_up; then
  say "no $driver output; creating the headless output $headless instead"
  created=$(hyprctl output create headless "$headless" 2>&1) || true
  [[ $created == ok* ]] || die "hyprctl output create headless $headless: $created"
  wait_for "the 1920x1080 output $headless" "$limit" monitor_up || die "the headless output did not come up"
fi
say "output $output at 1920x1080"

summary=$out/summary.md
{
  echo "### Desktop capture"
  echo
  echo "$(hyprctl version | sed -n 1p), output $output at 1920x1080 on $AQ_DRM_DEVICES ($(drm_of "$AQ_DRM_DEVICES")), software GL."
  echo
  if [[ -f $out/versions.txt ]]; then
    echo '```'
    cat "$out/versions.txt"
    echo '```'
    echo
  fi
  echo "| # | scene | ms | on screen | shot |"
  echo "| --- | --- | --- | --- | --- |"
} >"$summary"

n=0
while IFS=$'\t' read -r -u 3 id ms need what; do
  [[ -z $id || $id == \#* ]] && continue
  n=$((n + 1))
  png=$(printf '%s/%02d-%s.png' "$frames" "$n" "$id")
  say "scene $n, $id: $what"
  set +e
  (
    set -e
    "scene_$id"
    sleep "$settle"
    dismiss
    grim -o "$output" "$png"
    checks=()
    eval "checks+=(${expect[$id]:-})"
    python3 "$here/assemble.py" check "$png" "${checks[@]}"
  )
  rc=$?
  set -e
  if ((rc == 0)); then
    result=yes
  elif [[ $need == optional ]]; then
    rm -f "$png"
    result="left out"
    annotate warning "optional scene $id was not on screen; the GIF goes without it"
    say "optional scene $id was not on screen; left out"
  else
    printf '| %s | %s | %s | %s | not on screen |\n' "$n" "$id" "$ms" "$what" >>"$summary"
    if grim -o "$output" "$logs/not-on-screen-$id.png" 2>/dev/null; then
      python3 "$here/assemble.py" describe "$logs/not-on-screen-$id.png" || true
    fi
    die "scene $id was not on screen (what the output showed instead: logs/not-on-screen-$id.png)"
  fi
  printf '| %s | %s | %s | %s | %s |\n' "$n" "$id" "$ms" "$what" "$result" >>"$summary"
  if declare -F "leave_$id" >/dev/null; then
    set +e
    (
      set -e
      "leave_$id"
    )
    rc=$?
    set -e
    ((rc == 0)) || die "could not leave scene $id"
  fi
done 3<"$here/scenes.tsv"

python3 "$here/assemble.py" gif "$here/scenes.tsv" "$frames" "$out/wardos-desktop.gif" | tee -a "$logs/assemble.log"
size=$(wc -c <"$out/wardos-desktop.gif")
current=0
if [[ -f $root/assets/wardos-desktop.gif ]]; then current=$(wc -c <"$root/assets/wardos-desktop.gif"); fi
{
  echo
  echo "wardos-desktop.gif: $size bytes (assets/wardos-desktop.gif now: $current bytes)."
} >>"$summary"
say "wardos-desktop.gif: $size bytes (assets/wardos-desktop.gif now: $current)"
