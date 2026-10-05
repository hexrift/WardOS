#!/usr/bin/env bash
# The README capture (issue #84, docs/desktop.md "The README animation"): the shipped
# Hyprland on a headless 1920x1080 output, software-rendered, with the shipped Waybar,
# mako, fuzzel and foot. Each scene of scenes.tsv is driven through `hyprctl dispatch`
# and wardos-menu-select (fuzzel --dmenu), shot with grim, and assemble.py turns the
# shots into the GIF. Nothing is drawn afterwards: every pixel is the compositor's.
#
#   desktop/capture/capture.sh OUT
#
# Runs as an unprivileged user (Hyprland refuses root) where image/install-desktop.sh
# has placed desktop/ and ward, wardd, ward-shell and wardos-theme-render are on PATH
# (CI: .github/workflows/desktop-capture.yml). The user is first set up the way a first
# login leaves it (wardos-refresh --all, the Ward Dark render, the onboarding markers,
# an output line in ~/.config/hypr/monitors.conf, ~/ward-demo as a git repository);
# then a session bus and Hyprland start. Writes OUT/frames/NN-<scene>.png,
# OUT/wardos-desktop.gif, OUT/summary.md and OUT/logs/. A required scene that is not
# on screen in time fails the run and prints Hyprland's log; an optional one (the lock
# screen) is left out with a warning.
set -euo pipefail

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; }
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
output=WARD-1
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
  pgrep pkill ps git python3 ward wardd ward-shell wardos-theme-render wardos-refresh \
  wardos-theme wardos-welcome wardos-launch wardos-menu wardos-power; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
[[ ${#missing[@]} -eq 0 ]] || die "not on PATH: ${missing[*]}"

# --- waiting ------------------------------------------------------------------------

# wait_for WHAT SECONDS CMD…: poll CMD until it succeeds; false after SECONDS, or as soon
# as Hyprland is gone, saying which.
wait_for() {
  local what=$1 secs=$2 end
  shift 2
  end=$((SECONDS + secs))
  until "$@"; do
    if [[ -n $hypr_pid ]] && ! kill -0 "$hypr_pid" 2>/dev/null; then
      echo "capture: Hyprland exited while waiting for $what" >&2
      return 1
    fi
    if ((SECONDS >= end)); then
      echo "capture: timed out after ${secs}s waiting for $what" >&2
      return 1
    fi
    sleep 0.2
  done
}

layer_up() { hyprctl layers -j 2>/dev/null | jq -e --arg ns "$1" '[.. | objects | .namespace? // empty] | index($ns) != null' >/dev/null; }
layer_gone() { ! layer_up "$1"; }
clients() { hyprctl clients -j 2>/dev/null | jq --arg c "$1" '[.[] | select(.class == $c and .mapped)] | length'; }
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
monitor_up() {
  hyprctl monitors -j 2>/dev/null |
    jq -e --arg n "$output" 'any(.[]; .name == $n and .width == 1920 and .height == 1080)' >/dev/null
}
theme_is() { [[ $(cat "$HOME/.config/wardos/theme/current/id" 2>/dev/null) == "$1" ]]; }
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
  inst=$(hyprctl instances -j 2>/dev/null | jq -r 'first(.[] | "\(.instance) \(.wl_socket)") // empty') || return 1
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

scene_tokyo() {
  hypr_run wardos-theme set tokyo-night
  wait_for "the Tokyo Night render" "$limit" theme_is tokyo-night
  wait_for "wardos-theme to finish" "$limit" idle wardos-theme
  wait_for "the bar" "$limit" layer_up waybar
  wait_for "the wallpaper" "$limit" layer_up wallpaper
  wait_for "the theme toast" "$limit" layer_up notifications
  sleep 1
  wait_for "the live trust bar" "$limit" bar_live
}

scene_lock() {
  hypr_run wardos-power lock
  wait_for "hyprlock" 20 running_for hyprlock 3
}

# --- the session --------------------------------------------------------------------

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

cleanup() {
  local status=$? pid
  trap - EXIT
  if [[ -n ${HYPRLAND_INSTANCE_SIGNATURE:-} ]]; then
    hyprctl monitors -j >"$logs/monitors.json" 2>&1 || true
    hyprctl clients -j >"$logs/clients.json" 2>&1 || true
    hyprctl layers -j >"$logs/layers.json" 2>&1 || true
  fi
  cp "$XDG_RUNTIME_DIR"/hypr/*/hyprland.log "$logs/" 2>/dev/null || true
  if ((status != 0)); then
    echo "capture: failed; Hyprland's log ($XDG_RUNTIME_DIR/hypr/*/hyprland.log), last 200 lines:" >&2
    tail -n 200 "$XDG_RUNTIME_DIR"/hypr/*/hyprland.log >&2 || echo "  (no log)" >&2
    echo "capture: what the session's clients printed ($logs/hyprland.out), last 100 lines:" >&2
    tail -n 100 "$logs/hyprland.out" >&2 || true
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
export HYPRLAND_HEADLESS_ONLY=1 LIBGL_ALWAYS_SOFTWARE=1
rm -rf "$frames" "$logs"
mkdir -p "$frames" "$logs"
cd "$HOME"

say "setting up $(id -un) as a first login leaves it"
wardos-refresh --all >"$logs/refresh.log"
wardos-theme render ward-dark
for marker in first-run-done calibrate-done welcome-done; do
  date -u +%Y-%m-%dT%H:%M:%SZ >"$HOME/.config/wardos/$marker"
done
printf 'monitor = %s, 1920x1080@60, 0x0, 1\n' "$output" >>"$HOME/.config/hypr/monitors.conf"
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
say "starting ${session[*]} (HYPRLAND_HEADLESS_ONLY=1, software GL)"
"${session[@]}" >"$logs/hyprland.out" 2>&1 &
hypr_pid=$!
pids+=("$hypr_pid")
wait_for "Hyprland's socket" "$limit" hypr_ready || die "Hyprland did not come up"
say "$(hyprctl version | sed -n 1p), instance $HYPRLAND_INSTANCE_SIGNATURE on $WAYLAND_DISPLAY"
created=$(hyprctl output create headless "$output" 2>&1) || true
[[ $created == ok* ]] || die "hyprctl output create headless $output: $created"
wait_for "the 1920x1080 output $output" "$limit" monitor_up || die "the headless output did not come up"

summary=$out/summary.md
{
  echo "### Desktop capture"
  echo
  echo "$(hyprctl version | sed -n 1p), headless $output 1920x1080, software GL."
  echo
  echo "| # | scene | ms | on screen | shot |"
  echo "| --- | --- | --- | --- | --- |"
} >"$summary"

n=0
while IFS=$'\t' read -r -u 3 id ms need _story what; do
  [[ -z $id || $id == \#* ]] && continue
  n=$((n + 1))
  png=$(printf '%s/%02d-%s.png' "$frames" "$n" "$id")
  say "scene $n, $id: $what"
  set +e
  (
    set -e
    "scene_$id"
    sleep "$settle"
    grim -o "$output" "$png"
    python3 "$here/assemble.py" check "$png"
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
    grim -o "$output" "$logs/not-on-screen-$id.png" 2>/dev/null || true
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
