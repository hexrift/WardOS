#!/usr/bin/env bash
# wardos.sh — the functions every wardos-* command shares (docs/desktop.md §Layout).
#
# Sourced, never run. A command finds it with
#   source "${WARDOS_LIB:-$(dirname "$(readlink -f "$0")")/../lib/wardos.sh}" ||
#     source /usr/lib/wardos/wardos.sh
# so the same script works from the repository (desktop/bin next to desktop/lib) and
# installed (/usr/bin next to /usr/lib/wardos).
#
#   wardos_config_dir / wardos_state_dir / wardos_data_dir   user directories (XDG)
#   wardos_share_dir      image defaults: $WARDOS_ROOT, else /usr/share/wardos
#   wardos_hypr_dir       the shipped Hyprland fragments (hyprland/ in the repo, hypr/ installed)
#   wardos_terminal       $TERMINAL (default foot); wardos_terminal_exec APP-ID CMD… opens one
#   wardos_browser        $BROWSER (default chromium);  wardos_editor  $VISUAL/$EDITOR (default nvim)
#   wardos_notify TITLE [BODY] [notify-send options…]    a notification tagged WardOS
#   wardos_menu PROMPT [ITEM…]   pick one line (items or stdin) through wardos-menu-select
#   wardos_has CMD        true when CMD is on PATH
#   wardos_backup PATH    copy PATH to PATH.bak before a command edits a file it did not create
#   wardos_usage          print the script's leading comment block (its --help text)
#   wardos_help ARGS…     print the usage and exit 0 when the first argument is -h/--help
#   wardos_die MSG        print to stderr, exit 1
#   wardos_conf_get FILE KEY            value of a key=value line
#   wardos_desktop_write FILE NAME EXEC ICON WMCLASS CATEGORIES COMMENT   a .desktop entry
#   wardos_slug TEXT      lower-case, dashes for spaces: the file name a display name gets

wardos_config_dir() { printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/wardos"; }
wardos_state_dir() { printf '%s\n' "${XDG_STATE_HOME:-$HOME/.local/state}/wardos"; }
wardos_data_dir() { printf '%s\n' "${XDG_DATA_HOME:-$HOME/.local/share}/wardos"; }
wardos_share_dir() { printf '%s\n' "${WARDOS_ROOT:-/usr/share/wardos}"; }

wardos_hypr_dir() {
  local share
  share=$(wardos_share_dir)
  if [[ -d "$share/hyprland" ]]; then printf '%s\n' "$share/hyprland"; else printf '%s\n' "$share/hypr"; fi
}

wardos_has() { command -v "$1" >/dev/null 2>&1; }

wardos_die() {
  printf '%s: %s\n' "$(basename "$0")" "$*" >&2
  exit 1
}

wardos_terminal() { printf '%s\n' "${TERMINAL:-foot}"; }

# The flag that names a terminal window's app id (Wayland) or class, per emulator.
wardos_terminal_class_flag() {
  case "$(basename "$(wardos_terminal)")" in
    alacritty | kitty | ghostty | wezterm) printf -- '--class\n' ;;
    *) printf -- '--app-id\n' ;;
  esac
}

# wardos_terminal_exec APP-ID CMD…  — a terminal window running CMD, with that app id.
wardos_terminal_exec() {
  local app_id=$1
  shift
  "$(wardos_terminal)" "$(wardos_terminal_class_flag)" "$app_id" -e "$@"
}

wardos_browser() { printf '%s\n' "${BROWSER:-chromium}"; }
wardos_editor() { printf '%s\n' "${VISUAL:-${EDITOR:-nvim}}"; }

# Terminal editors open inside a terminal window; anything else is launched as is.
wardos_editor_is_terminal() {
  case "$(basename "$(wardos_editor)")" in
    nvim | vim | vi | nano | hx | helix | micro | emacs) return 0 ;;
    *) return 1 ;;
  esac
}

# wardos_notify TITLE [BODY] [notify-send options…]. The desktop sends nothing when
# notify-send is missing (a plain terminal session) but never fails on it.
wardos_notify() {
  wardos_has notify-send || return 0
  local title=$1 body=${2:-}
  shift
  [[ $# -gt 0 ]] && shift
  notify-send -a WardOS "$@" "$title" "$body"
}

# wardos_menu PROMPT [ITEM…]: items as arguments, or one per line on stdin when none.
# Prints the chosen line; fails when the menu was cancelled.
wardos_menu() {
  local prompt=$1
  shift
  if [[ $# -gt 0 ]]; then
    printf '%s\n' "$@" | wardos-menu-select --prompt "$prompt"
  else
    wardos-menu-select --prompt "$prompt"
  fi
}

# wardos_backup PATH: docs/desktop.md §Commands, the `.bak` rule. Works for files and
# directories; a previous backup is replaced.
wardos_backup() {
  local path=$1
  [[ -e "$path" ]] || return 0
  rm -rf "$path.bak"
  cp -a "$path" "$path.bak"
}

# The usage block: every comment line after the shebang, up to the first blank or code
# line, with the comment marker stripped.
wardos_usage() {
  awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

wardos_help() {
  case "${1:-}" in
    -h | --help)
      wardos_usage
      exit 0
      ;;
  esac
}

# wardos_conf_get FILE KEY: the value of `KEY=value` (first match, surrounding spaces trimmed).
wardos_conf_get() {
  local file=$1 key=$2
  [[ -f "$file" ]] || return 1
  awk -F= -v k="$key" '$1 == k { sub(/^[ \t]+/, "", $2); v = $2; for (i = 3; i <= NF; i++) v = v "=" $i; print v; exit }' "$file"
}

wardos_slug() {
  printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9.+_-' '-' | sed 's/^-//; s/-$//'
}

# wardos_desktop_write FILE NAME EXEC ICON WMCLASS CATEGORIES COMMENT
wardos_desktop_write() {
  local file=$1 name=$2 exec=$3 icon=$4 wmclass=$5 categories=$6 comment=$7
  mkdir -p "$(dirname "$file")"
  cat >"$file" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=$name
Comment=$comment
Exec=$exec
Icon=$icon
Terminal=false
StartupNotify=true
StartupWMClass=$wmclass
Categories=$categories
EOF
}
