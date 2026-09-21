#!/usr/bin/env bash
# calibrate.sh — the CALIBRATE pickers shared by wardos-calibrate (in-session settings,
# ADR-0026) and wardos-provision-ui (first-boot provisioning, ADR-0027). Sourced after
# wardos.sh, never run. The pickers only choose; applying differs by caller (in-session
# goes direct through polkit, provisioning goes through the root broker), so no apply
# helper lives here.
#
#   calibrate_keep / calibrate_back        the "keep current" and "back" menu labels
#   calibrate_current_locale / _keymap / _timezone   the system's current values (or "")
#   calibrate_pick_locale     print the chosen UTF-8 locale, empty when kept/cancelled
#   calibrate_pick_keyboard   print the chosen X11 keymap layout, empty when kept/cancelled
#   calibrate_pick_timezone   region → city picker; print Region/City, empty when kept

calibrate_keep="· keep current"
calibrate_back="‹ back"

calibrate_current_locale() { localectl status 2>/dev/null | sed -n 's/.*System Locale: *LANG=//p' | head -n1; }
calibrate_current_keymap() { localectl status 2>/dev/null | sed -n 's/.* X11 Layout: *//p' | head -n1; }
calibrate_current_timezone() { timedatectl show -p Timezone --value 2>/dev/null || true; }

calibrate_pick_locale() {
  local cur choice
  cur=$(calibrate_current_locale)
  choice=$(
    {
      printf '%s\n' "$calibrate_keep${cur:+ ($cur)}"
      # UTF-8 locales only, the ones a desktop should offer.
      localectl list-locales 2>/dev/null | grep -Ei '\.utf-?8$' || true
    } | wardos_menu "Language · the system language and formats"
  ) || return 0
  [[ "$choice" == "$calibrate_keep"* ]] && return 0
  printf '%s\n' "$choice"
}

calibrate_pick_keyboard() {
  local cur choice
  cur=$(calibrate_current_keymap)
  choice=$(
    {
      printf '%s\n' "$calibrate_keep${cur:+ ($cur)}"
      localectl list-x11-keymap-layouts 2>/dev/null || true
    } | wardos_menu "Keyboard · the layout for the desktop, console and login"
  ) || return 0
  [[ "$choice" == "$calibrate_keep"* ]] && return 0
  printf '%s\n' "$choice"
}

calibrate_pick_timezone() {
  local cur region city zones regions
  cur=$(calibrate_current_timezone)
  zones=$(timedatectl list-timezones 2>/dev/null || true)
  [[ -n "$zones" ]] || { wardos_notify "Timezone" "No timezone data on this host"; return 0; }
  while true; do
    regions=$(printf '%s\n' "$zones" | cut -d/ -f1 | sort -u)
    region=$(
      printf '%s\n%s\n' "$calibrate_keep${cur:+ ($cur)}" "$regions" | wardos_menu "Timezone · region"
    ) || return 0
    [[ "$region" == "$calibrate_keep"* ]] && return 0
    # A single-segment zone (UTC, GMT…) is the answer as it stands.
    if ! printf '%s\n' "$zones" | grep -q "^$region/"; then
      printf '%s\n' "$region"
      return 0
    fi
    city=$(
      {
        printf '%s\n' "$calibrate_back"
        printf '%s\n' "$zones" | sed -n "s|^$region/||p" | sort
      } | wardos_menu "Timezone · $region"
    ) || return 0
    [[ "$city" == "$calibrate_back" ]] && continue
    printf '%s\n' "$region/$city"
    return 0
  done
}
