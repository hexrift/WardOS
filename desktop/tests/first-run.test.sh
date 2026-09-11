#!/usr/bin/env bash
# wardos-first-run: configs, the default theme, ward doctor, the default apps, the keys,
# once (a marker), unless --force.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env
for c in wardos-refresh wardos-theme ward wardos-keys wardos-webapp wardos-tui notify-send wardos-calibrate wardos-welcome; do mock "$c"; done
marker="$XDG_CONFIG_HOME/wardos/first-run-done"

wardos-first-run --help | grep -q '^Usage' || fail "--help prints the usage block"

wardos-first-run
assert_logged '^wardos-refresh --all$'
# The login re-apply is quiet (-q): the desktop autostart re-applies every login, so a
# toast here would be the duplicate the reference laptop showed (E-09).
assert_logged '^wardos-theme set -q ward-dark$'
# `ward doctor` is detached so its run (tens of seconds on a USB boot) never blocks the
# rest of onboarding; wait_logged gives the detached mock a moment to record the call.
wait_logged '^ward doctor$'
assert_logged '^wardos-webapp install --defaults$'
assert_logged '^wardos-tui install --defaults$'
assert_logged '^wardos-keys $'
assert_file "$marker"
# CALIBRATE runs after the keys and before the walkthrough (ADR-0026).
assert_logged '^wardos-calibrate $'
calibrate_line=$(grep -n '^wardos-calibrate $' "$MOCK_LOG" | head -n1 | cut -d: -f1)
welcome_line=$(grep -n '^wardos-welcome $' "$MOCK_LOG" | head -n1 | cut -d: -f1)
[[ -n "$calibrate_line" && -n "$welcome_line" && "$calibrate_line" -lt "$welcome_line" ]] ||
  fail "wardos-calibrate runs before wardos-welcome; log: $(cat "$MOCK_LOG")"
# first-run does not send the "Welcome to WardOS" greeting: the walkthrough (wardos-welcome)
# is its single sender, so the reference laptop's duplicate toast cannot recur (E-09).
assert_not_logged 'Welcome to WardOS'
# The walkthrough comes after the keys, once the marker is written. (The detached
# `ward doctor` above may land anywhere in the log, so assert order against the keys line,
# not that wardos-welcome is the very last line.)
assert_logged '^wardos-welcome $'
keys_at=$(grep -n '^wardos-keys $' "$MOCK_LOG" | head -1 | cut -d: -f1)
welcome_at=$(grep -n '^wardos-welcome $' "$MOCK_LOG" | head -1 | cut -d: -f1)
[[ -n "$keys_at" && -n "$welcome_at" && "$welcome_at" -gt "$keys_at" ]] ||
  fail "wardos-welcome must run after wardos-keys; log: $(cat "$MOCK_LOG")"

# One-time init runs once: a second login does NOT re-copy the defaults (no
# wardos-refresh/keys/webapp/tui, and no ward doctor — the user's config and backups stay
# put), but the resumable stages are offered again (#125). The stage mocks keep no marker,
# so calibrate and welcome are both invoked.
: >"$MOCK_LOG"
wardos-first-run
assert_not_logged '^wardos-refresh'
assert_not_logged '^wardos-keys'
assert_not_logged '^wardos-webapp'
assert_not_logged '^wardos-tui'
assert_not_logged '^ward doctor$'
assert_logged '^wardos-calibrate $'
assert_logged '^wardos-welcome $'
wardos-first-run --force
assert_logged '^wardos-refresh --all$'
wait_logged '^ward doctor$'  # let the detached doctor finish before the log is reused

# A missing ward is skipped and a failing theme set reported, neither is fatal.
rm "$MOCK_DIR/ward" "$marker"
mock wardos-theme "exit 1"
: >"$MOCK_LOG"
wardos-first-run
assert_logged '^wardos-keys $'
assert_file "$marker"
assert_logged '^notify-send -a WardOS .*Theme not applied'

# A failing setup step is non-fatal AND the marker is still written, so a re-login does
# not run first-run again (which would re-copy the defaults and clobber the user's real
# config backup). Onboarding continues to wardos-welcome despite the failure.
for c in wardos-refresh wardos-theme ward wardos-webapp wardos-tui; do mock "$c"; done
rm -f "$marker"
mock wardos-refresh "exit 1"
: >"$MOCK_LOG"
wardos-first-run
assert_file "$marker"
assert_logged '^notify-send -a WardOS .*Defaults not applied'
assert_logged '^wardos-keys $'
assert_logged '^wardos-welcome $'
wait_logged '^ward doctor$'  # let the detached doctor finish before the log is reused
# The next login does not re-run the one-time init (the marker survived the failed step, so
# the defaults are not re-copied and the user's backups are safe); the resumable stages are
# still offered (#125).
: >"$MOCK_LOG"
wardos-first-run
assert_not_logged '^wardos-refresh'
assert_logged '^wardos-welcome $'

# --- #125: a cancelled CALIBRATE resumes on the next login; a completed one self-skips,
#     and resuming never re-copies the user's configuration. The calibrate mock mimics the
#     real stage's marker contract: skip when its marker exists, else record completion
#     unless CAL_CANCEL is set (the harness logs the invocation before this body runs).
setup_env
for c in wardos-refresh wardos-theme ward wardos-keys wardos-webapp wardos-tui notify-send wardos-welcome; do mock "$c"; done
# shellcheck disable=SC2016  # the $-expressions are for the generated mock to expand at run time, not here
mock wardos-calibrate 'm="$XDG_CONFIG_HOME/wardos/calibrate-done"; [[ -e "$m" ]] && exit 0; [[ -n "${CAL_CANCEL:-}" ]] && exit 1; mkdir -p "$(dirname "$m")"; : >"$m"; exit 0'
frmarker="$XDG_CONFIG_HOME/wardos/first-run-done"
cal_marker="$XDG_CONFIG_HOME/wardos/calibrate-done"
rm -f "$frmarker" "$cal_marker" "$XDG_CONFIG_HOME/wardos/welcome-done"

# Sentinel user configuration and its backup: resuming onboarding must leave both
# byte-for-byte intact (only the one-time init runs wardos-refresh, and it runs once). Their
# exact bytes are compared across the retry below (#125), not merely "refresh wasn't called".
user_conf="$XDG_CONFIG_HOME/hypr/input.conf"
mkdir -p "$(dirname "$user_conf")"
printf 'input { kb_layout = gb }\n# my edit\n' >"$user_conf"
printf 'input { kb_layout = us }\n# original\n' >"$user_conf.bak"
conf_sum=$(cksum <"$user_conf"); bak_sum=$(cksum <"$user_conf.bak")

# Login 1, CALIBRATE cancelled: the one-time init runs and CALIBRATE is offered, but a
# cancellation records no completion marker.
: >"$MOCK_LOG"
CAL_CANCEL=1 wardos-first-run
assert_logged '^wardos-refresh --all$'
assert_logged '^wardos-calibrate $'
[[ ! -e "$cal_marker" ]] || fail "a cancelled CALIBRATE must not record completion"
wait_logged '^ward doctor$'

# Login 2, no longer cancelling: the one-time init does NOT repeat (no wardos-refresh, so
# the user's config and backups are untouched), CALIBRATE is offered again and completes.
: >"$MOCK_LOG"
wardos-first-run
assert_not_logged '^wardos-refresh'
assert_logged '^wardos-calibrate $'
assert_file "$cal_marker"
# The sentinel config and its .bak are byte-for-byte what they were before the retry.
[[ "$(cksum <"$user_conf")" == "$conf_sum" ]] || fail "resume must not modify the user's config"
[[ "$(cksum <"$user_conf.bak")" == "$bak_sum" ]] || fail "resume must not overwrite the user's backup"

# Login 3: CALIBRATE has completed, so the stage self-skips; the wrapper still delegates to
# it (and to the walkthrough) but re-copies nothing and no longer stalls on setup.
: >"$MOCK_LOG"
wardos-first-run
assert_not_logged '^wardos-refresh'
assert_logged '^wardos-calibrate $'
assert_logged '^wardos-welcome $'

# --- keyboard-local adoption (ADR-0027): a first-boot provisioning keyboard choice is adopted
# into this user's Hyprland config on the first login. With the recorded layout present, the
# one-time init calls `wardos-calibrate keyboard-local <layout>` (after wardos-refresh resets
# input.conf) so the desktop starts on the layout chosen at provisioning.
setup_env
for c in wardos-refresh wardos-theme ward wardos-keys wardos-webapp wardos-tui notify-send wardos-calibrate wardos-welcome; do mock "$c"; done
export WARDOS_KEYBOARD_STATE="$TMP/keyboard-layout"
printf 'fr\n' >"$WARDOS_KEYBOARD_STATE"
: >"$MOCK_LOG"
wardos-first-run
assert_logged '^wardos-calibrate keyboard-local fr$'
