#!/usr/bin/env bash
# wardos-provision-ui (ADR-0027): the unprivileged first-boot provisioning UI. Drives the
# fuzzel pickers via the stdin menu backend and mocks the broker transport (socat), so the
# request the UI sends can be inspected. It must never leak the password anywhere but the
# single socket request.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

export WARDOS_PROVISIONED_MARKER="$TMP/provisioned"
export WARDOS_PROVISION_SOCK="$TMP/sock"
socat_in="$TMP/socat.in"
# The broker transport: capture the request, reply OK.
# shellcheck disable=SC2016
mock socat 'cat >>"'"$socat_in"'"; printf "OK\n"'
# shellcheck disable=SC2016
mock localectl 'case "${1:-}" in
  status) printf "System Locale: LANG=en_US.UTF-8\n   X11 Layout: us\n" ;;
  list-locales) printf "%s\n" en_US.UTF-8 de_DE.UTF-8 ;;
  list-x11-keymap-layouts) printf "%s\n" us de fr ;;
esac'
# shellcheck disable=SC2016
mock timedatectl 'case "${1:-}" in
  list-timezones) printf "%s\n" Europe/Paris UTC ;;
  show) printf "UTC\n" ;;
esac'
mock notify-send

wardos-provision-ui --help | grep -q '^Usage' || fail "--help prints the usage block"

# Happy path: keep the three settings, then name/username/password, then create.
: >"$socat_in"
export WARDOS_MENU_CHOICE="· keep current (en_US.UTF-8)
· keep current (us)
· keep current (UTC)
Ada Lovelace
alice
hunter2secret
hunter2secret
Create account and finish"
rm -f "$XDG_RUNTIME_DIR/wardos-menu-select.cursor"
wardos-provision-ui || fail "provision-ui should succeed on the happy path"
grep -q '^ACCOUNT$' "$socat_in" || fail "an ACCOUNT request was sent; got: $(cat "$socat_in")"
grep -q '^alice$' "$socat_in" || fail "username in the ACCOUNT request"
grep -q '^Ada Lovelace$' "$socat_in" || fail "full name in the ACCOUNT request"
grep -q '^hunter2secret$' "$socat_in" || fail "password crosses the socket once"
# Settings were kept, so no LOCALE/KEYMAP/TIMEZONE request was sent.
assert_not_logged 'set-locale' # (localectl mock only lists; broker is mocked away)
if grep -q '^LOCALE$' "$socat_in"; then fail "kept language must send no LOCALE request"; fi
assert_logged '^notify-send -a WardOS .*Welcome to WardOS'

# The password must not be written to any file the UI created under HOME/state.
if grep -rIq 'hunter2secret' "$HOME" 2>/dev/null; then fail "password leaked into a file under HOME"; fi

# Already provisioned: the UI does nothing and does not touch the broker.
: >"$socat_in"
touch "$WARDOS_PROVISIONED_MARKER"
wardos-provision-ui || fail "provision-ui exits 0 when already provisioned"
[[ ! -s "$socat_in" ]] || fail "no broker traffic when already provisioned; got: $(cat "$socat_in")"

echo "ok   provision-ui.test.sh internal assertions"
