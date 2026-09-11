#!/usr/bin/env bash
# wardos-greetd-session (ADR-0027): greetd's marker-gated session selector. Marker present →
# the normal gtkgreet greeter; marker absent → the first-boot provisioning UI, a foot-hosted
# TUI under cage (xdg-shell, since cage has no layer-shell). `cage` is mocked so the exec'd/run
# command is captured; the bootstrap cage mock touches the marker to end the provisioning loop.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

export WARDOS_PROVISIONED_MARKER="$TMP/provisioned"
export WARDOS_PROVISION_STAGE="$TMP/provision.stage"

# --- provisioned → the normal greeter (byte-for-byte today's command) --------------------
: >"$MOCK_LOG"
mock cage
: >"$WARDOS_PROVISIONED_MARKER"
wardos-greetd-session
assert_logged '^cage -s -- gtkgreet -s /etc/greetd/wardos-greeter.css -c /usr/libexec/wardos-session$'
assert_not_logged 'foot'

# --- unprovisioned → the provisioning UI: cage hosting foot running the TUI ---------------
# The bootstrap cage mock provisions the machine (touches the marker) so the loop runs once
# and then hands off to the greeter.
: >"$MOCK_LOG"
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_STAGE"
# shellcheck disable=SC2016  # $WARDOS_PROVISIONED_MARKER expands in the mock, not now
mock cage 'touch "$WARDOS_PROVISIONED_MARKER"'
wardos-greetd-session
assert_logged '^cage -s -- foot --app-id wardos-provision -e wardos-provision-ui$'
# cage keeps VT switching (`-s`) on the bootstrap path too (text-console recovery).
grep -Eq '^cage -s -- foot ' "$MOCK_LOG" || fail "the bootstrap cage must use -s (VT recovery)"
# When provisioning finishes the loop hands off to the greeter.
assert_logged '^cage -s -- gtkgreet '

# --- E4: keymap staging plumbing — the session launches cage with XKB_DEFAULT_LAYOUT set from
#     the chosen layout, so the compositor's live layout matches BEFORE password entry -------
: >"$MOCK_LOG"
rm -f "$WARDOS_PROVISIONED_MARKER"
# The provisioning UI has recorded a chosen layout in the stage file (see provision-ui.test.sh
# for the write); the session must bring cage up under it.
printf 'KEYMAP=de\nVARIANT=\n' >"$WARDOS_PROVISION_STAGE"
# shellcheck disable=SC2016  # env/marker expand in the mock at run time
mock cage 'printf "cage-xkb=%s\n" "${XKB_DEFAULT_LAYOUT:-none}" >>"$MOCK_LOG"; touch "$WARDOS_PROVISIONED_MARKER"'
wardos-greetd-session
assert_logged '^cage-xkb=de$'

echo "ok   greetd-session.test.sh internal assertions"
