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

# --- FAIL CLOSED (#119 review): a persistent provisioning/restage failure must NEVER fall
#     through to the provisioned greeter while the marker is ABSENT. The provisioning UI keeps
#     exiting with the restage-persist-failure status (76) and never touches the marker; after
#     the bounded retries the selector leaves its loop with no marker, and it MUST fail closed
#     (exit non-zero → greetd restarts the provisioning session), NOT present gtkgreet on a
#     machine with no human account. `sleep` is mocked so the bounded backoff is instant
#     (deterministic, not timing-based). --------------------------------------------------------
: >"$MOCK_LOG"
rm -f "$WARDOS_PROVISIONED_MARKER" "$WARDOS_PROVISION_STAGE"
mock sleep                       # the bounded backoff must not actually wait
mock cage 'exit 76'              # the UI cannot persist its restage state, and never provisions
rc=0
wardos-greetd-session || rc=$?
[[ $rc -ne 0 ]] || fail "a persistent restage failure with the marker ABSENT must fail closed (non-zero exit), not fall through to the greeter"
assert_not_logged 'gtkgreet'     # the provisioned greeter must NEVER run without the marker
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "the fail-closed path must not have created a marker"

# --- run_greeter is reachable ONLY with the marker present: the belt-and-braces guard on the
#     greeter call refuses even a direct fall-through when the marker is absent. Here the loop
#     is skipped (marker present at entry) and the greeter runs; the pairing with the case above
#     proves gtkgreet ⇔ marker present. -----------------------------------------------------------
: >"$MOCK_LOG"
: >"$WARDOS_PROVISIONED_MARKER"
mock cage
wardos-greetd-session
assert_logged '^cage -s -- gtkgreet '   # marker present → greeter runs

echo "ok   greetd-session.test.sh internal assertions"
