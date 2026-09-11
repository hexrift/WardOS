#!/usr/bin/env bash
# wardos-greetd-session (ADR-0027): greetd's marker-gated session selector. Marker absent
# → the provisioning UI; marker present → the normal gtkgreet greeter. `cage` is mocked so
# the exec'd command is captured.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

export WARDOS_PROVISIONED_MARKER="$TMP/provisioned"
mock cage

# Unprovisioned → the provisioning UI.
: >"$MOCK_LOG"
rm -f "$WARDOS_PROVISIONED_MARKER"
wardos-greetd-session
assert_logged '^cage -s -- wardos-provision-ui$'

# Provisioned → the normal greeter (byte-for-byte today's command).
: >"$MOCK_LOG"
: >"$WARDOS_PROVISIONED_MARKER"
wardos-greetd-session
assert_logged '^cage -s -- gtkgreet -s /etc/greetd/wardos-greeter.css -c /usr/libexec/wardos-session$'

echo "ok   greetd-session.test.sh internal assertions"
