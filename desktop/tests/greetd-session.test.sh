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
# The dev-seed transaction journal, isolated in $TMP so the inhibit regression can drive it and
# so the selector's new fail-closed guard never trips on a real /var journal on a dev box.
export WARDOS_DEV_SEED_JOURNAL="$TMP/dev-seed.journal"

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
assert_logged '^cage -s -- foot -c /etc/greetd/wardos-provision-foot.ini --app-id wardos-provision -e wardos-provision-ui$'
# The bootstrap terminal must use the image-owned config, not the greeter account's HOME.
assert_not_logged '\\.config/wardos/theme/current/foot\\.ini'
# cage keeps VT switching (`-s`) on the bootstrap path too (text-console recovery).
grep -Eq '^cage -s -- foot ' "$MOCK_LOG" || fail "the bootstrap cage must use -s (VT recovery)"
# When provisioning finishes the loop hands off to the greeter.
assert_logged '^cage -s -- gtkgreet '

# --- PTY allocator failure is fail-closed and diagnostic ----------------------------------
# Force the complete allocator probe to fail. The selector must exit non-zero, emit the
# actionable diagnostic, and never launch Cage/foot.
: >"$MOCK_LOG"
rm -f "$WARDOS_PROVISIONED_MARKER"
mock python3 'exit 1'
mock cage 'fail "cage must not run when the greeter cannot allocate a PTY"'
pty_err="$TMP/pty.err"
rc=0
wardos-greetd-session 2>"$pty_err" || rc=$?
[[ "$rc" -ne 0 ]] || fail "PTY allocation failure must fail closed"
grep -Fq 'cannot allocate and use a complete PTY pair' "$pty_err" || fail "PTY failure must emit the greeter diagnostic"
assert_not_logged '^cage '
rm -f "$MOCK_DIR/python3" "$MOCK_DIR/cage"

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

# --- #119 review: cross-component dev-seed inhibit. While the dev-seed transaction journal is
#     present (an interrupted dev-seed may have left a residual wheel account with NO provisioned
#     marker), the selector must launch NEITHER the provisioning UI NOR the greeter — it FAILS
#     CLOSED (exit non-zero → greetd restarts, VT recovery available), the same discipline as the
#     marker guard, and guarded EARLY so it holds whether or not the marker is present. --------
# (b1) journal present, marker ABSENT (the dangerous unprovisioned + orphan state): fail closed;
#      no foot (provisioning UI), no gtkgreet. The cage mock would provision if the loop ran — it
#      must NOT be reached.
: >"$MOCK_LOG"
rm -f "$WARDOS_PROVISIONED_MARKER"
# shellcheck disable=SC2016  # $WARDOS_PROVISIONED_MARKER expands in the mock, not now
mock cage 'touch "$WARDOS_PROVISIONED_MARKER"'
printf 'devuser\n' >"$WARDOS_DEV_SEED_JOURNAL"
rc=0
wardos-greetd-session || rc=$?
[[ $rc -ne 0 ]] || fail "an unresolved dev-seed journal must make the selector FAIL CLOSED (non-zero exit)"
assert_not_logged 'foot'     # the provisioning UI must NOT launch
assert_not_logged 'gtkgreet' # the greeter must NOT launch
[[ ! -e "$WARDOS_PROVISIONED_MARKER" ]] || fail "the dev-seed-inhibited path must not run cage/provision"

# (b2) [#152] journal present, marker ALSO present: the marker is the durable transaction commit
#      point, so a journal still present alongside it cannot be a real unresolved pre-commit
#      transaction — it is provably stale (e.g. the marker committed but a crash/power-loss, or a
#      failed directory fsync inside remove_durable, kept the post-commit journal clear from
#      completing). Before the fix this fell into the SAME fail-closed branch as (b1) and refused
#      forever: a fully provisioned machine permanently unloginable via the greeter. The selector
#      must now reach the greeter anyway, and — since this test process can genuinely remove the
#      file — clear the stale journal along the way.
: >"$MOCK_LOG"
: >"$WARDOS_PROVISIONED_MARKER"
printf 'devuser\n' >"$WARDOS_DEV_SEED_JOURNAL"
mock cage
wardos-greetd-session
assert_logged '^cage -s -- gtkgreet '
[[ ! -e "$WARDOS_DEV_SEED_JOURNAL" ]] ||
  fail "#152: a stale dev-seed journal past a committed marker must be cleared, not leave the machine unloginable forever"

# (b3) [#152 review] the REAL production ownership boundary: wardos-greetd-session runs as the
#      unprivileged, locked `greeter` user, while wardos-dev-seed creates the journal as ROOT in
#      a root-owned directory — an unprivileged `rm -f` against it fails with EACCES. Simulate
#      that with a stubbed `rm` that always fails (this test process itself can otherwise remove
#      anything under $TMP, so only a stub proves the boundary deterministically). The selector
#      must still reach the greeter (the marker is authoritative regardless of cleanup success —
#      the durable cleanup is wardos-dev-seed's job, proven separately in dev-seed.test.sh's T6),
#      and it must say HONESTLY that the removal failed rather than discarding rm's exit status
#      and implying success (the previous `rm -f "$path" 2>/dev/null` bug this replaces).
: >"$MOCK_LOG"
: >"$WARDOS_PROVISIONED_MARKER"
printf 'devuser\n' >"$WARDOS_DEV_SEED_JOURNAL"
mock cage
mock rm 'exit 1' # simulates the root/greeter permission boundary deterministically
b3_err="$TMP/greetd-b3.err"
wardos-greetd-session 2>"$b3_err"
assert_logged '^cage -s -- gtkgreet ' # the greeter still runs — cleanup success is never required
rm -f "$MOCK_DIR/rm" # restore the real rm immediately: later test-script cleanup needs it to work
[[ -e "$WARDOS_DEV_SEED_JOURNAL" ]] ||
  fail "#152: when rm fails, the journal must genuinely remain (never claimed removed when it was not)"
grep -Fiq 'could not remove' "$b3_err" ||
  fail "#152: an rm failure must be reported honestly, not silently discarded; got: $(cat "$b3_err")"

# Once reconciliation clears the journal, the selector resumes normally (marker present → greeter).
: >"$MOCK_LOG"
rm -f "$WARDOS_DEV_SEED_JOURNAL"
: >"$WARDOS_PROVISIONED_MARKER"
mock cage
wardos-greetd-session
assert_logged '^cage -s -- gtkgreet ' # journal cleared → the normal greeter runs again

echo "ok   greetd-session.test.sh internal assertions"
