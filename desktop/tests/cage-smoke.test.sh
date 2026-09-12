#!/usr/bin/env bash
# cage-smoke (ADR-0027, #119 review item 4): an INTEGRATION smoke that starts the ACTUAL
# shipped first-boot bootstrap boundary headlessly — cage (wlroots headless backend) hosting
# `foot --app-id wardos-provision` running the real `wardos-provision-ui` — and proves the
# first surface comes up and STAYS ALIVE, then tears it down. This is the boundary the T480s
# exposed: a layer-shell client (fuzzel) ABORTS under cage (cage speaks xdg-shell only), so a
# client that dies on startup must be caught here. greetd-session.test.sh MOCKS cage, so it can
# never catch that class of protocol/session/environment mismatch; this test does not mock it.
#
# WHAT IT EXERCISES (authoritatively, where a compositor is available):
#   - Proof A  cage + foot bring a surface up and run the client (a marker the client writes as
#              its first act proves foot actually ran it), and the client STAYS ALIVE for a
#              bounded interval (cage/foot are still running after it).
#   - Negative the SAME boundary with a client that exits immediately (a faithful proxy for the
#              fuzzel-aborts-on-startup failure) is DETECTED as dead — proving this smoke is not
#              a no-op and really would catch a client that dies on startup.
#   - Proof B  the REAL shipped `wardos-provision-ui` under `foot --app-id wardos-provision`
#              under cage does NOT abort on startup and stays alive for the bounded interval —
#              the exact regression the T480s hit.
#
# GATING / WHAT CANNOT BE EXERCISED HERE, AND WHY:
#   - If `cage` or `foot` is not installed, the test SKIPS with a clear message (never FAILS on
#     a compositor-less runner). CI runs it for real in a Fedora container (matching the image's
#     Fedora 44 cage/foot/wlroots) — see the `desktop-compositor` job in .github/workflows/verify.yml.
#   - If the binaries ARE installed but the headless compositor cannot bring up ANY surface here
#     (no wlroots headless backend on this kernel/container), Proof A's startup marker never
#     appears; the test SKIPS and prints cage's own diagnostics rather than faking a pass. The
#     genuine end-to-end proof on real graphics hardware remains the hardware boot (the USB build).
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

if ! command -v cage >/dev/null 2>&1 || ! command -v foot >/dev/null 2>&1; then
  echo "skip cage-smoke.test.sh: cage and/or foot not installed (run where the compositor ships; the CI desktop-compositor job runs it on Fedora with real cage/foot/wlroots)"
  exit 0
fi

# --- headless compositor environment -----------------------------------------------------
# A private, 0700 XDG_RUNTIME_DIR (wlroots requires it) and the wlroots headless backend with
# no libinput devices, software-rendered (pixman) so no GPU/DRM is needed.
runtime="$TMP/cage-run"
mkdir -p "$runtime"
chmod 700 "$runtime"
export XDG_RUNTIME_DIR="$runtime"
export WLR_BACKENDS=headless
export WLR_LIBINPUT_NO_DEVICES=1
export WLR_RENDERER=pixman
export XDG_SESSION_TYPE=wayland
cage_log="$TMP/cage.log"

# The interval the first surface must stay alive to count as "up and stable". A client that
# dies on startup (the T480s failure) tears the whole boundary down well within this window.
interval=3

# alive PID       true iff the process is still running.
# teardown PID     stop the boundary and reap it (its shutdown signal status is irrelevant).
# wait_marker P N  true once file P exists, polling up to N tenths of a second.
alive() { kill -0 "$1" 2>/dev/null; }
teardown() {
  kill "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}
wait_marker() {
  local p=$1 n=$2 i
  for ((i = 0; i < n; i++)); do
    [[ -e "$p" ]] && return 0
    sleep 0.1
  done
  [[ -e "$p" ]]
}

# --- Proof A: the boundary comes up, runs the client, and it stays alive -----------------
# The harness client writes its startup marker as its FIRST act (so the marker's presence proves
# foot actually ran it, i.e. the surface came up under cage), then sleeps well past the interval.
up="$TMP/client.up"
client="$TMP/alive-client.sh"
cat >"$client" <<EOF
#!/usr/bin/env bash
: >"$up"
exec sleep $((interval + 20))
EOF
chmod +x "$client"

cage -s -- foot --app-id wardos-provision -e "$client" >"$cage_log" 2>&1 &
cage_pid=$!

# Wait up to 12 s for the surface to come up (the client to run). If it never does, the headless
# compositor could not start HERE — an environmental gap, not a client abort (the client writes
# its marker before it could fail): SKIP and document, do not FAIL on a compositor-less runner.
if ! wait_marker "$up" 120; then
  teardown "$cage_pid"
  echo "skip cage-smoke.test.sh: cage/foot are installed but no surface came up in this environment (headless wlroots backend unavailable here); cage said:"
  sed 's/^/    /' "$cage_log" 2>/dev/null || true
  echo "  (the CI desktop-compositor job runs this for real on Fedora; the final proof is the hardware boot)"
  exit 0
fi

# The surface came up. Now the authoritative liveness assertion: after the bounded interval the
# boundary must STILL be running — the first surface stayed alive rather than aborting.
sleep "$interval"
alive "$cage_pid" || fail "Proof A: the boundary did not stay alive for ${interval}s after the surface came up (cage exited); cage said:
$(cat "$cage_log" 2>/dev/null)"
teardown "$cage_pid"

# --- Negative self-check: a client that dies on startup is DETECTED as dead --------------
# This proves the liveness assertion above is real: the SAME boundary with a client that exits
# immediately (a faithful proxy for fuzzel aborting under cage) must be seen as NOT alive after
# the interval. If this "passed" as alive, the smoke would be a no-op.
up2="$TMP/dying.up"
dying="$TMP/dying-client.sh"
cat >"$dying" <<EOF
#!/usr/bin/env bash
: >"$up2"
exit 1
EOF
chmod +x "$dying"

: >"$cage_log"
cage -s -- foot --app-id wardos-provision -e "$dying" >"$cage_log" 2>&1 &
dying_pid=$!
# foot runs the client (marker appears), the client exits at once, foot exits, cage exits.
wait_marker "$up2" 120 || fail "negative self-check: foot never ran even the dying client (surface did not come up on the second launch)"
sleep "$interval"
if alive "$dying_pid"; then
  teardown "$dying_pid"
  fail "negative self-check: a client that dies on startup was NOT detected — the smoke would not catch the T480s failure (a layer-shell client aborting under cage)"
fi

# --- Proof B: the REAL shipped wardos-provision-ui stays alive under the real boundary ----
# Byte-for-byte the bootstrap command from wardos-greetd-session. The marker is absent, so the
# UI enters provisioning and blocks reading the terminal — it must NOT abort under cage (the
# T480s regression). Point WARDOS_LIB at the in-tree lib and the socket at an unused path (the
# UI blocks on input long before it would reach the broker), and put desktop/bin on PATH.
export WARDOS_LIB="$WARDOS_ROOT/lib/wardos.sh"
export WARDOS_PROVISIONED_MARKER="$TMP/ui-provisioned" # absent → the UI runs the provisioning flow
export WARDOS_PROVISION_STAGE="$TMP/ui-stage"
export WARDOS_PROVISION_SOCK="$TMP/ui-nosock"
: >"$cage_log"
cage -s -- foot --app-id wardos-provision -e wardos-provision-ui >"$cage_log" 2>&1 &
ui_pid=$!
# Give the real client time to come up and (if it were going to abort) do so, then assert it is
# still alive: the shipped surface came up under cage and stayed alive.
sleep "$((interval + 2))"
alive "$ui_pid" || fail "Proof B: the real wardos-provision-ui aborted on startup under cage+foot (the T480s failure class); cage said:
$(cat "$cage_log" 2>/dev/null)"
teardown "$ui_pid"

echo "ok   cage-smoke.test.sh internal assertions (real cage+foot+wardos-provision-ui boundary)"
