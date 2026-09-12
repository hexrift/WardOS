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
# REQUIRE-MODE vs OPTIONAL SKIP (#119 review):
#   - By DEFAULT (WARDOS_SMOKE_REQUIRE unset) an environmental gap — cage/foot absent, or the
#     headless compositor cannot bring up ANY surface here — is a documented SKIP (never a FAIL on
#     a compositor-less dev box or runner).
#   - With WARDOS_SMOKE_REQUIRE=1 every such gap is a FAILURE instead. The dedicated CI job
#     (`desktop-compositor` in .github/workflows/verify.yml) EXPLICITLY installs the compositor
#     stack and sets this, so the required check can NEVER go green via a skip — it must actually
#     exercise the boundary. The genuine end-to-end proof on real graphics hardware remains the
#     hardware boot (the USB build); this is the headless CI boundary.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

# In require-mode an environmental gap is a hard failure; otherwise a documented skip (exit 0).
# CI's desktop-compositor job sets WARDOS_SMOKE_REQUIRE=1 (it installs cage/foot/wlroots itself).
require="${WARDOS_SMOKE_REQUIRE:-}"

# audit LINE: print named evidence to the log AND, in CI, to the job step summary, so a green
# check is provably the boundary running (Proof A, the negative control, real-UI Proof B) rather
# than an environmental skip.
audit() {
  echo "$1"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then printf '%s\n' "$1" >>"$GITHUB_STEP_SUMMARY"; fi
}

if ! command -v cage >/dev/null 2>&1 || ! command -v foot >/dev/null 2>&1; then
  if [[ -n "$require" ]]; then
    fail "WARDOS_SMOKE_REQUIRE=1 but cage and/or foot is not installed — the required desktop-compositor job must exercise the boundary, not skip; install the compositor stack (cage foot wlroots)"
  fi
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
  diag=$(sed 's/^/    /' "$cage_log" 2>/dev/null || true)
  if [[ -n "$require" ]]; then
    fail "WARDOS_SMOKE_REQUIRE=1 but no surface came up here (headless wlroots backend unavailable) — the required desktop-compositor job must exercise the boundary, not skip. cage said:
$diag"
  fi
  echo "skip cage-smoke.test.sh: cage/foot are installed but no surface came up in this environment (headless wlroots backend unavailable here); cage said:"
  echo "$diag"
  echo "  (the CI desktop-compositor job runs this for real on Fedora; the final proof is the hardware boot)"
  exit 0
fi

# The surface came up. Now the authoritative liveness assertion: after the bounded interval the
# boundary must STILL be running — the first surface stayed alive rather than aborting.
sleep "$interval"
alive "$cage_pid" || fail "Proof A: the boundary did not stay alive for ${interval}s after the surface came up (cage exited); cage said:
$(cat "$cage_log" 2>/dev/null)"
teardown "$cage_pid"
audit "cage-smoke: Proof A EXECUTED and PASSED — cage+foot brought a surface up, ran the client (startup marker observed), and it stayed alive ${interval}s"

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
audit "cage-smoke: negative control EXECUTED and PASSED — a client that exits on startup was detected DEAD after ${interval}s (the smoke is not a no-op)"

# --- Proof B: the REAL shipped wardos-provision-ui stays alive under the real boundary ----
# Byte-for-byte the bootstrap command from wardos-greetd-session. The marker is absent, so the
# UI enters provisioning and blocks reading the terminal — it must NOT abort under cage (the
# T480s regression). Point WARDOS_LIB at the in-tree lib and the socket at an unused path (the
# UI blocks on input long before it would reach the broker), and put desktop/bin on PATH.
#
# POSITIVE real-UI evidence (#119 review): a bare `kill -0` on the outer cage PID can be satisfied
# by a cage/foot hang BEFORE the client is ever exec'd. So the client is a thin wrapper that writes
# a startup marker as its LAST act immediately BEFORE `exec`-ing the real wardos-provision-ui: the
# marker's presence proves foot actually ran the client and reached the real-UI exec, and where
# pgrep is available we further assert a wardos-provision-ui process is present as a descendant.
# This positive evidence is REQUIRED to appear (Proof A already proved the compositor can bring a
# surface up here, so a missing marker now is a genuine hang, not an environmental gap) BEFORE the
# liveness interval — a hang before client execution now FAILS rather than passing a bare kill -0.
export WARDOS_LIB="$WARDOS_ROOT/lib/wardos.sh"
export WARDOS_PROVISIONED_MARKER="$TMP/ui-provisioned" # absent → the UI runs the provisioning flow
export WARDOS_PROVISION_STAGE="$TMP/ui-stage"
export WARDOS_PROVISION_SOCK="$TMP/ui-nosock"
ui_up="$TMP/ui.up"
ui_client="$TMP/ui-client.sh"
cat >"$ui_client" <<EOF
#!/usr/bin/env bash
: >"$ui_up"
exec wardos-provision-ui
EOF
chmod +x "$ui_client"
: >"$cage_log"
cage -s -- foot --app-id wardos-provision -e "$ui_client" >"$cage_log" 2>&1 &
ui_pid=$!
# REQUIRED positive evidence: foot launched the client and reached the real-UI exec.
if ! wait_marker "$ui_up" 120; then
  teardown "$ui_pid"
  fail "Proof B: foot never launched the real wardos-provision-ui (startup marker absent) — cage/foot hung before client execution; cage said:
$(cat "$cage_log" 2>/dev/null)"
fi
# Extra descendant evidence where pgrep is available: the real UI process is actually present
# under the boundary (bounded poll, so the exec just after the marker is not raced).
ui_evidence="startup marker"
if command -v pgrep >/dev/null 2>&1; then
  ui_seen=0
  for ((i = 0; i < 30; i++)); do
    if pgrep -f 'wardos-provision-ui' >/dev/null 2>&1; then
      ui_seen=1
      break
    fi
    sleep 0.1
  done
  [[ "$ui_seen" -eq 1 ]] || {
    teardown "$ui_pid"
    fail "Proof B: no wardos-provision-ui process is present under the boundary after its startup marker; cage said:
$(cat "$cage_log" 2>/dev/null)"
  }
  ui_evidence="startup marker + live descendant"
fi
# Only now the liveness assertion: the real UI came up and did NOT abort on startup (T480s class).
sleep "$((interval + 2))"
alive "$ui_pid" || fail "Proof B: the real wardos-provision-ui aborted on startup under cage+foot (the T480s failure class); cage said:
$(cat "$cage_log" 2>/dev/null)"
teardown "$ui_pid"
audit "cage-smoke: real-UI Proof B EXECUTED and PASSED — foot launched the real wardos-provision-ui ($ui_evidence) and it stayed alive $((interval + 2))s under cage"

echo "ok   cage-smoke.test.sh internal assertions (real cage+foot+wardos-provision-ui boundary)"
