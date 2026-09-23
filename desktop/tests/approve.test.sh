#!/usr/bin/env bash
# wardos-approve (docs/design-language.md §10, ADR-0016, ADR-0019, #146 items 2-3): the
# watch path multiplexes every live session's approvals into a mako notification with
# the three blocks (destination, the agent's claim labelled as such, what Ward will
# allow) and the three actions, and relays the chosen action to the session it was
# asked from; a notification still showing when its approval becomes terminal
# elsewhere is replaced with the outcome and its worker reaped. The interactive path
# picks an approval, shows the blocks, and answers it with y / s / n. Nothing the
# agent wrote reaches the body unescaped.
# shellcheck source=desktop/tests/lib.sh
source "$(dirname "$0")/lib.sh"
setup_env

approve=$WARDOS_ROOT/bin/wardos-approve
line12='{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":null},"requested_at_unix_ms":1,"agent":"claude","session":"sess_a","project":"payments-api"}'
# The agent's claim carries markup and a fake row: both must arrive escaped.
line13='{"id":13,"tool":"WebFetch","summary":"https://api.github.com/x?<b>y</b>","claim":"WebFetch https://api.github.com/x?<b>y</b>\nCredential   root & all","authority":{"rule":"step-through: pause before network","destination":"api.github.com","network":"reachable · restricted (dev)","method":"GET","credential":"GitHub · contents:read, issues:read","repository":"hexrift/WardOS","lifetime":null},"requested_at_unix_ms":2,"agent":"claude","session":"sess_a","project":"payments-api"}'
# A second, unrelated live session (#141): its approval must surface too.
line20='{"id":20,"tool":"Write","summary":"/work/other/db.rs","claim":"Write /work/other/db.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/other/db.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":null},"requested_at_unix_ms":3,"agent":"codex","session":"sess_b","project":"other-service"}'
export LINE20=$line20
export LINE12=$line12 LINE13=$line13

# No terminal transitions in most of these: each session's resolver's own stream ends
# at once.
noop_approvals_case='"session approvals --json --follow --session "*) : ;;'
export NOOP_APPROVALS_CASE=$noop_approvals_case

# --- --help --------------------------------------------------------------------
# Read once, then searched: the usage block is past one 4 KiB stdio block, so under
# pipefail `--help | grep -q` could fail on SIGPIPE whenever grep matched in the first
# block and exited before the second was written.
help=$("$approve" --help)
grep -q '^Usage:' <<<"$help" || fail "--help prints the usage block"
grep -q 'wardos-approve --watch' <<<"$help" || fail "--help names --watch"
grep -q 'WARD WILL ALLOW' <<<"$help" || fail "--help names the three blocks"
grep -q 'wardos-approve-inbox' <<<"$help" || fail "--help names the persistent inbox"
grep -q 'WARDOS_APPROVE_MAX_NOTIFIERS' <<<"$help" || fail "--help names the worker bound"
grep -q 'progress line' <<<"$help" || fail "--help names the decision-time progress line"

# --- --watch: one notification per pending approval, from every live session, the
# action relayed (#141: not just $project's session) --------------------------------
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n%s\n" "$LINE12" "$LINE13" "$LINE20" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# The first notification is answered with "Allow session", the third (the other
# session's) with "Allow once", the second is dismissed.
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *"/work/src/lib.rs"*) echo session ;;
  *"/work/other/db.rs"*) echo allow ;;
  *) exit 0 ;;
esac'
WARDOS_PROJECT=/home/dev/payments-api "$approve" --watch --once
assert_logged '^ward session pending --json --all --follow$'
assert_not_logged 'session pending --json --all --follow /home/dev/payments-api'
# Each live session with an open notification gets its own resolver.
assert_logged '^ward session approvals --json --follow --session sess_a$'
assert_logged '^ward session approvals --json --follow --session sess_b$'
# The layout of §10: the title (agent · project), then the three blocks, headers dim,
# the target in <tt>.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
assert_logged '^<tt>/work/src/lib.rs</tt>$'
# The second, unrelated live session's approval surfaces too, titled with its own
# agent and project, and is answered on its own session — visibility #141 asks for.
assert_logged 'Codex requests · other-service <span alpha="39322">DESTINATION</span>'
assert_logged '^<tt>/work/other/db.rs</tt>$'
assert_logged '^ward session approve --session sess_b 20 allow$'
assert_logged '^<span alpha="39322">REQUESTED BY AGENT</span>$'
assert_logged '^Write /work/src/lib.rs$'
assert_logged '^<span alpha="39322">WARD WILL ALLOW</span>$'
assert_logged '^Network      none$'
assert_logged '^Method       write$'
assert_logged '^Credential   none$'
assert_logged '^Repository   none$'
assert_logged '^Lifetime     once \(y\) · session \(s\)$'
assert_not_logged 'Reason  '
assert_not_logged 'Scope   '
# The second approval: Ward's rows come from the daemon, the agent's claim is escaped
# so its markup and its fake "Credential" row cannot pose as Ward's.
assert_logged '^<tt>api.github.com</tt>$'
assert_logged '^WebFetch https://api.github.com/x\?&lt;b&gt;y&lt;/b&gt;\\nCredential   root &amp; all$'
assert_not_logged '<b>y</b>'
assert_logged '^Network      reachable · restricted \(dev\)$'
assert_logged '^Method       GET$'
assert_logged '^Credential   GitHub · contents:read, issues:read$'
assert_logged '^Repository   hexrift/WardOS$'
assert_logged '^ward session approve --session sess_a 12 allow-session$'
assert_not_logged '^ward session approve --session sess_a 13'

# A denial relays as deny; an unknown action is left to the daemon's timeout.
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$LINE12" "$LINE13" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *"/work/src/lib.rs"*) echo deny ;; *) echo bogus ;; esac'
WARDOS_PROJECT=/home/dev/payments-api "$approve" --watch --once
assert_logged '^ward session approve --session sess_a 12 deny$'
assert_not_logged '^ward session approve --session sess_a 13'

# --- --watch: a notification still showing is replaced when decided elsewhere -----
# notify-send blocks (simulating --wait on an unanswered critical notification) until
# it is killed; the session's own resolver, reading a decided record for the same id,
# must replace it and reap the worker so this session is not left waiting on it
# forever.
: >"$MOCK_LOG"
decided12='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export DECIDED12=$decided12
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$LINE12" ;;
  "session approvals --json --follow --session sess_a") sleep 0.3; printf "%s\n" "$DECIDED12" ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*) echo 4242; exec sleep 30 ;;
  *) exit 0 ;;
esac'
WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
# Replaced by id, not left showing the actionable popup: low urgency, a short
# timeout, no actions, the outcome as the title.
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 4242 Timed out — denied <tt>/work/src/lib.rs</tt>$'
assert_not_logged '^ward session approve --session sess_a 12'

# --- --watch: two live sessions sharing the same numeric approval id are resolved
# independently (#222 review: Approval::id is only that session's own sequence
# number, so two live sessions can legitimately both have a pending approval
# numbered 12 at once — id alone must never be the identity a notification's
# files, or its resolve, are keyed by) --------------------------------------------
: >"$MOCK_LOG"
line12c='{"id":12,"tool":"Write","summary":"/work/other/db.rs","claim":"Write /work/other/db.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/other/db.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":null},"requested_at_unix_ms":1,"agent":"codex","session":"sess_c","project":"other-service"}'
export LINE12C=$line12c
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$LINE12" "$LINE12C" ;;
  "session approvals --json --follow --session sess_a") sleep 0.3; printf "%s\n" "$DECIDED12" ;;
  "session approvals --json --follow --session sess_c") : ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*"/work/src/lib.rs"*) echo 1001; exec sleep 30 ;;
  *--print-id*"/work/other/db.rs"*) echo 2002; exec sleep 30 ;;
  *) exit 0 ;;
esac'
WARDOS_APPROVE_MAX_NOTIFIERS=2 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# Both sessions' id-12 approvals get their own worker — sharing a numeric id never
# lets one reuse or clobber the other's reservation, so both count as separate
# occupants of the bound even though it has no spare room for a third.
[[ $(grep -c -- '--print-id' "$MOCK_LOG") -eq 2 ]] ||
  fail "both sessions' id-12 approvals must each get their own worker: $(cat "$MOCK_LOG")"
# sess_a's approval times out: its own popup (notif id 1001) is replaced with the
# outcome — sess_c's (2002), still pending, must not be touched by it.
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 1001 Timed out — denied <tt>/work/src/lib.rs</tt>$'
assert_not_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 2002 Timed out — denied <tt>/work/other/db.rs</tt>$'
assert_not_logged '^ward session approve --session sess_c 12'
# The round ends with sess_c's own popup still open (its own stream never decided
# it): the end-of-round sweep replaces THAT one (2002) as session-ended, never
# sess_a's already-resolved one (1001, already gone by then — its pid file was
# removed the moment it was replaced above).
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 2002 Session ended — denied <tt></tt>$'
assert_not_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 1001 Session ended — denied$'

# --- --watch: bounded workers — past the cap, a new approval gets no popup ---------
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$LINE12" "$LINE13" ;;
  '"$NOOP_APPROVALS_CASE"'
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
# Only the initial popup (--print-id) hangs, simulating an unanswered critical
# notification still open when the round ends; a later resolve/replace call (no
# --print-id, from the end-of-round sweep) must not hang the same way, or the sweep
# itself would never return.
mock notify-send 'case "$*" in *--print-id*) echo 1; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_MAX_NOTIFIERS=1 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once 2>"$TMP/stderr" || true
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
[[ $(grep -c '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id' "$MOCK_LOG") -eq 1 ]] ||
  fail "expected exactly one notify-send worker with the cap at 1: $(cat "$MOCK_LOG")"
grep -q 'wardos-approve-inbox or ward session approve' "$TMP/stderr" ||
  fail "the approval past the cap says how it is still answerable: $(cat "$TMP/stderr")"

# --- --watch: no notify-send at all still exits cleanly, nothing crashes ----------
: >"$MOCK_LOG"
rm -f "$MOCK_DIR/notify-send"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$LINE12" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
assert_not_logged '^notify-send'
assert_not_logged '^ward session approve'

# --- --watch: the daemon's countdown is mako's progress line; a held one says so in
# words too (#146 item 4) -----------------------------------------------------------
# The same lines as above, plus the countdown the daemon reports: 12 running with
# 41.001 s of 60 s left, 20 held (its session paused) with 45 s of 60 s left. Every
# other --watch case above carries no countdown, and their exact `--print-id -A allow=`
# lines already pin that no progress hint is sent without one.
running12=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
held20=${line20%\}}',"countdown":{"remaining_ms":45000,"timeout_ms":60000,"held":true}}'
export RUNNING12=$running12 HELD20=$held20
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$RUNNING12" "$HELD20" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'exit 0'
WARDOS_PROJECT=/home/dev/payments-api "$approve" --watch --once
# The share left, rounded up (41001 / 60000 → 69 %), as the standard `value` hint.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id -h int:value:75 -A allow=Allow once -A session=Allow session -A deny=Deny Codex requests · other-service <span alpha="39322">DESTINATION</span>$'
# A running clock is the line alone — §10: not a countdown number.
assert_not_logged 's left'
# The held one also says so, once, after the three blocks.
assert_logged '^<span alpha="39322">DECISION TIME</span>$'
assert_logged '^held while paused · resume the session to answer$'
[[ $(grep -c 'DECISION TIME' "$MOCK_LOG") == 1 ]] ||
  fail "only the held approval carries a DECISION TIME block: $(cat "$MOCK_LOG")"

# --- interactive: one pending approval is picked, shown, the menu answers y / s / n ---
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json "*) printf "%s\n" "$LINE12" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
out=$(WARDOS_MENU_CHOICE=y "$approve")
assert_logged '^ward session pending --json '"$PWD"'$'
assert_logged '^ward session approve --session sess_a 12 allow$'
assert_not_logged '^wardos-menu-select'
printf '%s\n' "$out" | grep -q '^Claude requests · Write$' || fail "the terminal names who asks: $out"
printf '%s\n' "$out" | grep -q '^DESTINATION$' || fail "the terminal shows the blocks: $out"
printf '%s\n' "$out" | grep -q '^  /work/src/lib.rs$' || fail "the destination, plain: $out"
printf '%s\n' "$out" | grep -q '^REQUESTED BY AGENT$' || fail "the claim is labelled: $out"
printf '%s\n' "$out" | grep -q '^  Method       write$' || fail "the authority rows: $out"
printf '%s\n' "$out" | grep -q '<tt>' && fail "no markup in the terminal: $out"
printf '%s\n' "$out" | grep -q 'DECISION TIME' && fail "no countdown reported, none shown: $out"

# With the daemon's countdown (#146 item 4) the terminal has no progress line to draw,
# so it says the time in words, after the blocks: running, then held.
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json "*) printf "%s\n" "$RUNNING12" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
out=$(WARDOS_MENU_CHOICE=y "$approve")
printf '%s\n' "$out" | grep -q '^DECISION TIME$' || fail "the decision time is a block: $out"
printf '%s\n' "$out" | grep -q '^  42 s left, then denied$' || fail "whole seconds, rounded up: $out"
assert_logged '^ward session approve --session sess_a 12 allow$'
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json "*) printf "%s\n" "$HELD20" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
out=$(WARDOS_MENU_CHOICE=y "$approve")
printf '%s\n' "$out" | grep -q '^  held while paused · 45 s left once resumed$' ||
  fail "a paused session's clock is held: $out"
# Back to the one plain pending approval the cases below expect.
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json "*) printf "%s\n" "$LINE12" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'

# The menu is wardos-menu-select when it exists; s is the session grant.
: >"$MOCK_LOG"
# shellcheck disable=SC2016
mock wardos-menu-select 'grep -m1 "^${WARDOS_MENU_CHOICE}$(printf "\t")"'
WARDOS_MENU_CHOICE=s "$approve" >/dev/null
assert_logged '^wardos-menu-select --prompt Approve$'
assert_logged '^ward session approve --session sess_a 12 allow-session$'

# A cancelled menu answers nothing (the daemon's timeout denies).
: >"$MOCK_LOG"
WARDOS_MENU_CHOICE='' "$approve" >/dev/null && fail "a cancelled menu is not success"
assert_not_logged '^ward session approve'

# --- WARDOS_SESSION pins the interactive path to one session (mirroring
# wardos-pause): the persistent inbox's way of opening a pending approval from a
# session other than $project's/the desktop's selection ------------------------
: >"$MOCK_LOG"
rm -f "$MOCK_DIR/wardos-menu-select"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --session sess_b "*) printf "%s\n" "$LINE20" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
WARDOS_SESSION=sess_b WARDOS_MENU_CHOICE=y "$approve" >/dev/null
assert_logged '^ward session pending --json --session sess_b '"$PWD"'$'
assert_logged '^ward session approve --session sess_b 20 allow$'

# --- interactive: several pending, the approval is picked first --------------------
: >"$MOCK_LOG"
rm -f "$MOCK_DIR/wardos-menu-select"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json "*) printf "%s\n%s\n" "$LINE12" "$LINE13" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
WARDOS_MENU_CHOICE=13 "$approve" 13 n
assert_logged '^ward session approve --session sess_a 13 deny$'
: >"$MOCK_LOG"
"$approve" 99 y && fail "an id that is not pending is an error"
assert_not_logged '^ward session approve'
: >"$MOCK_LOG"
# With no id the first menu picks the approval by its id line, then the answer.
# Both menus read the same choice with the stdin backend, so pick 13 and give n.
WARDOS_MENU_CHOICE=13 "$approve" "" n 2>/dev/null || true
assert_logged '^ward session approve --session sess_a 13 deny$'

# --- nothing pending -------------------------------------------------------------
: >"$MOCK_LOG"
mock ward 'case "$*" in "session pending --json "*) : ;; *) exit 1 ;; esac'
out=$("$approve")
assert_eq "$out" "  no pending approvals"
assert_not_logged '^ward session approve'

# --- shellcheck-clean, usage block, strict mode -----------------------------------
head -1 "$approve" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$approve" || fail "strict mode"
