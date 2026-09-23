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
grep -q '(×N)' <<<"$help" || fail "--help names duplicate-notice grouping"

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

# --- --watch: "--once" does not return until every worker has actually relayed its
# answer, not merely until its notify-send child has exited (#224) -----------------
# notify_one still has to read $out, decide and call `ward session approve` after
# notify-send itself is gone; a mock `ward` slow enough to still be running when
# "--once" returns would prove the race the issue reported — an answer landing, as
# an orphan, after this round's run_dir (and in the real bug, the whole mock dir)
# was already torn down.
: >"$MOCK_LOG"
rm -f "$TMP/answered"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$LINE12" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) sleep 0.3; touch "$TMP/answered"; exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'echo deny'
WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
assert_file "$TMP/answered"

# --- --watch: a `ward session approve` call, and its own worker, still running
# past wait_for_notifiers' own grace window are both actually stopped — not just
# signalled — before run_dir is removed (#226 review) -----------------------------
# The previous case only proves the *ordinary* path (answered inside the grace
# window). This proves the boundary itself, the way the review specifically asked:
# by confirming neither the `ward` call's own pid nor its worker's (notify_one's
# own $BASHPID, observable from inside the mock as its $PPID — notify_one
# backgrounds `ward session approve` directly) still exists the instant
# "--watch --once" returns. The mock ignores TERM so only sweep_run_dir's KILL
# escalation, not the natural scheduling gap between a `kill` call and this check
# a few function returns later, can be what closes this — a bare `kill` alone does
# not prove termination (a killed pid routinely still answers `kill -0` right
# after), and checking only after an unforced delay would let that same gap paper
# over a sweep that never actually escalates or joins.
: >"$MOCK_LOG"
rm -f "$TMP/answer-pid" "$TMP/worker-pid"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$LINE12" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*)
    trap "" TERM
    printf "%s\n" "$$" >"$TMP/answer-pid"
    printf "%s\n" "$PPID" >"$TMP/worker-pid"
    sleep 20
    exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'echo deny'
WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
assert_file "$TMP/answer-pid"
assert_file "$TMP/worker-pid"
if kill -0 "$(cat "$TMP/answer-pid")" 2>/dev/null; then
  fail "the ward session approve call was still alive when --watch --once returned"
fi
if kill -0 "$(cat "$TMP/worker-pid")" 2>/dev/null; then
  fail "the worker was still alive when --watch --once returned"
fi

# --- sweep_run_dir: a killed answer is reaped before its worker is stopped, so
# neither is alive the instant sweep_run_dir returns (#226 review, exact-head
# 1a5865f) ------------------------------------------------------------------------
# The --watch --once case above checks only after the whole command has unwound,
# by which point the system reaper has usually collected an orphaned answer — it
# passed against the racy ordering. This checks at the exact return of the real
# sweep_run_dir (loaded from the script itself, not a copy), repeated because the
# race is a scheduling one: KILL the answer, then stop its worker before the
# worker's own `wait "$answer_pid"` has reaped it, and the answer is orphaned
# still alive. The answer ignores TERM so every round goes through the KILL
# escalation, the path the race lives on.
eval "$(sed -n '/^wait_deadline() {$/,/^}$/p; /^stop_answer() {$/,/^}$/p; /^stop_answers() {$/,/^}$/p; /^sweep_run_dir() {$/,/^}$/p' "$approve")"
# Two kinds of round: the worker resumes on its own mid-teardown (1.4s, inside the
# answer's escalation), and the worker is held stopped for the whole teardown —
# through both answer waits and the worker's own escalation boundary — so only
# sweep_run_dir making it runnable again can get the answer reaped (#226 review,
# exact-head 07f9525).
for round in resume-1 resume-2 held-1 held-2; do
  run_dir=$(mktemp -d "$TMP/sweep.XXXXXX")
  sweep_worker() {
    local worker_file=$run_dir/k.worker answer_file=$run_dir/k.answer answer_pid=""
    trap 'rm -f "$worker_file" "$answer_file"' RETURN
    # The same TERM handling notify_one itself has: stop and reap its own answer.
    trap '
      if [[ -n ${answer_pid:-} ]]; then
        kill "$answer_pid" 2>/dev/null || true
        wait_deadline "$answer_pid" 1
        kill -0 "$answer_pid" 2>/dev/null && kill -KILL "$answer_pid" 2>/dev/null
        wait "$answer_pid" 2>/dev/null || true
      fi
      exit 143
    ' TERM
    printf '%s\n' "$BASHPID" >"$worker_file"
    bash -c 'trap "" TERM; exec sleep 20' &
    answer_pid=$!
    printf '%s\n' "$answer_pid" >"$answer_file"
    wait "$answer_pid" 2>/dev/null || true
  }
  sweep_worker &
  for _ in $(seq 100); do [[ -s $run_dir/k.answer ]] && break; sleep 0.02; done
  answer_pid=$(cat "$run_dir/k.answer")
  worker_pid=$(cat "$run_dir/k.worker")
  # Model a worker that has not yet resumed from its own `wait` when its answer is
  # killed (the reviewer's scenario — descheduled, not merely busy: bash reaps a
  # finished child from its SIGCHLD handling whenever it runs at all). Hold the
  # worker stopped across the answer's TERM grace and KILL, and let it run again
  # shortly after. Stopping the worker in that gap (the old ordering) leaves a
  # TERM pending that kills it the instant it resumes, before it can reap, so the
  # answer is orphaned; waiting for the reap first (stop_answers) lets the resumed
  # worker reap it normally.
  kill -STOP "$worker_pid"
  resume_pid=""
  if [[ $round == resume-* ]]; then
    ( sleep 1.4; kill -CONT "$worker_pid" 2>/dev/null ) &
    resume_pid=$!
  fi
  sweep_run_dir
  if [[ -n $resume_pid ]]; then wait "$resume_pid" 2>/dev/null || true; fi
  if kill -0 "$answer_pid" 2>/dev/null; then
    kill -KILL "$answer_pid" 2>/dev/null || true
    fail "round $round: the answer was still alive when sweep_run_dir returned"
  fi
  if kill -0 "$worker_pid" 2>/dev/null; then
    fail "round $round: the worker was still alive when sweep_run_dir returned"
  fi
  rm -rf "$run_dir"
done
unset -v run_dir answer_pid worker_pid resume_pid

# --- --watch: notifier_loop's own .worker reservation never races notify_one's
# RETURN trap into recreating a stale marker for an already-finished pid (#226
# review) --------------------------------------------------------------------------
# An instant return (no notify-send at all, the fastest path through notify_one) is
# the worst case for this race: looped, to give the scheduler a chance to hit it,
# rather than asserted as a single run. This does not prove the ordering by timing
# alone (see notify_one's own comment for the actual argument: notify_one writes
# its own $BASHPID as its first action, strictly before its own later removal of
# the same file, instead of notifier_loop writing $! from a second, racing process)
# — it only proves nothing observably hangs, crashes, or leaves an unpicked-up
# approval behind across many fast rounds.
: >"$MOCK_LOG"
rm -f "$MOCK_DIR/notify-send"
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$LINE12" ;;
  '"$NOOP_APPROVALS_CASE"'
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
for _ in $(seq 1 50); do
  WARDOS_PROJECT=/home/dev/payments-api timeout 5 "$approve" --watch --once
done
assert_not_logged '^ward session approve'

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

# --- --watch: exact duplicates share one notification; answering it answers every id
# gathered under it (#146 item 7) — an agent that fires the same tool call twice
# before the first is answered, say, must not open two identical popups -----------
: >"$MOCK_LOG"
dup_a=$line12
dup_b=${line12/\"id\":12/\"id\":14}
export DUP_A=$dup_a DUP_B=$dup_b
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$DUP_A" "$DUP_B" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# A brief, realistic delay before answering (mirroring a person's reaction time, not
# an instant auto-dismiss): the second line's read is near-instant, but still a real
# race against this worker's own background startup, so this is what actually gives
# it room to land in ids_file before the popup is asked to show anything.
mock notify-send 'case "$*" in *--print-id*) echo 6161; sleep 0.2; echo session ;; *) exit 0 ;; esac'
# The count in the title is a snapshot taken shortly after the group's coalescing
# window (notify_one's own comment on it), racing the main loop's read of the second
# line the same way #224/#226 raced notify_one's startup against wait_for_notifiers —
# widened here well past that jitter so the assertion below tests the intended
# behaviour, not this environment's scheduling noise on any given run.
WARDOS_APPROVE_COALESCE_S=0.5 WARDOS_PROJECT=/home/dev/payments-api "$approve" --watch --once
[[ $(grep -c -- '--print-id' "$MOCK_LOG") -eq 1 ]] ||
  fail "two exact duplicates must share one popup, not open two: $(cat "$MOCK_LOG")"
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api \(×2\) <span alpha="39322">DESTINATION</span>$'
assert_not_logged 'payments-api <span'
assert_logged '^ward session approve --session sess_a 12 allow-session$'
assert_logged '^ward session approve --session sess_a 14 allow-session$'

# --- --watch: identical requests from two different live sessions are never grouped
# (#146 item 7: grouping never crosses sessions, even when title and body would
# otherwise read the same) ----------------------------------------------------------
: >"$MOCK_LOG"
dup_other_session='{"id":21,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":null},"requested_at_unix_ms":1,"agent":"claude","session":"sess_d","project":"payments-api"}'
export DUP_OTHER_SESSION=$dup_other_session
noop_sess_d='"session approvals --json --follow --session sess_d") : ;;'
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$LINE12" "$DUP_OTHER_SESSION" ;;
  '"$NOOP_APPROVALS_CASE"'
  '"$noop_sess_d"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'echo allow'
WARDOS_APPROVE_MAX_NOTIFIERS=2 WARDOS_PROJECT=/home/dev/payments-api "$approve" --watch --once
[[ $(grep -c -- '--print-id' "$MOCK_LOG") -eq 2 ]] ||
  fail "the same request from two different sessions must not be grouped: $(cat "$MOCK_LOG")"
assert_not_logged '×2'
assert_logged '^ward session approve --session sess_d 21 allow$'
assert_logged '^ward session approve --session sess_a 12 allow$'

# --- --watch: one of two duplicates is decided elsewhere while the group's popup is
# still open — it is left open for the other one, not replaced or re-answered, and the
# eventual sweep answers only what is left (#146 item 7) ----------------------------
: >"$MOCK_LOG"
dup_x=$line12
dup_y=${line12/\"id\":12/\"id\":16}
export DUP_X=$dup_x DUP_Y=$dup_y
decided16='{"approval":{"id":16,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export DECIDED16=$decided16
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$DUP_X" "$DUP_Y" ;;
  "session approvals --json --follow --session sess_a") sleep 0.3; printf "%s\n" "$DECIDED16" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# Never itself answers: stays open (--wait, killed only by the round's own sweep) so
# the only way id16 becomes terminal here is the resolver's decided record above.
mock notify-send 'case "$*" in *--print-id*) echo 5151; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
assert_not_logged '^notify-send .* -r 5151 Timed out — denied'
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 5151 Session ended — denied <tt></tt>$'
assert_not_logged '^ward session approve --session sess_a 16'
assert_not_logged '^ward session approve --session sess_a 12'

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
