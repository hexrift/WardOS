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

# Most of these do not care about the live-refresh loop (#146 item 4's live-refresh
# half, below) either: an unanswered "session pending --json --all" (no --follow —
# notify_one's own refresh tick, never notifier_loop's multiplexed stream) with
# nothing defined for it here is treated exactly like a decided approval — the
# refresh loop stops rather than erroring (current_countdown_for) — so this is a
# safe, explicit no-op for every test that is not itself exercising a refresh tick.
noop_refresh_case='"session pending --json --all") : ;;'
export NOOP_REFRESH_CASE=$noop_refresh_case

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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
# sweep_run_dir now also calls stop_refresh/stop_refreshes (#146 item 4's
# live-refresh half) unconditionally, so they must be loaded here too even
# though this test's own synthetic run_dir holds no .refresh files for them to
# act on.
eval "$(sed -n '/^wait_deadline() {$/,/^}$/p; /^stop_answer() {$/,/^}$/p; /^stop_answers() {$/,/^}$/p; /^stop_refresh() {$/,/^}$/p; /^stop_refreshes() {$/,/^}$/p; /^sweep_run_dir() {$/,/^}$/p' "$approve")"
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

# --- sweep_run_dir: a killed refresh loop is reaped before its worker is stopped,
# so neither is alive the instant sweep_run_dir returns (#146 item 4 review: the
# same class of orphan #226 already fixed for a `ward session approve` call —
# stop_refresh, mirroring stop_answer — now proven for the live-refresh loop) -----
# The worker is held stopped for the whole teardown, through the refresh loop's own
# TERM/KILL escalation, mirroring the answer test's own "held" rounds above: only
# sweep_run_dir making the worker runnable again lets it reap its own refresh loop.
# The refresh loop ignores TERM so this goes through the KILL escalation, the path
# the equivalent #226 race for answer_pids lived on.
run_dir=$(mktemp -d "$TMP/sweep-refresh.XXXXXX")
refresh_test_worker() {
  local worker_file=$run_dir/k.worker refresh_file=$run_dir/k.refresh refresh_pid=""
  trap 'rm -f "$worker_file" "$refresh_file"' RETURN
  # The same TERM handling notify_one itself now has for its own refresh_pid.
  trap '
    if [[ -n ${refresh_pid:-} ]]; then
      kill "$refresh_pid" 2>/dev/null || true
      wait "$refresh_pid" 2>/dev/null || true
    fi
    exit 143
  ' TERM
  printf '%s\n' "$BASHPID" >"$worker_file"
  bash -c 'trap "" TERM; exec sleep 20' &
  refresh_pid=$!
  printf '%s\n' "$refresh_pid" >"$refresh_file"
  wait "$refresh_pid" 2>/dev/null || true
}
refresh_test_worker &
for _ in $(seq 100); do [[ -s $run_dir/k.refresh ]] && break; sleep 0.02; done
refresh_pid=$(cat "$run_dir/k.refresh")
worker_pid=$(cat "$run_dir/k.worker")
kill -STOP "$worker_pid"
sweep_run_dir
if kill -0 "$refresh_pid" 2>/dev/null; then
  kill -KILL "$refresh_pid" 2>/dev/null || true
  fail "the refresh loop was still alive when sweep_run_dir returned"
fi
if kill -0 "$worker_pid" 2>/dev/null; then
  fail "the worker was still alive when sweep_run_dir returned"
fi
rm -rf "$run_dir"
unset -v run_dir refresh_pid worker_pid

# --- sweep_run_dir: an empty reserved .refresh marker is an ownership handoff,
# not a two-second scheduling deadline. A refresh child held before publishing its
# marker for longer than the old timeout is still reaped through its owning worker,
# and cannot wake later to recreate state after the sweep returned (#250) ----------
run_dir=$(mktemp -d "$TMP/sweep-refresh-handoff.XXXXXX")
rm -f "$TMP/delayed_refresh_pid"
refresh_handoff_worker() {
  local worker_file=$run_dir/k.worker refresh_file=$run_dir/k.refresh
  local refresh_pid="" refresh_spawning=0
  trap 'rm -f "$worker_file" "$refresh_file"' RETURN
  trap '
    if [[ -z $refresh_pid && $refresh_spawning -eq 1 ]]; then refresh_pid=$!; fi
    if [[ -n $refresh_pid ]]; then
      kill "$refresh_pid" 2>/dev/null || true
      wait_deadline "$refresh_pid" 1
      if kill -0 "$refresh_pid" 2>/dev/null; then
        kill -KILL "$refresh_pid" 2>/dev/null || true
      fi
      wait "$refresh_pid" 2>/dev/null || true
    fi
    exit 143
  ' TERM
  printf '%s\n' "$BASHPID" >"$worker_file"
  : >"$refresh_file"
  refresh_spawning=1
  bash -c 'printf "%s\n" "$$" >"$1"; trap "" TERM; sleep 5; printf "%s\n" "$$" >"$2"; exec sleep 20' \
    _ "$TMP/delayed_refresh_pid" "$refresh_file" &
  refresh_pid=$!
  refresh_spawning=0
  wait "$refresh_pid" 2>/dev/null || true
}
refresh_handoff_worker &
for _ in $(seq 100); do
  [[ -s $run_dir/k.worker && -f $run_dir/k.refresh && -s $TMP/delayed_refresh_pid ]] && break
  sleep 0.02
done
worker_pid=$(cat "$run_dir/k.worker")
refresh_pid=$(cat "$TMP/delayed_refresh_pid")
[[ ! -s $run_dir/k.refresh ]] || fail "handoff marker must still be empty before the delayed child publishes"
sweep_run_dir
if kill -0 "$worker_pid" 2>/dev/null; then fail "handoff owner survived sweep_run_dir"; fi
if kill -0 "$refresh_pid" 2>/dev/null; then
  kill -KILL "$refresh_pid" 2>/dev/null || true
  fail "delayed refresh child survived the empty-marker handoff sweep"
fi
[[ ! -e $run_dir/k.refresh ]] || fail "empty refresh reservation survived teardown"
rm -rf "$run_dir"
unset -v run_dir refresh_pid worker_pid

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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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
  '"$NOOP_REFRESH_CASE"'
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

# --- --watch: a second identical pending record delivered after the first popup
# exits (its notify-send child is gone) but before its worker actually finishes
# reading its own membership must join that same still-open generation, not reuse
# its files for a second one and misdirect or lose the first's ids (#228 review,
# round 2: round 1's own fix still let this happen, because releasing .worker and
# then sweeping every marker naming key were two separate, unsynchronised steps —
# a new generation could claim key the instant .worker was gone, and the old
# generation's own sweep, still running, could delete that brand new generation's
# marker right back out, since it too matched key). Forced, not hoped for: a
# barrier on notify_one's own `tail -n1 "$out"` — the one external command between
# the popup closing and this worker reading its own .ids — holds it open for a
# real 0.3s window, and the third pending line is not even written until that
# barrier confirms the window has started -------------------------------------
: >"$MOCK_LOG"
rm -f "$TMP/notify_one_past_action"
gen_a=$line12
gen_b=${line12/\"id\":12/\"id\":15}
export GEN_A=$gen_a GEN_B=$gen_b
# tail is called exactly once in wardos-approve, as notify_one's own "$out" read;
# every other call in this test file is real tail. Computes the true answer at once,
# signals it is about to hand it back, then sits on it — reproducing exactly the
# window #228 found unprotected, not a guess at when it might occur.
# shellcheck disable=SC2016
mock tail 'out=$(command -p tail "$@"); : >"$TMP/notify_one_past_action"; sleep 0.3; printf "%s\n" "$out"'
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow")
    printf "%s\n" "$GEN_A"
    for _ in $(seq 1 200); do [[ -f "$TMP/notify_one_past_action" ]] && break; sleep 0.01; done
    printf "%s\n" "$GEN_B"
    ;;
  '"$NOOP_REFRESH_CASE"'
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'echo allow'
WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
[[ $(grep -c -- '--print-id' "$MOCK_LOG") -eq 1 ]] ||
  fail "a duplicate arriving in this exact window must join the one open popup, never a second: $(cat "$MOCK_LOG")"
assert_logged '^ward session approve --session sess_a 12 allow$'
assert_logged '^ward session approve --session sess_a 15 allow$'

# --- --watch: a resolver removing one id from a group and notifier_loop appending
# another to the very same still-open .ids file must not lose either write (#228
# review, round 2). Forced, not hoped for: a barrier on resolve_notification's own
# `grep -vFx` — its only external command, and the one place it reads .ids —
# computes the true (pre-append) filtered result at once, signals it, then sits on
# it for 0.3s; the append is not even attempted until that signal fires, so it
# always lands while the resolver's read is stale and its write has not happened
# yet — exactly the interleaving that loses the append without key.lock ----------
: >"$MOCK_LOG"
mock tail 'command -p tail "$@"'
rm -f "$TMP/race_setup_done" "$TMP/resolver_past_read"
race_a=$line12
race_b=${line12/\"id\":12/\"id\":17}
race_c=${line12/\"id\":12/\"id\":18}
export RACE_A=$race_a RACE_B=$race_b RACE_C=$race_c
decided17='{"approval":{"id":17,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export DECIDED17=$decided17
# grep -vFx 17 is resolve_notification's only call, for this id only; every other
# grep in this test file (including assert_logged's own) passes straight through.
# shellcheck disable=SC2016
mock grep 'if [[ "$*" == "-vFx 17 "* ]]; then
  out=$(command -p grep "$@")
  : >"$TMP/resolver_past_read"
  sleep 0.3
  printf "%s\n" "$out"
else
  command -p grep "$@"
fi'
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow")
    printf "%s\n%s\n" "$RACE_A" "$RACE_B"
    # A settle delay, not a race of its own: comfortably more than local pipe/jq/read
    # latency for two lines, so notifier_loop has certainly joined 17 into the group
    # (its own id marker written) before this signals the resolver below to act on
    # it — the race under test is only the one the grep barrier forces, next.
    sleep 0.2
    : >"$TMP/race_setup_done"
    for _ in $(seq 1 200); do [[ -f "$TMP/resolver_past_read" ]] && break; sleep 0.01; done
    printf "%s\n" "$RACE_C"
    ;;
  '"$NOOP_REFRESH_CASE"'
  "session approvals --json --follow --session sess_a")
    for _ in $(seq 1 200); do [[ -f "$TMP/race_setup_done" ]] && break; sleep 0.01; done
    printf "%s\n" "$DECIDED17"
    ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 7171; sleep 0.6; echo allow ;; *) exit 0 ;; esac'
WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
[[ $(grep -c -- '--print-id' "$MOCK_LOG") -eq 1 ]] ||
  fail "17, 18 and 12 are one key: only one popup, whatever races land on its .ids: $(cat "$MOCK_LOG")"
assert_logged '^ward session approve --session sess_a 12 allow$'
assert_logged '^ward session approve --session sess_a 18 allow$'
assert_not_logged '^ward session approve --session sess_a 17'

# --- --watch: a same-key duplicate arriving while a just-resolved generation's
# popup is still being closed gets its own new popup, never silently dropped
# against a generation whose membership resolve_notification has already emptied
# (#228 review, round 3, item 1: key.current was left naming the closed-out
# generation until notify_one's own eventual close_generation got around to
# clearing it — a same-key arrival in that gap joined a membership file that no
# longer existed and was never answered by anyone). Forced, not hoped for: a
# barrier on finish_notification's own notify-send replace call (its only external
# command) holds it open for a real 0.3s window after resolve_notification's own
# locked section — which now clears key.current itself — has already completed,
# and the duplicate is not written until that barrier confirms the window has
# started -----------------------------------------------------------------------
: >"$MOCK_LOG"
mock tail 'command -p tail "$@"'
mock grep 'command -p grep "$@"'
rm -f "$TMP/fin_setup_done" "$TMP/finish_notification_started" "$TMP/first_popup_seen"
fin_a=$line12
fin_b=${line12/\"id\":12/\"id\":19}
export FIN_A=$fin_a FIN_B=$fin_b
decided12='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export DECIDED12=$decided12
# The first --print-id call is this generation's own popup: it never itself
# answers (killed only by finish_notification below, once the resolver decides its
# sole member elsewhere), so the only way id 12 could be relayed is a bug. The
# second is the duplicate's own new popup, answered normally.
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*)
    if [[ -f "$TMP/first_popup_seen" ]]; then
      echo allow
    else
      : >"$TMP/first_popup_seen"
      echo 9191
      exec sleep 30
    fi
    ;;
  *"-t 4000"*) : >"$TMP/finish_notification_started"; sleep 0.3; exit 0 ;;
  *) exit 0 ;;
esac'
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow")
    printf "%s\n" "$FIN_A"
    # A settle delay, not a race of its own (see the earlier .ids race test):
    # comfortably more than local pipe/jq/read latency, so notifier_loop has
    # certainly opened 12'"'"'s own generation (marker and .ids both published,
    # atomically, by open_new_generation) before this signals the resolver below.
    sleep 0.2
    : >"$TMP/fin_setup_done"
    for _ in $(seq 1 300); do [[ -f "$TMP/finish_notification_started" ]] && break; sleep 0.01; done
    printf "%s\n" "$FIN_B"
    ;;
  '"$NOOP_REFRESH_CASE"'
  "session approvals --json --follow --session sess_a")
    for _ in $(seq 1 200); do [[ -f "$TMP/fin_setup_done" ]] && break; sleep 0.01; done
    printf "%s\n" "$DECIDED12"
    ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
[[ $(grep -c -- '--print-id' "$MOCK_LOG") -eq 2 ]] ||
  fail "a same-key duplicate arriving while the resolved generation's popup is still closing must get its own popup: $(cat "$MOCK_LOG")"
assert_logged '^ward session approve --session sess_a 19 allow$'
assert_not_logged '^ward session approve --session sess_a 12'

# --- --watch: a resolver's terminal event for a brand-new id and notifier_loop's
# own first arrival of that id, delivered with no settle between them at all, never
# answer the id more than once (#228 review, round 3, item 2: join_open_generation
# and open_new_generation used to publish an id's own membership marker only after
# releasing key.lock, so a resolver arriving in that gap found no marker, did
# nothing, and this worker later relayed an answer for an id the daemon had already
# decided elsewhere). The marker is now published under the same lock, and by the
# same subshell, as the membership write itself — the two are never two events for
# a barrier to land between, so unlike the other tests here this one is not a forced
# reproduction of a specific interleaving; it is a standing invariant check under
# realistic adversarial timing (no settle delay at all, both sides going as fast as
# they can) that this worker still never answers an id more than once ------------
: >"$MOCK_LOG"
mock tail 'command -p tail "$@"'
mock grep 'command -p grep "$@"'
new_a=$line12
export NEW_A=$new_a
decided12_fast='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export DECIDED12_FAST=$decided12_fast
mock notify-send 'case "$*" in *--print-id*) echo 4242; sleep 0.3; echo allow ;; *) exit 0 ;; esac'
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$NEW_A" ;;
  '"$NOOP_REFRESH_CASE"'
  "session approvals --json --follow --session sess_a") printf "%s\n" "$DECIDED12_FAST" ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
[[ $(grep -c -- '^ward session approve --session sess_a 12' "$MOCK_LOG") -le 1 ]] ||
  fail "id 12 must never be answered by this worker more than once, whatever order the resolver and the first arrival land in: $(cat "$MOCK_LOG")"

# --- --watch: if the daemon-backed resolver removes the last group member before
# this popup's own click is relayed, zero attempted relays are not confirmation of
# that local click. Hold the resolver exactly after membership removal and before its
# terminal replacement; notify_one must leave the tracked popup alone until the
# resolver publishes the authoritative daemon outcome (#250) -----------------------
: >"$MOCK_LOG"
rm -f "$TMP/empty_ids_popup_ready" "$TMP/resolve_barrier.reached" "$TMP/resolve_barrier.release"
empty_ids_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
empty_ids_decided='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export EMPTY_IDS_RUNNING=$empty_ids_running EMPTY_IDS_DECIDED=$empty_ids_decided
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$EMPTY_IDS_RUNNING" ;;
  "session approvals --json --follow --session sess_a")
    for _ in $(seq 1 300); do [[ -f "$TMP/empty_ids_popup_ready" ]] && break; sleep 0.01; done
    printf "%s\n" "$EMPTY_IDS_DECIDED"
    ;;
  '"$NOOP_REFRESH_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*)
    echo 6363
    : >"$TMP/empty_ids_popup_ready"
    for _ in $(seq 1 500); do [[ -f "$TMP/resolve_barrier.reached" ]] && break; sleep 0.01; done
    echo deny
    ;;
  *) exit 0 ;;
esac'
WARDOS_TESTING=1 WARDOS_TEST_RESOLVE_BARRIER="$TMP/resolve_barrier" \
  WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once &
approve_pid=$!
for _ in $(seq 1 500); do [[ -f "$TMP/resolve_barrier.reached" ]] && break; sleep 0.01; done
assert_file "$TMP/resolve_barrier.reached"
sleep 0.2
assert_not_logged '^ward session approve --session sess_a 12 deny$'
assert_not_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 6363 Denied <tt>/work/src/lib.rs</tt>$'
: >"$TMP/resolve_barrier.release"
wait "$approve_pid"
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 6363 Timed out — denied <tt>/work/src/lib.rs</tt>

# --- --watch: an already-open notification's countdown/progress hint refreshes in
# place across ticks, from the daemon's own current countdown each time, rather than
# staying frozen at whatever it was when the popup opened (#146 item 4's live-refresh
# half) --------------------------------------------------------------------------
: >"$MOCK_LOG"
rm -f "$TMP/refresh_ticks"
tick1=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
tick2=${line12%\}}',"countdown":{"remaining_ms":9001,"timeout_ms":60000,"held":false}}'
export TICK1=$tick1 TICK2=$tick2
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$RUNNING12" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session pending --json --all")
    n=$(( $(cat "$TMP/refresh_ticks" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" >"$TMP/refresh_ticks"
    if (( n == 1 )); then printf "%s\n" "$TICK1"; else printf "%s\n" "$TICK2"; fi
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# Never itself answers: stays open (--wait, killed only by the round's own
# end-of-round sweep) so a small refresh interval gets several ticks in before then.
mock notify-send 'case "$*" in *--print-id*) echo 3131; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# 41001/60000 -> 69 %, 9001/60000 -> 16 %: the same rounding-up share
# progress_value already uses elsewhere, now read fresh on two different ticks of
# the same still-open popup (notify-send -r 3131, never --print-id again) rather
# than opening — or staying frozen as — one popup for the whole time it is open.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 3131 -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 3131 -h int:value:16 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
[[ $(grep -c -- '--print-id' "$MOCK_LOG") -eq 1 ]] ||
  fail "a refresh tick must never open a second popup: $(cat "$MOCK_LOG")"

# --- --watch: a refresh tick that is already mid-flight when its approval becomes
# terminal elsewhere must not resurrect the notification with stale pending content
# afterward (#146 item 4 review — the resolved-during-refresh race) ---------------
# Forced, not hoped for: a barrier on the refresh tick's own daemon query (its
# only external command between reading a — by then already stale — "still
# pending" answer and deciding whether to replace the popup with it) holds that
# query open until the resolver's own terminal replace has already completed, so
# the tick's own with_notiflock check is guaranteed to find pid_file already gone
# — proving the lock actually closes the race rather than merely not having lost
# it by luck on this run.
: >"$MOCK_LOG"
rm -f "$TMP/refresh_query_started" "$TMP/finish_done"
race_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
race_decided='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export RACE_RUNNING=$race_running RACE_DECIDED=$race_decided
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$RACE_RUNNING" ;;
  "session pending --json --all")
    : >"$TMP/refresh_query_started"
    for _ in $(seq 1 300); do [[ -f "$TMP/finish_done" ]] && break; sleep 0.01; done
    printf "%s\n" "$RACE_RUNNING"
    ;;
  "session approvals --json --follow --session sess_a")
    for _ in $(seq 1 300); do [[ -f "$TMP/refresh_query_started" ]] && break; sleep 0.01; done
    printf "%s\n" "$RACE_DECIDED"
    ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# The finish barrier is on this mock's own "-t 4000" replace call (finish_notification's
# only external command): it signals the instant that replace has actually happened,
# which is what the refresh tick above is really waiting to be true before it acts.
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*) echo 8181; exec sleep 30 ;;
  *"-t 4000"*) : >"$TMP/finish_done" ;;
  *) exit 0 ;;
esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# Resolved exactly once, with the outcome — never re-shown as pending afterward,
# and the refresh tick that raced it never got to replace anything at all.
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 8181 Timed out — denied <tt>/work/src/lib.rs</tt>$'
assert_not_logged '^notify-send -a WardOS -c ward-approval -u critical -r 8181'

# --- --watch: a refresh tick already mid-flight when the popup's own action is
# answered (the self-decided/timed-out counterpart of the race above, #250 review)
# must not be able to land more than the one redraw it was already committed to,
# and the notification's own final content must be the real outcome — never that
# stale redraw — because notify_one's own cleanup both retires pid_file and
# corrects the notification in the same locked step, ordered after any in-flight
# tick (#250 review, second round) ------------------------------------------------
# Forced the same way as the race above: the tick's own "-u critical -r" call is
# barriered so it is guaranteed to still be inside with_notiflock, mid-notify-send,
# the instant notify-send --print-id returns "deny". Confirms three things: the
# already in-flight tick is still allowed to finish (with_notiflock does not reach
# into a call already running under the lock — only orders whichever of this and a
# later tick's own check-then-act runs next), that no later tick ever gets that far
# again once pid_file is gone, and that the notification's own last write is the
# real "Denied" outcome, not the tick's stale "still pending" redraw.
: >"$MOCK_LOG"
rm -f "$TMP/orphan_refresh_started" "$TMP/orphan_release" "$TMP/orphan_refresh_done"
orphan_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
export ORPHAN_RUNNING=$orphan_running
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$ORPHAN_RUNNING" ;;
  "session pending --json --all") printf "%s\n" "$ORPHAN_RUNNING" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*) echo 5252; sleep 0.15; echo deny ;;
  *"-u critical -r "*)
    : >"$TMP/orphan_refresh_started"
    for _ in $(seq 1 500); do [[ -f "$TMP/orphan_release" ]] && break; sleep 0.01; done
    : >"$TMP/orphan_refresh_done"
    exit 0 ;;
  *) exit 0 ;;
esac'
# Backgrounded, not run to completion first: notify_one's own fixed cleanup now
# takes with_notiflock before removing pid_file, so it legitimately blocks for as
# long as the tick above is still inside that same lock — "--once" itself does not
# return until every worker has actually finished (#224, the case above), so it
# cannot be used here to observe the tick mid-flight the way the race above did.
# refresh_interval (0.02s) is far shorter than the --print-id delay (0.15s) above
# on purpose: the first tick fires almost immediately and, once it is barriered
# here, holds with_notiflock for as long as the barrier does — refresh_loop is
# strictly sequential (it does not start a next tick until this one's own
# with_notiflock call returns), so nothing else can race in behind it. The
# foreground side holds the barrier well past the --print-id delay before
# releasing it, so notify_one's own cleanup has certainly already reached, and
# is already queued behind, this same lock by the time it opens.
WARDOS_APPROVE_REFRESH_S=0.02 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once &
approve_pid=$!
for _ in $(seq 1 300); do [[ -f "$TMP/orphan_refresh_started" ]] && break; sleep 0.01; done
assert_file "$TMP/orphan_refresh_started"
[[ -f "$TMP/orphan_refresh_done" ]] &&
  fail "the refresh tick's notify-send call must still be an unreleased orphan while notify_one's cleanup waits on it"
sleep 0.3
: >"$TMP/orphan_release"
wait "$approve_pid"
assert_file "$TMP/orphan_refresh_done"
assert_logged '^ward session approve --session sess_a 12 deny$'
# The one already-committed redraw is allowed to land...
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 5252 .*-A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api'
# ...but with_notiflock's ordering means pid_file is already gone by the time any
# later tick could check it, so refresh_loop stops itself rather than looping again.
[[ $(grep -c -- '-u critical -r 5252' "$MOCK_LOG") -le 1 ]] ||
  fail "at most the one already in-flight redraw may land, never another after cleanup: $(cat "$MOCK_LOG")"
# ...and notify_one's own cleanup corrects the notification right after — the
# same lock, requested while the tick above already held it, so this is always
# the next write and therefore the last thing on screen, never the tick's stale
# "still pending" content with dead, actionable-looking buttons.
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 5252 Denied <tt>/work/src/lib.rs</tt>$'
last_pending=$(grep -n -- '-u critical -r 5252' "$MOCK_LOG" | tail -1 | cut -d: -f1)
corrected=$(grep -n -- '-u low -t 4000 -r 5252 Denied' "$MOCK_LOG" | tail -1 | cut -d: -f1)
[[ -n $last_pending && -n $corrected && $corrected -gt $last_pending ]] ||
  fail "the real outcome must be written after every stale redraw, not before: $(cat "$MOCK_LOG")"

# --- --watch: a transient daemon/jq failure on a refresh tick's own query does not
# permanently stop the live refresh — only that one tick is skipped, the same as
# every other command in this loop that can fail (#250 review, second round:
# `current_countdown_for ... || return 0` treated every failure, including a
# passing daemon hiccup, as "nothing left to refresh", contrary to the "skip a
# tick" behaviour this file's own comments already claim for the loop) --------------
: >"$MOCK_LOG"
rm -f "$TMP/transient_ticks"
recovers_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
export RECOVERS_RUNNING=$recovers_running
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$RECOVERS_RUNNING" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session pending --json --all")
    n=$(( $(cat "$TMP/transient_ticks" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" >"$TMP/transient_ticks"
    if (( n == 1 )); then
      echo "ward: daemon unreachable" >&2
      exit 1
    fi
    printf "%s\n" "$RECOVERS_RUNNING"
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 7171; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# The first, failing tick must not be the last: a redraw from a later, succeeding
# tick still lands — the loop survived the one failure instead of exiting on it.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 7171 -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
[[ $(cat "$TMP/transient_ticks" 2>/dev/null || echo 0) -ge 2 ]] ||
  fail "the query must be retried after a transient failure, not abandoned: only $(cat "$TMP/transient_ticks" 2>/dev/null || echo 0) attempt(s)"

# --- --watch: a refresh tick whose representative id resolves elsewhere while an
# exact duplicate is still gathered under the same popup switches to that surviving
# member instead of stopping the whole live refresh (#250 review, second round:
# current_countdown_for failing for one id — because the group's daemon-reported
# membership moved on, not because the daemon or jq failed — must not be read as
# "nothing left to refresh" when a fresh read of the group's own members, right
# there in the next two lines, says otherwise) --------------------------------------
: >"$MOCK_LOG"
rm -f "$TMP/switch_id12_gone" "$TMP/switch_ready"
switch_dup_a=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
switch_dup_b=${line12/\"id\":12/\"id\":14}
switch_dup_b=${switch_dup_b%\}}',"countdown":{"remaining_ms":9001,"timeout_ms":60000,"held":false}}'
switch_decided_12='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"remembered","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export SWITCH_DUP_A=$switch_dup_a SWITCH_DUP_B=$switch_dup_b SWITCH_DECIDED_12=$switch_decided_12
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$SWITCH_DUP_A" "$SWITCH_DUP_B" ;;
  "session approvals --json --follow --session sess_a")
    for _ in $(seq 1 300); do [[ -f "$TMP/switch_ready" ]] && break; sleep 0.01; done
    printf "%s\n" "$SWITCH_DECIDED_12"
    ;;
  "session pending --json --all")
    if [[ -f "$TMP/switch_id12_gone" ]]; then
      printf "%s\n" "$SWITCH_DUP_B"
    else
      printf "%s\n%s\n" "$SWITCH_DUP_A" "$SWITCH_DUP_B"
    fi
    ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 8282; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once &
approve_pid=$!
# id 12 is the group's representative (inserted first): the first tick(s) show
# its own countdown (41001/60000 -> 69 %).
wait_logged '^notify-send -a WardOS -c ward-approval -u critical -r 8282 -h int:value:69 '
# id 12 becomes terminal — resolve_notification removes it from the group's own
# ids file, leaving 14 as the sole surviving member — and, from here on, the
# daemon no longer reports it pending either.
: >"$TMP/switch_id12_gone"
: >"$TMP/switch_ready"
# A later tick must pick up id 14's own countdown (9001/60000 -> 16 %) instead of
# the loop having stopped the moment id 12 stopped being reported.
wait_logged '^notify-send -a WardOS -c ward-approval -u critical -r 8282 -h int:value:16 '
wait "$approve_pid"

# --- --watch: a pause (and resume) that happens after the notification opened is
# reflected on the next refresh tick — the countdown visibly holds, then resumes
# counting, from the daemon's own held/remaining_ms accounting (PR #225), with no
# pause notion of this script's own (#146 item 4's live-refresh half) -------------
: >"$MOCK_LOG"
rm -f "$TMP/pause_ticks"
open_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
after_pause=${line12%\}}',"countdown":{"remaining_ms":20000,"timeout_ms":60000,"held":true}}'
after_resume=${line12%\}}',"countdown":{"remaining_ms":15000,"timeout_ms":60000,"held":false}}'
export OPEN_RUNNING=$open_running AFTER_PAUSE=$after_pause AFTER_RESUME=$after_resume
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$OPEN_RUNNING" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session pending --json --all")
    n=$(( $(cat "$TMP/pause_ticks" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" >"$TMP/pause_ticks"
    if (( n == 1 )); then printf "%s\n" "$AFTER_PAUSE"; else printf "%s\n" "$AFTER_RESUME"; fi
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 4141; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# Opened running: no DECISION TIME block yet, only the progress hint (69 %).
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
# First refresh tick: paused after opening — the same wording a freshly-opened held
# popup already uses, now shown on a refresh of one that opened running; the hint
# holds at the daemon's own reported share (20000/60000 -> 34 %), not still ticking
# down on its own.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 4141 -h int:value:34 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
# Second refresh tick: resumed — the DECISION TIME block is gone again and the hint
# moves on from where the pause left it (15000/60000 -> 25 %), not from 69 % as
# though the pause had never happened.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 4141 -h int:value:25 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
assert_logged '^held while paused · resume the session to answer$'
[[ $(grep -c 'DECISION TIME' "$MOCK_LOG") == 1 ]] ||
  fail "only the paused refresh tick carries a DECISION TIME block: $(cat "$MOCK_LOG")"

# --- shellcheck-clean, usage block, strict mode -----------------------------------
head -1 "$approve" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$approve" || fail "strict mode"

assert_not_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 6363 Session ended — denied '
assert_not_logged '^ward session approve --session sess_a 12 deny

# --- --watch: an already-open notification's countdown/progress hint refreshes in
# place across ticks, from the daemon's own current countdown each time, rather than
# staying frozen at whatever it was when the popup opened (#146 item 4's live-refresh
# half) --------------------------------------------------------------------------
: >"$MOCK_LOG"
rm -f "$TMP/refresh_ticks"
tick1=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
tick2=${line12%\}}',"countdown":{"remaining_ms":9001,"timeout_ms":60000,"held":false}}'
export TICK1=$tick1 TICK2=$tick2
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$RUNNING12" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session pending --json --all")
    n=$(( $(cat "$TMP/refresh_ticks" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" >"$TMP/refresh_ticks"
    if (( n == 1 )); then printf "%s\n" "$TICK1"; else printf "%s\n" "$TICK2"; fi
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# Never itself answers: stays open (--wait, killed only by the round's own
# end-of-round sweep) so a small refresh interval gets several ticks in before then.
mock notify-send 'case "$*" in *--print-id*) echo 3131; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# 41001/60000 -> 69 %, 9001/60000 -> 16 %: the same rounding-up share
# progress_value already uses elsewhere, now read fresh on two different ticks of
# the same still-open popup (notify-send -r 3131, never --print-id again) rather
# than opening — or staying frozen as — one popup for the whole time it is open.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 3131 -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 3131 -h int:value:16 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
[[ $(grep -c -- '--print-id' "$MOCK_LOG") -eq 1 ]] ||
  fail "a refresh tick must never open a second popup: $(cat "$MOCK_LOG")"

# --- --watch: a refresh tick that is already mid-flight when its approval becomes
# terminal elsewhere must not resurrect the notification with stale pending content
# afterward (#146 item 4 review — the resolved-during-refresh race) ---------------
# Forced, not hoped for: a barrier on the refresh tick's own daemon query (its
# only external command between reading a — by then already stale — "still
# pending" answer and deciding whether to replace the popup with it) holds that
# query open until the resolver's own terminal replace has already completed, so
# the tick's own with_notiflock check is guaranteed to find pid_file already gone
# — proving the lock actually closes the race rather than merely not having lost
# it by luck on this run.
: >"$MOCK_LOG"
rm -f "$TMP/refresh_query_started" "$TMP/finish_done"
race_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
race_decided='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export RACE_RUNNING=$race_running RACE_DECIDED=$race_decided
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$RACE_RUNNING" ;;
  "session pending --json --all")
    : >"$TMP/refresh_query_started"
    for _ in $(seq 1 300); do [[ -f "$TMP/finish_done" ]] && break; sleep 0.01; done
    printf "%s\n" "$RACE_RUNNING"
    ;;
  "session approvals --json --follow --session sess_a")
    for _ in $(seq 1 300); do [[ -f "$TMP/refresh_query_started" ]] && break; sleep 0.01; done
    printf "%s\n" "$RACE_DECIDED"
    ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# The finish barrier is on this mock's own "-t 4000" replace call (finish_notification's
# only external command): it signals the instant that replace has actually happened,
# which is what the refresh tick above is really waiting to be true before it acts.
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*) echo 8181; exec sleep 30 ;;
  *"-t 4000"*) : >"$TMP/finish_done" ;;
  *) exit 0 ;;
esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# Resolved exactly once, with the outcome — never re-shown as pending afterward,
# and the refresh tick that raced it never got to replace anything at all.
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 8181 Timed out — denied <tt>/work/src/lib.rs</tt>$'
assert_not_logged '^notify-send -a WardOS -c ward-approval -u critical -r 8181'

# --- --watch: a refresh tick already mid-flight when the popup's own action is
# answered (the self-decided/timed-out counterpart of the race above, #250 review)
# must not be able to land more than the one redraw it was already committed to,
# and the notification's own final content must be the real outcome — never that
# stale redraw — because notify_one's own cleanup both retires pid_file and
# corrects the notification in the same locked step, ordered after any in-flight
# tick (#250 review, second round) ------------------------------------------------
# Forced the same way as the race above: the tick's own "-u critical -r" call is
# barriered so it is guaranteed to still be inside with_notiflock, mid-notify-send,
# the instant notify-send --print-id returns "deny". Confirms three things: the
# already in-flight tick is still allowed to finish (with_notiflock does not reach
# into a call already running under the lock — only orders whichever of this and a
# later tick's own check-then-act runs next), that no later tick ever gets that far
# again once pid_file is gone, and that the notification's own last write is the
# real "Denied" outcome, not the tick's stale "still pending" redraw.
: >"$MOCK_LOG"
rm -f "$TMP/orphan_refresh_started" "$TMP/orphan_release" "$TMP/orphan_refresh_done"
orphan_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
export ORPHAN_RUNNING=$orphan_running
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$ORPHAN_RUNNING" ;;
  "session pending --json --all") printf "%s\n" "$ORPHAN_RUNNING" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*) echo 5252; sleep 0.15; echo deny ;;
  *"-u critical -r "*)
    : >"$TMP/orphan_refresh_started"
    for _ in $(seq 1 500); do [[ -f "$TMP/orphan_release" ]] && break; sleep 0.01; done
    : >"$TMP/orphan_refresh_done"
    exit 0 ;;
  *) exit 0 ;;
esac'
# Backgrounded, not run to completion first: notify_one's own fixed cleanup now
# takes with_notiflock before removing pid_file, so it legitimately blocks for as
# long as the tick above is still inside that same lock — "--once" itself does not
# return until every worker has actually finished (#224, the case above), so it
# cannot be used here to observe the tick mid-flight the way the race above did.
# refresh_interval (0.02s) is far shorter than the --print-id delay (0.15s) above
# on purpose: the first tick fires almost immediately and, once it is barriered
# here, holds with_notiflock for as long as the barrier does — refresh_loop is
# strictly sequential (it does not start a next tick until this one's own
# with_notiflock call returns), so nothing else can race in behind it. The
# foreground side holds the barrier well past the --print-id delay before
# releasing it, so notify_one's own cleanup has certainly already reached, and
# is already queued behind, this same lock by the time it opens.
WARDOS_APPROVE_REFRESH_S=0.02 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once &
approve_pid=$!
for _ in $(seq 1 300); do [[ -f "$TMP/orphan_refresh_started" ]] && break; sleep 0.01; done
assert_file "$TMP/orphan_refresh_started"
[[ -f "$TMP/orphan_refresh_done" ]] &&
  fail "the refresh tick's notify-send call must still be an unreleased orphan while notify_one's cleanup waits on it"
sleep 0.3
: >"$TMP/orphan_release"
wait "$approve_pid"
assert_file "$TMP/orphan_refresh_done"
assert_logged '^ward session approve --session sess_a 12 deny$'
# The one already-committed redraw is allowed to land...
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 5252 .*-A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api'
# ...but with_notiflock's ordering means pid_file is already gone by the time any
# later tick could check it, so refresh_loop stops itself rather than looping again.
[[ $(grep -c -- '-u critical -r 5252' "$MOCK_LOG") -le 1 ]] ||
  fail "at most the one already in-flight redraw may land, never another after cleanup: $(cat "$MOCK_LOG")"
# ...and notify_one's own cleanup corrects the notification right after — the
# same lock, requested while the tick above already held it, so this is always
# the next write and therefore the last thing on screen, never the tick's stale
# "still pending" content with dead, actionable-looking buttons.
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 5252 Denied <tt>/work/src/lib.rs</tt>$'
last_pending=$(grep -n -- '-u critical -r 5252' "$MOCK_LOG" | tail -1 | cut -d: -f1)
corrected=$(grep -n -- '-u low -t 4000 -r 5252 Denied' "$MOCK_LOG" | tail -1 | cut -d: -f1)
[[ -n $last_pending && -n $corrected && $corrected -gt $last_pending ]] ||
  fail "the real outcome must be written after every stale redraw, not before: $(cat "$MOCK_LOG")"

# --- --watch: a transient daemon/jq failure on a refresh tick's own query does not
# permanently stop the live refresh — only that one tick is skipped, the same as
# every other command in this loop that can fail (#250 review, second round:
# `current_countdown_for ... || return 0` treated every failure, including a
# passing daemon hiccup, as "nothing left to refresh", contrary to the "skip a
# tick" behaviour this file's own comments already claim for the loop) --------------
: >"$MOCK_LOG"
rm -f "$TMP/transient_ticks"
recovers_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
export RECOVERS_RUNNING=$recovers_running
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$RECOVERS_RUNNING" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session pending --json --all")
    n=$(( $(cat "$TMP/transient_ticks" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" >"$TMP/transient_ticks"
    if (( n == 1 )); then
      echo "ward: daemon unreachable" >&2
      exit 1
    fi
    printf "%s\n" "$RECOVERS_RUNNING"
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 7171; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# The first, failing tick must not be the last: a redraw from a later, succeeding
# tick still lands — the loop survived the one failure instead of exiting on it.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 7171 -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
[[ $(cat "$TMP/transient_ticks" 2>/dev/null || echo 0) -ge 2 ]] ||
  fail "the query must be retried after a transient failure, not abandoned: only $(cat "$TMP/transient_ticks" 2>/dev/null || echo 0) attempt(s)"

# --- --watch: a refresh tick whose representative id resolves elsewhere while an
# exact duplicate is still gathered under the same popup switches to that surviving
# member instead of stopping the whole live refresh (#250 review, second round:
# current_countdown_for failing for one id — because the group's daemon-reported
# membership moved on, not because the daemon or jq failed — must not be read as
# "nothing left to refresh" when a fresh read of the group's own members, right
# there in the next two lines, says otherwise) --------------------------------------
: >"$MOCK_LOG"
rm -f "$TMP/switch_id12_gone" "$TMP/switch_ready"
switch_dup_a=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
switch_dup_b=${line12/\"id\":12/\"id\":14}
switch_dup_b=${switch_dup_b%\}}',"countdown":{"remaining_ms":9001,"timeout_ms":60000,"held":false}}'
switch_decided_12='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"remembered","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export SWITCH_DUP_A=$switch_dup_a SWITCH_DUP_B=$switch_dup_b SWITCH_DECIDED_12=$switch_decided_12
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$SWITCH_DUP_A" "$SWITCH_DUP_B" ;;
  "session approvals --json --follow --session sess_a")
    for _ in $(seq 1 300); do [[ -f "$TMP/switch_ready" ]] && break; sleep 0.01; done
    printf "%s\n" "$SWITCH_DECIDED_12"
    ;;
  "session pending --json --all")
    if [[ -f "$TMP/switch_id12_gone" ]]; then
      printf "%s\n" "$SWITCH_DUP_B"
    else
      printf "%s\n%s\n" "$SWITCH_DUP_A" "$SWITCH_DUP_B"
    fi
    ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 8282; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once &
approve_pid=$!
# id 12 is the group's representative (inserted first): the first tick(s) show
# its own countdown (41001/60000 -> 69 %).
wait_logged '^notify-send -a WardOS -c ward-approval -u critical -r 8282 -h int:value:69 '
# id 12 becomes terminal — resolve_notification removes it from the group's own
# ids file, leaving 14 as the sole surviving member — and, from here on, the
# daemon no longer reports it pending either.
: >"$TMP/switch_id12_gone"
: >"$TMP/switch_ready"
# A later tick must pick up id 14's own countdown (9001/60000 -> 16 %) instead of
# the loop having stopped the moment id 12 stopped being reported.
wait_logged '^notify-send -a WardOS -c ward-approval -u critical -r 8282 -h int:value:16 '
wait "$approve_pid"

# --- --watch: a pause (and resume) that happens after the notification opened is
# reflected on the next refresh tick — the countdown visibly holds, then resumes
# counting, from the daemon's own held/remaining_ms accounting (PR #225), with no
# pause notion of this script's own (#146 item 4's live-refresh half) -------------
: >"$MOCK_LOG"
rm -f "$TMP/pause_ticks"
open_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
after_pause=${line12%\}}',"countdown":{"remaining_ms":20000,"timeout_ms":60000,"held":true}}'
after_resume=${line12%\}}',"countdown":{"remaining_ms":15000,"timeout_ms":60000,"held":false}}'
export OPEN_RUNNING=$open_running AFTER_PAUSE=$after_pause AFTER_RESUME=$after_resume
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$OPEN_RUNNING" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session pending --json --all")
    n=$(( $(cat "$TMP/pause_ticks" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" >"$TMP/pause_ticks"
    if (( n == 1 )); then printf "%s\n" "$AFTER_PAUSE"; else printf "%s\n" "$AFTER_RESUME"; fi
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 4141; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# Opened running: no DECISION TIME block yet, only the progress hint (69 %).
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
# First refresh tick: paused after opening — the same wording a freshly-opened held
# popup already uses, now shown on a refresh of one that opened running; the hint
# holds at the daemon's own reported share (20000/60000 -> 34 %), not still ticking
# down on its own.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 4141 -h int:value:34 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
# Second refresh tick: resumed — the DECISION TIME block is gone again and the hint
# moves on from where the pause left it (15000/60000 -> 25 %), not from 69 % as
# though the pause had never happened.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 4141 -h int:value:25 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
assert_logged '^held while paused · resume the session to answer$'
[[ $(grep -c 'DECISION TIME' "$MOCK_LOG") == 1 ]] ||
  fail "only the paused refresh tick carries a DECISION TIME block: $(cat "$MOCK_LOG")"

# --- shellcheck-clean, usage block, strict mode -----------------------------------
head -1 "$approve" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$approve" || fail "strict mode"


# --- --watch: an already-open notification's countdown/progress hint refreshes in
# place across ticks, from the daemon's own current countdown each time, rather than
# staying frozen at whatever it was when the popup opened (#146 item 4's live-refresh
# half) --------------------------------------------------------------------------
: >"$MOCK_LOG"
rm -f "$TMP/refresh_ticks"
tick1=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
tick2=${line12%\}}',"countdown":{"remaining_ms":9001,"timeout_ms":60000,"held":false}}'
export TICK1=$tick1 TICK2=$tick2
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$RUNNING12" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session pending --json --all")
    n=$(( $(cat "$TMP/refresh_ticks" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" >"$TMP/refresh_ticks"
    if (( n == 1 )); then printf "%s\n" "$TICK1"; else printf "%s\n" "$TICK2"; fi
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# Never itself answers: stays open (--wait, killed only by the round's own
# end-of-round sweep) so a small refresh interval gets several ticks in before then.
mock notify-send 'case "$*" in *--print-id*) echo 3131; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# 41001/60000 -> 69 %, 9001/60000 -> 16 %: the same rounding-up share
# progress_value already uses elsewhere, now read fresh on two different ticks of
# the same still-open popup (notify-send -r 3131, never --print-id again) rather
# than opening — or staying frozen as — one popup for the whole time it is open.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 3131 -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 3131 -h int:value:16 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
[[ $(grep -c -- '--print-id' "$MOCK_LOG") -eq 1 ]] ||
  fail "a refresh tick must never open a second popup: $(cat "$MOCK_LOG")"

# --- --watch: a refresh tick that is already mid-flight when its approval becomes
# terminal elsewhere must not resurrect the notification with stale pending content
# afterward (#146 item 4 review — the resolved-during-refresh race) ---------------
# Forced, not hoped for: a barrier on the refresh tick's own daemon query (its
# only external command between reading a — by then already stale — "still
# pending" answer and deciding whether to replace the popup with it) holds that
# query open until the resolver's own terminal replace has already completed, so
# the tick's own with_notiflock check is guaranteed to find pid_file already gone
# — proving the lock actually closes the race rather than merely not having lost
# it by luck on this run.
: >"$MOCK_LOG"
rm -f "$TMP/refresh_query_started" "$TMP/finish_done"
race_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
race_decided='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"timed-out","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export RACE_RUNNING=$race_running RACE_DECIDED=$race_decided
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$RACE_RUNNING" ;;
  "session pending --json --all")
    : >"$TMP/refresh_query_started"
    for _ in $(seq 1 300); do [[ -f "$TMP/finish_done" ]] && break; sleep 0.01; done
    printf "%s\n" "$RACE_RUNNING"
    ;;
  "session approvals --json --follow --session sess_a")
    for _ in $(seq 1 300); do [[ -f "$TMP/refresh_query_started" ]] && break; sleep 0.01; done
    printf "%s\n" "$RACE_DECIDED"
    ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# The finish barrier is on this mock's own "-t 4000" replace call (finish_notification's
# only external command): it signals the instant that replace has actually happened,
# which is what the refresh tick above is really waiting to be true before it acts.
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*) echo 8181; exec sleep 30 ;;
  *"-t 4000"*) : >"$TMP/finish_done" ;;
  *) exit 0 ;;
esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# Resolved exactly once, with the outcome — never re-shown as pending afterward,
# and the refresh tick that raced it never got to replace anything at all.
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 8181 Timed out — denied <tt>/work/src/lib.rs</tt>$'
assert_not_logged '^notify-send -a WardOS -c ward-approval -u critical -r 8181'

# --- --watch: a refresh tick already mid-flight when the popup's own action is
# answered (the self-decided/timed-out counterpart of the race above, #250 review)
# must not be able to land more than the one redraw it was already committed to,
# and the notification's own final content must be the real outcome — never that
# stale redraw — because notify_one's own cleanup both retires pid_file and
# corrects the notification in the same locked step, ordered after any in-flight
# tick (#250 review, second round) ------------------------------------------------
# Forced the same way as the race above: the tick's own "-u critical -r" call is
# barriered so it is guaranteed to still be inside with_notiflock, mid-notify-send,
# the instant notify-send --print-id returns "deny". Confirms three things: the
# already in-flight tick is still allowed to finish (with_notiflock does not reach
# into a call already running under the lock — only orders whichever of this and a
# later tick's own check-then-act runs next), that no later tick ever gets that far
# again once pid_file is gone, and that the notification's own last write is the
# real "Denied" outcome, not the tick's stale "still pending" redraw.
: >"$MOCK_LOG"
rm -f "$TMP/orphan_refresh_started" "$TMP/orphan_release" "$TMP/orphan_refresh_done"
orphan_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
export ORPHAN_RUNNING=$orphan_running
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$ORPHAN_RUNNING" ;;
  "session pending --json --all") printf "%s\n" "$ORPHAN_RUNNING" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
# shellcheck disable=SC2016
mock notify-send 'case "$*" in
  *--print-id*) echo 5252; sleep 0.15; echo deny ;;
  *"-u critical -r "*)
    : >"$TMP/orphan_refresh_started"
    for _ in $(seq 1 500); do [[ -f "$TMP/orphan_release" ]] && break; sleep 0.01; done
    : >"$TMP/orphan_refresh_done"
    exit 0 ;;
  *) exit 0 ;;
esac'
# Backgrounded, not run to completion first: notify_one's own fixed cleanup now
# takes with_notiflock before removing pid_file, so it legitimately blocks for as
# long as the tick above is still inside that same lock — "--once" itself does not
# return until every worker has actually finished (#224, the case above), so it
# cannot be used here to observe the tick mid-flight the way the race above did.
# refresh_interval (0.02s) is far shorter than the --print-id delay (0.15s) above
# on purpose: the first tick fires almost immediately and, once it is barriered
# here, holds with_notiflock for as long as the barrier does — refresh_loop is
# strictly sequential (it does not start a next tick until this one's own
# with_notiflock call returns), so nothing else can race in behind it. The
# foreground side holds the barrier well past the --print-id delay before
# releasing it, so notify_one's own cleanup has certainly already reached, and
# is already queued behind, this same lock by the time it opens.
WARDOS_APPROVE_REFRESH_S=0.02 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once &
approve_pid=$!
for _ in $(seq 1 300); do [[ -f "$TMP/orphan_refresh_started" ]] && break; sleep 0.01; done
assert_file "$TMP/orphan_refresh_started"
[[ -f "$TMP/orphan_refresh_done" ]] &&
  fail "the refresh tick's notify-send call must still be an unreleased orphan while notify_one's cleanup waits on it"
sleep 0.3
: >"$TMP/orphan_release"
wait "$approve_pid"
assert_file "$TMP/orphan_refresh_done"
assert_logged '^ward session approve --session sess_a 12 deny$'
# The one already-committed redraw is allowed to land...
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 5252 .*-A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api'
# ...but with_notiflock's ordering means pid_file is already gone by the time any
# later tick could check it, so refresh_loop stops itself rather than looping again.
[[ $(grep -c -- '-u critical -r 5252' "$MOCK_LOG") -le 1 ]] ||
  fail "at most the one already in-flight redraw may land, never another after cleanup: $(cat "$MOCK_LOG")"
# ...and notify_one's own cleanup corrects the notification right after — the
# same lock, requested while the tick above already held it, so this is always
# the next write and therefore the last thing on screen, never the tick's stale
# "still pending" content with dead, actionable-looking buttons.
assert_logged '^notify-send -a WardOS -c ward-approval -u low -t 4000 -r 5252 Denied <tt>/work/src/lib.rs</tt>$'
last_pending=$(grep -n -- '-u critical -r 5252' "$MOCK_LOG" | tail -1 | cut -d: -f1)
corrected=$(grep -n -- '-u low -t 4000 -r 5252 Denied' "$MOCK_LOG" | tail -1 | cut -d: -f1)
[[ -n $last_pending && -n $corrected && $corrected -gt $last_pending ]] ||
  fail "the real outcome must be written after every stale redraw, not before: $(cat "$MOCK_LOG")"

# --- --watch: a transient daemon/jq failure on a refresh tick's own query does not
# permanently stop the live refresh — only that one tick is skipped, the same as
# every other command in this loop that can fail (#250 review, second round:
# `current_countdown_for ... || return 0` treated every failure, including a
# passing daemon hiccup, as "nothing left to refresh", contrary to the "skip a
# tick" behaviour this file's own comments already claim for the loop) --------------
: >"$MOCK_LOG"
rm -f "$TMP/transient_ticks"
recovers_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
export RECOVERS_RUNNING=$recovers_running
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$RECOVERS_RUNNING" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session pending --json --all")
    n=$(( $(cat "$TMP/transient_ticks" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" >"$TMP/transient_ticks"
    if (( n == 1 )); then
      echo "ward: daemon unreachable" >&2
      exit 1
    fi
    printf "%s\n" "$RECOVERS_RUNNING"
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 7171; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# The first, failing tick must not be the last: a redraw from a later, succeeding
# tick still lands — the loop survived the one failure instead of exiting on it.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 7171 -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
[[ $(cat "$TMP/transient_ticks" 2>/dev/null || echo 0) -ge 2 ]] ||
  fail "the query must be retried after a transient failure, not abandoned: only $(cat "$TMP/transient_ticks" 2>/dev/null || echo 0) attempt(s)"

# --- --watch: a refresh tick whose representative id resolves elsewhere while an
# exact duplicate is still gathered under the same popup switches to that surviving
# member instead of stopping the whole live refresh (#250 review, second round:
# current_countdown_for failing for one id — because the group's daemon-reported
# membership moved on, not because the daemon or jq failed — must not be read as
# "nothing left to refresh" when a fresh read of the group's own members, right
# there in the next two lines, says otherwise) --------------------------------------
: >"$MOCK_LOG"
rm -f "$TMP/switch_id12_gone" "$TMP/switch_ready"
switch_dup_a=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
switch_dup_b=${line12/\"id\":12/\"id\":14}
switch_dup_b=${switch_dup_b%\}}',"countdown":{"remaining_ms":9001,"timeout_ms":60000,"held":false}}'
switch_decided_12='{"approval":{"id":12,"tool":"Write","summary":"/work/src/lib.rs","claim":"Write /work/src/lib.rs","authority":{"rule":"step-through: pause before writes","destination":"/work/src/lib.rs","network":"none","method":"write","credential":"none","repository":null,"lifetime":"once"},"requested_at_unix_ms":1},"outcome":"remembered","decided_at_unix_ms":9,"agent":"claude","session":"sess_a"}'
export SWITCH_DUP_A=$switch_dup_a SWITCH_DUP_B=$switch_dup_b SWITCH_DECIDED_12=$switch_decided_12
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n%s\n" "$SWITCH_DUP_A" "$SWITCH_DUP_B" ;;
  "session approvals --json --follow --session sess_a")
    for _ in $(seq 1 300); do [[ -f "$TMP/switch_ready" ]] && break; sleep 0.01; done
    printf "%s\n" "$SWITCH_DECIDED_12"
    ;;
  "session pending --json --all")
    if [[ -f "$TMP/switch_id12_gone" ]]; then
      printf "%s\n" "$SWITCH_DUP_B"
    else
      printf "%s\n%s\n" "$SWITCH_DUP_A" "$SWITCH_DUP_B"
    fi
    ;;
  "session approve "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 8282; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once &
approve_pid=$!
# id 12 is the group's representative (inserted first): the first tick(s) show
# its own countdown (41001/60000 -> 69 %).
wait_logged '^notify-send -a WardOS -c ward-approval -u critical -r 8282 -h int:value:69 '
# id 12 becomes terminal — resolve_notification removes it from the group's own
# ids file, leaving 14 as the sole surviving member — and, from here on, the
# daemon no longer reports it pending either.
: >"$TMP/switch_id12_gone"
: >"$TMP/switch_ready"
# A later tick must pick up id 14's own countdown (9001/60000 -> 16 %) instead of
# the loop having stopped the moment id 12 stopped being reported.
wait_logged '^notify-send -a WardOS -c ward-approval -u critical -r 8282 -h int:value:16 '
wait "$approve_pid"

# --- --watch: a pause (and resume) that happens after the notification opened is
# reflected on the next refresh tick — the countdown visibly holds, then resumes
# counting, from the daemon's own held/remaining_ms accounting (PR #225), with no
# pause notion of this script's own (#146 item 4's live-refresh half) -------------
: >"$MOCK_LOG"
rm -f "$TMP/pause_ticks"
open_running=${line12%\}}',"countdown":{"remaining_ms":41001,"timeout_ms":60000,"held":false}}'
after_pause=${line12%\}}',"countdown":{"remaining_ms":20000,"timeout_ms":60000,"held":true}}'
after_resume=${line12%\}}',"countdown":{"remaining_ms":15000,"timeout_ms":60000,"held":false}}'
export OPEN_RUNNING=$open_running AFTER_PAUSE=$after_pause AFTER_RESUME=$after_resume
# shellcheck disable=SC2016
mock ward 'case "$*" in
  "session pending --json --all --follow") printf "%s\n" "$OPEN_RUNNING" ;;
  '"$NOOP_APPROVALS_CASE"'
  "session pending --json --all")
    n=$(( $(cat "$TMP/pause_ticks" 2>/dev/null || echo 0) + 1 ))
    printf "%s\n" "$n" >"$TMP/pause_ticks"
    if (( n == 1 )); then printf "%s\n" "$AFTER_PAUSE"; else printf "%s\n" "$AFTER_RESUME"; fi
    ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac'
mock notify-send 'case "$*" in *--print-id*) echo 4141; exec sleep 30 ;; *) exit 0 ;; esac'
WARDOS_APPROVE_REFRESH_S=0.05 WARDOS_PROJECT=/home/dev/payments-api timeout 10 "$approve" --watch --once
# Opened running: no DECISION TIME block yet, only the progress hint (69 %).
assert_logged '^notify-send -a WardOS -c ward-approval -u critical --wait --print-id -h int:value:69 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
# First refresh tick: paused after opening — the same wording a freshly-opened held
# popup already uses, now shown on a refresh of one that opened running; the hint
# holds at the daemon's own reported share (20000/60000 -> 34 %), not still ticking
# down on its own.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 4141 -h int:value:34 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
# Second refresh tick: resumed — the DECISION TIME block is gone again and the hint
# moves on from where the pause left it (15000/60000 -> 25 %), not from 69 % as
# though the pause had never happened.
assert_logged '^notify-send -a WardOS -c ward-approval -u critical -r 4141 -h int:value:25 -A allow=Allow once -A session=Allow session -A deny=Deny Claude requests · payments-api <span alpha="39322">DESTINATION</span>$'
assert_logged '^held while paused · resume the session to answer$'
[[ $(grep -c 'DECISION TIME' "$MOCK_LOG") == 1 ]] ||
  fail "only the paused refresh tick carries a DECISION TIME block: $(cat "$MOCK_LOG")"

# --- shellcheck-clean, usage block, strict mode -----------------------------------
head -1 "$approve" | grep -q '^#!/usr/bin/env bash$' || fail "shebang"
grep -q '^set -euo pipefail$' "$approve" || fail "strict mode"
